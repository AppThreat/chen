package io.appthreat.jimple2cpg.util

import org.slf4j.LoggerFactory
import soot.asm.{AsmClassProvider, AsmClassSource}
import soot.{ClassProvider, ClassSource, IFoundFile, JimpleClassProvider, Scene, SourceLocator}

import java.io.{ByteArrayInputStream, File as JFile, InputStream}
import java.net.URI
import java.nio.file.{Files, Path, Paths}
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.ZipFile
import scala.jdk.CollectionConverters.*
import scala.util.{Try, Using}

/** Where Soot reads the JDK classes (`java.lang.Object`, `java.security.MessageDigest`, ...) of the
  * analysed program from.
  *
  * Soot looks JDK 9+ classes up in the `jrt:/` file system of the running JVM. A GraalVM native
  * image has no usable `jrt:/` file system (and no `java.home`), so in a native image the classes
  * of an installed JDK are read straight from its `lib/modules` image instead.
  */
sealed trait JdkClasses:
  /** A one-line description for logs and diagnostics. */
  def describe: String

object JdkClasses:

  /** Soot's own lookup through the running JVM's `jrt:/` file system. */
  case object Platform extends JdkClasses:
    def describe: String = "the running JVM (jrt:/)"

  /** The classes of a JDK 9+ installation, read from its `lib/modules` image. */
  final case class Image(home: Path, image: JImage) extends JdkClasses:
    def describe: String = s"the JDK at $home (${JImage.imageFile(home)})"

  /** The class path jars (`rt.jar`, ...) of a JDK 8 installation. */
  final case class Jars(home: Path, jars: List[Path]) extends JdkClasses:
    def describe: String = s"the JDK at $home (${jars.mkString(JFile.pathSeparator)})"

  /** No JDK could be found: JDK types stay phantom, so the hierarchy above them is unknown. */
  final case class Missing(searched: List[String]) extends JdkClasses:
    def describe: String =
        if searched.isEmpty then "no JDK" else s"no JDK (searched ${searched.mkString(", ")})"

  /** Selects the strategy: `auto` (default), `platform` (Soot's jrt:/ lookup), `image` (always an
    * installed JDK's image, even on the JVM) or `none` (no JDK classes).
    */
  val ModeProperty = "chen.jimple.jdk-classes"
  val ModeEnv      = "CHEN_JIMPLE_JDK_CLASSES"

  /** Environment variables that may name a JDK home, in order of preference. */
  val HomeEnvVars: List[String] = List("ATOM_JAVA_HOME", "JAVA_HOME", "JDK_HOME")
end JdkClasses

/** The process environment that JDK discovery depends on, injectable for tests. */
final case class JdkEnvironment(
  env: Map[String, String] = sys.env,
  props: Map[String, String] = sys.props.toMap,
  jrtAvailable: () => Boolean = () => JdkClassSource.jrtAvailable,
  wellKnownRoots: List[Path] = JdkClassSource.defaultWellKnownRoots
)

object JdkClassSource:

  import JdkClasses.*

  private val logger = LoggerFactory.getLogger(getClass)

  /** Opened images, by real path: the mapping is read-only and reused across frontend runs. */
  private val images = new ConcurrentHashMap[Path, JImage]()

  /** Whether this runtime can read its own classes through `jrt:/`, as Soot does. False in a
    * GraalVM native image, where the provider is missing or does not serve the JDK modules.
    */
  lazy val jrtAvailable: Boolean = Try {
      Files.isRegularFile(jrtModulesRoot.resolve("java.base/java/lang/Object.class"))
  }.getOrElse(false)

  /** The `modules` directory of jrt:/, located as Soot's `getRootModulesPathOfJDK` does:
    * `Paths.get("jrt:/")` is `/modules` on some JDKs and `/` on others (JDK-8227076).
    */
  private[jimple2cpg] def jrtModulesRoot: Path =
    val root = Paths.get(URI.create("jrt:/"))
    if root.endsWith("modules") then root else root.resolve("modules")

  /** Resolve where the JDK classes come from.
    *
    * @param explicitHome
    *   A JDK home requested by the user (`--jdk-path`). Used whenever it is a valid JDK, also on
    *   the JVM.
    */
  def resolve(
    explicitHome: Option[String],
    environment: JdkEnvironment = JdkEnvironment()
  ): JdkClasses =
    val mode = environment.props.get(ModeProperty)
        .orElse(environment.env.get(ModeEnv))
        .map(_.trim.toLowerCase(Locale.ROOT))
        .filter(_.nonEmpty)
        .getOrElse("auto")
    val explicit = explicitHome.map(_.trim).filter(_.nonEmpty)
    mode match
      case "none"     => Missing(Nil)
      case "platform" => Platform
      case "image"    => discover(explicit, environment)
      case other =>
          if other != "auto" then
            logger.warn(s"Unknown $ModeProperty value '$other'; using 'auto'.")
          explicit.flatMap(home => fromHome(Paths.get(home))) match
            case Some(found) => found
            case None =>
                explicit.foreach(home =>
                    logger.warn(
                      s"'$home' is not a JDK home (no lib/modules or rt.jar); ignoring it."
                    )
                )
                if environment.jrtAvailable() then Platform else discover(None, environment)
  end resolve

  /** Find an installed JDK without the help of `jrt:/`. */
  private def discover(explicit: Option[String], environment: JdkEnvironment): JdkClasses =
    val candidates = candidateHomes(explicit, environment)
    candidates.iterator.flatMap(fromHome).nextOption() match
      case Some(found) => found
      case None        => Missing(candidates.map(_.toString).distinct)

  /** Candidate JDK homes, most specific first. */
  private[util] def candidateHomes(
    explicit: Option[String],
    environment: JdkEnvironment
  ): List[Path] =
    val fromConfig = explicit.toList.flatMap(toPath)
    val fromEnv    = JdkClasses.HomeEnvVars.flatMap(environment.env.get).flatMap(toPath)
    // A native image has no java.home unless one is passed with -Djava.home.
    val fromProps = environment.props.get("java.home").toList.flatMap(toPath)
    val fromPath  = environment.env.get("PATH").toList.flatMap(javaHomesOnPath)
    val installed = environment.wellKnownRoots.flatMap(installedHomes)
    (fromConfig ++ fromEnv ++ fromProps ++ fromPath ++ installed).distinct

  private def toPath(s: String): Option[Path] =
      Option(s).map(_.trim).filter(_.nonEmpty).flatMap(p => Try(Paths.get(p)).toOption)

  /** The homes of the `java` executables on PATH, following symlinks (`/usr/bin/java` ->
    * `/usr/lib/jvm/x/bin/java`). A JDK 8 `jre/bin/java` maps to the JDK above it.
    */
  private def javaHomesOnPath(pathEnv: String): List[Path] =
    val exe = if isWindows then List("java.exe") else List("java")
    pathEnv.split(JFile.pathSeparator).toList.flatMap(toPath).flatMap { dir =>
        exe.map(dir.resolve).filter(Files.isExecutable).flatMap { java =>
            Try(java.toRealPath()).toOption.flatMap(real => Option(real.getParent))
                .flatMap(bin => Option(bin.getParent))
                .toList
                .flatMap { home =>
                    if home.getFileName != null && home.getFileName.toString == "jre" then
                      Option(home.getParent).toList :+ home
                    else List(home)
                }
        }
    }

  /** The JDK homes directly under a well-known installation root, newest first. */
  private def installedHomes(root: Path): List[Path] =
      if !Files.isDirectory(root) then Nil
      else
        Try(Using.resource(Files.list(root))(_.iterator().asScala.toList)).getOrElse(Nil)
            .flatMap { dir =>
              // macOS bundles keep the home in Contents/Home.
              val macHome = dir.resolve("Contents").resolve("Home")
              if Files.isDirectory(macHome) then Some(macHome)
              else if Files.isDirectory(dir) then Some(dir)
              else None
            }
            .sortBy(home => javaVersion(home))(using Ordering[Int].reverse)

  /** The feature version of a JDK home from its `release` file, or 0 when unknown. */
  private[util] def javaVersion(home: Path): Int =
      Try {
          Using.resource(scala.io.Source.fromFile(home.resolve("release").toFile)) { src =>
              src.getLines()
                  .collectFirst {
                      case line if line.startsWith("JAVA_VERSION=") =>
                          line.stripPrefix("JAVA_VERSION=").replace("\"", "")
                  }
                  .map(featureVersion)
                  .getOrElse(0)
          }
      }.getOrElse(0)

  /** `1.8.0_412` -> 8, `21.0.7` -> 21, `26-ea` -> 26. */
  private[util] def featureVersion(version: String): Int =
    val parts = version.takeWhile(c => c.isDigit || c == '.').split('.').filter(_.nonEmpty)
    parts.headOption.flatMap(_.toIntOption) match
      case Some(1) => parts.lift(1).flatMap(_.toIntOption).getOrElse(0)
      case Some(v) => v
      case None    => 0

  /** The JDK classes of a home: its jimage (JDK 9+) or its rt.jar (JDK 8). */
  def fromHome(home: Path): Option[JdkClasses] =
    val imageFile = JImage.imageFile(home)
    if Files.isRegularFile(imageFile) then
      openImage(imageFile) match
        case Some(image) => Some(Image(home, image))
        case None        => None
    else
      val libs = List(home.resolve("jre").resolve("lib"), home.resolve("lib"))
      libs.find(lib => Files.isRegularFile(lib.resolve("rt.jar"))).map { lib =>
        // jce.jar holds javax.crypto, which rt.jar classes refer to.
        val jars = List("rt.jar", "jce.jar", "jsse.jar").map(lib.resolve).filter(p =>
            Files.isRegularFile(p)
        )
        Jars(home, jars)
      }

  private def openImage(file: Path): Option[JImage] =
    val key = Try(file.toRealPath()).getOrElse(file.toAbsolutePath)
    Option(images.get(key)).orElse {
        JImage.open(key) match
          case scala.util.Success(image) if image.containsClass("java/lang/Object") =>
              images.putIfAbsent(key, image)
              Some(images.get(key))
          case scala.util.Success(_) =>
              logger.warn(s"'$file' holds no java.lang.Object; not using it as the JDK.")
              None
          case scala.util.Failure(err) =>
              logger.warn(s"Unable to read the JDK image '$file': ${err.getMessage}")
              None
    }

  private def isWindows: Boolean =
      sys.props.getOrElse("os.name", "").toLowerCase(Locale.ROOT).contains("win")

  /** Where JDKs are commonly installed, for when no environment variable or PATH entry names one.
    */
  def defaultWellKnownRoots: List[Path] =
    val home = sys.props.get("user.home").toList
    val roots =
        if isWindows then
          List("Java", "Eclipse Adoptium", "Microsoft", "Zulu", "Amazon Corretto", "BellSoft")
              .flatMap(vendor =>
                  sys.env.get("ProgramFiles").toList.map(pf => s"$pf${JFile.separator}$vendor")
              )
        else
          List(
            "/Library/Java/JavaVirtualMachines",
            "/usr/lib/jvm",
            "/usr/java",
            "/opt/java"
          ) ++ home.flatMap(h =>
              List(
                s"$h/Library/Java/JavaVirtualMachines",
                s"$h/.sdkman/candidates/java",
                s"$h/.jdks"
              )
          )
    roots.flatMap(toPath)
  end defaultWellKnownRoots

  /** Configure Soot's class path and class providers to read JDK classes from `jdk`.
    *
    * @param appClassPath
    *   The application class path entries (extracted classes, the scala library, ...).
    * @return
    *   The Soot class path that was set.
    */
  def configureSoot(jdk: JdkClasses, appClassPath: Seq[String]): String =
    val options = soot.options.Options.v()
    val appCp   = appClassPath.filter(_.nonEmpty)
    jdk match
      case Platform =>
          // Soot appends the running JVM's default class path (jrt:/ on JDK 9+).
          val cp = appCp.mkString(JFile.pathSeparator)
          options.set_soot_classpath(cp)
          options.set_prepend_classpath(true)
          cp
      case Jars(_, jars) =>
          val cp = (appCp ++ jars.map(_.toString)).mkString(JFile.pathSeparator)
          options.set_soot_classpath(cp)
          options.set_prepend_classpath(false)
          cp
      case Image(_, image) =>
          val cp = appCp.mkString(JFile.pathSeparator)
          options.set_soot_classpath(cp)
          // Without the default class path Soot never enters its jrt:/ (java9) mode.
          options.set_prepend_classpath(false)
          // Soot adds this basic class itself when it builds the default JDK 9+ class path.
          Scene.v().addBasicClass("java.lang.invoke.StringConcatFactory")
          // The providers Soot would set up for src-prec class, with the JDK image last, where
          // Soot puts its jrt:/ provider.
          SourceLocator.v().setClassProviders(
            new java.util.LinkedList[ClassProvider](
              java.util.List.of(
                new AsmClassProvider(),
                new JimpleClassProvider(),
                new JImageClassProvider(image)
              )
            )
          )
          cp
      case Missing(_) =>
          val cp = appCp.mkString(JFile.pathSeparator)
          options.set_soot_classpath(cp)
          options.set_prepend_classpath(false)
          cp
    end match
  end configureSoot
end JdkClassSource

/** Serves classes from a JDK image to Soot, in place of Soot's jrt:/ provider. */
final class JImageClassProvider(image: JImage) extends ClassProvider:
  override def find(className: String): ClassSource =
    val internalName = className.replace('.', '/')
    image.readClass(internalName) match
      case Some(bytes) =>
          new AsmClassSource(className, new JImageFoundFile(image, internalName, bytes))
      case None => null

/** A class file read from a JDK image. */
final class JImageFoundFile(image: JImage, internalName: String, bytes: Array[Byte])
    extends IFoundFile:
  override def getFilePath: String        = image.path.toString
  override def isZipFile: Boolean         = false
  override def getZipFile: ZipFile        = null
  override def getFile: JFile             = image.path.toFile
  override def getAbsolutePath: String    = s"${image.path}!/$internalName.class"
  override def inputStream(): InputStream = new ByteArrayInputStream(bytes)
  override def close(): Unit              = ()
