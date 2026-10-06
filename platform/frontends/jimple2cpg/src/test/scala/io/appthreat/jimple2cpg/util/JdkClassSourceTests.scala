package io.appthreat.jimple2cpg.util

import io.appthreat.jimple2cpg.util.JdkClasses.*
import org.scalatest.BeforeAndAfterEach
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import soot.asm.AsmClassSource
import soot.{G, ModulePathSourceLocator, Scene, SourceLocator}

import java.io.File as JFile
import java.nio.file.{Files, Path, Paths}
import java.util.zip.{ZipEntry, ZipOutputStream}
import scala.util.{Try, Using}

class JdkClassSourceTests extends AnyWordSpec with Matchers with BeforeAndAfterEach:

  private val realHome  = Paths.get(System.getProperty("java.home"))
  private val realImage = JImage.imageFile(realHome)

  override protected def afterEach(): Unit =
    G.reset()
    super.afterEach()

  private def tempDir(prefix: String): Path =
    val dir = Files.createTempDirectory(prefix)
    dir.toFile.deleteOnExit()
    dir

  /** A JDK 9+ home whose lib/modules is the running JDK's image. */
  private def fakeModularHome(root: Path, name: String, version: String): Path =
    val home = Files.createDirectories(root.resolve(name))
    Files.createDirectories(home.resolve("lib"))
    Try(Files.createSymbolicLink(JImage.imageFile(home), realImage))
        .orElse(Try(Files.copy(realImage, JImage.imageFile(home))))
        .getOrElse(cancel("cannot link or copy lib/modules"))
    Files.writeString(home.resolve("release"), s"JAVA_VERSION=\"$version\"\n")
    home

  /** A JDK 8 home with jre/lib/rt.jar and jce.jar (empty archives). */
  private def fakeJdk8Home(root: Path): Path =
    val home = root.resolve("jdk8")
    val lib  = Files.createDirectories(home.resolve("jre").resolve("lib"))
    for jar <- List("rt.jar", "jce.jar") do
      Using.resource(new ZipOutputStream(Files.newOutputStream(lib.resolve(jar)))) { zip =>
        zip.putNextEntry(new ZipEntry("java/lang/"))
        zip.closeEntry()
      }
    Files.writeString(home.resolve("release"), "JAVA_VERSION=\"1.8.0_412\"\n")
    home

  /** An environment without any JDK and without jrt:/, like a native image on a bare machine. */
  private def bareNative(
    env: Map[String, String] = Map.empty,
    props: Map[String, String] = Map.empty,
    roots: List[Path] = Nil
  ): JdkEnvironment =
      JdkEnvironment(env = env, props = props, jrtAvailable = () => false, wellKnownRoots = roots)

  "JdkClassSource.resolve" should {
      "use Soot's jrt:/ lookup on the JVM" in {
          JdkClassSource.resolve(None) shouldBe Platform
          JdkClassSource.jrtAvailable shouldBe true
      }

      "use JAVA_HOME's image when jrt:/ is unavailable (native image)" in {
          val home = fakeModularHome(tempDir("jdk-env"), "jdk", "21.0.7")
          JdkClassSource.resolve(None, bareNative(env = Map("JAVA_HOME" -> home.toString))) match
            case Image(h, image) =>
                h shouldBe home
                image.containsClass("java/lang/Object") shouldBe true
            case other => fail(s"unexpected $other")
      }

      "prefer ATOM_JAVA_HOME over JAVA_HOME" in {
          val root  = tempDir("jdk-pref")
          val atom  = fakeModularHome(root, "atom-jdk", "25")
          val other = fakeModularHome(root, "other-jdk", "21")
          val env   = Map("JAVA_HOME" -> other.toString, "ATOM_JAVA_HOME" -> atom.toString)
          JdkClassSource.resolve(None, bareNative(env = env)) match
            case Image(h, _) => h shouldBe atom
            case other       => fail(s"unexpected $other")
      }

      "skip environment entries that are not JDK homes" in {
          val root  = tempDir("jdk-skip")
          val valid = fakeModularHome(root, "jdk", "23")
          val env = Map(
            "ATOM_JAVA_HOME" -> root.resolve("missing").toString,
            "JAVA_HOME"      -> Files.createDirectories(root.resolve("empty")).toString,
            "JDK_HOME"       -> valid.toString
          )
          JdkClassSource.resolve(None, bareNative(env = env)) match
            case Image(h, _) => h shouldBe valid
            case other       => fail(s"unexpected $other")
      }

      "use a java.home passed to the native image" in {
          val home = fakeModularHome(tempDir("jdk-prop"), "jdk", "25")
          JdkClassSource.resolve(None, bareNative(props = Map("java.home" -> home.toString))) match
            case Image(h, _) => h shouldBe home
            case other       => fail(s"unexpected $other")
      }

      "follow the java executable on PATH to its JDK home" in {
          val root = tempDir("jdk-path")
          val home = fakeModularHome(root, "jdk", "25")
          val bin  = Files.createDirectories(home.resolve("bin"))
          val java = Files.writeString(bin.resolve(if isWindows then "java.exe" else "java"), "")
          java.toFile.setExecutable(true)
          // /usr/bin/java -> <home>/bin/java, as alternatives and Homebrew lay it out.
          val usrBin  = Files.createDirectories(root.resolve("usr").resolve("bin"))
          val link    = Try(Files.createSymbolicLink(usrBin.resolve(java.getFileName), java))
          val pathDir = if link.isSuccess then usrBin else bin
          val env     = Map("PATH" -> s"${root.resolve("nothing")}${JFile.pathSeparator}$pathDir")
          JdkClassSource.resolve(None, bareNative(env = env)) match
            case Image(h, _) => h.toRealPath() shouldBe home.toRealPath()
            case other       => fail(s"unexpected $other")
      }

      "pick the newest JDK under a well-known install root" in {
          val root = tempDir("jdk-roots")
          fakeModularHome(root, "temurin-17", "17.0.19")
          val newest = fakeModularHome(root, "temurin-25", "25.0.1")
          fakeModularHome(root, "temurin-21", "21.0.7")
          // A macOS bundle: the home is Contents/Home.
          val macRoot = tempDir("jdk-mac")
          val bundle  = Files.createDirectories(macRoot.resolve("zulu-26.jdk").resolve("Contents"))
          val macHome = fakeModularHome(bundle, "Home", "26.0.2")
          JdkClassSource.resolve(None, bareNative(roots = List(root))) match
            case Image(h, _) => h shouldBe newest
            case other       => fail(s"unexpected $other")
          JdkClassSource.resolve(None, bareNative(roots = List(macRoot, root))) match
            case Image(h, _) => h shouldBe macHome
            case other       => fail(s"unexpected $other")
      }

      "use a JDK 8 rt.jar" in {
          val home = fakeJdk8Home(tempDir("jdk8"))
          JdkClassSource.resolve(None, bareNative(env = Map("JAVA_HOME" -> home.toString))) match
            case Jars(h, jars) =>
                h shouldBe home
                jars.map(_.getFileName.toString) shouldBe List("rt.jar", "jce.jar")
            case other => fail(s"unexpected $other")
      }

      "honour an explicit JDK home, also on the JVM" in {
          val home = fakeModularHome(tempDir("jdk-explicit"), "jdk", "21")
          JdkClassSource.resolve(Some(home.toString)) match
            case Image(h, _) => h shouldBe home
            case other       => fail(s"unexpected $other")
      }

      "fall back when the explicit JDK home is invalid" in {
          val bogus = tempDir("jdk-bogus").toString
          JdkClassSource.resolve(Some(bogus)) shouldBe Platform
          val home = fakeModularHome(tempDir("jdk-fallback"), "jdk", "21")
          JdkClassSource.resolve(
            Some(bogus),
            bareNative(env = Map("JAVA_HOME" -> home.toString))
          ) match
            case Image(h, _) => h shouldBe home
            case other       => fail(s"unexpected $other")
      }

      "report what was searched when no JDK exists" in {
          val missing = tempDir("jdk-none").resolve("nope")
          JdkClassSource.resolve(None, bareNative(env = Map("JAVA_HOME" -> missing.toString))) match
            case Missing(searched) =>
                searched should contain(missing.toString)
            case other => fail(s"unexpected $other")
      }

      "reject a lib/modules that is not a jimage" in {
          val home = Files.createDirectories(tempDir("jdk-corrupt").resolve("jdk").resolve("lib"))
              .getParent
          Files.writeString(JImage.imageFile(home), "garbage")
          JdkClassSource.resolve(
            None,
            bareNative(env = Map("JAVA_HOME" -> home.toString))
          ) shouldBe a[Missing]
      }

      "follow the mode property" in {
          val home = fakeModularHome(tempDir("jdk-mode"), "jdk", "21")
          val env  = Map("JAVA_HOME" -> home.toString)
          def withMode(mode: String) =
              JdkEnvironment(
                env = env,
                props = Map(ModeProperty -> mode),
                jrtAvailable = () => true
              )
          JdkClassSource.resolve(None, withMode("none")) shouldBe Missing(Nil)
          JdkClassSource.resolve(None, withMode("platform")) shouldBe Platform
          JdkClassSource.resolve(None, withMode("auto")) shouldBe Platform
          JdkClassSource.resolve(None, withMode("bogus")) shouldBe Platform
          JdkClassSource.resolve(None, withMode(" IMAGE ")) shouldBe a[Image]
          JdkClassSource.resolve(
            None,
            JdkEnvironment(
              env = env + (ModeEnv -> "image"),
              props = Map.empty,
              jrtAvailable = () => true
            )
          ) shouldBe a[Image]
      }
  }

  "JdkClassSource.featureVersion" should {
      "parse release versions" in {
          JdkClassSource.featureVersion("1.8.0_412") shouldBe 8
          JdkClassSource.featureVersion("21.0.7") shouldBe 21
          JdkClassSource.featureVersion("26-ea") shouldBe 26
          JdkClassSource.featureVersion("25") shouldBe 25
          JdkClassSource.featureVersion("") shouldBe 0
          JdkClassSource.featureVersion("abc") shouldBe 0
      }
  }

  "JdkClassSource.configureSoot" should {
      "serve JDK classes from the image without Soot's jrt:/ mode" in {
          val app = tempDir("soot-app").toString
          val jdk = JdkClassSource.fromHome(realHome).get
          jdk shouldBe a[Image]
          JdkClassSource.configureSoot(jdk, Seq(app, "")) shouldBe app
          val cp = Scene.v().getSootClassPath
          (cp should not).include(ModulePathSourceLocator.DUMMY_CLASSPATH_JDK9_FS)
          val source = SourceLocator.v().getClassSource("java.lang.Object")
          source shouldBe a[AsmClassSource]
          SourceLocator.v().getClassSource("java.security.MessageDigest") should not be null
          SourceLocator.v().getClassSource("com.example.Missing") shouldBe null
          Scene.v().isBasicClass("java.lang.invoke.StringConcatFactory") shouldBe true
      }

      "keep Soot's default class path on the JVM" in {
          val app = tempDir("soot-platform").toString
          JdkClassSource.configureSoot(Platform, Seq(app))
          Scene.v().getSootClassPath should include(ModulePathSourceLocator.DUMMY_CLASSPATH_JDK9_FS)
      }

      "put JDK 8 jars on the class path" in {
          val app  = tempDir("soot-jdk8").toString
          val home = fakeJdk8Home(tempDir("jdk8-soot"))
          val cp   = JdkClassSource.configureSoot(JdkClassSource.fromHome(home).get, Seq(app))
          cp should include("rt.jar")
          (Scene.v().getSootClassPath should not).include(
            ModulePathSourceLocator.DUMMY_CLASSPATH_JDK9_FS
          )
      }

      "leave the JDK out when none was found" in {
          val app = tempDir("soot-missing").toString
          JdkClassSource.configureSoot(Missing(Nil), Seq(app)) shouldBe app
          (Scene.v().getSootClassPath should not).include(
            ModulePathSourceLocator.DUMMY_CLASSPATH_JDK9_FS
          )
      }
  }

  private def isWindows = System.getProperty("os.name").toLowerCase.contains("win")
end JdkClassSourceTests
