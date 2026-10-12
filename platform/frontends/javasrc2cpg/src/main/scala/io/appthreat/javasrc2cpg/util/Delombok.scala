package io.appthreat.javasrc2cpg.util

import better.files.File
import io.appthreat.x2cpg.utils.ExternalCommand
import Delombok.DelombokMode.*
import org.slf4j.LoggerFactory

import java.nio.file.Paths
import scala.util.{Failure, Success, Try}

object Delombok:

  sealed trait DelombokMode
  // Don't run delombok at all.
  object DelombokMode:
    case object NoDelombok  extends DelombokMode
    case object Default     extends DelombokMode
    case object TypesOnly   extends DelombokMode
    case object RunDelombok extends DelombokMode

  private val logger = LoggerFactory.getLogger(this.getClass)

  private def systemJavaPath: String =
      sys.env
          .get("JAVA_HOME")
          .flatMap { javaHome =>
            val javaExecutable = File(javaHome, "bin", "java")
            Option.when(javaExecutable.exists && javaExecutable.isExecutable) {
                javaExecutable.canonicalPath
            }
          }
          .getOrElse("java")

  /** The classpath for the forked delombok `java`: this JVM's `java.class.path`, plus the jar
    * holding lombok when the property does not already name it. sbt 2 runs forked tests in a worker
    * whose `java.class.path` only holds the sbt worker jars (the test classpath lives on a
    * classloader); packaged and plain `java -cp` runs already carry lombok, directly or through a
    * launcher jar's manifest, where the extra entry is harmless.
    */
  private lazy val forkClasspath: String =
    val separator = java.io.File.pathSeparator
    val property  = Option(System.getProperty("java.class.path")).getOrElse("")
    val entries   = property.split(separator).filter(_.nonEmpty).toSeq
    val lombokJar = Try {
        val location = Class
            .forName("lombok.launch.Main", false, getClass.getClassLoader)
            .getProtectionDomain
            .getCodeSource
            .getLocation
        Paths.get(location.toURI).toAbsolutePath.toString
    }.toOption
    val listed = entries.map(e => Try(Paths.get(e).toAbsolutePath.toString).getOrElse(e)).toSet
    (entries ++ lombokJar.filterNot(listed.contains)).mkString(separator)

  private def delombokToTempDirCommand(tempDir: File, analysisJavaHome: Option[String]) =
    val javaPath = analysisJavaHome.getOrElse(systemJavaPath)
    val classPathArg = Try(File.newTemporaryFile("classpath").deleteOnExit()) match
      case Success(file) =>
          if forkClasspath.nonEmpty then
            // Write classpath to a file to work around Windows length limits.
            file.write(forkClasspath)
            s"@${file.canonicalPath}"
          else forkClasspath
      case Failure(t) =>
          logger.debug(
            s"Failed to create classpath file for delombok execution. Results may be missing on Windows systems"
          )
          forkClasspath
    if classPathArg.nonEmpty then
      s"$javaPath -cp $classPathArg lombok.launch.Main delombok . -d ${tempDir.canonicalPath}"
    else ""

  def run(projectDir: String, analysisJavaHome: Option[String]): String =
      Try(File.newTemporaryDirectory(prefix = "delombok").deleteOnExit()) match
        case Success(tempDir) =>
            val externalCommand = delombokToTempDirCommand(tempDir, analysisJavaHome)
            if externalCommand.nonEmpty then
              ExternalCommand.run(
                externalCommand,
                cwd = projectDir
              ) match
                case Success(_) =>
                    tempDir.path.toAbsolutePath.toString

                case Failure(t) =>
                    logger.debug(s"Executing delombok failed", t)
                    logger.debug(
                      "Creating AST with original source instead. Some methods and type information will be missing."
                    )
                    projectDir
            else ""

        case Failure(e) =>
            logger.debug(
              s"Failed to create temporary directory for delomboked source. Methods and types may be missing",
              e
            )
            projectDir

  def parseDelombokModeOption(delombokModeStr: Option[String]): DelombokMode =
      delombokModeStr.map(_.toLowerCase) match
        case None                 => Default
        case Some("no-delombok")  => NoDelombok
        case Some("default")      => Default
        case Some("types-only")   => TypesOnly
        case Some("run-delombok") => RunDelombok
        case Some(value) =>
            logger.debug(s"Found unrecognised delombok mode `$value`. Using default instead.")
            Default
end Delombok
