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

  private def delombokToTempDirCommand(tempDir: File, analysisJavaHome: Option[String]) =
    val javaPath = analysisJavaHome.getOrElse(systemJavaPath)
    val classPathArg = Try(File.newTemporaryFile("classpath").deleteOnExit()) match
      case Success(file) =>
          if System.getProperty("java.class.path").nonEmpty then
            // Write classpath to a file to work around Windows length limits.
            file.write(System.getProperty("java.class.path"))
            s"@${file.canonicalPath}"
          else System.getProperty("java.class.path")
      case Failure(t) =>
          logger.debug(
            s"Failed to create classpath file for delombok execution. Results may be missing on Windows systems"
          )
          System.getProperty("java.class.path")
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
