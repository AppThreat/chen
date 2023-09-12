package io.appthreat.console.cpgcreation

import io.appthreat.console.FrontendConfig
import io.appthreat.console.FrontendConfig

import java.nio.file.Path
import scala.util.Try

case class JsCpgGenerator(config: FrontendConfig, rootPath: Path) extends CpgGenerator {
  private lazy val command: Path = if (isWin) rootPath.resolve("js2cpg.bat") else rootPath.resolve("js2cpg.sh")

  /** Generate a CPG for the given input path. Returns the output path, or None, if no CPG was generated.
    */
  override def generate(inputPath: String, outputPath: String = "app.atom"): Try[String] = {
    val arguments = Seq(inputPath, "--output", outputPath) ++ config.cmdLineParams
    runShellCommand(command.toString, arguments).map(_ => outputPath)
  }

  override def isAvailable: Boolean =
    command.toFile.exists

  override def isJvmBased = true
}
