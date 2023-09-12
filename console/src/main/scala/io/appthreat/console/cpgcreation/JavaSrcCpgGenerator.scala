package io.appthreat.console.cpgcreation

import io.appthreat.console.FrontendConfig
import io.appthreat.javasrc2cpg.{Config, JavaSrc2Cpg, Main}
import io.appthreat.console.FrontendConfig
import io.appthreat.x2cpg.X2Cpg
import io.shiftleft.codepropertygraph.Cpg

import java.nio.file.Path
import scala.util.Try

/** Source-based front-end for Java
  */
case class JavaSrcCpgGenerator(config: FrontendConfig, rootPath: Path) extends CpgGenerator {
  private lazy val command: Path = if (isWin) rootPath.resolve("javasrc2cpg.bat") else rootPath.resolve("javasrc2cpg")
  private var javaConfig: Option[Config] = None

  /** Generate a CPG for the given input path. Returns the output path, or None, if no CPG was generated.
    */
  override def generate(inputPath: String, outputPath: String = "cpg.bin"): Try[String] = {
    val arguments = config.cmdLineParams.toSeq ++ Seq(inputPath, "--output", outputPath)
    javaConfig = X2Cpg.parseCommandLine(arguments.toArray, Main.getCmdLineParser, Config())
    runShellCommand(command.toString, arguments).map(_ => outputPath)
  }

  override def applyPostProcessingPasses(cpg: Cpg): Cpg = {
    if (javaConfig.forall(_.enableTypeRecovery))
      JavaSrc2Cpg.typeRecoveryPasses(cpg, javaConfig).foreach(_.createAndApply())
    super.applyPostProcessingPasses(cpg)
  }

  override def isAvailable: Boolean =
    command.toFile.exists

  override def isJvmBased = true
}
