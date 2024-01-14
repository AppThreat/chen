package io.appthreat.console.cpgcreation

import better.files.File
import io.appthreat.console.FrontendConfig
import io.shiftleft.codepropertygraph.Cpg

import java.nio.file.Path
import scala.util.Try

case class AtomGenerator(
  config: FrontendConfig,
  rootPath: Path,
  language: String,
  sliceMode: String = "reachables",
  slicesFile: String = "reachables.slices.json"
) extends CpgGenerator:
    private lazy val command: String = "atom"

    /** Generate an atom for the given input path. Returns the output path, or None, if no CPG was
      * generated.
      */
    override def generate(inputPath: String, outputPath: String = "app.atom"): Try[String] =
        val arguments = Seq(
          sliceMode,
          "-s",
          slicesFile,
          "--output",
          (File(inputPath) / outputPath).pathAsString,
          "--language",
          language,
          inputPath
        ) ++ config.cmdLineParams
        runShellCommand(command, arguments).map(_ => (File(inputPath) / outputPath).pathAsString)

    override def isAvailable: Boolean = true

    override def applyPostProcessingPasses(atom: Cpg): Cpg =
        atom

    override def isJvmBased = false
end AtomGenerator
