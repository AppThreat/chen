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
  private lazy val command: String       = sys.env.getOrElse("ATOM_CMD", "atom")
  private lazy val cdxgenCommand: String = sys.env.getOrElse("CDXGEN_CMD", "cdxgen")

  /** Generate an atom for the given input path. Returns the output path, or None, if no CPG was
    * generated.
    */
  override def generate(inputPath: String, outputPath: String = "app.atom"): Try[String] =
    // If there is no bom.json file in the root directory, attempt to automatically invoke cdxgen
    val bomPath = File(inputPath) / "bom.json"
    if !bomPath.exists then
      val cdxLanguage = language.toLowerCase().replace("src", "")
      val arguments = Seq(
        "-t",
        cdxLanguage,
        "--deep",
        "-o",
        (File(inputPath) / "bom.json").pathAsString,
        inputPath
      )
      runShellCommand(cdxgenCommand, arguments)
    val arguments = Seq(
      sliceMode,
      "-s",
      (File(inputPath) / slicesFile).pathAsString,
      "--output",
      (File(inputPath) / outputPath).pathAsString,
      "--language",
      language,
      inputPath
    ) ++ config.cmdLineParams
    runShellCommand(command, arguments).map(_ => (File(inputPath) / outputPath).pathAsString)
  end generate

  override def isAvailable: Boolean = true

  override def applyPostProcessingPasses(atom: Cpg): Cpg =
      atom

  override def isJvmBased = false
end AtomGenerator
