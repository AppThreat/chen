package io.appthreat.console.cpgcreation

import io.appthreat.console.FrontendConfig
import io.shiftleft.codepropertygraph.Cpg

import java.nio.file.Path
import scala.util.Try
import better.files.File
import better.files.File.LinkOptions

case class CdxGenerator(config: FrontendConfig, rootPath: Path, language: String)
    extends CpgGenerator:
    private lazy val command: String = "cdxgen"

    /** Generate a CycloneDX BoM for the given input path. Returns the output path, or None, if no
      * cdx was generated.
      */
    override def generate(inputPath: String, outputPath: String = "bom.json"): Try[String] =
        var outFile =
            if File(outputPath).isDirectory(linkOptions = LinkOptions.noFollow) then
                (File(outputPath) / "bom.json").pathAsString
            else outputPath
        val arguments =
            Seq("-o", outFile, "-t", language, "--deep", inputPath) ++ config.cmdLineParams
        runShellCommand(command, arguments).map(_ => outFile)

    override def isAvailable: Boolean = true

    override def applyPostProcessingPasses(atom: Cpg): Cpg =
        atom

    override def isJvmBased = false
end CdxGenerator
