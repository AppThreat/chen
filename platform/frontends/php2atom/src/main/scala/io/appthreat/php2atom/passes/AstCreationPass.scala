package io.appthreat.php2atom.passes

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.astcreation.AstCreator
import io.appthreat.php2atom.parser.PhpParser
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.{SourceFiles, ValidationMode}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import org.slf4j.LoggerFactory

import scala.jdk.CollectionConverters.*

class AstCreationPass(config: Config, cpg: Cpg, parser: PhpParser)(implicit
  withSchemaValidation: ValidationMode
) extends ConcurrentWriterCpgPass[String](cpg):

  private val logger = LoggerFactory.getLogger(this.getClass)

  val PhpSourceFileExtensions: Set[String] = Set(".php")

  override def generateParts(): Array[String] = SourceFiles
      .determine(
        config.inputPath,
        PhpSourceFileExtensions
      )
      .toArray

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
    val relativeFilename = if filename == config.inputPath then
      File(filename).name
    else
      File(config.inputPath).relativize(File(filename)).toString
    if !config.ignoredFilesRegex.matches(
        relativeFilename
      ) && !config.defaultIgnoredFilesRegex.exists(_.matches(relativeFilename))
    then
      parser.parseFile(filename, config.phpIni) match
        case Some(parseResult) =>
            diffGraph.absorb(
              new AstCreator(relativeFilename, parseResult)(
                config.schemaValidation
              ).createAst()
            )

        case None =>
            logger.debug(s"Could not parse file $filename. Results will be missing!")
  end runOnPart
end AstCreationPass
