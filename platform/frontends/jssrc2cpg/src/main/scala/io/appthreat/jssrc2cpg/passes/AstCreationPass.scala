package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.astcreation.AstCreator
import io.appthreat.jssrc2cpg.parser.BabelJsonParser
import io.appthreat.jssrc2cpg.utils.AstGenRunner.AstGenRunnerResult
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.utils.{Report, TimeUtils}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import io.shiftleft.utils.IOUtils

import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.EnumerationHasAsScala
import scala.util.{Failure, Success, Try}

class AstCreationPass(
  cpg: Cpg,
  astGenRunnerResult: AstGenRunnerResult,
  config: Config,
  report: Report = new Report()
)(
  implicit withSchemaValidation: ValidationMode
) extends ConcurrentWriterCpgPass[(String, String)](cpg):

  private val usedTypes: ConcurrentHashMap[(String, String), Boolean] = new ConcurrentHashMap()

  override def generateParts(): Array[(String, String)] = astGenRunnerResult.parsedFiles.toArray

  def allUsedTypes(): List[(String, String)] =
      usedTypes.keys().asScala.filterNot { case (typeName, _) => typeName == Defines.Any }.toList

  override def finish(): Unit = super.finish()

  override def runOnPart(diffGraph: DiffGraphBuilder, input: (String, String)): Unit =
    val (rootPath, jsonFilename) = input
    val ((gotCpg, filename), duration) = TimeUtils.time {
        val parseResult = BabelJsonParser.readFile(Paths.get(rootPath), Paths.get(jsonFilename))
        val fileLOC     = IOUtils.readLinesInFile(Paths.get(parseResult.fullPath)).size
        report.addReportInfo(parseResult.filename, fileLOC, parsed = true)
        Try {
            val localDiff = new AstCreator(config, parseResult, usedTypes).createAst()
            diffGraph.absorb(localDiff)
        } match
          case Failure(exception) =>
              println(
                s"$jsonFilename failed due to ${exception.getStackTrace.take(20).mkString("\n")}"
              )
              (false, parseResult.filename)
          case Success(_) =>
              (true, parseResult.filename)
    }
    report.updateReport(filename, cpg = gotCpg, duration)
end AstCreationPass
