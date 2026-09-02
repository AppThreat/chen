package io.appthreat.ruby2atom

import better.files.File
import io.appthreat.ruby2atom.astcreation.AstCreator
import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst.StatementList
import io.appthreat.ruby2atom.datastructures.{RubyProgramSummary, RubyProgramSummaryBuilder}
import io.appthreat.ruby2atom.parser.*
import io.appthreat.ruby2atom.passes.{AstCreationPass, ConfigFileCreationPass}
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.frontendspecific.ruby2atom.*
import io.appthreat.x2cpg.passes.base.AstLinkerPass
import io.appthreat.x2cpg.passes.callgraph.NaiveCallLinker
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass, XTypeRecoveryConfig}
import io.appthreat.x2cpg.utils.{ConcurrentTaskUtil, ExternalCommand}
import io.appthreat.x2cpg.{SourceFiles, X2CpgFrontend}
import io.shiftleft.codepropertygraph.generated.{Cpg, Languages}
import io.shiftleft.passes.CpgPassBase
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory
import upickle.default.*

import java.nio.file.{Files, Paths}
import scala.collection.mutable
import scala.util.control.NonFatal
import scala.util.matching.Regex
import scala.util.{Failure, Success, Try, Using}

class Ruby2Atom extends X2CpgFrontend[Config]:

  private val logger = LoggerFactory.getLogger(getClass)

  override def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config: Config) { (cpg, config) =>
        new MetaDataPass(cpg, Languages.RUBYSRC, config.inputPath).createAndApply()
        new ConfigFileCreationPass(cpg).createAndApply()
        createCpgAction(cpg, config)
      }

  private def createCpgAction(cpg: Cpg, config: Config): Unit =
      File.usingTemporaryDirectory("ruby2atomOut") { tmpDir =>
        val astGenResult = RubyAstGenRunner(config).execute(tmpDir)

        val unknownTypes = mutable.Map.empty[String, Int]
        val parsedFiles = ConcurrentTaskUtil
            .runUsingThreadPool(Ruby2Atom.parseAstGenResults(
              astGenResult.parsedFiles,
              unknownTypes
            ))
            .flatMap {
                case Failure(exception) => None
                case Success(parsed)    => Option(parsed)
            }
        if unknownTypes.nonEmpty then
          val counts = unknownTypes.toSeq
              .sortBy { case (typ, _) => typ }
              .map { case (typ, n) => s"$typ=$n" }
              .mkString(", ")
          logger.warn(
            s"Node types unknown to this ruby2atom version were downgraded to placeholder nodes (${counts}). " +
                "This usually means the `rbastgen` generator is newer than this frontend."
          )

        // First pass: a program-wide type inventory that `require` handling and scope
        // resolution consult during AST creation (plan 04 §6).
        val programSummary = RubyProgramSummaryBuilder.build(
          parsedFiles.map(parsed => parsed.relativeFilePath -> parsed.program)
        )

        val astCreators = parsedFiles.map { parsed =>
            new AstCreator(
              parsed.fullFilePath,
              cpg.metaData.root.headOption,
              programSummary,
              enableFileContents = false,
              rootNode = parsed.program
            )(using config.schemaValidation)
        }
        AstCreationPass(cpg, astCreators).createAndApply()
        ImportsPass(cpg).createAndApply()
        ImplicitRequirePass(cpg).createAndApply()
        TypeNodePass.withTypesFromCpg(cpg).createAndApply()
      }
end Ruby2Atom

object Ruby2Atom:

  private val logger = LoggerFactory.getLogger(getClass)

  /** One parsed astgen JSON file: its require-style relative path, its absolute path (chen re-reads
    * the source from there) and the rebuilt intermediate AST.
    */
  final case class ParsedFile(
    relativeFilePath: String,
    fullFilePath: String,
    program: StatementList
  )

  /** Parses the generated AST Gen files in parallel. Node types that could not be lowered are
    * aggregated into `unknownTypeSink` (one count per type) instead of logging per node. AST
    * creation happens later, once every file is parsed and the program summary is available.
    */
  def parseAstGenResults(
    astFiles: List[String],
    unknownTypeSink: mutable.Map[String, Int] = mutable.Map.empty
  ): Iterator[() => ParsedFile] =
      astFiles.map { fileName => () =>
          try
            val parserResult = RubyJsonParser.readFile(Paths.get(fileName))
            val creator      = new RubyJsonToNodeCreator()
            val rubyProgram  = creator.visitProgram(parserResult.json)
            if creator.unknownTypeReport.nonEmpty then
              Ruby2Atom.synchronized {
                  creator.unknownTypeReport.foreach { case (typ, n) =>
                      unknownTypeSink.updateWith(typ)((old) => Some(old.getOrElse(0) + n))
                  }
              }
            Ruby2Atom.ParsedFile(parserResult.filename, parserResult.fullPath, rubyProgram)
          catch
            case NonFatal(exception) =>
                logger.error(s"Failed to parse AST file '$fileName'", exception)
                throw exception
      }.iterator
end Ruby2Atom
