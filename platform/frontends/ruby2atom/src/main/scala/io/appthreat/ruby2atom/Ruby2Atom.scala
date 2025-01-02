package io.appthreat.ruby2atom

import better.files.File
import io.appthreat.ruby2atom.astcreation.AstCreator
import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst.StatementList
import io.appthreat.ruby2atom.datastructures.RubyProgramSummary
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
import upickle.default.*

import java.nio.file.{Files, Paths}
import scala.util.matching.Regex
import scala.util.{Failure, Success, Try, Using}

class Ruby2Atom extends X2CpgFrontend[Config]:

  override def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config: Config) { (cpg, config) =>
        new MetaDataPass(cpg, Languages.RUBYSRC, config.inputPath).createAndApply()
        new ConfigFileCreationPass(cpg).createAndApply()
        createCpgAction(cpg, config)
      }

  private def createCpgAction(cpg: Cpg, config: Config): Unit =
      File.usingTemporaryDirectory("ruby2atomOut") { tmpDir =>
        val astGenResult = RubyAstGenRunner(config).execute(tmpDir)

        val astCreators = ConcurrentTaskUtil
            .runUsingThreadPool(
              Ruby2Atom.processAstGenRunnerResults(
                astGenResult.parsedFiles,
                config,
                cpg.metaData.root.headOption
              )
            )
            .flatMap {
                case Failure(exception)  => None
                case Success(astCreator) => Option(astCreator)
            }
        AstCreationPass(cpg, astCreators).createAndApply()
        TypeNodePass.withTypesFromCpg(cpg).createAndApply()
      }
end Ruby2Atom

object Ruby2Atom:

  /** Parses the generated AST Gen files in parallel and produces AstCreators from each.
    */
  def processAstGenRunnerResults(
    astFiles: List[String],
    config: Config,
    projectRoot: Option[String]
  ): Iterator[() => AstCreator] =
      astFiles.map { fileName => () =>
        val parserResult   = RubyJsonParser.readFile(Paths.get(fileName))
        val rubyProgram    = new RubyJsonToNodeCreator().visitProgram(parserResult.json)
        val sourceFileName = parserResult.fullPath
        new AstCreator(
          sourceFileName,
          projectRoot,
          enableFileContents = false,
          rootNode = rubyProgram
        )(config.schemaValidation)
      }.iterator
end Ruby2Atom
