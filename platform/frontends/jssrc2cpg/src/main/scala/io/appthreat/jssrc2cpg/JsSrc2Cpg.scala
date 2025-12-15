package io.appthreat.jssrc2cpg

import better.files.File
import io.appthreat.jssrc2cpg.utils.AstGenRunner
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import JsSrc2Cpg.postProcessingPasses
import io.appthreat.jssrc2cpg.passes.{
    AstCreationPass,
    BuiltinTypesPass,
    ConfigPass,
    ConstClosurePass,
    ImportResolverPass,
    ImportsPass,
    JavaScriptInheritanceNamePass,
    JavaScriptTypeHintCallLinker,
    JavaScriptTypeRecoveryPass,
    JsMetaDataPass,
    PrivateKeyFilePass,
    TypeNodePass
}
import io.appthreat.jssrc2cpg.passes.*
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.passes.frontend.XTypeRecoveryConfig
import io.appthreat.x2cpg.utils.{HashUtil, Report}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPassBase
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

import scala.util.Try

class JsSrc2Cpg extends X2CpgFrontend[Config]:

  private val report: Report = new Report()

  def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config) { (cpg, config) =>
        def processAstGenDir(astGenDir: File): Unit =
          val astGenResult = new AstGenRunner(config).execute(astGenDir)
          val hash = HashUtil.sha256(astGenResult.parsedFiles.map { case (_, file) =>
              File(file).path
          })

          val astCreationPass =
              new AstCreationPass(cpg, astGenResult, config, report)(using config.schemaValidation)
          astCreationPass.createAndApply()

          new TypeNodePass(astCreationPass.allUsedTypes(), cpg).createAndApply()
          new JsMetaDataPass(cpg, hash, config.inputPath).createAndApply()
          new BuiltinTypesPass(cpg).createAndApply()
          new ConfigPass(cpg, config, report).createAndApply()
          new PrivateKeyFilePass(cpg, config, report).createAndApply()
          new ImportsPass(cpg).createAndApply()

          report.print()
        config.astGenOutDir match
          case Some(dirPath) =>
              val outDir = File(dirPath)
              outDir.createDirectoryIfNotExists(createParents = true)
              processAstGenDir(outDir)
          case None =>
              File.usingTemporaryDirectory("jssrc2cpgOut") { tmpDir =>
                  processAstGenDir(tmpDir)
              }
      }

  // This method is intended for internal use only and may be removed at any time.
  def createCpgWithAllOverlays(config: Config): Try[Cpg] =
    val maybeCpg = createCpgWithOverlays(config)
    maybeCpg.map { cpg =>
      new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(cpg))
      postProcessingPasses(cpg, Option(config)).foreach(_.createAndApply())
      cpg
    }
end JsSrc2Cpg

object JsSrc2Cpg:

  def postProcessingPasses(cpg: Cpg, config: Option[Config] = None): List[CpgPassBase] =
    val typeRecoveryConfig = config
        .map(c => XTypeRecoveryConfig(c.typePropagationIterations, !c.disableDummyTypes))
        .getOrElse(XTypeRecoveryConfig())
    List(
      new JavaScriptInheritanceNamePass(cpg),
      new ConstClosurePass(cpg),
      new ImportResolverPass(cpg),
      new JavaScriptTypeRecoveryPass(cpg, typeRecoveryConfig),
      new JavaScriptTypeHintCallLinker(cpg)
    )
