package io.appthreat.jssrc2cpg.types

import better.files.File
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.jssrc2cpg.{Config, JsSrc2Cpg}
import io.appthreat.jssrc2cpg.passes.{
    AbstractPassTest,
    AstCreationPass,
    BuiltinTypesPass,
    Defines,
    ImportsPass,
    JsMetaDataPass,
    TypeNodePass
}
import io.appthreat.jssrc2cpg.utils.AstGenRunner
import io.appthreat.x2cpg.{ValidationMode, X2Cpg}
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

/** Type recovery on the `native-kinds` fixture, with and without the span file: what the frontend
  * types with the checker's type must not stop recovery from resolving a call to the package it
  * comes from.
  */
class NativeTypeRecoveryTests extends AbstractPassTest:

  private implicit val schemaValidationMode: ValidationMode = ValidationMode.Enabled

  private def recovered(spans: Boolean)(f: Cpg => Unit): Unit =
    val root = File(getClass.getResource("/native-kinds").toURI)
    File.usingTemporaryDirectory("jssrc2cpgNativeRecovery") { dir =>
      root.children.filter(c => spans || !c.name.endsWith(".typespans")).foreach(
        _.copyToDirectory(dir)
      )
      val config = Config(tsTypes = true).withInputPath(dir.toString)
          .withOutputPath(dir.toString).withAstGenOutDir(dir.toString)
      val cpg    = newEmptyCpg()
      val result = new AstGenRunner(config).execute(dir)
      val pass   = new AstCreationPass(cpg, result, config)
      pass.createAndApply()
      new TypeNodePass(pass.allUsedTypes(), cpg).createAndApply()
      new BuiltinTypesPass(cpg).createAndApply()
      new JsMetaDataPass(cpg, "hash", config.inputPath).createAndApply()
      new ImportsPass(cpg).createAndApply()
      X2Cpg.applyDefaultOverlays(cpg)
      new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(cpg))
      JsSrc2Cpg.postProcessingPasses(cpg, Option(config)).foreach(_.createAndApply())
      f(cpg)
    }
  end recovered

  private def valueCall(cpg: Cpg) =
      cpg.call.nameExact("value").filter(_.file.name.exists(_.endsWith("native-kinds.ts"))).l

  "type recovery" should {
      "resolve a call on a field typed by the checker the same way with and without spans" in {
          var without = List.empty[String]
          recovered(spans = false)(cpg => without = valueCall(cpg).map(_.methodFullName))
          var withSpans = List.empty[String]
          recovered(spans = true)(cpg => withSpans = valueCall(cpg).map(_.methodFullName))
          without should not be empty
          // a class of the project and one of a package that is not in the graph
          without.exists(_.contains("ext-lib")) shouldBe true
          withSpans shouldBe without
      }

      "keep the field access typed by the checker" in recovered(spans = true) { cpg =>
          cpg.call.name("<operator>.fieldAccess").code("this.box").lineNumber(32).typeFullName
              .l shouldBe List(
            "Box"
          )
      }
  }
end NativeTypeRecoveryTests
