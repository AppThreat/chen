package io.appthreat.jssrc2cpg.types

import better.files.File
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.jssrc2cpg.{Config, JsSrc2Cpg}
import io.appthreat.jssrc2cpg.passes.{
    AbstractPassTest,
    AstCreationPass,
    BuiltinTypesPass,
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

/** Type recovery on the `receiver-types` fixture (a TypeScript 6 type map, no span map): a member
  * call on a field keeps the type the frontend read for the field from the type map, also where a
  * local of the method has the field's name.
  */
class ReceiverTypeRecoveryTests extends AbstractPassTest:

  private implicit val schemaValidationMode: ValidationMode = ValidationMode.Enabled

  private def recovered(f: Cpg => Unit): Unit =
    val root = File(getClass.getResource("/receiver-types").toURI)
    File.usingTemporaryDirectory("jssrc2cpgReceiverRecovery") { dir =>
      root.children.foreach(_.copyToDirectory(dir))
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

  "type recovery" should {
      "resolve a call on a field through the field's checker type, beside a local of its name" in recovered {
          cpg =>
              // `this.isSubmitting.set(true)` in run() and `this.isSubmitting.set(...)` in reset(),
              // where `const isSubmitting = 0` is a local of the method
              cpg.call.nameExact("set").map(c => (c.method.name, c.methodFullName)).l.sorted shouldBe
                  List(
                    ("reset", "@angular/core:WritableSignal:set"),
                    ("run", "@angular/core:WritableSignal:set")
                  )
      }

      "keep the file's extension in a call on a parameter typed by a class of the file" in recovered {
          cpg =>
              // `f.get("b")` with `f: Feed`: the class keeps `.ts` before `::program`, and is named by
              // its constructor (`:<init>`), as everywhere in recovery
              cpg.call.nameExact("get").filter(_.method.name == "use").methodFullName.l shouldBe
                  List("receiver-types.ts::program:Feed:<init>:get")
      }
  }
end ReceiverTypeRecoveryTests
