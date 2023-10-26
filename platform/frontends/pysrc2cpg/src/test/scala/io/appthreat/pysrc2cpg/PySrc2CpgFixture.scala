package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.dataflowengineoss.semanticsloader.FlowSemantic
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.base.AstLinkerPass
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, LanguageFrontend, TestCpg}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

trait PythonFrontend extends LanguageFrontend {
  override val fileSuffix: String = ".py"

  override def execute(sourceCodePath: java.io.File): Cpg = {
    new Py2CpgOnFileSystem().createCpg(sourceCodePath.getAbsolutePath)(new Py2CpgOnFileSystemConfig()).get
  }
}

class PySrcTestCpg extends TestCpg with PythonFrontend {
  private var _withOssDataflow = false
  private var _extraFlows      = List.empty[FlowSemantic]

  def withOssDataflow(value: Boolean = true): this.type = {
    _withOssDataflow = value
    this
  }

  def withExtraFlows(value: List[FlowSemantic] = List.empty): this.type = {
    _extraFlows = value
    this
  }

  override def applyPasses(): Unit = {
    X2Cpg.applyDefaultOverlays(this)
    new ImportsPass(this).createAndApply()
    new ImportResolverPass(this).createAndApply()
    new PythonInheritanceNamePass(this).createAndApply()
    new DynamicTypeHintFullNamePass(this).createAndApply()
    new PythonTypeRecoveryPass(this).createAndApply()
    new PythonTypeHintCallLinker(this).createAndApply()

    // Some of passes above create new methods, so, we
    // need to run the ASTLinkerPass one more time
    new AstLinkerPass(this).createAndApply()

    if (_withOssDataflow) {
      val context = new LayerCreatorContext(this)
      val options = new OssDataFlowOptions(extraFlows = _extraFlows)
      new OssDataFlow(options).run(context)
    }
  }
}

class PySrc2CpgFixture(withOssDataflow: Boolean = false, extraFlows: List[FlowSemantic] = List.empty)
    extends Code2CpgFixture(() => new PySrcTestCpg().withOssDataflow(withOssDataflow).withExtraFlows(extraFlows)) {

  implicit val resolver: ICallResolver = NoResolve
  implicit val context: EngineContext  = EngineContext()

}
