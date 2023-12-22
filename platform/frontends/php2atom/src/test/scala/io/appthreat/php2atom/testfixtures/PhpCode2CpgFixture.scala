package io.appthreat.php2atom.testfixtures

import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.php2atom.{Config, Php2Atom}
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, DefaultTestCpg, LanguageFrontend}
import io.appthreat.x2cpg.passes.frontend.XTypeRecoveryConfig
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}

import java.io.File
import io.appthreat.x2cpg.testfixtures.TestCpg
import io.appthreat.x2cpg.X2Cpg
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import io.appthreat.dataflowengineoss.layers.dataflows.OssDataFlowOptions
import io.appthreat.dataflowengineoss.layers.dataflows.OssDataFlow
import io.appthreat.php2atom.passes.PhpSetKnownTypesPass

trait PhpFrontend extends LanguageFrontend {
  override val fileSuffix: String = ".php"

  override def execute(sourceCodeFile: File): Cpg = {
    implicit val defaultConfig: Config = getConfig().map(_.asInstanceOf[Config]).getOrElse(Config())
    new Php2Atom().createCpg(sourceCodeFile.getAbsolutePath).get
  }
}

class PhpTestCpg(runOssDataflow: Boolean) extends TestCpg with PhpFrontend {

  override protected def applyPasses(): Unit = {
    X2Cpg.applyDefaultOverlays(this)
    if (runOssDataflow) {
      val context = new LayerCreatorContext(this)
      val options = new OssDataFlowOptions()
      new OssDataFlow(options).run(context)
    }
    Php2Atom.postProcessingPasses(this).foreach(_.createAndApply())
  }
}

class PhpCode2CpgFixture(runOssDataflow: Boolean = false)
    extends Code2CpgFixture(() => new PhpTestCpg(runOssDataflow)) {
  implicit val resolver: ICallResolver           = NoResolve
  implicit lazy val engineContext: EngineContext = EngineContext()
}
