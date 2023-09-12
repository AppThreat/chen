package io.appthreat.jssrc2cpg.testfixtures

import io.appthreat.jssrc2cpg.JsSrc2Cpg
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, TestCpg}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

class DataFlowTestCpg extends TestCpg with JsSrc2CpgFrontend {
  override val fileSuffix: String = ".js"

  override def applyPasses(): Unit = {
    X2Cpg.applyDefaultOverlays(this)

    val context = new LayerCreatorContext(this)
    val options = new OssDataFlowOptions()
    new OssDataFlow(options).run(context)
    JsSrc2Cpg.postProcessingPasses(this).foreach(_.createAndApply())
  }

}

class DataFlowCodeToCpgSuite extends Code2CpgFixture(() => new DataFlowTestCpg()) {

  implicit var context: EngineContext = EngineContext()

  protected def flowToResultPairs(path: Path): List[(String, Integer)] =
    path.resultPairs().collect { case (firstElement: String, secondElement: Option[Integer]) =>
      (firstElement, secondElement.get)
    }
}
