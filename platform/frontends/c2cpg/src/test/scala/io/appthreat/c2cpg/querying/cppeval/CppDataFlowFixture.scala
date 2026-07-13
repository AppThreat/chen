package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.C2CpgFrontend
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, TestCpg}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

/** Like DataFlowCodeToCpgSuite but drives the C++ (.cpp) frontend so we can exercise the DDG/PDG
  * overlays on real C++ sources.
  */
class CppDataFlowTestCpg extends TestCpg with C2CpgFrontend:
  override val fileSuffix: String = FileDefaults.CPP_EXT

  override protected def applyPasses(): Unit =
    X2Cpg.applyDefaultOverlays(this)
    val context = new LayerCreatorContext(this)
    val options = new OssDataFlowOptions()
    new OssDataFlow(options).run(context)

class CppDataFlowCodeToCpgSuite extends Code2CpgFixture(() => new CppDataFlowTestCpg()):
  protected implicit val context: EngineContext = EngineContext()
