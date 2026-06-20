package io.appthreat.dataflowengineoss.layers.dataflows

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.passes.reachingdef.{FluxReachingDefPass, ReachingDefPass}
import io.appthreat.dataflowengineoss.semanticsloader.{FlowSemantic, Semantics}
import io.shiftleft.passes.CpgPassBase
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext, LayerCreatorOptions}

object OssDataFlow:
  val overlayName: String = "dataflowOss"
  val description: String = "Layer to support the OSS lightweight data flow tracker"

  def defaultOpts = new OssDataFlowOptions()

/** @param useFluxEngine
  *   opt into the "Flux" reaching-definitions engine ([[FluxReachingDefPass]]) - a low-allocation
  *   drop-in for the classic [[ReachingDefPass]] that produces identical `REACHING_DEF` edges.
  *   Defaults to `false`, so the classic engine remains the default.
  */
class OssDataFlowOptions(
  var maxNumberOfDefinitions: Int = 4000,
  var extraFlows: List[FlowSemantic] = List.empty[FlowSemantic],
  var useFluxEngine: Boolean = false
) extends LayerCreatorOptions {}

class OssDataFlow(opts: OssDataFlowOptions)(implicit
  s: Semantics = Semantics.fromList(DefaultSemantics().elements ++ opts.extraFlows)
) extends LayerCreator:

  override val overlayName: String = OssDataFlow.overlayName
  override val description: String = OssDataFlow.description

  override def create(context: LayerCreatorContext, storeUndoInfo: Boolean): Unit =
    val cpg = context.cpg
    val reachingDefPass: CpgPassBase =
        if opts.useFluxEngine then new FluxReachingDefPass(cpg, opts.maxNumberOfDefinitions)
        else new ReachingDefPass(cpg, opts.maxNumberOfDefinitions)
    val enhancementExecList = Iterator(reachingDefPass)
    enhancementExecList.zipWithIndex.foreach { case (pass, index) =>
        runPass(pass, context, storeUndoInfo, index)
    }
