package io.appthreat.dataflowengineoss.layers.dataflows

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.passes.reachingdef.{FluxReachingDefPass, ReachingDefPass}
import io.appthreat.dataflowengineoss.semanticsloader.{FlowSemantic, Semantics}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPassBase
import io.shiftleft.semanticcpg.language.*
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
  var useFluxEngine: Boolean = false,
  var maxNumberOfCfgNodes: Int = 50000
) extends LayerCreatorOptions {}

class OssDataFlow(opts: OssDataFlowOptions)(implicit
  s: Semantics = Semantics.fromList(DefaultSemantics().elements ++ opts.extraFlows)
) extends LayerCreator:

  override val overlayName: String = OssDataFlow.overlayName
  override val description: String = OssDataFlow.description

  override def create(context: LayerCreatorContext, storeUndoInfo: Boolean): Unit =
    val cpg = context.cpg
    // `DefaultSemantics()` is language neutral: a summary keyed on a bare name (PHP's `e`,
    // `esc_html`, ...) would otherwise clear taint for a same-named function in a C/Java/JS graph,
    // since FlowSemantic matching is by exact methodFullName with no language scoping. The
    // language-specific flows are therefore added here, where the graph - and hence its language -
    // is known. Adding them is purely additive, so an explicitly supplied `Semantics` is honoured.
    val effectiveSemantics: Semantics = languageAwareSemantics(cpg)

    val reachingDefPass: CpgPassBase =
        if opts.useFluxEngine then
          new FluxReachingDefPass(cpg, opts.maxNumberOfDefinitions, opts.maxNumberOfCfgNodes)(using
            effectiveSemantics
          )
        else
          new ReachingDefPass(cpg, opts.maxNumberOfDefinitions, opts.maxNumberOfCfgNodes)(using
            effectiveSemantics
          )
    val enhancementExecList = Iterator(reachingDefPass)
    enhancementExecList.zipWithIndex.foreach { case (pass, index) =>
        runPass(pass, context, storeUndoInfo, index)
    }
  end create

  /** The configured semantics plus any flows that only apply to this graph's language. */
  private def languageAwareSemantics(cpg: Cpg): Semantics =
    val extra = cpg.metaData.language.headOption
        .map(DefaultSemantics.flowsForLanguage)
        .getOrElse(List.empty)
    if extra.isEmpty then s else Semantics.fromList(s.elements ++ extra)
end OssDataFlow
