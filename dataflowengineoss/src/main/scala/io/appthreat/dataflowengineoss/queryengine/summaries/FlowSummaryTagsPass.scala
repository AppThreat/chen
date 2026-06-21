package io.appthreat.dataflowengineoss.queryengine.summaries

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** Persists method flow summaries (CHEN3_PLAN §5 / backlog G-5) as CPG-native `flow-summary` tags
  * on the METHOD nodes they describe, so the context-independent facts serialize with the `.atom`
  * and can be reloaded without recomputation. Each method gets at most one `flow-summary` tag whose
  * value is [[MethodFlowSummary.encode]]; the method's full name is the tag's owner, so it is not
  * stored in the value. METHOD is a taggable node type, so this applies cleanly at DiffGraph apply.
  */
class FlowSummaryTagsPass(cpg: Cpg, summaries: Map[String, MethodFlowSummary]) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
      summaries.foreach { case (fullName, summary) =>
          cpg.method
              .fullNameExact(fullName)
              .newTagNodePair(FlowSummaryTags.TagName, summary.encode)
              .store()(using dstGraph)
      }

object FlowSummaryTags:

  /** The tag name under which a method's encoded flow summary is stored. */
  val TagName: String = "flow-summary"

  /** Rebuild the summary map from `flow-summary` tags already present on a (cached) CPG, so the
    * query engine can be primed without recomputing summaries. Methods without the tag, or with a
    * malformed value, are skipped.
    */
  def fromCpg(cpg: Cpg): Map[String, MethodFlowSummary] =
      cpg.method.flatMap { m =>
          m.tag
              .nameExact(TagName)
              .value
              .headOption
              .flatMap(v => MethodFlowSummary.decode(m.fullName, v))
              .map(m.fullName -> _)
      }.toMap
