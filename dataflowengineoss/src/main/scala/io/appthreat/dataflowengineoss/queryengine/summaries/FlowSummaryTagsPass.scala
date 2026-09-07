package io.appthreat.dataflowengineoss.queryengine.summaries

import io.appthreat.dataflowengineoss.semanticsloader.FlowSemantic
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Method
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

  /** Flow semantics for the summarised methods of `cpg` that the engine ''cannot explore'' - the
    * dependency signatures ingested by `python-deps=summaries`, whose summaries were computed from
    * the library's own source before its bodies were discarded.
    *
    * Only non-explorable methods qualify ([[io.shiftleft.semanticcpg.language.MethodExplorability]]
    *   - a method with a body in the graph, internal or external, is explored by the engine itself,
    *     and declaring a semantic for one would replace that exploration with a two-line
    *     approximation of it. Opaque methods are the opposite case: the engine cannot explore them,
    *     so its only choice today is the permissive default in which every argument taints the
    *     call's result and every sibling argument. A summary derived from the real body is strictly
    *     better evidence than that default, in both directions - it keeps the flows the library
    *     really has and drops the ones it does not.
    *
    * This is also what keeps `full` and `summaries` from combining: `python-deps=full` parses
    * dependency bodies into the graph, so those methods are explorable and can never gain a
    * declared semantic - and `full` never writes `flow-summary` tags in the first place.
    *
    * `exclude` holds full names that already have a hand-written semantic. Those win: a curated
    * semantic encodes intent (which parameter is the sanitizer, which is the sink) that a
    * data-dependence summary cannot see.
    */
  def externalSemantics(cpg: Cpg, exclude: Set[String] = Set.empty): List[FlowSemantic] =
      // Driven from the tags rather than from `cpg.method`: the summarised methods are a small
      // subset of a graph's methods, and starting from the tag index visits only them.
      cpg.tag.nameExact(TagName).flatMap { tag =>
          tag._taggedByIn.collectAll[Method].flatMap { m =>
              if MethodExplorability.isExplorable(m) || exclude.contains(m.fullName) || m.parameter.isEmpty
              then None
              else MethodFlowSummary.decode(m.fullName, tag.value).map(MethodFlowSummary.toSemantic)
          }
      }.l
end FlowSummaryTags
