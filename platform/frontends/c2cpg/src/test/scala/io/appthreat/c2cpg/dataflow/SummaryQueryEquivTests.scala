package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.DefaultSemantics
import _root_.io.appthreat.dataflowengineoss.language.*
import _root_.io.appthreat.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import _root_.io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryComputer
import _root_.io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import _root_.io.shiftleft.semanticcpg.language.*

/** Proves that enabling method flow summaries (`EngineConfig.useSummaries`) is result preserving:
  * the summary-guided pruning only removes provably empty cross-call work, so the taint flows are
  * exactly the same as with the pruning turned off. The fixture includes an output-parameter
  * mutation and a callee that never writes its output parameter, which is the case the pruning
  * targets.
  */
class SummaryQueryEquivTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |void copy(int *dst, int src) { *dst = src; }   // writes dst from src
      |void untouched(int *dst, int src) { }          // never writes dst
      |
      |int chain(int p0) {
      |  int a = p0;
      |  int out1 = 0;
      |  copy(&out1, a);
      |  int out2 = 0;
      |  untouched(&out2, a);
      |  return out1 + out2;
      |}
      |""".stripMargin)

  private val baselineCtx = EngineContext(DefaultSemantics(), EngineConfig(useSummaries = false))
  private val summaryCtx =
      EngineContext(
        DefaultSemantics(),
        EngineConfig(useSummaries = true, summaries = FlowSummaryComputer.computeAll(cpg))
      )

  private def flowSet(
    sinks: Iterator[CfgNode],
    sources: Iterator[CfgNode]
  )(ctx: EngineContext): Set[List[Long]] =
      sinks.reachableByFlows(sources)(using ctx).map(_.elements.map(_.id)).toSet

  private def assertSameFlows(
    sinks: () => Iterator[CfgNode],
    sources: () => Iterator[CfgNode]
  ): Unit =
    val baseline = flowSet(sinks(), sources())(baselineCtx)
    val summary  = flowSet(sinks(), sources())(summaryCtx)
    baseline should not be empty
    withClue(s"only-baseline=${baseline -- summary}\nonly-summary=${summary -- baseline}\n") {
        summary shouldBe baseline
    }

  "the summary-guided engine" should:
    "match the baseline for flows to the return of `chain`" in:
      assertSameFlows(() => cpg.method.name("chain").methodReturn, () => cpg.identifier)

    "match the baseline for flows to arguments of `copy`" in:
      assertSameFlows(() => cpg.call.name("copy").argument(1), () => cpg.identifier)
end SummaryQueryEquivTests
