package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.queryengine.summaries.{
    FlowSummaryComputer,
    FlowSummaryTags,
    FlowSummaryTagsPass,
    MethodFlowSummary
}
import _root_.io.shiftleft.semanticcpg.language.*

/** Proves G-5: flow summaries persist as CPG-native `flow-summary` tags on METHOD nodes and reload
  * losslessly, so the query engine can be primed from a cached `.atom` without recomputation.
  */
class FlowSummaryTagsTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |void copy(int *dst, int src) { *dst = src; }
      |void untouched(int *dst, int src) { }
      |int constant() { return 42; }
      |int forward(int p0) { return p0; }
      |""".stripMargin)

  "the flow-summary tag round-trip" should:
    "reload exactly the computed summaries from the tagged CPG" in:
      val computed = FlowSummaryComputer.computeAll(cpg)
      new FlowSummaryTagsPass(cpg, computed).createAndApply()
      val reloaded = FlowSummaryTags.fromCpg(cpg)
      reloaded shouldBe computed

    "encode and decode every summary without loss" in:
      val computed = FlowSummaryComputer.computeAll(cpg)
      computed.values.foreach { s =>
          MethodFlowSummary.decode(s.methodFullName, s.encode) shouldBe Some(s)
      }

    "decode a malformed value to None and a non-summary string to None" in:
      MethodFlowSummary.decode("m", "not a summary") shouldBe None
      MethodFlowSummary.decode("m", "r=;o=;ri=0;pi=") shouldBe
          Some(MethodFlowSummary("m", Set.empty, Map.empty, returnFromInternal = false, Set.empty))
end FlowSummaryTagsTests
