package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.language.*
import _root_.io.appthreat.dataflowengineoss.queryengine.summaries.MethodFlowSummary
import _root_.io.shiftleft.codepropertygraph.generated.nodes.Method
import _root_.io.shiftleft.semanticcpg.language.*

/** Validates the context-independent [[MethodFlowSummary]] (CHEN3_PLAN §5 foundation) against the
  * classic engine: the parameter-to-return facts in the summary must match what `reachableByFlows`
  * reports for that method in isolation.
  */
class MethodFlowSummaryTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |int flow(int p0, int q0) {
      |  int a = p0;
      |  int b = a;
      |  return b;        // p0 -> return; q0 does NOT reach return
      |}
      |
      |int noflow(int p0) {
      |  int x = 42;
      |  return x;        // nothing reaches return
      |}
      |""".stripMargin)

  /** Ground truth from the classic engine: parameter indices whose value reaches the return. */
  private def paramsReachingReturn(name: String): Set[Int] =
      cpg.method.name(name).parameter.l.filter { p =>
          cpg.method.name(name).methodReturn.reachableByFlows(Iterator(p)).nonEmpty
      }.map(_.index).toSet

  "MethodFlowSummary.paramToReturn" should:
    "match the classic engine for a propagating method" in:
      val summary = MethodFlowSummary.of(cpg.method.name("flow").head)
      summary.paramToReturn shouldBe paramsReachingReturn("flow")
      summary.paramToReturn should not be empty

    "match the classic engine for a second method (independent CPG region)" in:
      val summary = MethodFlowSummary.of(cpg.method.name("noflow").head)
      summary.paramToReturn shouldBe paramsReachingReturn("noflow")
end MethodFlowSummaryTests
