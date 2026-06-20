package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.language.*
import _root_.io.appthreat.dataflowengineoss.queryengine.summaries.{
    FlowSummaryComputer,
    MethodFlowSummary
}
import _root_.io.shiftleft.semanticcpg.language.*

/** Validates the interprocedural [[FlowSummaryComputer]] against the classic engine. Summaries are
  * built callee-before-caller, so a caller's parameter-to-return facts must include flows that only
  * exist because a callee passes the argument through to its return.
  */
class FlowSummaryComputerTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |int id(int p) {
      |  return p;            // p -> return
      |}
      |
      |int wrapper(int a, int b) {
      |  int r = id(a);       // a flows through id() to r
      |  return r;            // a -> return; b does NOT reach return
      |}
      |
      |int leaf(int x, int y) {
      |  return x;            // x -> return; y does not
      |}
      |
      |int ping(int n);
      |int pong(int n) { return ping(n - 1); }   // mutually recursive
      |int ping(int n) { return pong(n - 1); }
      |""".stripMargin)

  /** Ground truth from the classic engine: parameter indices whose value reaches the return. */
  private def paramsReachingReturn(name: String): Set[Int] =
      cpg.method.name(name).parameter.l.filter { p =>
          cpg.method.name(name).methodReturn.reachableByFlows(Iterator(p)).nonEmpty
      }.map(_.index).toSet

  "FlowSummaryComputer" should:
    "compute interprocedural param-to-return facts matching the classic engine" in:
      val summaries = FlowSummaryComputer.computeAll(cpg)

      summaries(cpg.method.name("leaf").head.fullName).paramToReturn shouldBe
          paramsReachingReturn("leaf")

      // The interesting case: wrapper only reaches its return through the callee id().
      val wrapperSummary = summaries(cpg.method.name("wrapper").head.fullName)
      wrapperSummary.paramToReturn shouldBe paramsReachingReturn("wrapper")
      wrapperSummary.paramToReturn should not be empty

    "never drop a flow that the intra-procedural summary already found" in:
      // Plugging in callee summaries only adds flows, so for every method the interprocedural
      // result must be a superset of the purely intra-procedural one.
      val full = FlowSummaryComputer.computeAll(cpg)
      cpg.method.internal.l.foreach { m =>
        val intraOnly = MethodFlowSummary.of(m)
        val computed  = full(m.fullName)
        intraOnly.paramToReturn.subsetOf(computed.paramToReturn) shouldBe true
        intraOnly.paramToParamOut.foreach { case (in, outs) =>
            outs.subsetOf(computed.reachedParamOuts(in)) shouldBe true
        }
      }

    "produce a summary for every internal method" in:
      val summaries = FlowSummaryComputer.computeAll(cpg)
      cpg.method.internal.fullName.toSet.foreach { fn =>
          summaries.contains(fn) shouldBe true
      }

    "terminate on a mutually recursive call graph" in:
      // ping/pong form a cycle; the fixpoint over the recursive component must converge.
      val summaries = FlowSummaryComputer.computeAll(cpg)
      summaries.contains(cpg.method.name("ping").head.fullName) shouldBe true
      summaries.contains(cpg.method.name("pong").head.fullName) shouldBe true
end FlowSummaryComputerTests
