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

  /** Ground truth from the classic engine: parameter indices whose value reaches a RETURN statement
    * of the method.
    *
    * The sink is the `return` statements, not METHOD_RETURN. Asking the engine to reach
    * METHOD_RETURN asks a different question - "is this parameter's definition still live at the
    * method exit" - which is true of every parameter, including the ones the body never reads. That
    * made the oracle claim `q0` reaches the return of `int flow(int p0, int q0) { return b; }`,
    * contradicting this file's own inline comments, and it is not the fact a summary is used for:
    * the caller wants to know whether taint in an argument comes back out of the call. The query
    * engine draws the same line when it descends into a callee, collecting exactly the `Return`
    * predecessors of METHOD_RETURN.
    */
  private def paramsReachingReturn(name: String): Set[Int] =
      cpg.method.name(name).parameter.l.filter { p =>
          cpg.method.name(name).ast.isReturn.reachableByFlows(Iterator(p)).nonEmpty
      }.map(_.index).toSet

  "MethodFlowSummary.paramToReturn" should:
    "match the classic engine for a propagating method" in:
      val summary = MethodFlowSummary.of(cpg.method.name("flow").head)
      summary.paramToReturn shouldBe paramsReachingReturn("flow")
      summary.paramToReturn should not be empty

    "match the classic engine for a second method (independent CPG region)" in:
      val summary = MethodFlowSummary.of(cpg.method.name("noflow").head)
      summary.paramToReturn shouldBe paramsReachingReturn("noflow")

    "record nothing for a parameter the body never reads" in:
      // Stated without reference to any oracle, because this is the fact the summary exists to
      // carry and the one a derived flow semantic acts on: `noflow` returns a constant, so a
      // tainted argument does not come back out of a call to it. An unread parameter is still
      // live at METHOD_RETURN, so a summary that measures liveness rather than the returned
      // expression reports a pass-through here and can then only ever agree with the engine's
      // permissive default for an opaque callee - never correct it.
      MethodFlowSummary.of(cpg.method.name("noflow").head).paramToReturn shouldBe empty
      MethodFlowSummary.of(cpg.method.name("flow").head).paramToReturn shouldBe Set(1)
end MethodFlowSummaryTests
