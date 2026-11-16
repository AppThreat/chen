package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.{DataFlowCodeToCpgSuite, DataFlowTestCpg}
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

  // Two files each define a `static` function of the same name. The call linker keeps them apart,
  // but a summary is looked up by full name, so it must hold for both bodies.
  private val sameNameCpg: DataFlowTestCpg = new DataFlowTestCpg()
      .moreCode(
        """
        |static int pick(int v, int w) { return v; }
        |int use_a(int v, int w) { return pick(v, w); }
        |
        |int loop_b(int v, int n);
        |static int step(int v, int n, int *out) {
        |  if (n <= 0) return 0;
        |  return loop_b(v, n - 1);
        |}
        |int loop_a(int v, int n) { int o = 0; return step(v, n, &o); }
        |""".stripMargin,
        "a.c"
      )
      .moreCode(
        """
        |static int pick(int v, int w) { return w; }
        |int use_b(int v, int w) { return pick(v, w); }
        |
        |int loop_a(int v, int n);
        |static int step(int v, int n, int *out) {
        |  *out = v;
        |  if (n <= 0) return v;
        |  return loop_a(v, n - 1);
        |}
        |int loop_b(int v, int n) { int o = 0; return step(v, n, &o); }
        |""".stripMargin,
        "b.c"
      )

  "FlowSummaryComputer with same-named static functions" should:
    "summarise the name with the flows of every body" in:
      val summaries = FlowSummaryComputer.computeAll(sameNameCpg)
      summaries("pick").paramToReturn shouldBe Set(1, 2)
      summaries("use_a").paramToReturn should contain(1)
      summaries("use_b").paramToReturn should contain(2)

    "converge when the bodies share a recursive component" in:
      // loop_a -> step (a.c) -> loop_b -> step (b.c) -> loop_a is one component with two `step`
      // bodies, and only the b.c body writes its first argument through `out`. With a slot per
      // name that each body overwrote, the component never converged.
      val summaries = FlowSummaryComputer.computeAll(sameNameCpg)
      summaries("step").reachedParamOuts(1) should contain(3)
      summaries("step").paramToReturn should contain(1)
      summaries("loop_a").paramToReturn should contain(1)
      summaries("loop_b").paramToReturn should contain(1)
end FlowSummaryComputerTests
