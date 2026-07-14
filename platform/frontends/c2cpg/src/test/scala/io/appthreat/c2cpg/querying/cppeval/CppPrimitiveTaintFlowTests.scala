package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*

/** Regression coverage for taint propagation through primitive-typed (int/float/double/bool)
  * variables. This used to be dropped: `hasDefinedFlowTo` short-circuited to `false` whenever the
  * target had a primitive eval-type, so `int q = p; sink(q)` reported NO flow from `p` - breaking
  * the most common data flow of all. Verified under both reaching-def engines (they share the same
  * `DdgGenerator`/`EdgeValidator`) because atom runs the Flux engine by default.
  */
class CppPrimitiveTaintFlowTests extends CppDataFlowCodeToCpgSuite:
  taintSpecs("classic reaching-def engine", flowCount)

  private def flowCount(cpg: io.shiftleft.codepropertygraph.generated.Cpg, m: String): Int =
      cpg.method.nameExact(m).call.nameExact("sink").argument(1)
          .reachableByFlows(cpg.method.nameExact(m).parameter.nameExact("p")).size

  private def taintSpecs(
    engine: String,
    count: (io.shiftleft.codepropertygraph.generated.Cpg, String) => Int
  ): Unit =
      s"primitive taint under the $engine" should {
          "flow through a primitive local (regression: int q = p; sink(q))" in {
              val cpg = code("""
                  |void sink(int v) {}
                  |int declInit(int p) { int q = p; sink(q); return 0; }
                  |int plainAssign(int p) { int q; q = p; sink(q); return 0; }
                  |""".stripMargin)
              count(cpg, "declInit") should be > 0
              count(cpg, "plainAssign") should be > 0
          }

          "flow through arithmetic and a chain of primitive assignments" in {
              val cpg = code("""
                  |void sink(int v) {}
                  |int chained(int p) {
                  |    int a = p;
                  |    int b = a + 1;
                  |    int c = b;
                  |    sink(c);
                  |    return 0;
                  |}
                  |""".stripMargin)
              count(cpg, "chained") should be > 0
          }

          "flow interprocedurally through a primitive parameter" in {
              val cpg = code("""
                  |void sink(int v) {}
                  |int helper(int v) { int w = v; return w; }
                  |int inter(int p) {
                  |    int a = helper(p);
                  |    sink(a);
                  |    return 0;
                  |}
                  |""".stripMargin)
              count(cpg, "inter") should be > 0
          }
      }
end CppPrimitiveTaintFlowTests

/** The same specs under the Flux engine (atom's default). */
class CppPrimitiveTaintFlowFluxTests extends CppFluxDataFlowCodeToCpgSuite:
  private def flowCount(cpg: io.shiftleft.codepropertygraph.generated.Cpg, m: String): Int =
      cpg.method.nameExact(m).call.nameExact("sink").argument(1)
          .reachableByFlows(cpg.method.nameExact(m).parameter.nameExact("p")).size

  "primitive taint under the flux reaching-def engine" should {
      "flow through a primitive local (regression)" in {
          val cpg = code("""
              |void sink(int v) {}
              |int declInit(int p) { int q = p; sink(q); return 0; }
              |""".stripMargin)
          flowCount(cpg, "declInit") should be > 0
      }

      "flow through arithmetic and a chain of primitive assignments" in {
          val cpg = code("""
              |void sink(int v) {}
              |int chained(int p) {
              |    int a = p;
              |    int b = a + 1;
              |    int c = b;
              |    sink(c);
              |    return 0;
              |}
              |""".stripMargin)
          flowCount(cpg, "chained") should be > 0
      }
  }
end CppPrimitiveTaintFlowFluxTests
