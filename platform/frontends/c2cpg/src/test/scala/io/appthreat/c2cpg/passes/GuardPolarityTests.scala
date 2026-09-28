package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A guard's truth after its structure is decided by which branch reaches the use: when the else
  * exits, the condition HOLDS after the if - reading it as false turned `i >= 16` into a bound.
  */
class GuardPolarityTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |void note(void);
    |
    |/* the else exits: after the if, i >= 16 holds - the write is out of bounds */
    |void else_exits_after_a_too_large_test(unsigned i)
    |{
    |    int buf[16];
    |    if (i >= 16) {
    |        note();
    |    } else {
    |        return;
    |    }
    |    buf[i] = 1;
    |    note();
    |}
    |
    |/* the correct twin: the else exits and i < 16 holds after the if */
    |void else_exits_after_a_bounding_test(unsigned i)
    |{
    |    int buf[16];
    |    if (i < 16) {
    |        note();
    |    } else {
    |        return;
    |    }
    |    buf[i] = 1;
    |    note();
    |}
    |
    |/* the correct twin: the then exits, so i < 16 holds after the if */
    |void then_exits(int i)
    |{
    |    int buf[16];
    |    if (i < 0 || i >= 16)
    |        return;
    |    buf[i] = 1;
    |    note();
    |}
    |""".stripMargin,
    "guardpolarity.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def boundFindings(method: String): List[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l)
          .filter(_.startsWith("MS-BOUND")).l

  "a guard after its structure" should:
    "hold when the else exits, so a too-large test is no bound" in {
        boundFindings("else_exits_after_a_too_large_test") should not be empty
    }
    "bound the index when the else exits after a bounding test" in {
        boundFindings("else_exits_after_a_bounding_test") shouldBe empty
    }
    "bound the index after an early exit" in {
        boundFindings("then_exits") shouldBe empty
    }
end GuardPolarityTests
