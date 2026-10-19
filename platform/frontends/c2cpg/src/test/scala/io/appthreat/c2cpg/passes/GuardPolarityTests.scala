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
    |
    |#include <stddef.h>
    |#include <string.h>
    |/* a loop's exit: after it, n > 32 has failed, so the last copy is at most 32 bytes */
    |void after_a_chunking_loop(unsigned char *out, size_t total)
    |{
    |    unsigned char block[32];
    |    unsigned char *cp;
    |    size_t n;
    |    memset(block, 1, sizeof(block));
    |    for (cp = out, n = total; n > 32; n -= 32, cp += 32)
    |        memcpy(cp, block, 32);
    |    memcpy(cp, block, n);
    |}
    |
    |/* the chunk is a digest's size, 32 or 64, and the source holds 64 */
    |void after_a_digest_sized_loop(unsigned char *out, size_t total, int kind)
    |{
    |    unsigned char digest[64];
    |    unsigned char *cp;
    |    size_t chunk, n;
    |    if (kind == 5)
    |        chunk = 32;
    |    else
    |        chunk = 64;
    |    memset(digest, 1, sizeof(digest));
    |    for (cp = out, n = total; n > chunk; n -= chunk, cp += chunk)
    |        memcpy(cp, digest, chunk);
    |    memcpy(cp, digest, n);
    |}
    |
    |/* the twin: a break leaves the loop with the condition still true */
    |void after_a_loop_with_a_break(unsigned char *out, size_t total)
    |{
    |    unsigned char block[32];
    |    unsigned char *cp;
    |    size_t n;
    |    memset(block, 1, sizeof(block));
    |    for (cp = out, n = total; n > 32; n -= 32, cp += 32) {
    |        if (cp[0] == 0)
    |            break;
    |        memcpy(cp, block, 32);
    |    }
    |    memcpy(cp, block, n);
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
    "bound the length after the loop whose condition failed" in {
        boundFindings("after_a_chunking_loop") shouldBe empty
    }
    "bound the length by a chunk every value of which fits the source" in {
        boundFindings("after_a_digest_sized_loop") shouldBe empty
    }
    "leave the length unbounded when a break also leaves the loop" in {
        boundFindings("after_a_loop_with_a_break") should not be empty
    }
end GuardPolarityTests
