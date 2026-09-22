package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** MS-INT-001 / MS-INT-002 (part 4, D0): the integer rules over the C5 width facts. Every positive
  * mirrors a corpus shape (c/cwe190_integer_overflow.c, c/ffmpeg-shapes/lossy_cast_in_guard.c, the
  * hevc.c:847 realloc), and every negative is the paired correctly-written variant - including the
  * FIXED trees' own shapes: a guard bounding an operand, a widened operand, and a cast sitting on
  * the guard's BOUND side instead of the bounded value.
  */
class MemorySafetyIntegerRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <stdint.h>
    |
    |struct nal_array { void *nal; uint16_t numNalus; };
    |
    |/* ---- MS-INT-001 ---- */
    |
    |/* the hevc.c:847 shape: the attacker-influenced COUNT factor of a count-by-size realloc */
    |void *bad_count_unguarded(struct nal_array *array)
    |{
    |    uint16_t numNalus = array->numNalus;
    |    void *p = reallocarray(array->nal, numNalus + 1, sizeof(*array->nal));
    |    array->nal = p;
    |    return p;
    |}
    |
    |/* the fixed tree adds exactly this guard - the rule must stand down */
    |void *good_count_guarded(struct nal_array *array)
    |{
    |    if (array->numNalus >= 65535) return NULL;
    |    void *p = reallocarray(array->nal, array->numNalus + 1, sizeof(*array->nal));
    |    array->nal = p;
    |    return p;
    |}
    |
    |/* the cwe190 fixture's addition shape */
    |void *bad_add_overflow(int len)
    |{
    |    return malloc(len + 1);
    |}
    |
    |/* widened before the multiply: the product already computes at 64 bits */
    |void *good_widened(unsigned int count)
    |{
    |    return malloc((size_t) count * 64);
    |}
    |
    |/* the cwe190 fixture's guarded multiplication */
    |void *good_mul_guarded(unsigned int count)
    |{
    |    if (count > 4294967295u / 4) return NULL;
    |    return malloc(count * 4);
    |}
    |
    |/* ---- MS-INT-002 ---- */
    |
    |/* the CVE-2026-75145 shape: the guard tests the re-signed view, the use reads uint32_t */
    |int bad_resign_guard(uint32_t obu_size, int remaining, unsigned char *dst,
    |                     const unsigned char *src)
    |{
    |    if ((long)obu_size > remaining)
    |        return -1;
    |    memcpy(dst, src, obu_size);
    |    return 0;
    |}
    |
    |/* the fixed tree's shape: the cast is on the BOUND, the bounded value never changed width */
    |int good_resign_on_bound(uint32_t obu_size, int frame_size)
    |{
    |    if (obu_size > (unsigned) frame_size)
    |        return -1;
    |    frame_size -= obu_size;
    |    return frame_size;
    |}
    |
    |/* a sign-changing cast that feeds a copy length with no guard around it: not this rule */
    |int good_cast_in_copy(int n, unsigned char *d, const unsigned char *s)
    |{
    |    memcpy(d, s, (size_t) n);
    |    return 0;
    |}
    |""".stripMargin,
    "integers.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  /** (rule id, line) pairs found on ANY expression of the method. */
  private def findingsIn(method: String): Set[(String, Int)] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Expression]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(a =>
              a.tag.name("ms-finding").value.l.map(v =>
                  (v, a.lineNumber.map(_.toInt).getOrElse(-1))
              )
          )
          .l
          .toSet

  "MS-INT-001" should:

    "fire on the attacker-influenced count factor of a count-by-size realloc (hevc.c:847)" in {
        findingsIn("bad_count_unguarded").map(_._1) shouldBe Set("MS-INT-001")
        // the finding names the arithmetic itself, not the memory call
        findingsIn("bad_count_unguarded").forall { case (_, line) => line > 0 } shouldBe true
    }

    "fire on the corpus fixture's unguarded addition length" in {
        findingsIn("bad_add_overflow").map(_._1) shouldBe Set("MS-INT-001")
    }

    "stand down when a guard bounds the count from above (the fixed tree's guard)" in {
        findingsIn("good_count_guarded") shouldBe empty
    }

    "stand down when an operand was widened before the arithmetic" in {
        findingsIn("good_widened") shouldBe empty
    }

    "stand down when the multiplication is guarded (the cwe190 fixture's good_ pair)" in {
        findingsIn("good_mul_guarded") shouldBe empty
    }

  "MS-INT-002" should:

    "fire where the guard tests the re-signed view and the use reads the declared one" in {
        // the memcpy in the same fixture draws the BOUND rules too - the length is an
        // unguarded caller param - so assert presence, not exclusivity
        findingsIn("bad_resign_guard").map(_._1) should contain("MS-INT-002")
        findingsIn("bad_resign_guard").count(_._1 == "MS-INT-002") shouldBe 1
    }

    "not fire when the cast is on the guard's bound (the fixed tree's shape)" in {
        findingsIn("good_resign_on_bound") shouldBe empty
    }

    "not fire on a resign cast that feeds a length with no guard around it" in {
        findingsIn("good_cast_in_copy") shouldBe empty
    }
end MemorySafetyIntegerRuleTests
