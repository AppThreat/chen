package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** The rules find pointer arithmetic by the frontend's tag, so the pointer is the pointer whatever
  * its type is spelled as and whichever side of the operator it is written on.
  */
class PointerArithmeticRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <string.h>
    |
    |#define HDR 12
    |typedef const unsigned char *cursor_t;
    |
    |int bad_plain_walk(const unsigned char *buf, int len, int step)
    |{
    |    const unsigned char *p = buf;
    |    int sum = 0;
    |    while (sum < len)
    |    {
    |        sum += p[0];
    |        p += step;
    |    }
    |    return sum;
    |}
    |
    |int bad_typedef_walk(cursor_t buf, int len, int step)
    |{
    |    cursor_t p = buf;
    |    int sum = 0;
    |    while (sum < len)
    |    {
    |        sum += p[0];
    |        p += step;
    |    }
    |    return sum;
    |}
    |
    |int good_integer_walk(const unsigned char *buf, int len, int step)
    |{
    |    int i = 0;
    |    int sum = 0;
    |    while (sum < len)
    |    {
    |        sum += buf[0];
    |        i += step;
    |    }
    |    return sum + i;
    |}
    |
    |void bad_offset_copy(const char *in)
    |{
    |    char buf[16];
    |    memcpy(buf + HDR, in, 8);
    |}
    |
    |void good_offset_copy(const char *in)
    |{
    |    char buf[16];
    |    memcpy(buf + HDR, in, 4);
    |}
    |
    |void offset_first(const char *in, int off)
    |{
    |    char buf[16];
    |    memcpy(off + buf, in, 4);
    |}
    |""".stripMargin,
    "walks.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  "a pointer walked by an attacker's step" should {
      "be found whatever the pointer's type is spelled as" in {
          findingsIn("bad_plain_walk") should contain("MS-BOUND-003")
          findingsIn("bad_typedef_walk") should contain("MS-BOUND-003")
      }

      "not be confused with an integer stepped the same way" in {
          findingsIn("good_integer_walk") should not contain "MS-BOUND-003"
      }
  }

  "a copy into a buffer at an offset" should {
      "shrink the capacity by a constant offset" in {
          cpg.method.name("good_offset_copy").call.nameExact("memcpy").argument(1)
              .tag.name(ExtentPass.TagExtent).value.l shouldBe List(s"${ExtentPass.ValueConst}:4")
          findingsIn("bad_offset_copy") should contain("MS-BOUND-006")
          findingsIn("good_offset_copy") should not contain "MS-BOUND-006"
      }

      "take the buffer as the base when the offset is written first" in {
          cpg.method.name("offset_first").call.nameExact("memcpy").argument(1)
              .tag.name(ExtentPass.TagExtent).value.l shouldBe
              List(s"${ExtentPass.ValueOffset}:${ExtentPass.ValueConst}:16")
      }
  }
end PointerArithmeticRuleTests
