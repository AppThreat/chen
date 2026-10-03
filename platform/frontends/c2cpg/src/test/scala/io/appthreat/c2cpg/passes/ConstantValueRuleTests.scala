package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** The rules read a constant the frontend evaluated as they read a literal: a macro constant, an
  * enumerator or a sizeof is a known length, capacity, scale or stored value.
  */
class ConstantValueRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |#define HDR_LEN (16 * 4)
    |enum { SMALL = 8, ITEM = 12, LIMIT = 100, COUNT = 4 };
    |struct big { char d[64]; };
    |
    |void bad_macro_len_past_alloc(const char *in)
    |{
    |    char *buf = (char *)malloc(10);
    |    if (buf == NULL) return;
    |    memcpy(buf, in, HDR_LEN);
    |    free(buf);
    |}
    |
    |void good_enum_len(const char *in)
    |{
    |    char *buf = (char *)malloc(16);
    |    if (buf == NULL) return;
    |    memcpy(buf, in, SMALL);
    |    free(buf);
    |}
    |
    |void bad_past_counted_alloc(const char *in)
    |{
    |    char *buf = (char *)calloc(COUNT, sizeof(int));
    |    if (buf == NULL) return;
    |    memcpy(buf, in, 100);
    |    free(buf);
    |}
    |
    |void good_within_counted_alloc(const char *in)
    |{
    |    char *buf = (char *)calloc(COUNT, sizeof(int));
    |    if (buf == NULL) return;
    |    memcpy(buf, in, 16);
    |    free(buf);
    |}
    |
    |void *scaled_alloc(unsigned n)
    |{
    |    if (n > LIMIT) return NULL;
    |    return malloc(n * ITEM);
    |}
    |
    |void stores(int wide)
    |{
    |    unsigned char fits = 5;
    |    unsigned char size = sizeof(struct big);
    |    unsigned short len = HDR_LEN;
    |    unsigned char cast = (unsigned char) SMALL;
    |    unsigned char over = 300;
    |    unsigned char narrowed = wide;
    |}
    |""".stripMargin,
    "constants.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
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

  "a constant length or capacity" should {
      "count as known when a macro writes it" in {
          findingsIn("bad_macro_len_past_alloc") should contain("MS-BOUND-007")
      }

      "stay silent when an enumerator length fits" in {
          findingsIn("good_enum_len") should not contain "MS-BOUND-007"
      }

      "size a count-by-size allocation from constant factors" in {
          // the allocation is named, and its size read as count * size bytes
          cpg.method.name("good_within_counted_alloc").call.nameExact("memcpy").argument(1)
              .tag.name(ExtentPass.TagExtent).value.l.map(_.takeWhile(_ != ':')) shouldBe
              List(ExtentPass.ValueAlloc)
          findingsIn("bad_past_counted_alloc") should contain("MS-BOUND-007")
          findingsIn("good_within_counted_alloc") should not contain "MS-BOUND-007"
      }
  }

  "a guard on a variable" should {
      "bound the length the variable is scaled by an enumerator into" in {
          val sizeArg = cpg.method.name("scaled_alloc").call.nameExact("malloc").argument(1).l
          sizeArg.tag.name(GuardPass.TagAbove).size shouldBe 1
      }
  }

  "storing a constant" should {
      "narrow nothing when the destination holds it" in {
          val narrowed = cpg.method.name("stores").call.nameExact("<operator>.assignment")
              .filter(_.tag.name(IntegerWidthPass.TagNarrow).nonEmpty).argument(1).code.l
          narrowed shouldBe List("over", "narrowed")
          cpg.method.name("stores").call.nameExact("<operator>.cast")
              .tag.name(IntegerWidthPass.TagNarrow).size shouldBe 0
      }
  }
end ConstantValueRuleTests
