package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 10 review: the libavformat shapes the part 10 arms got wrong. */
class Part10ReviewTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <limits.h>
    |
    |/* the rhs mentions the handle but is a NEW block: the old one is lost */
    |char *bad_strdup_self(void)
    |{
    |    char *p = (char *)malloc(16);
    |    if (!p) return NULL;
    |    p[0] = 0;
    |    p = strdup(p);
    |    return p;
    |}
    |
    |/* asfdec_f.c / rmdec.c: converting to unsigned IS the lower bound */
    |int good_unsigned_upper_guard(int name_len, unsigned char *dst, const unsigned char *src)
    |{
    |    if ((unsigned)name_len > INT_MAX / 2)
    |        return -1;
    |    memcpy(dst, src, name_len);
    |    return 0;
    |}
    |
    |/* CVE-2026-75145: converting to SIGNED lets the too-large through */
    |int bad_signed_upper_guard(unsigned int obu_size, int remaining, unsigned char *dst,
    |                           const unsigned char *src)
    |{
    |    if ((long)obu_size > remaining)
    |        return -1;
    |    memcpy(dst, src, obu_size);
    |    return 0;
    |}
    |
    |/* lazy initialisation in a program that never starts a thread */
    |static int inited;
    |void lazy_init(void)
    |{
    |    if (!inited) {
    |        inited = 1;
    |    }
    |}
    |
    |/* avienc.c / http.c: an array sized by its string initialiser */
    |int string_table(void)
    |{
    |    char crlf[] = "\r\n";
    |    return crlf[0];
    |}
    |""".stripMargin,
    "part10review.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "the overwrite arm" should:
    "report `p = strdup(p)`: mentioning the handle is not moving it" in {
        findingsIn("bad_strdup_self") should contain("MS-ALLOC-003")
    }

  "MS-INT-002" should:
    "stay silent on a signed value converted to unsigned and bounded above" in {
        findingsIn("good_unsigned_upper_guard") should not contain "MS-INT-002"
    }
    "still report an unsigned value converted to signed and bounded above" in {
        findingsIn("bad_signed_upper_guard") should contain("MS-INT-002")
    }

  "MS-TOCTOU-001" should:
    "not report check-then-act in a program with no second thread" in {
        findingsIn("lazy_init") should not contain "MS-TOCTOU-001"
    }

  "MS-ALLOC-008" should:
    "not report an array sized by its string initialiser" in {
        findingsIn("string_table") should not contain "MS-ALLOC-008"
    }
end Part10ReviewTests
