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
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 6 review: negative controls for the shapes the F1-F5 changes get wrong. Every function here
  * is correct C; none may carry the named finding.
  */
class Part6ReviewTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <stdio.h>
    |
    |struct pt { int x; int y; };
    |
    |/* F4: an array's const extent counts ELEMENTS, a memset length counts BYTES */
    |void good_int_array_clear(void)
    |{
    |    int a[10];
    |    memset(a, 0, 40);
    |    a[0] = 1;
    |}
    |
    |void good_struct_array_clear(void)
    |{
    |    struct pt pts[4];
    |    memset(pts, 0, 32);
    |    pts[0].x = 1;
    |}
    |
    |/* F4: the positive shape still fires: a byte array written past its end */
    |void bad_char_array(void)
    |{
    |    char b[10];
    |    memset(b, 0, 40);
    |}
    |
    |/* F4: an integer formatted into a fixed buffer is not an unbounded string copy */
    |void good_sprintf_int(int n)
    |{
    |    char buf[32];
    |    sprintf(buf, "%d", n);
    |    puts(buf);
    |}
    |
    |/* low-arm volume: FFmpeg's paired-allocation check narrows BOTH pointers */
    |int good_paired_check(size_t n)
    |{
    |    char *a = (char *)malloc(n);
    |    char *b = (char *)malloc(n);
    |    if (!a || !b)
    |        goto fail;
    |    a[0] = b[0] = 0;
    |    free(a);
    |    free(b);
    |    return 0;
    |fail:
    |    free(a);
    |    free(b);
    |    return -1;
    |}
    |
    |/* low-arm volume: an int error code from an allocate-into-out-param call is not a block */
    |int my_reallocp(void *ptr, size_t n);
    |int good_error_code(char **out, size_t n)
    |{
    |    char *p = NULL;
    |    int ret;
    |    if (!p)
    |        ret = 1;
    |    if (ret)
    |        return ret;
    |    *out = p;
    |    return 0;
    |}
    |
    |/* low-arm volume: a null test in the use's own expression protects it */
    |int good_inline_guards(const char *s)
    |{
    |    char *e = strchr(s, ',');
    |    char *f = strchr(s, ';');
    |    char *g = strchr(s, ':');
    |    int n = e && e[1] == 'x';
    |    n += (!f || f[1] == 'y');
    |    n += g ? g[1] : 0;
    |    return n;
    |}
    |
    |/* F4: calloc's capacity is count * size, not the size argument alone */
    |void good_calloc_clear(void)
    |{
    |    char *p = (char *)calloc(10, 4);
    |    if (!p)
    |        return;
    |    memset(p, 0, 40);
    |    free(p);
    |}
    |
    |/* F5: a static POINTER local holds heap storage */
    |void good_static_cache(size_t n)
    |{
    |    static char *cache;
    |    free(cache);
    |    cache = (char *)malloc(n);
    |}
    |
    |/* F2: the allocation failed on the taken branch; the other branch frees it */
    |int good_assign_in_cond(size_t n)
    |{
    |    char *p;
    |    if (!(p = (char *)malloc(n)))
    |        return -1;
    |    p[0] = 0;
    |    free(p);
    |    return 0;
    |}
    |
    |int good_assign_in_cond_pos(size_t n)
    |{
    |    char *p;
    |    if ((p = (char *)malloc(n))) {
    |        p[0] = 0;
    |        free(p);
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "review6.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method
          .nameExact(method)
          .ast
          .collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  "part 6 negative controls" should:
    "not compare a byte length with an element count (int array)" in {
        findingsIn("good_int_array_clear") should not contain "MS-BOUND-006"
    }
    "not compare a byte length with an element count (struct array)" in {
        findingsIn("good_struct_array_clear") should not contain "MS-BOUND-006"
    }
    "still report a byte array overrun" in {
        findingsIn("bad_char_array") should contain("MS-BOUND-006")
    }
    "not treat a formatted integer as an unbounded copy" in {
        findingsIn("good_sprintf_int") should not contain "MS-BOUND-006"
    }
    "narrow both pointers of a disjunctive null check" in {
        findingsIn("good_paired_check") should not contain "MS-NULL-001"
        findingsIn("good_paired_check") should not contain "MS-ALLOC-003"
    }
    "not revive a guard-nulled variable as an allocation" in {
        findingsIn("good_error_code") should not contain "MS-ALLOC-003"
    }
    "honour short-circuit and ternary null tests" in {
        findingsIn("good_inline_guards") should not contain "MS-NULL-001"
    }
    "not size a calloc by its element size alone" in {
        findingsIn("good_calloc_clear") should not contain "MS-BOUND-007"
    }
    "not report a static pointer local as non-heap or leaked" in {
        findingsIn("good_static_cache") should not contain "MS-ALLOC-005"
        findingsIn("good_static_cache") should not contain "MS-ALLOC-003"
    }
    "narrow an assignment-in-condition on the right branch" in {
        // MS-ALLOC-008 (a caller-param size, `low`) is the only finding either may carry
        (findingsIn("good_assign_in_cond") - "MS-ALLOC-008") shouldBe empty
        (findingsIn("good_assign_in_cond_pos") - "MS-ALLOC-008") shouldBe empty
    }
end Part6ReviewTests
