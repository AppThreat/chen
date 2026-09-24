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

/** MS-BOUND-006/007 (F4, part 6): a write or copy overruns a buffer whose capacity the graph knows.
  * Every positive is a corpus CWE-121/122 row that the four bounds rules missed while the extent,
  * the length and the guard were all on the graph; every negative is the good pair.
  */
class CapacityOverrunRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |
    |/* the cwe121 rows: strcpy/sprintf into a declared array - the copy family with
    |   NO length argument, so MS-BOUND-002 (which reads the mem-len argument) could
    |   not even ask the question */
    |void bad_implicit_strcpy(const char *userInput)
    |{
    |    char dest[16];
    |    strcpy(dest, userInput);
    |    printf("%s\n", dest);
    |}
    |
    |void bad_implicit_sprintf(const char *userInput)
    |{
    |    char dest[16];
    |    sprintf(dest, "hello %s", userInput);
    |}
    |
    |/* the guard the author wrote: the source's LENGTH is bounded, one line up */
    |void good_checked_strcpy(const char *userInput)
    |{
    |    char dest[16];
    |    if (strlen(userInput) < sizeof(dest))
    |        strcpy(dest, userInput);
    |}
    |
    |void good_bounded_snprintf(const char *userInput)
    |{
    |    char dest[16];
    |    snprintf(dest, sizeof(dest), "%s", userInput);
    |}
    |
    |/* the cwe122 rows: a constant length past an allocation's size. The extent was
    |   `unknown` until ExtentPass learned to look through the cast. */
    |void bad_const_past_alloc(const char *userInput)
    |{
    |    char *buf = (char *)malloc(10);
    |    if (buf == NULL) return;
    |    memcpy(buf, userInput, 100);
    |    free(buf);
    |}
    |
    |void bad_const_past_realloc(char *userInput)
    |{
    |    char *buf = (char *)malloc(64);
    |    if (buf == NULL) return;
    |    buf = (char *)realloc(buf, 8);
    |    if (buf == NULL) return;
    |    memcpy(buf, userInput, 64);
    |    free(buf);
    |}
    |
    |void good_matching_len(const char *userInput)
    |{
    |    size_t n = strlen(userInput) + 1;
    |    char *buf = (char *)malloc(n);
    |    if (buf == NULL) return;
    |    memcpy(buf, userInput, n);
    |    free(buf);
    |}
    |
    |/* the struct-array row (CVE-2026-64831's shape): a loop write bounded by an
    |   unvalidated count into a member array whose extent is in the type */
    |#define MAX_HRD 16
    |struct vps_params { int hrd[MAX_HRD]; int nb_hrd; };
    |
    |void bad_loop_count_write(struct vps_params *vps, const int *src, int count)
    |{
    |    int i;
    |    for (i = 0; i < count; i++)
    |        vps->hrd[i] = src[i];
    |    vps->nb_hrd = count;
    |}
    |
    |/* the loop is bounded by the SAME count that sizes the allocation: bounded
    |   by construction, whatever count is */
    |void good_self_sized_loop(int count)
    |{
    |    int i;
    |    int *arr = (int *)malloc(count * sizeof(int));
    |    if (!arr) return;
    |    for (i = 0; i < count; i++)
    |        arr[i] = i;
    |    free(arr);
    |}
    |
    |void good_capped_loop_write(struct vps_params *vps, const int *src, int count)
    |{
    |    int i;
    |    if (count > MAX_HRD) return;
    |    for (i = 0; i < count; i++)
    |        vps->hrd[i] = src[i];
    |    vps->nb_hrd = count;
    |}
    |
    |/* the capacity binder (M15's one-function scope): init_put_bits stores its buffer
    |   into a member and buf+size into another - the (buffer, capacity) constructor
    |   concluded from the body, so the claimed capacity meets the buffer's real extent */
    |struct put_bit_context { unsigned char *buf; unsigned char *buf_end; unsigned char *ptr; };
    |
    |static void init_put_bits(struct put_bit_context *s, unsigned char *buf, int size)
    |{
    |    s->buf = buf;
    |    s->buf_end = buf + size;
    |    s->ptr = buf;
    |}
    |
    |void bad_context_sized_past_buffer(int n)
    |{
    |    unsigned char buffer[128];
    |    struct put_bit_context pb;
    |    init_put_bits(&pb, buffer, 1024);
    |}
    |
    |void good_context_sized_right(int n)
    |{
    |    unsigned char buffer[128];
    |    struct put_bit_context pb;
    |    init_put_bits(&pb, buffer, sizeof(buffer));
    |}
    |""".stripMargin,
    "capacity.c"
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
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  "MS-BOUND-006/007" should:

    "fire on the implicit strcpy into a fixed buffer (the cwe121 row)" in {
        findingsIn("bad_implicit_strcpy") shouldBe Set("MS-BOUND-006")
    }

    "fire on the implicit sprintf with an attacker format argument" in {
        findingsIn("bad_implicit_sprintf") shouldBe Set("MS-BOUND-006")
    }

    "stay silent when the source's length is guarded" in {
        findingsIn("good_checked_strcpy") shouldBe empty
    }

    "stay silent when the copy declares its own bound" in {
        findingsIn("good_bounded_snprintf") shouldBe empty
    }

    "fire on a constant length past an allocation's size (the cwe122 row)" in {
        findingsIn("bad_const_past_alloc") shouldBe Set("MS-BOUND-007")
    }

    "fire on a constant length past a shrunk reallocation" in {
        findingsIn("bad_const_past_realloc") shouldBe Set("MS-BOUND-007")
    }

    "stay silent when the length matches the allocation" in {
        // the control is THIS rule's question; MS-ALLOC-008's own unbounded-size claim about
        // the same site (n is attacker-chosen with no cap) is a different, true finding
        findingsIn("good_matching_len") should not contain "MS-BOUND-007"
    }

    "fire on a loop write bounded by an unvalidated count (the struct-array row)" in {
        findingsIn("bad_loop_count_write") shouldBe Set("MS-BOUND-006")
    }

    "stay silent when the count is capped against the extent's constant" in {
        findingsIn("good_capped_loop_write") shouldBe empty
    }

    "stay silent when the loop bound sizes the allocation itself" in {
        // the loop cannot overrun a buffer sized by its own bound; MS-ALLOC-009's
        // unbounded-size question about the same count is separate, true, and at low
        findingsIn("good_self_sized_loop") should not contain "MS-BOUND-006"
        findingsIn("good_self_sized_loop") should not contain "MS-BOUND-007"
    }

    "conclude the capacity binder from the body and fire on a capacity past the buffer" in {
        findingsIn("bad_context_sized_past_buffer") shouldBe Set("MS-BOUND-006")
    }

    "stay silent when the binder is handed the buffer's real size" in {
        findingsIn("good_context_sized_right") shouldBe empty
    }
end CapacityOverrunRuleTests
