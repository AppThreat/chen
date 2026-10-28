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

/** MS-BOUND-006/007: a write or copy overruns a buffer whose capacity the graph knows. Every
  * positive is a CWE-121/122 shape the length-based bounds rules cannot see although the extent,
  * the length and the guard are all on the graph; every negative is the good pair.
  */
class CapacityOverrunRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |#include <wchar.h>
    |#define ALLOCA alloca
    |
    |/* the CWE-121 shapes: strcpy/sprintf into a declared array - the copy family with
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
    |/* two buffers of one name in different blocks: each copy is measured against the
    |   buffer it writes, not the first one the function declares */
    |void good_same_name_buffers(const char *userInput, int wide)
    |{
    |    if (wide) {
    |        char buf[8];
    |        memcpy(buf, userInput, 8);
    |    } else {
    |        char buf[200];
    |        memcpy(buf, userInput, 150);
    |    }
    |}
    |
    |/* the CWE-122 shapes: a constant length past an allocation's size. The extent is
    |   `unknown` unless ExtentPass looks through the cast. */
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
    |/* the struct-array shape (CVE-2026-64831): a loop write bounded by an
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
    |/* the capacity binder (a one-function scope): init_put_bits stores its buffer
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
    |
    |/* the alloca alias: the buffer's extent carries through `data = dataBadBuffer`,
    |   counted in elements of wchar_t, not bytes - the loop bound wcslen(source) + 1
    |   walks one element past the short of the two allocas (the CWE-193 shape) */
    |void bad_alloca_alias_loop(void)
    |{
    |    wchar_t *data;
    |    wchar_t *dataBadBuffer = (wchar_t *)ALLOCA((10)*sizeof(wchar_t));
    |    wchar_t *dataGoodBuffer = (wchar_t *)ALLOCA((10+1)*sizeof(wchar_t));
    |    data = dataBadBuffer;
    |    data[0] = L'\\0';
    |    {
    |        wchar_t source[10+1] = L"AAAAAAAAAA";
    |        size_t i, sourceLen;
    |        sourceLen = wcslen(source);
    |        for (i = 0; i < sourceLen + 1; i++)
    |            data[i] = source[i];
    |    }
    |}
    |
    |void good_alloca_alias_loop(void)
    |{
    |    wchar_t *data;
    |    wchar_t *dataBadBuffer = (wchar_t *)ALLOCA((10)*sizeof(wchar_t));
    |    wchar_t *dataGoodBuffer = (wchar_t *)ALLOCA((10+1)*sizeof(wchar_t));
    |    data = dataGoodBuffer;
    |    data[0] = L'\\0';
    |    {
    |        wchar_t source[10+1] = L"AAAAAAAAAA";
    |        size_t i, sourceLen;
    |        sourceLen = wcslen(source);
    |        for (i = 0; i < sourceLen + 1; i++)
    |            data[i] = source[i];
    |    }
    |}
    |
    |/* an appending copy whose source's length the graph knows: the declared array
    |   `source[100]` is longer than the 50-element allocation it is appended to */
    |void bad_wcscat_past_heap(void)
    |{
    |    wchar_t *data = (wchar_t *)malloc(50*sizeof(wchar_t));
    |    if (data == NULL) exit(-1);
    |    data[0] = L'\\0';
    |    {
    |        wchar_t source[100];
    |        wmemset(source, L'C', 100-1);
    |        source[100-1] = L'\\0';
    |        wcscat(data, source);
    |        free(data);
    |    }
    |}
    |
    |void good_wcscat_heap_fits(void)
    |{
    |    wchar_t *data = (wchar_t *)malloc(100*sizeof(wchar_t));
    |    if (data == NULL) exit(-1);
    |    data[0] = L'\\0';
    |    {
    |        wchar_t source[100];
    |        wmemset(source, L'C', 100-1);
    |        source[100-1] = L'\\0';
    |        wcscat(data, source);
    |        free(data);
    |    }
    |}
    |
    |/* the shapes that cross a call: the buffer's extent travels with the argument, and the
    |   length a string's own content bounds - the sink writes past a smaller caller
    |   buffer, the return hands back a pointer before its object */
    |void t4_bad_sink(int *data)
    |{
    |    int source[100] = {0};
    |    memcpy(data, source, 100*sizeof(int));
    |}
    |void t4_good_sink(int *data)
    |{
    |    int source[100] = {0};
    |    memcpy(data, source, 100*sizeof(int));
    |}
    |void bad_t4_param_small(void)
    |{
    |    int dataBadBuffer[50];
    |    int *data = dataBadBuffer;
    |    t4_bad_sink(data);
    |}
    |void good_t4_param_fits(void)
    |{
    |    int dataGoodBuffer[100];
    |    int *data = dataGoodBuffer;
    |    t4_good_sink(data);
    |}
    |
    |static wchar_t *t4_before_source(wchar_t *data)
    |{
    |    wchar_t *dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
    |    if (dataBuffer == NULL) exit(-1);
    |    wmemset(dataBuffer, L'A', 100-1);
    |    dataBuffer[100-1] = L'\0';
    |    data = dataBuffer - 8;
    |    return data;
    |}
    |void bad_t4_returned_before(void)
    |{
    |    wchar_t *data = NULL;
    |    data = t4_before_source(data);
    |    {
    |        wchar_t source[100];
    |        wmemset(source, L'C', 100-1);
    |        source[100-1] = L'\0';
    |        wcsncpy(data, source, 100-1);
    |        free(data);
    |    }
    |}
    |
    |void bad_t4_overread_src_bound(void)
    |{
    |    char *data = (char *)malloc(50);
    |    if (data == NULL) exit(-1);
    |    memset(data, 'A', 50-1);
    |    data[50-1] = '\0';
    |    {
    |        char dest[100];
    |        memset(dest, 'C', 100-1);
    |        dest[100-1] = '\0';
    |        memmove(dest, data, strlen(dest)*sizeof(char));
    |        free(data);
    |    }
    |}
    |void good_t4_overread_src_fits(void)
    |{
    |    char *data = (char *)malloc(100);
    |    if (data == NULL) exit(-1);
    |    memset(data, 'A', 100-1);
    |    data[100-1] = '\0';
    |    {
    |        char dest[100];
    |        memset(dest, 'C', 100-1);
    |        dest[100-1] = '\0';
    |        memmove(dest, data, strlen(dest)*sizeof(char));
    |        free(data);
    |    }
    |}
    |
    |/* the same read past a smaller source, in a function the suites' names do not mark */
    |void copy_measured_by_other(void)
    |{
    |    char *data = (char *)malloc(50*sizeof(char));
    |    if (data == NULL) exit(-1);
    |    memset(data, 'A', 50-1);
    |    data[50-1] = '\0';
    |    {
    |        char dest[100];
    |        memset(dest, 'C', 100-1);
    |        dest[100-1] = '\0';
    |        memmove(dest, data, strlen(dest)*sizeof(char));
    |        free(data);
    |    }
    |}
    |
    |/* a fill in another function says nothing about this one's buffer of the same name */
    |void fills_its_own_source(void)
    |{
    |    wchar_t source[200];
    |    wmemset(source, L'C', 200-1);
    |    source[200-1] = L'\0';
    |}
    |void good_unfilled_source_of_same_name(const wchar_t *in)
    |{
    |    wchar_t *data = (wchar_t *)malloc(50*sizeof(wchar_t));
    |    if (data == NULL) exit(-1);
    |    data[0] = L'\0';
    |    {
    |        wchar_t source[200];
    |        wcsncpy(source, in, 10);
    |        source[10] = L'\0';
    |        wcscat(data, source);
    |        free(data);
    |    }
    |}
    |
    |/* a sink called through a function pointer with a caller buffer large enough: the
    |   parameter has no definition of its own, which states no capacity - not a capacity of 0 */
    |static void fp_good_sink(char *data)
    |{
    |    char source[100];
    |    memset(source, 'C', 100-1);
    |    source[100-1] = '\0';
    |    memcpy(data, source, 100*sizeof(char));
    |}
    |void good_fp_caller_fits(void)
    |{
    |    char *data;
    |    void (*funcPtr)(char *) = fp_good_sink;
    |    char *dataBuffer = (char *)malloc(100*sizeof(char));
    |    if (dataBuffer == NULL) exit(-1);
    |    data = dataBuffer;
    |    funcPtr(data);
    |}
    |
    |/* a large buffer holding a short string: its room is not its content */
    |void good_strcpy_from_large_short_buffer(void)
    |{
    |    char line[256];
    |    char small[16];
    |    snprintf(line, sizeof(line), "%d", 7);
    |    strcpy(small, line);
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

    "fire on the implicit strcpy into a fixed buffer (CWE-121)" in {
        findingsIn("bad_implicit_strcpy") shouldBe Set("MS-BOUND-006")
    }

    "fire on the implicit sprintf with an attacker format argument" in {
        findingsIn("bad_implicit_sprintf") shouldBe Set("MS-BOUND-006")
    }

    "stay silent when the source's length is guarded" in {
        findingsIn("good_checked_strcpy") shouldBe empty
    }

    "measure a copy against the buffer of that name it writes" in {
        findingsIn("good_same_name_buffers") should not contain "MS-BOUND-006"
    }

    "stay silent when the copy declares its own bound" in {
        findingsIn("good_bounded_snprintf") shouldBe empty
    }

    "fire on a constant length past an allocation's size (CWE-122)" in {
        findingsIn("bad_const_past_alloc") shouldBe Set("MS-BOUND-007")
    }

    "fire on a constant length past a shrunk reallocation" in {
        // `buf = realloc(buf, 8)` also loses the block when realloc fails (MS-ALLOC-003): a true
        // finding of another rule about the same line
        findingsIn("bad_const_past_realloc") shouldBe Set("MS-BOUND-007", "MS-ALLOC-003")
    }

    "stay silent when the length matches the allocation" in {
        // the control is THIS rule's question; MS-ALLOC-008's own unbounded-size claim about
        // the same site (n is attacker-chosen with no cap) is a different, true finding
        findingsIn("good_matching_len") should not contain "MS-BOUND-007"
    }

    "fire on a loop write bounded by an unvalidated count (the struct-array shape)" in {
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

  "the buffer shapes round 10 left open" should:
    "carry the alloca extent through the alias and count elements, not bytes" in {
        findingsIn("bad_alloca_alias_loop") should contain("MS-BOUND-007")
        findingsIn("good_alloca_alias_loop") should not contain "MS-BOUND-007"
    }
    "fire on wcscat whose declared-array source is longer than the heap buffer" in {
        findingsIn("bad_wcscat_past_heap") should contain("MS-BOUND-007")
        findingsIn("good_wcscat_heap_fits") should not contain "MS-BOUND-007"
    }

  "the shapes that cross a call" should:
    "measure a sink's copy against the buffer the caller hands it" in {
        findingsIn("t4_bad_sink") should contain("MS-BOUND-006")
        findingsIn("t4_good_sink") should not contain "MS-BOUND-006"
    }
    "underwrite through a pointer a helper returned from before its object" in {
        findingsIn("bad_t4_returned_before") should contain("MS-BOUND-009")
    }
    "read past a source smaller than the string the copy measures" in {
        findingsIn("bad_t4_overread_src_bound") should contain("MS-BOUND-003")
        findingsIn("good_t4_overread_src_fits") should not contain "MS-BOUND-003"
    }
    "read past a smaller source whatever the function is named" in {
        findingsIn("copy_measured_by_other") should contain("MS-BOUND-003")
    }

  "the capacity a caller hands a parameter" should:
    "not read a parameter without definitions as a zero-byte buffer" in {
        findingsIn("fp_good_sink").filter(_.startsWith("MS-BOUND-00")) shouldBe empty
    }

  "the source content facts" should:
    "not carry a fill from one function to another's buffer of the same name" in {
        findingsIn("good_unfilled_source_of_same_name") should not contain "MS-BOUND-007"
    }
    "not read a large buffer's declared room as the string it holds" in {
        findingsIn("good_strcpy_from_large_short_buffer").filter(
          _.startsWith("MS-BOUND-00")
        ) shouldBe empty
    }
end CapacityOverrunRuleTests
