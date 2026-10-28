package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** MS-INT-003 over an input-fed operand: the guard forms the reader understands - a failing
  * disjunction after an exit (a return, a goto, a call that does not return), a loop's break side
  *   - and the operands that cannot wrap (a pointer, a masked field).
  */
class InputArithmeticGuardTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdio.h>
    |#include <stdlib.h>
    |#include <string.h>
    |#include <wchar.h>

|int bad_input_sum(void)
|{
|    char buf[20] = "";
|    int a = 0;
|    if (fgets(buf, 20, stdin) != NULL) a = atoi(buf);
|    int r = a + 1;
|    return r;
|}
|
|int good_exit_after_failing_disjunction(void)
|{
|    char buf[20] = "";
|    int a = 0;
|    if (fgets(buf, 20, stdin) != NULL) a = atoi(buf);
|    if (a < 0 || a > 100) exit(1);
|    int r = a + 1;
|    return r;
|}
|
|int good_goto_after_failing_disjunction(void)
|{
|    char buf[20] = "";
|    int a = 0;
|    int r = 0;
|    if (fgets(buf, 20, stdin) != NULL) a = atoi(buf);
|    if (a < 0 || a > 100) goto out;
|    r = a + 1;
|out:
|    return r;
|}
|
|int good_break_side_of_loop(void)
|{
|    char buf[20] = "";
|    int a = 0;
|    int r = 0;
|    if (fgets(buf, 20, stdin) != NULL) a = atoi(buf);
|    for (int i = 0; i < 3; i++)
|    {
|        if (a > 100) break;
|        r = a + 1;
|    }
|    return r;
|}
|
|int bad_break_in_another_loop(void)
|{
|    char buf[20] = "";
|    int a = 0;
|    int r = 0;
|    if (fgets(buf, 20, stdin) != NULL) a = atoi(buf);
|    for (int i = 0; i < 3; i++)
|    {
|        if (i > 1) break;
|    }
|    r = a + 1;
|    return r;
|}
|
|void good_pointer_walk_over_input(void)
|{
|    char buf[20] = "";
|    char *p = buf;
|    if (fgets(buf, 20, stdin) == NULL) return;
|    while (*p) p++;
|}
|
    |struct small_t { int i; };
    |void bad_member_past_allocation(void)
    |{
    |    struct small_t *p = (struct small_t *)malloc(1);
    |    p->i = atoi("1");
    |}
    |
    |void good_member_in_allocation(void)
    |{
    |    struct small_t *p = (struct small_t *)malloc(sizeof(struct small_t));
    |    if (p == NULL) return;
    |    p->i = atoi("1");
    |    free(p);
    |}
    |
    |int good_masked_field_sum(void)
|{
|    int x = 0;
|    if (fread(&x, sizeof(x), 1, stdin) != 1) return -1;
|    int core = ((x >> 4) & 0x3fff) + 1;
|    return core + 4;
|}
|void bad_overread_alias_strlen(void)
|{
|    char *data;
|    char small[50];
|    char big[100];
|    char dest[100];
|    memset(small, 'A', 49);
|    small[49] = '\0';
|    memset(big, 'C', 99);
|    big[99] = '\0';
|    data = small;
|    size_t i, destLen;
|    memset(dest, 'C', 99);
|    dest[99] = '\0';
|    destLen = strlen(dest);
|    for (i = 0; i < destLen; i++)
|    {
|        dest[i] = data[i];
|    }
|}
|
|void good_overread_alias_strlen(void)
|{
|    char *data;
|    char big[100];
|    char dest[100];
|    memset(big, 'A', 99);
|    big[99] = '\0';
|    data = big;
|    size_t i, destLen;
|    memset(dest, 'C', 99);
|    dest[99] = '\0';
|    destLen = strlen(dest);
|    for (i = 0; i < destLen; i++)
|    {
|        dest[i] = data[i];
|    }
|}
|
|void bad_overread_alias_wcslen(void)
|{
|    wchar_t *data;
|    wchar_t small[50];
|    wchar_t dest[100];
|    wmemset(small, L'A', 49);
|    small[49] = L'\0';
|    data = small;
|    size_t i, destLen;
|    wmemset(dest, L'C', 99);
|    dest[99] = L'\0';
|    destLen = wcslen(dest);
|    for (i = 0; i < destLen; i++)
|    {
|        dest[i] = data[i];
|    }
|}
|
|void good_overread_alias_wcslen(void)
|{
|    wchar_t *data;
|    wchar_t big[100];
|    wchar_t dest[100];
|    wmemset(big, L'A', 99);
|    big[99] = L'\0';
|    data = big;
|    size_t i, destLen;
|    wmemset(dest, L'C', 99);
|    dest[99] = L'\0';
|    destLen = wcslen(dest);
|    for (i = 0; i < destLen; i++)
|    {
|        dest[i] = data[i];
|    }
|}
    |
    |int good_bool_flag_count(void)
    |{
    |    const char *a = getenv("A"), *b = getenv("B");
    |    int n = (a != NULL) + (b != NULL) + !(a == b);
    |    return n + 1;
    |}
    |
    |int good_bool_converted_count(char *buf)
    |{
    |    int n = (int)(buf[0] != 0) - (int)(buf[1] != 0);
    |    return n + 1;
    |}
    |
    |char *good_pointer_plus_len(char *cur, size_t len)
    |{
    |    if (fgets(cur, 20, stdin) == NULL) return cur;
    |    return cur + len;
    |}
    |""".stripMargin,
    "input_arith.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "arithmetic on an input-fed value" should:
    "be reported when nothing bounds it" in {
        findingsIn("bad_input_sum") should contain("MS-INT-003")
    }
    "be reported when the only break is another loop's" in {
        findingsIn("bad_break_in_another_loop") should contain("MS-INT-003")
    }
    "stand down after a failing disjunction that exits the function" in {
        findingsIn("good_exit_after_failing_disjunction") should not contain "MS-INT-003"
    }
    "stand down after a failing disjunction that jumps away" in {
        findingsIn("good_goto_after_failing_disjunction") should not contain "MS-INT-003"
    }
    "stand down on the loop's break side of a guard" in {
        findingsIn("good_break_side_of_loop") should not contain "MS-INT-003"
    }
    "never treat a pointer step as integer arithmetic" in {
        findingsIn("good_pointer_walk_over_input") should not contain "MS-INT-003"
    }
    "report a struct member written through a pointer to a smaller allocation" in {
        findingsIn("bad_member_past_allocation") should contain("MS-BOUND-004")
        findingsIn("good_member_in_allocation") should not contain "MS-BOUND-004"
    }
    "stand down on a masked field plus a small constant" in {
        findingsIn("good_masked_field_sum") should not contain "MS-INT-003"
    }
    "never treat boolean operands as a wrap - flags, comparisons, and their conversions" in {
        findingsIn("good_bool_flag_count") should not contain "MS-INT-003"
        findingsIn("good_bool_converted_count") should not contain "MS-INT-003"
    }
    "never treat a pointer plus a length as integer arithmetic" in {
        findingsIn("good_pointer_plus_len") should not contain "MS-INT-003"
    }

  "a loop bounded by a string's length over a pointer to a smaller buffer" should:
    "report the read of the smaller buffer (char)" in {
        findingsIn("bad_overread_alias_strlen") should contain("MS-BOUND-003")
    }
    "stay silent when the pointer names a buffer as large as the string's (char)" in {
        findingsIn("good_overread_alias_strlen") should not contain "MS-BOUND-003"
    }
    "report the read of the smaller buffer (wchar_t)" in {
        findingsIn("bad_overread_alias_wcslen") should contain("MS-BOUND-003")
    }
    "stay silent when the pointer names a buffer as large as the string's (wchar_t)" in {
        findingsIn("good_overread_alias_wcslen") should not contain "MS-BOUND-003"
    }
end InputArithmeticGuardTests
