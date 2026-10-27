package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A loop bound held in a variable that carries a string's length (`n = strlen(dest)` over `char
  * dest[100]` is at most 99) against a read through a pointer to a smaller buffer: the over-read
  * the loop's index reaches at the read itself.
  */
class LoopBoundOverreadTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdio.h>
    |#include <string.h>
    |#include <wchar.h>

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
    |""".stripMargin,
    "overread.c"
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
end LoopBoundOverreadTests
