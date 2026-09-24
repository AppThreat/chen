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

/** MS-ALLOC-005..009 (F5, part 6): the deallocation of the wrong thing and the uncontrolled
  * allocation size. Every positive is one of the eleven corpus rows; every negative is the good
  * pair from the same fixture.
  */
class WrongDeallocationRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* the cwe761 fixture: free of an offset pointer, and of non-heap storage */
    |void bad_free_offset(const char *userInput)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    strncpy(p, userInput, 63);
    |    p[63] = 0;
    |    p = p + 4;
    |    free(p);
    |}
    |
    |void good_free_original(const char *userInput)
    |{
    |    char *p = (char *)malloc(64);
    |    char *cursor;
    |    if (p == NULL) return;
    |    strncpy(p, userInput, 63);
    |    cursor = p + 4;
    |    (void)cursor;
    |    free(p);
    |}
    |
    |void bad_free_static(void)
    |{
    |    static char buf[64];
    |    free(buf);
    |}
    |
    |void bad_free_string_literal(void)
    |{
    |    char *p = "literal";
    |    free(p);
    |}
    |
    |void bad_free_stack(void)
    |{
    |    char buf[32];
    |    free(buf);
    |}
    |
    |void bad_free_address_of_local(void)
    |{
    |    int x = 1;
    |    int *q = &x;
    |    free(q);
    |}
    |
    |void good_free_heap(void)
    |{
    |    char *p = (char *)malloc(8);
    |    if (p == NULL) return;
    |    free(p);
    |}
    |
    |""".stripMargin,
    "wrongfree.c"
  )
      .moreCode(
        """
    |#include <stdlib.h>
    |
    |/* the cwe762 fixture rows the graph can see: cross-family mismatch. A .cpp
    |   file - the C parser reads `delete` as a bare call and the operator forms
    |   never appear. */
    |void bad_mismatched_malloc_delete(void)
    |{
    |    int *p = (int *)malloc(sizeof(int) * 16);
    |    delete p;
    |}
    |
    |void bad_mismatched_new_free(void)
    |{
    |    int *p = new int(5);
    |    free(p);
    |}
    |
    |void good_matched_new_delete(void)
    |{
    |    int *p = new int(5);
    |    delete p;
    |}
    |""".stripMargin,
        "mismatch.cpp"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |
    |/* the cwe789 fixture: attacker-controlled sizes with and without the cap */
    |void bad_malloc_from_input(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p = (char *)malloc(n);
    |    if (p) free(p);
    |}
    |
    |void bad_alloca_from_input(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p = (char *)alloca(n);
    |    if (p) p[0] = 0;
    |}
    |
    |void good_capped(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p;
    |    if (n == 0 || n > 4096) return;
    |    p = (char *)malloc(n);
    |    if (p) free(p);
    |}
    |
    |void good_constant_size(void)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p) free(p);
    |}
    |""".stripMargin,
        "uncontrolled.c"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |
    |/* the cwe680 row: an allocation sized by unguarded caller arithmetic */
    |int *bad_mul_overflow(unsigned int count)
    |{
    |    int *arr = (int *)malloc(count * sizeof(int));
    |    if (arr == NULL) return NULL;
    |    free(arr);
    |    return NULL;
    |}
    |""".stripMargin,
        "sizeoverflow.c"
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

  "MS-ALLOC-005/006/007 (wrong deallocation)" should:
    "fire on a free of pointer arithmetic over the allocation (cwe761 row)" in {
        findingsIn("bad_free_offset") should contain("MS-ALLOC-006")
    }
    "stay silent when the arithmetic result is not what is freed" in {
        findingsIn("good_free_original") should not contain "MS-ALLOC-006"
    }
    "fire on a free of a static local (cwe590 row)" in {
        findingsIn("bad_free_static") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a string literal (cwe590 row)" in {
        findingsIn("bad_free_string_literal") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a stack array (cwe562 fixture's 590 row)" in {
        findingsIn("bad_free_stack") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a local's address (590 through the state fact)" in {
        findingsIn("bad_free_address_of_local") should contain("MS-ALLOC-005")
    }
    "stay silent on an ordinary heap free" in {
        findingsIn("good_free_heap") shouldBe empty
    }
    "fire on malloc released with delete (cwe762 row)" in {
        findingsIn("bad_mismatched_malloc_delete") should contain("MS-ALLOC-007")
    }
    "fire on new released with free (cwe762 row)" in {
        findingsIn("bad_mismatched_new_free") should contain("MS-ALLOC-007")
    }
    "stay silent on a matched new/delete pair" in {
        findingsIn("good_matched_new_delete") should not contain "MS-ALLOC-007"
    }

  "MS-ALLOC-008/009 (uncontrolled size)" should:
    "fire on an attacker-controlled malloc size (cwe789 row)" in {
        findingsIn("bad_malloc_from_input") shouldBe Set("MS-ALLOC-008")
    }
    "fire on an attacker-controlled alloca size (cwe789 stack row)" in {
        findingsIn("bad_alloca_from_input") shouldBe Set("MS-ALLOC-008")
    }
    "stay silent when the size is capped above" in {
        findingsIn("good_capped") shouldBe empty
    }
    "stay silent on a constant size" in {
        findingsIn("good_constant_size") shouldBe empty
    }
    "fire on an allocation sized by unguarded caller arithmetic (cwe680 row)" in {
        findingsIn("bad_mul_overflow") should contain("MS-ALLOC-009")
    }
end WrongDeallocationRuleTests
