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

/** MS-ALLOC-005..009: the deallocation of the wrong thing and the uncontrolled allocation size.
  * Every positive is a classic CWE-761/590/762/789/680 shape; every negative is its good pair.
  */
class WrongDeallocationRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* the CWE-761 shape: free of an offset pointer, and of non-heap storage */
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
    |/* the Juliet CWE-761 shape: the walk moves the pointer, the free follows the walk */
    |void bad_walk_then_free(char *data)
    |{
    |    for (; *data != '\0'; data++)
    |    {
    |        if (*data == 'x') break;
    |    }
    |    free(data);
    |}
    |
    |void good_walk_a_copy(char *data)
    |{
    |    char *cursor = data;
    |    for (; *cursor != '\0'; cursor++)
    |    {
    |        if (*cursor == 'x') break;
    |    }
    |    free(data);
    |}
    |
    |/* the Juliet CWE-415 shape: the suite marks the first release too */
    |void bad_double_free(void)
    |{
    |    char *p = (char *)malloc(100);
    |    if (p == NULL) exit(-1);
    |    free(p);
    |    free(p);
    |}
    |
    |void good_free_elements_then_container(char **elem, unsigned long n)
    |{
    |    unsigned long i;
    |    for (i = 0; i < n; i++) free(elem[i]);
    |    free(elem);
    |}
    |
    |void good_free_once(void)
    |{
    |    char *p = (char *)malloc(100);
    |    if (p == NULL) exit(-1);
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
    |/* the CWE-762 shapes: a cross-family mismatch, and an array allocation
    |   released by the scalar form (and the reverse). A .cpp file - the C
    |   parser reads `delete` as a bare call and the operator forms never
    |   appear. */
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
    |
    |void bad_array_new_scalar_delete(void)
    |{
    |    char *p = new char[16];
    |    delete p;
    |}
    |
    |void bad_scalar_new_array_delete(void)
    |{
    |    int *p = new int(5);
    |    delete[] p;
    |}
    |
    |void good_matched_array_new_delete(void)
    |{
    |    char *p = new char[16];
    |    delete[] p;
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
    |/* the Juliet CWE-789 / CWE-680 shapes over C++ new[] and scanf-filled sizes */
    |void bad_new_count_lower_bound(void)
    |{
    |    size_t data = 0;
    |    char inputBuffer[20] = "";
    |    if (fgets(inputBuffer, 20, stdin) != NULL) data = strtoul(inputBuffer, NULL, 0);
    |    if (data > strlen("hello"))
    |    {
    |        char *p = new char[data];
    |        strcpy(p, "hello");
    |        delete[] p;
    |    }
    |}
    |
    |void good_new_count_capped(void)
    |{
    |    size_t data = 0;
    |    char inputBuffer[20] = "";
    |    if (fgets(inputBuffer, 20, stdin) != NULL) data = strtoul(inputBuffer, NULL, 0);
    |    if (data > strlen("hello") && data < 1000)
    |    {
    |        char *p = new char[data];
    |        strcpy(p, "hello");
    |        delete[] p;
    |    }
    |}
    |
    |void bad_scanf_size_after_init(void)
    |{
    |    size_t data = 0;
    |    fscanf(stdin, "%zu", &data);
    |    char *p = (char *)malloc(data * sizeof(char));
    |    if (p) free(p);
    |}
    |
    |void good_strlen_size_after_init(const char *s)
    |{
    |    size_t data = 0;
    |    data = strlen(s);
    |    char *p = (char *)malloc(data * sizeof(char));
    |    if (p) free(p);
    |}
    |
    |void bad_new_overflowed_bytes(void)
    |{
    |    int data = -1;
    |    char inputBuffer[20] = "";
    |    if (fgets(inputBuffer, 20, stdin) != NULL) data = atoi(inputBuffer);
    |    size_t dataBytes = data * sizeof(int);
    |    int *intPointer = (int *)new char[dataBytes];
    |    for (size_t i = 0; i < (size_t)data; i++)
    |    {
    |        intPointer[i] = 0;
    |    }
    |    delete[] intPointer;
    |}
    |""".stripMargin,
        "r10alloc.cpp"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |
    |/* the CWE-789 shape: attacker-controlled sizes with and without the cap */
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
    |/* the CWE-680 shape: an allocation sized by unguarded caller arithmetic */
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
    "fire on a free of pointer arithmetic over the allocation (CWE-761)" in {
        findingsIn("bad_free_offset") should contain("MS-ALLOC-006")
    }
    "report a walked-then-freed pointer at the walk's increment, where the suite marks it" in {
        val walks = cpg.method.name("bad_walk_then_free").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-006"))
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Call].l
        walks.map(_.code) shouldBe List("data++")
    }
    "report both releases of a double free (CWE-415)" in {
        val sites = cpg.method.name("bad_double_free").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.AstNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-001")).l
        sites.flatMap(_.lineNumber).map(_.toInt).distinct.size shouldBe 2
        findingsIn("good_free_once") should not contain "MS-ALLOC-001"
        findingsIn("good_free_elements_then_container") should not contain "MS-ALLOC-001"
    }
    "stay silent when the walk is over a copy and the original is freed" in {
        findingsIn("good_walk_a_copy") should not contain "MS-ALLOC-006"
    }
    "stay silent when the arithmetic result is not what is freed" in {
        findingsIn("good_free_original") should not contain "MS-ALLOC-006"
    }
    "fire on a free of a static local (CWE-590)" in {
        findingsIn("bad_free_static") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a string literal (CWE-590)" in {
        findingsIn("bad_free_string_literal") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a stack array (CWE-590)" in {
        findingsIn("bad_free_stack") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a local's address (CWE-590 through the state fact)" in {
        findingsIn("bad_free_address_of_local") should contain("MS-ALLOC-005")
    }
    "stay silent on an ordinary heap free" in {
        findingsIn("good_free_heap") shouldBe empty
    }
    "fire on malloc released with delete (CWE-762)" in {
        findingsIn("bad_mismatched_malloc_delete") should contain("MS-ALLOC-007")
    }
    "fire on new released with free (CWE-762)" in {
        findingsIn("bad_mismatched_new_free") should contain("MS-ALLOC-007")
    }
    "stay silent on a matched new/delete pair" in {
        findingsIn("good_matched_new_delete") should not contain "MS-ALLOC-007"
    }
    "fire on new[] released with a scalar delete, and new with delete[] (CWE-762)" in {
        findingsIn("bad_array_new_scalar_delete") should contain("MS-ALLOC-007")
        findingsIn("bad_scalar_new_array_delete") should contain("MS-ALLOC-007")
    }
    "stay silent on a matched new[]/delete[] pair" in {
        findingsIn("good_matched_array_new_delete") should not contain "MS-ALLOC-007"
    }

  "MS-ALLOC-008/009 (uncontrolled size)" should:
    "fire on a new[] count with only a lower bound (CWE-789)" in {
        findingsIn("bad_new_count_lower_bound") should contain("MS-ALLOC-008")
    }
    "stay silent on a new[] count capped above" in {
        findingsIn("good_new_count_capped") should not contain "MS-ALLOC-008"
    }
    "fire on a scanf-filled size whose initialiser is a constant" in {
        findingsIn("bad_scanf_size_after_init") should contain("MS-ALLOC-008")
    }
    "stay silent on a strlen-derived size with a constant initialiser" in {
        findingsIn("good_strlen_size_after_init") should not contain "MS-ALLOC-008"
    }
    "fire on the write over a new[] sized by overflowed arithmetic (CWE-680)" in {
        findingsIn("bad_new_overflowed_bytes") should contain("MS-BOUND-007")
    }
    "fire on an attacker-controlled malloc size (CWE-789)" in {
        findingsIn("bad_malloc_from_input") shouldBe Set("MS-ALLOC-008")
    }
    "fire on an attacker-controlled alloca size (CWE-789, stack)" in {
        findingsIn("bad_alloca_from_input") shouldBe Set("MS-ALLOC-008")
    }
    "stay silent when the size is capped above" in {
        findingsIn("good_capped") shouldBe empty
    }
    "stay silent on a constant size" in {
        findingsIn("good_constant_size") shouldBe empty
    }
    "fire on an allocation sized by unguarded caller arithmetic (CWE-680)" in {
        findingsIn("bad_mul_overflow") should contain("MS-ALLOC-009")
    }
end WrongDeallocationRuleTests
