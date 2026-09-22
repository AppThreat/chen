package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    MemoryApiPass,
    MemorySafetyFindingPass
}
import io.shiftleft.codepropertygraph.generated.nodes.{Return, StoredNode}
import io.shiftleft.semanticcpg.language.*

/** MS4 (part 4, D3): allocation-state rules over the AllocationStatePass facts. Every positive
  * mirrors a corpus fixture (c/cwe415_double_free.c, c/cwe416_use_after_free.c,
  * c/cwe401_memory_leak.c); every negative is the paired correctly-written variant - the
  * free-and-reset idiom, the free inside a guard that also returns, a realloc feeding the next
  * free.
  */
class AllocationStatePassTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |
    |/* ---- MS-ALLOC-001, double free ---- */
    |
    |void bad_direct(void)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL) return;
    |    free(p);
    |    free(p);
    |}
    |
    |void bad_branch(int flag)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL) return;
    |    if (flag) { free(p); }
    |    free(p);
    |}
    |
    |static void cleanup(char *p) { free(p); }
    |
    |void bad_via_wrapper(void)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL) return;
    |    cleanup(p);
    |    free(p);
    |}
    |
    |void good_nulled(void)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL) return;
    |    free(p);
    |    p = NULL;
    |    free(p);
    |}
    |
    |/* ---- MS-ALLOC-002, use after free ---- */
    |
    |void bad_uaf(void)
    |{
    |    char *p = (char *)malloc(32);
    |    if (p == NULL) return;
    |    free(p);
    |    p[0] = 'x';
    |}
    |
    |void good_nulled_uaf(void)
    |{
    |    char *p = (char *)malloc(32);
    |    if (p == NULL) return;
    |    free(p);
    |    p = NULL;
    |    if (p != NULL) { p[0] = 'a'; }
    |}
    |
    |/* ---- MS-ALLOC-003, leak ---- */
    |
    |int bad_leak_early_return(int n)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return 1;
    |    if (n < 0) { return 2; }
    |    free(p);
    |    return 0;
    |}
    |
    |int bad_leak_two_exits(int n)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return 1;
    |    if (n < 0) { return 2; }
    |    if (n > 99) { return 3; }
    |    free(p);
    |    return 0;
    |}
    |
    |void bad_leak_no_explicit_return(void)
    |{
    |    char *p = (char *)malloc(64);
    |    p[0] = 'x';
    |}
    |
    |void bad_leak_overwrite(void)
    |{
    |    char *p = (char *)malloc(64);
    |    p = (char *)malloc(128);
    |    free(p);
    |}
    |
    |void good_freed(int n)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    if (n < 0) { free(p); return; }
    |    free(p);
    |}
    |
    |/* ---- realloc frees its input and yields a fresh pointer ---- */
    |
    |char *bad_realloc_then_free(char *old, int n)
    |{
    |    char *p = (char *)malloc(16);
    |    p = realloc(p, n);
    |    if (p == NULL) return NULL;
    |    free(p);
    |    return p;
    |}
    |
    |/* two allocation sites merging around a loop: the worklist must terminate */
    |void loop_two_sites(int n)
    |{
    |    char *p = NULL;
    |    int i = 0;
    |    while (i < n)
    |    {
    |        if (i % 2) p = malloc(4); else p = malloc(8);
    |        free(p);
    |        i++;
    |    }
    |}
    |
    |/* ownership handed off through a struct member: no leak */
    |struct box { char *buf; };
    |
    |void good_stash_into_member(struct box *b)
    |{
    |    char *grown = malloc(32);
    |    b->buf = grown;
    |}
    |
    |/* ---- MS-ALLOC-004, double close ---- */
    |
    |void bad_double_close(const char *path)
    |{
    |    FILE *f = fopen(path, "r");
    |    if (f == NULL) return;
    |    fclose(f);
    |    fclose(f);
    |}
    |""".stripMargin,
    "alloc_state.c"
  )

  new MemoryApiPass(cpg).createAndApply()
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

  "MS-ALLOC-001" should:

    "fire on a direct double free" in {
        findingsIn("bad_direct") shouldBe Set("MS-ALLOC-001")
    }

    "fire on the conditional double free (freed on some path)" in {
        findingsIn("bad_branch") shouldBe Set("MS-ALLOC-001")
    }

    "fire through an inferred free wrapper" in {
        findingsIn("bad_via_wrapper") shouldBe Set("MS-ALLOC-001")
    }

    "stay silent behind the free-and-reset idiom" in {
        findingsIn("good_nulled") shouldBe empty
    }

  "MS-ALLOC-002" should:

    "fire on a write through a freed pointer" in {
        findingsIn("bad_uaf") shouldBe Set("MS-ALLOC-002")
    }

    "stay silent when the pointer was nulled and re-checked" in {
        findingsIn("good_nulled_uaf") shouldBe empty
    }

  "MS-ALLOC-003" should:

    "fire at the early return that abandons the allocation" in {
        findingsIn("bad_leak_early_return") shouldBe Set("MS-ALLOC-003")
    }

    "report the EARLIEST leaking exit, not the last one" in {
        // two early returns abandon the same allocation; the fact belongs on the first, which is
        // where a reader fixes it. `minBy(-line)` reported the last one instead.
        val leaks = cpg.method
            .name("bad_leak_two_exits")
            .ast
            .collectAll[StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-003"))
            .l
        leaks.size shouldBe 1
        // and it is the explicit `return 2;`, not the implicit end - METHOD_RETURN carries the
        // function's DECLARATION line, so ordering exits by line alone hands it every leak
        leaks.head.label shouldBe "RETURN"
        leaks.head.propertyOption("CODE").get.toString should include("2")
    }

    "fire at the implicit end of a function with no explicit return" in {
        // the fact lands on METHOD_RETURN, which is a CFG_NODE and NOT an Expression - the
        // renderer has to name it to see it
        cpg.method
            .name("bad_leak_no_explicit_return")
            .methodReturn
            .tag
            .name("ms-finding")
            .value
            .l should contain("MS-ALLOC-003")
    }

    "fire at the assignment that overwrites the only handle" in {
        findingsIn("bad_leak_overwrite") shouldBe Set("MS-ALLOC-003")
    }

    "stay silent when every path frees" in {
        findingsIn("good_freed") shouldBe empty
    }

  "realloc" should:

    "not turn into a double free: the realloc frees the input, the free frees the result" in {
        findingsIn("bad_realloc_then_free") shouldBe empty
    }

  "MS-ALLOC-004" should:

    "fire on a double close of a file handle" in {
        findingsIn("bad_double_close") shouldBe Set("MS-ALLOC-004")
    }

  "worklist termination" should:

    "converge when two allocation sites merge around a loop" in {
        findingsIn("loop_two_sites") shouldBe empty
    }

  "ownership transfer" should:

    "not report a leak when the pointer is stored into a struct member" in {
        findingsIn("good_stash_into_member") shouldBe empty
    }
end AllocationStatePassTests
