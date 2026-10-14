package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    MemoryApiPass,
    MemorySafetyFindingPass
}
import io.shiftleft.codepropertygraph.generated.nodes.{Return, StoredNode}
import io.shiftleft.semanticcpg.language.*

/** Allocation-state rules over the AllocationStatePass facts. Every positive mirrors a classic CWE
  * shape (the CWE-415 double free, the CWE-416 use after free, the CWE-401 memory leak); every
  * negative is the paired correctly-written variant - the free-and-reset idiom, the free inside a
  * guard that also returns, a realloc feeding the next free.
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
    |/* the free a macro spells: the invocation's argument is the free site */
    |#define wrap_free(p) free(p)
    |void bad_conditional_macro_free(int flag)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL) return;
    |    if (flag) { wrap_free(p); }
    |    wrap_free(p);
    |}
    |/* the use a macro's argument makes, when the macro frees nothing, is not a free */
    |#define wrap_use(p) strlen(p)
    |void bad_uaf_macro_use(int flag)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    if (flag) { wrap_free(p); }
    |    wrap_use(p);
    |}
    |
    |/* a free only a branch a constant condition rules out reaches frees nothing */
    |void good_dead_branch_free(void)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL) return;
    |    if (0) { free(p); }
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
    |/* ---- a helper that never returns ---- */
    |
    |/* a helper whose every path ends in the C library's terminator: a caller's path that
    |   reaches its call ends there, whatever the helper freed first */
    |static void die(int rc)
    |{
    |    exit(rc);
    |}
    |int good_freed_before_die(int n)
    |{
    |    char *p = (char *)malloc(32);
    |    if (p == NULL) return -1;
    |    if (n < 0) {
    |        free(p);
    |        die(1);
    |    }
    |    p[0] = 'a';
    |    free(p);
    |    return 0;
    |}
    |/* the same free on a branch that falls through: the read and the second free are
    |   reached with the freed state */
    |int bad_freed_in_branch(int n)
    |{
    |    char *p = (char *)malloc(32);
    |    if (p == NULL) return -1;
    |    if (n < 0) {
    |        free(p);
    |    }
    |    p[0] = 'a';
    |    free(p);
    |    return 0;
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
    |/* ---- the unbraced if ---- */
    |
    |/* the good_capped shape (a capped CWE-789 allocation): the false edge of an unbraced
    |   `if (p) free(p);` runs to the implicit end, and a naive narrowing sees NOTHING there - the
    |   allocated state flowed into METHOD_RETURN and reported a leak on the path where the free
    |   never ran */
    |void good_capped_unbraced(size_t n)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p) free(p);
    |}
    |
    |/* an unbraced error path with a value: the then side is where the condition holds, and
    |   every path here frees */
    |int good_unbraced_retval(int n)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return 1;
    |    if (n >= 0) { free(p); return 0; }
    |    free(p);
    |    return 2;
    |}
    |
    |/* `if (q != NULL) return;` abandons the allocation on the path where q IS non-null; a
    |   notEquals narrowing that inverts both branches marks q NULL exactly there,
    |   silencing the leak */
    |void bad_leak_notEquals_return(void)
    |{
    |    char *q = (char *)malloc(64);
    |    if (q != NULL) return;
    |    free(q);
    |}
    |
    |/* the free-and-reset idiom's dead branch must not revive into a phantom allocation */
    |void good_reset_recheck(void)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    free(p);
    |    p = NULL;
    |    if (p != NULL) { p[0] = 'a'; }
    |}
    |
    |/* ---- realloc frees its input and yields a fresh pointer ---- */
    |
    |char *bad_realloc_then_free(char *old, int n)
    |{
    |    char *p = (char *)malloc(16);
    |    p = realloc(p, 16);
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
    |
    |/* ---- leak facts from CONVERGED states, and the fd failure check ---- */
    |
    |/* the CWE-367 stat-then-open shape: the guarded close frees on the taken path, so the join
    |   at the implicit end is maybe-freed. A leak recorded from the PRE-join visit - the false
    |   edge delivering `allocated` to the implicit end before the freed path joins in -
    |   restates a fact the join had already retracted */
    |void good_guarded_close(const char *path)
    |{
    |    int fd = open(path, 1);
    |    if (fd >= 0) close(fd);
    |}
    |
    |/* the CWE-416 free-in-a-loop shape: the free runs on every iteration of a loop that
    |   always executes; only the synthetic zero-trip path leaves the allocation live, and
    |   only until the back edge joins in */
    |void good_loop_freed(void)
    |{
    |    char *p = (char *)malloc(32);
    |    int i;
    |    for (i = 0; i < 3; i++)
    |    {
    |        p[0] = 'a';
    |        free(p);
    |    }
    |}
    |
    |/* the CWE-367 openat-then-fstat fix: an int-handle acquisition's failure sentinel is
    |   -1, not NULL - the exit under `fd < 0` holds no descriptor and leaks nothing */
    |int good_fd_checked(const char *path)
    |{
    |    int fd = open(path, 1);
    |    if (fd < 0) return -1;
    |    (void)write(fd, "data", 4);
    |    close(fd);
    |    return 0;
    |}
    |""".stripMargin,
    "alloc_state.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |
    |/* a static helper of the same name as another file's that does return: a call of it is not
    |   the end of its caller's path */
    |static void die(int rc)
    |{
    |    (void)rc;
    |}
    |int bad_freed_before_returning_helper(int n)
    |{
    |    char *p = (char *)malloc(32);
    |    if (p == NULL) return -1;
    |    if (n < 0) {
    |        free(p);
    |        die(1);
    |    }
    |    p[0] = 'a';
    |    free(p);
    |    return 0;
    |}
    |""".stripMargin,
    "alloc_state_helper.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  /** The MS-ALLOC rules only. MS-NULL-001 also reads this pass's facts and fires on several of
    * these fixtures' unchecked parameters - it has its own suite.
    */
  private def findingsIn(method: String): Set[String] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet
          .filter(_.startsWith("MS-ALLOC"))

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

    "fire through a macro that is the free" in {
        findingsIn("bad_conditional_macro_free") shouldBe Set("MS-ALLOC-001")
    }

    "stay silent when the first free is on a branch a constant condition rules out" in {
        findingsIn("good_dead_branch_free") shouldBe empty
    }

    "stay silent behind the free-and-reset idiom" in {
        findingsIn("good_nulled") shouldBe empty
    }

  "MS-ALLOC-002" should:

    "fire on a write through a freed pointer" in {
        findingsIn("bad_uaf") shouldBe Set("MS-ALLOC-002")
    }

    "fire through a macro's argument when the macro frees nothing" in {
        findingsIn("bad_uaf_macro_use") shouldBe Set("MS-ALLOC-002")
    }

    "stay silent when the pointer was nulled and re-checked" in {
        findingsIn("good_nulled_uaf") shouldBe empty
    }

    "stay silent when the freeing branch ends in a helper that never returns" in {
        findingsIn("good_freed_before_die") shouldBe empty
    }

    "fire when the freeing branch falls through to the use" in {
        findingsIn("bad_freed_in_branch") should not be empty
    }

    "fire when the helper the call reaches returns, though a same-named one elsewhere exits" in {
        findingsIn("bad_freed_before_returning_helper") should not be empty
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

    "anchor a leak at the ALLOCATION when the exit is the implicit end of the function" in {
        // METHOD_RETURN's line is the function's declaration, which is not a location a reader
        // can act on - a CWE-401 loop leak would be reported lines away from its own malloc
        // for exactly this reason. The allocation is the statement that leaks.
        val anchors = cpg.method
            .name("bad_leak_no_explicit_return")
            .ast
            .collectAll[StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-003"))
            .l
        anchors.size shouldBe 1
        anchors.head.label shouldBe "CALL"
        anchors.head.propertyOption("CODE").get.toString should include("malloc")
    }

    "fire at the assignment that overwrites the only handle" in {
        findingsIn("bad_leak_overwrite") shouldBe Set("MS-ALLOC-003")
    }

    "stay silent when every path frees" in {
        findingsIn("good_freed") shouldBe empty
    }

  "the unbraced if" should:

    "stay silent when an unbraced `if (p) free(p);` frees on the taken path (good_capped)" in {
        // the false edge to the implicit end is narrowed to p-is-null; without that the
        // allocation stays live there and the negative control reads as a leak
        findingsIn("good_capped_unbraced") shouldBe empty
    }

    "keep the early-return narrowing for an unbraced `if (c) return 1;`" in {
        findingsIn("good_unbraced_retval") shouldBe empty
    }

    "not invert `if (q != NULL)`: the taken path abandons the allocation" in {
        findingsIn("bad_leak_notEquals_return") shouldBe Set("MS-ALLOC-003")
    }

    "not revive a NULL RESET into a phantom allocation under a non-null guard" in {
        findingsIn("good_reset_recheck") shouldBe empty
    }

  "converged leak facts" should:

    "stay silent when a guarded close frees on the taken path (the join is maybe-freed)" in {
        // recorded eagerly per worklist visit, the fact restated the pre-join `allocated`
        // state the false edge delivered to the implicit end before the freed path joined in
        findingsIn("good_guarded_close") should not contain "MS-ALLOC-003"
    }

    "stay silent when the free runs on every iteration of an always-entered loop" in {
        findingsIn("good_loop_freed") should not contain "MS-ALLOC-003"
    }

    "stay silent at an exit under an int-handle acquisition's failure check" in {
        // `if (fd < 0) return -1;` - the descriptor's failure sentinel is negative, and the
        // exit on that side holds no resource to leak
        findingsIn("good_fd_checked") should not contain "MS-ALLOC-003"
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
