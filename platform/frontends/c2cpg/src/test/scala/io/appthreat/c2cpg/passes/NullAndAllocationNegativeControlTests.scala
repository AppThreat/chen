package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    MemoryApiPass,
    MemorySafetyFindingPass
}
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Negative controls for null-guard, free-summary and escape shapes that are easy to misjudge.
  * Every function here is correct C; none may carry a finding at medium or above.
  */
class NullAndAllocationNegativeControlTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <stdio.h>
    |
    |struct node { struct node *next; int v; };
    |struct ctx { char *buf; int *p; };
    |
    |/* a for loop's BODY is on the condition's TRUE edge */
    |int good_for_walk(const char *s)
    |{
    |    int n = 0;
    |    char *e;
    |    for (e = strchr(s, ','); e != NULL; e = strchr(e + 1, ','))
    |        n += e[1];
    |    return n;
    |}
    |
    |/* a do-while body is re-entered on the TRUE edge */
    |int good_do_walk(const char *s)
    |{
    |    int n = 0;
    |    char *e = strchr(s, ',');
    |    if (!e)
    |        return 0;
    |    do {
    |        n += e[1];
    |        e = strchr(e + 1, ',');
    |    } while (e != NULL);
    |    return n;
    |}
    |
    |/* a free on the error path only (goto fail) is NOT an unconditional free */
    |static int init_or_free(char *p, int n)
    |{
    |    if (n < 0)
    |        goto fail;
    |    p[0] = 0;
    |    return 0;
    |fail:
    |    free(p);
    |    return -1;
    |}
    |
    |void good_goto_fail_wrapper(int n)
    |{
    |    char *p = (char *)malloc(16);
    |    if (!p)
    |        return;
    |    if (init_or_free(p, n) < 0)
    |        return;
    |    free(p);
    |}
    |
    |/* a freep-style wrapper that NULLS the caller's pointer */
    |static void my_freep(char **pp)
    |{
    |    printf("free\n");
    |    free(*pp);
    |    *pp = NULL;
    |}
    |
    |void good_freep_nulls(void)
    |{
    |    char *p = (char *)malloc(16);
    |    my_freep(&p);
    |    my_freep(&p);
    |    free(p);
    |}
    |
    |/* returns a fresh allocation on one path, a borrowed pointer on another */
    |static char *get_or_alloc(char *cache, size_t n)
    |{
    |    if (cache)
    |        return cache;
    |    return (char *)malloc(n);
    |}
    |
    |void good_borrowed_return(char *cache)
    |{
    |    char *q = get_or_alloc(cache, 8);
    |    free(q);
    |    free(cache);
    |}
    |
    |/* a static local outlives the frame */
    |const char *good_static_buf(int v)
    |{
    |    static char buf[32];
    |    snprintf(buf, sizeof(buf), "%d", v);
    |    return buf;
    |}
    |
    |/* &local stored into a LOCAL struct's member does not leave the frame */
    |int good_local_struct(void)
    |{
    |    int x = 1;
    |    struct ctx c;
    |    c.p = &x;
    |    return *c.p;
    |}
    |
    |/* an int compared with 0 is not a null guard */
    |int good_int_zero(int size, char *dst)
    |{
    |    memset(dst, 0, size);
    |    if (size == 0)
    |        return 0;
    |    if (!size)
    |        return 1;
    |    return 2;
    |}
    |
    |/* ---- a call is not a dereference ---- */
    |
    |struct inner6 { int x; };
    |struct outer6 { struct inner6 *in; };
    |
    |/* a helper that only logs the pointer reads through nothing - handing it an
    |   unchecked nullable pointer is not a dereference */
    |static void log_ptr6(const char *tag, char *maybe)
    |{
    |    printf("%s %p\n", tag, (void *)maybe);
    |}
    |
    |void good_null_tolerant_helper(void)
    |{
    |    char *p = (char *)malloc(16);
    |    log_ptr6("p", p);
    |    if (!p)
    |        return;
    |    free(p);
    |}
    |
    |/* a helper that guards its parameter first dereferences it on SOME path only */
    |static int first_or_zero6(char *s)
    |{
    |    if (s == NULL)
    |        return 0;
    |    return s[0];
    |}
    |
    |void good_guarded_helper(void)
    |{
    |    char *p = (char *)malloc(16);
    |    int c = first_or_zero6(p);
    |    if (!p)
    |        return;
    |    (void)c;
    |    free(p);
    |}
    |
    |/* handing &p to a wrapper passes the SLOT, not the pointer - not a deref of p */
    |static void reset_if_needed6(char **pp)
    |{
    |    if (*pp) {
    |        free(*pp);
    |        *pp = NULL;
    |    }
    |}
    |
    |void good_addressof_not_use(void)
    |{
    |    char *p = (char *)malloc(16);
    |    reset_if_needed6(&p);
    |    if (!p)
    |        return;
    |    free(p);
    |}
    |
    |/* a use inside the structure whose own condition guards the variable is protected
    |   by that guard - a loop body under its trailer is not a check-after-use */
    |size_t good_guarded_loop_use(char *s)
    |{
    |    size_t n = 0;
    |    do {
    |        n += strlen(s);
    |    } while (s != NULL);
    |    return n;
    |}
    |
    |/* a guard that follows a REDEFINITION speaks about a different value */
    |size_t good_guard_after_reassign(char *s, char *t)
    |{
    |    size_t n = strlen(s);
    |    s = t;
    |    if (s == NULL)
    |        return 0;
    |    return n;
    |}
    |
    |/* a cross-type field chain is an owned sub-object initialised with its parent
    |   (FFmpeg's s->priv_data->x idiom), not a traversal hop */
    |void good_cross_type_chain(struct outer6 *o)
    |{
    |    o->in->x = 1;
    |}
    |
    |/* ---- the leak rule's phantom allocations ---- */
    |
    |/* a function whose only value return is an int counter whose defs are
    |   literals - the ff_get_line shape. `return i` with `int i = 0` satisfied
    |   "every return flows from an allocation" because the NULL-literal
    |   fallback of allocates-return accepted the 0, and every caller's counter
    |   variable became a tracked allocation that "leaked" at every exit. */
    |static int counter_reader(const char *s)
    |{
    |    int i = 0;
    |    while (s[i])
    |        i++;
    |    return i;
    |}
    |
    |void good_counter_return_is_not_an_allocation(int n)
    |{
    |    int len = counter_reader("x");
    |    if (len == 0)
    |        return;
    |    (void)len;
    |}
    |
    |/* the FFmpeg error-path idiom - the allocation is assigned INSIDE the
    |   guard's own condition, `if (!(p = malloc(n)))`. The failed allocation is
    |   NULL on the taken branch: nothing leaked there. */
    |int good_assign_in_guard_leak_check(size_t n)
    |{
    |    char *p;
    |    if (!(p = (char *)malloc(64)))
    |        return -1;
    |    p[0] = 1;
    |    free(p);
    |    return 0;
    |}
    |
    |/* the same shape with the assignment as the bare condition */
    |int good_bare_assign_guard(size_t n)
    |{
    |    char *p;
    |    if ((p = (char *)malloc(64)))
    |        p[0] = 2;
    |    else
    |        return -1;
    |    free(p);
    |    return 0;
    |}
    |
    |/* an int-returning function that allocates into an OUT-PARAM and returns an
    |   error code - the ff_get_extradata shape. Neither the wrapper inference nor the
    |   allocates-return summary may conclude "allocator" for it: every caller's `ret`
    |   error variable became a phantom live allocation that "leaked" at each exit. */
    |static int alloc_into_param(char **out, int n)
    |{
    |    *out = (char *)malloc(64);
    |    if (!*out)
    |        return -1;
    |    return 0;
    |}
    |
    |int good_int_returning_allocator(int n)
    |{
    |    char *p = NULL;
    |    int ret = alloc_into_param(&p, n);
    |    if (ret < 0)
    |        return ret;
    |    p[0] = 1;
    |    free(p);
    |    return 0;
    |}
    |
    |/* a list cursor copied into prev is not the NULL prev started as */
    |void good_list_insert(struct node **head, struct node *item)
    |{
    |    struct node *prev = NULL, *curr = *head;
    |    while (curr != NULL && curr->v < item->v) {
    |        prev = curr;
    |        curr = curr->next;
    |    }
    |    item->next = curr;
    |    if (*head == curr)
    |        *head = item;
    |    else
    |        prev->next = item;
    |}
    |
    |/* storage that is either a frame array or a heap block, released behind its own test */
    |int good_stack_or_heap(int n)
    |{
    |    int stack[16];
    |    int *storage;
    |    if (n < 16)
    |        storage = stack;
    |    else
    |        storage = malloc(n * sizeof(*storage));
    |    if (storage == NULL)
    |        return 0;
    |    storage[0] = n;
    |    if (storage != stack)
    |        free(storage);
    |    return 1;
    |}
    |
    |/* freed, then rebound to what an unknown producer returns: the release is of the old block */
    |char *fetch_buffer(int n);
    |int good_rebound_after_free(int n)
    |{
    |    char *buf = malloc(16);
    |    if (buf == NULL)
    |        return -1;
    |    buf[0] = 0;
    |    free(buf);
    |    buf = fetch_buffer(n);
    |    if (buf == NULL)
    |        return -1;
    |    buf[0] = 1;
    |    return buf[1];
    |}
    |
    |/* a do-while(0) block runs once: its false condition never re-enters the body */
    |int good_free_in_do_while_zero(struct node *head)
    |{
    |    struct node *curr;
    |    char *list = malloc(16);
    |    if (list == NULL)
    |        return -1;
    |    do {
    |        for (curr = head; curr != NULL; curr = curr->next) {
    |            if (curr->v < 0) {
    |                free(list);
    |                return -1;
    |            }
    |        }
    |        free(list);
    |    } while (0);
    |    return 0;
    |}
    |
    |/* a walked pointer rebound to a fresh copy before the free */
    |int good_walk_then_dup(char *kv)
    |{
    |    while (*kv == ' ')
    |        kv++;
    |    kv = strdup(kv);
    |    if (kv == NULL)
    |        return -1;
    |    free(kv);
    |    return 0;
    |}
    |
    |/* curl's glob_set: a failed realloc jumps to the cleanup with the old block still live */
    |#define my_realloc(p, n) realloc(p, n)
    |int good_realloc_into_temp(const char *pattern, int done)
    |{
    |    char **elem = NULL;
    |    size_t palloc = 0;
    |    while (!done) {
    |        if (*pattern == 0) goto error;
    |        if (*pattern == ',') {
    |            if (!palloc) {
    |                char **arr = my_realloc(elem, palloc * 2 * sizeof(char *));
    |                if (!arr) {
    |                    goto error;
    |                }
    |                elem = arr;
    |                goto error;
    |            }
    |        }
    |    }
    |error:
    |    free(elem);
    |    return 1;
    |}
    |
    |int bad_realloc_plain_stale_read(size_t n)
    |{
    |    char *p = malloc(8);
    |    if (p == NULL) return 1;
    |    char *tmp = realloc(p, n);
    |    if (tmp != NULL) {
    |        p[0] = 'x';
    |        free(tmp);
    |    }
    |    return 0;
    |}
    |
    |int bad_realloc_macro_stale_read(size_t n)
    |{
    |    char *p = malloc(8);
    |    if (p == NULL) return 1;
    |    char *tmp = my_realloc(p, n);
    |    if (tmp != NULL) {
    |        p[0] = 'x';
    |        free(tmp);
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "null_alloc_controls.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method
          .name(method)
          .ast
          .collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  private def effectsOf(method: String): Set[String] =
      cpg.method.name(method).flatMap(_.tag.name(AllocationStatePass.TagEffect).value.l).l.toSet

  private def nullUsesIn(method: String): List[String] =
      cpg.method
          .name(method)
          .ast
          .collectAll[StoredNode]
          .flatMap(_.tag.name(AllocationStatePass.TagNullUse).value.l)
          .l

  "null and allocation negative controls" should:
    "not mark a for-loop body null" in { nullUsesIn("good_for_walk") shouldBe empty }
    "not mark a do-while body null" in { nullUsesIn("good_do_walk") shouldBe empty }
    "not summarise an error-path free" in {
        // the maybe-frees fact, not a summary: the error-path return is not a leak of a
        // block the callee may already have released
        effectsOf("init_or_free") shouldBe Set("effect:maybe-frees-param:1")
        findingsIn("good_goto_fail_wrapper") shouldBe empty
    }
    "not report a double free through a nulling freep wrapper" in {
        findingsIn("good_freep_nulls") should not contain "MS-ALLOC-001"
    }
    "not summarise allocates-return for a sometimes-borrowed return" in {
        effectsOf("get_or_alloc") shouldBe empty
    }
    "not report a static local as a stack escape" in {
        findingsIn("good_static_buf") should not contain "MS-ESC-001"
    }
    "not report &local stored in a local struct" in {
        findingsIn("good_local_struct") should not contain "MS-ESC-001"
    }
    "not treat an int compared with 0 as a null guard" in {
        findingsIn("good_int_zero") should not contain "MS-NULL-001"
    }
    "not count a pointer handed to a non-reading helper as a dereference" in {
        findingsIn("good_null_tolerant_helper") shouldBe empty
    }
    "not conclude derefs-param for a helper that guards first" in {
        effectsOf("first_or_zero6") shouldBe empty
        findingsIn("good_guarded_helper") shouldBe empty
    }
    "not count &p handed to a wrapper as a dereference of p" in {
        findingsIn("good_addressof_not_use") shouldBe empty
    }
    "not fire check-after-use inside the guard's own loop" in {
        findingsIn("good_guarded_loop_use") shouldBe empty
    }
    "not fire check-after-use when the guard follows a redefinition" in {
        findingsIn("good_guard_after_reassign") shouldBe empty
    }
    "not fire the chained-parameter arm on a cross-type sub-object chain" in {
        findingsIn("good_cross_type_chain") shouldBe empty
    }
    "not conclude allocates-return for a literal-only counter return" in {
        effectsOf("counter_reader") shouldBe empty
        findingsIn("good_counter_return_is_not_an_allocation") shouldBe empty
    }
    "not leak where the allocation is assigned inside the guard's condition" in {
        findingsIn("good_assign_in_guard_leak_check") shouldBe empty
        findingsIn("good_bare_assign_guard") shouldBe empty
    }
    "not infer an allocator for an int-returning out-param allocator" in {
        // derefs-param:1 is honest (`*out` loads through the slot); no allocator claim
        effectsOf("alloc_into_param") shouldBe Set("effect:derefs-param:1")
        findingsIn("good_int_returning_allocator") shouldBe empty
    }
    "not claim a definite null for a list cursor copied into prev" in {
        nullUsesIn("good_list_insert").filter(
          _.startsWith(AllocationStatePass.NullDefinite)
        ) shouldBe empty
    }
    "not report a frame array release behind the author's own test" in {
        findingsIn("good_stack_or_heap").filter(
          _.contains(MemorySafetyFindingPass.RuleNonHeapFree)
        ) shouldBe empty
    }
    "not keep a freed state across a rebinding to an unknown producer" in {
        findingsIn("good_rebound_after_free") shouldBe empty
    }
    "not follow a do-while(0) back edge into a second free" in {
        findingsIn("good_free_in_do_while_zero") shouldBe empty
    }
    "not report a walked pointer rebound before the free" in {
        findingsIn("good_walk_then_dup").filter(
          _.contains(MemorySafetyFindingPass.RuleOffsetFree)
        ) shouldBe empty
    }
    "not read a failed realloc's input as released on the cleanup path" in {
        findingsIn("good_realloc_into_temp") shouldBe empty
        // the successful side still consumed the input: a read of it there is a use after free
        findingsIn("bad_realloc_plain_stale_read") should contain("MS-ALLOC-002")
        findingsIn("bad_realloc_macro_stale_read") should contain("MS-ALLOC-002")
    }
end NullAndAllocationNegativeControlTests
