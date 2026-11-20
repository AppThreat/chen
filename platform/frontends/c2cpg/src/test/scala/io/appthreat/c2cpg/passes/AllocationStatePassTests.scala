package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    MemoryApiPass,
    MemorySafetyFindingPass
}
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Return, StoredNode}
import io.shiftleft.semanticcpg.language.*

/** Allocation-state rules over the AllocationStatePass facts. Every positive mirrors a classic CWE
  * shape (the CWE-415 double free, the CWE-416 use after free, the CWE-401 memory leak); every
  * negative is the paired correctly-written variant - the free-and-reset idiom, the free inside a
  * guard that also returns, a realloc feeding the next free.
  */
class AllocationStatePassTests extends DataFlowCodeToCpgSuite:

  // the deep-chain fixture's length: far past the state pass's steal-walk bound of
  // eight definitions, at the depth a real tree's definition chains reach
  private val DeepStealChainLength = 4000

  private val cpg = code(
    """
    |#include <fcntl.h>
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |#include <sys/socket.h>
    |#include <unistd.h>
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
    |/* the same defect over a descriptor open returned */
    |void bad_double_close_descriptor(const char *path)
    |{
    |    int fd = open(path, 1);
    |    if (fd < 0) return;
    |    close(fd);
    |    close(fd);
    |}
    |
    |/* and over a descriptor socket returned */
    |void bad_double_close_socket(void)
    |{
    |    int s = socket(AF_INET, SOCK_STREAM, 0);
    |    if (s < 0) return;
    |    close(s);
    |    close(s);
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
  ).moreCode(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* ---- destroy functions: release what the argument owns, then the argument ---- */
    |
    |struct item {
    |    char *name;
    |    int refs;
    |};
    |
    |static struct item *item_new(const char *name)
    |{
    |    struct item *it = (struct item *)calloc(1, sizeof(*it));
    |    if (it == NULL)
    |        return NULL;
    |    it->name = strdup(name);
    |    it->refs = 1;
    |    return it;
    |}
    |
    |/* frees the member, then the argument, with no guard */
    |void item_destroy(struct item *it)
    |{
    |    free(it->name);
    |    free(it);
    |}
    |
    |/* the same destroy behind a NULL guard on the argument */
    |void item_destroy_guarded(struct item *it)
    |{
    |    if (it == NULL)
    |        return;
    |    free(it->name);
    |    free(it);
    |}
    |
    |struct word_node {
    |    struct word_node *next;
    |    char *value;
    |};
    |
    |struct word_list {
    |    struct word_node *head;
    |    size_t count;
    |};
    |
    |/* frees every node and its value in a loop, then the list */
    |void word_list_destroy(struct word_list *list)
    |{
    |    struct word_node *node = list->head;
    |    while (node != NULL) {
    |        struct word_node *next = node->next;
    |        free(node->value);
    |        free(node);
    |        node = next;
    |    }
    |    list->head = NULL;
    |    free(list);
    |}
    |
    |struct panel {
    |    struct item *owner;
    |    struct word_list *labels;
    |    char *title;
    |};
    |
    |/* the members released by their own destroy functions, then the panel */
    |void panel_destroy(struct panel *p)
    |{
    |    item_destroy_guarded(p->owner);
    |    word_list_destroy(p->labels);
    |    free(p->title);
    |    free(p);
    |}
    |
    |/* releases only when the flag says the object is ours */
    |void item_release_if_owned(struct item *it, int owned)
    |{
    |    if (owned) {
    |        free(it->name);
    |        free(it);
    |    }
    |}
    |
    |/* releases the member and keeps the struct the caller's */
    |void item_release_name(struct item *it)
    |{
    |    free(it->name);
    |    it->name = NULL;
    |}
    |
    |/* frees the argument on some paths only */
    |void item_destroy_if_loaded(struct item *it, int loaded)
    |{
    |    free(it->name);
    |    if (loaded)
    |        free(it);
    |}
    |
    |/* frees the argument when its reference count reaches zero */
    |void item_unref(struct item *it)
    |{
    |    if (--it->refs == 0)
    |        free(it);
    |}
    |
    |/* ---- the callers ---- */
    |
    |/* destroy, then hand the slot to a fresh object */
    |void good_destroy_then_reassign(void)
    |{
    |    struct item *it = item_new("old");
    |    if (it == NULL)
    |        return;
    |    item_destroy_guarded(it);
    |    it = item_new("new");
    |    if (it == NULL)
    |        return;
    |    (void)it->refs;
    |    item_destroy(it);
    |}
    |
    |/* the flag says the object is not ours to free: a use after the call is sound */
    |int good_use_after_flag_release(void)
    |{
    |    struct item *it = item_new("borrowed");
    |    if (it == NULL)
    |        return -1;
    |    item_release_if_owned(it, 0);
    |    return it->refs;
    |}
    |
    |/* the flag says "not ours", so the caller's own release is the only one */
    |void good_owned_release_after_flag(void)
    |{
    |    struct item *it = item_new("mine");
    |    if (it == NULL)
    |        return;
    |    item_release_if_owned(it, 0);
    |    free(it->name);
    |    free(it);
    |}
    |
    |/* the member was released, the struct itself was not */
    |void good_use_after_member_release(void)
    |{
    |    struct item *it = item_new("kept");
    |    if (it == NULL)
    |        return;
    |    item_release_name(it);
    |    (void)it->refs;
    |    free(it);
    |}
    |
    |/* the count has not reached zero: the object is alive */
    |int good_use_after_nonzero_unref(void)
    |{
    |    struct item *it = item_new("shared");
    |    if (it == NULL)
    |        return -1;
    |    it->refs = 2;
    |    item_unref(it);
    |    return it->refs;
    |}
    |
    |/* this caller's mode leaves the object alive */
    |int good_use_after_partial_destroy(void)
    |{
    |    struct item *it = item_new("cached");
    |    if (it == NULL)
    |        return -1;
    |    item_destroy_if_loaded(it, 0);
    |    return it->refs;
    |}
    |
    |/* every path destroys exactly once, the error paths through a goto */
    |int good_goto_error_cleanup(int mode)
    |{
    |    struct item *it = item_new("cfg");
    |    char *buf = NULL;
    |    int rc = -1;
    |    if (it == NULL)
    |        goto out;
    |    buf = (char *)malloc(64);
    |    if (buf == NULL)
    |        goto out;
    |    memset(buf, 0, 64);
    |    buf[0] = 'x';
    |    rc = mode;
    |out:
    |    free(buf); /* free(NULL) is a no-op on the early paths */
    |    item_destroy_guarded(it);
    |    return rc;
    |}
    |
    |/* a list, its node and the node's value all destroyed exactly once */
    |void good_list_destroy_and_discard(void)
    |{
    |    struct word_list *list = (struct word_list *)calloc(1, sizeof(*list));
    |    if (list == NULL)
    |        return;
    |    struct word_node *node = (struct word_node *)calloc(1, sizeof(*node));
    |    if (node == NULL) {
    |        free(list);
    |        return;
    |    }
    |    node->value = strdup("utf8");
    |    list->head = node;
    |    list->count = 1;
    |    word_list_destroy(list);
    |}
    |
    |/* a static handle destroyed once, reset, then the guarded no-op destroy */
    |static struct item *cached_item;
    |
    |void good_static_destroy_and_reset(void)
    |{
    |    cached_item = item_new("static");
    |    if (cached_item == NULL)
    |        return;
    |    item_destroy_guarded(cached_item);
    |    cached_item = NULL;
    |    item_destroy_guarded(cached_item);
    |}
    |
    |/* a use after a NULL-guarded destroy */
    |void bad_use_after_guarded_destroy(void)
    |{
    |    struct item *it = item_new("session");
    |    if (it == NULL)
    |        return;
    |    item_destroy_guarded(it);
    |    (void)it->refs;
    |}
    |
    |/* a use after a destroy that walked the list of members */
    |void bad_use_after_list_destroy(void)
    |{
    |    struct word_list *list = (struct word_list *)calloc(1, sizeof(*list));
    |    if (list == NULL)
    |        return;
    |    struct word_node *node = (struct word_node *)calloc(1, sizeof(*node));
    |    if (node == NULL) {
    |        free(list);
    |        return;
    |    }
    |    node->value = strdup("utf8");
    |    list->head = node;
    |    list->count = 1;
    |    word_list_destroy(list);
    |    (void)list->count;
    |}
    |
    |/* a use after a destroy that called the other destroy functions */
    |void bad_use_after_panel_destroy(void)
    |{
    |    struct panel *p = (struct panel *)calloc(1, sizeof(*p));
    |    if (p == NULL)
    |        return;
    |    p->owner = item_new("table");
    |    p->title = strdup("/etc/app.conf");
    |    panel_destroy(p);
    |    (void)p->title;
    |}
    |
    |/* ---- freep wrappers behind a guard on the pointee ---- */
    |
    |/* releases the pointee behind a NULL guard on it, and resets the slot */
    |static void slot_freep_guarded(char **slot)
    |{
    |    if (*slot == NULL)
    |        return;
    |    free(*slot);
    |    *slot = NULL;
    |}
    |
    |/* releases the pointee behind a NULL guard on it, and leaves the slot dangling */
    |static void slot_freep_no_reset(char **slot)
    |{
    |    if (*slot != NULL)
    |        free(*slot);
    |}
    |
    |/* releases the pointee only when another parameter says so */
    |static void slot_freep_if_owned(char **slot, int owned)
    |{
    |    if (owned) {
    |        free(*slot);
    |        *slot = NULL;
    |    }
    |}
    |
    |/* releases the pointee only when it equals a sentinel value, not NULL */
    |static void slot_freep_if_sentinel(char **slot, char *sentinel)
    |{
    |    if (*slot == sentinel) {
    |        free(*slot);
    |        *slot = NULL;
    |    }
    |}
    |
    |/* the guarded freep leaves the slot null: a fresh object and a second call are sound */
    |void good_guarded_freep_reassign(void)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL)
    |        return;
    |    slot_freep_guarded(&p);
    |    p = (char *)malloc(16);
    |    if (p == NULL)
    |        return;
    |    p[0] = 'x';
    |    slot_freep_guarded(&p);
    |}
    |
    |/* the non-resetting guarded freep leaves the slot dangling: a release before
    |   the call is a double free at the call */
    |void bad_double_free_before_guarded_freep(void)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL)
    |        return;
    |    free(p);
    |    slot_freep_no_reset(&p);
    |}
    |""".stripMargin,
    "destroy_functions.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* The GCC cleanup attribute: one release per exit of the variable's scope, each
    | * a compiler-placed call with the variable's address. The cleanup function here
    | * releases the pointee and leaves the slot empty (the non-resetting shape); the
    | * steal function moves the pointee out and empties the slot without releasing
    | * anything; the statement-expression macro spells that move inline, the way the
    | * kernel's no_free_ptr and systemd's TAKE_PTR macros do.
    | */
    |static inline void freep(void *p) { free(*(void **)p); }
    |#define __free_heap __attribute__((cleanup(freep)))
    |
    |static inline void *steal(void **pp) { void *p = *pp; *pp = NULL; return p; }
    |
    |/* returns the pointee without ever storing NULL through the slot: a
    |   hand-off to the caller, not a steal */
    |static inline void *returns_pointee_no_steal(void **pp) { return *pp; }
    |
    |/* the resetting spelling: the slot is emptied after the release, through the
    |   same cast the release reads through */
    |static inline void freep_reset(void *p) { free(*(void **)p); *(void **)p = NULL; }
    |#define __free_reset __attribute__((cleanup(freep_reset)))
    |
    |#define no_free_steal(p) ({ __typeof__(p) _p_ = (p); (p) = NULL; _p_; })
    |
    |/* used inside the scope, released where the block ends and at the early return;
    |   only the buffer's CONTENT leaves by value */
    |int cleanup_ok(const char *data)
    |{
    |    char *buf __free_heap = malloc(64);
    |    if (!buf)
    |        return -1;
    |    memcpy(buf, data, 16);
    |    buf[16] = 0;
    |    return buf[0];
    |}
    |
    |/* the path that frees by hand resets the slot, so the scope-end release of the
    |   reset slot is a no-op; the other path's block is released at scope end */
    |int cleanup_conditional_reset(int mode)
    |{
    |    char *buf __free_heap = malloc(32);
    |    if (!buf)
    |        return -1;
    |    if (mode) {
    |        free(buf);
    |        buf = NULL;
    |    }
    |    return 0;
    |}
    |
    |/* ownership moves out through the steal: the cleanup releases an empty slot */
    |char *cleanup_return_stolen(void)
    |{
    |    char *buf __free_heap = malloc(32);
    |    if (!buf)
    |        return NULL;
    |    return steal((void **)&buf);
    |}
    |
    |/* the free-and-reset idiom inside a cleanup scope */
    |int cleanup_reset_after_free(void)
    |{
    |    char *buf __free_heap = malloc(32);
    |    if (!buf)
    |        return -1;
    |    buf[0] = 'r';
    |    free(buf);
    |    buf = NULL;
    |    return 0;
    |}
    |
    |/* one buffer per iteration, released where each iteration's block ends */
    |int cleanup_in_loop(int n)
    |{
    |    int total = 0;
    |    for (int i = 0; i < n; i++) {
    |        char *buf __free_heap = malloc(16);
    |        if (!buf)
    |            continue;
    |        buf[0] = 'l';
    |        total += buf[0];
    |    }
    |    return total;
    |}
    |
    |/* the early exit through the label releases the buffer; the fall-through path
    |   releases it where the block ends; nothing doubles */
    |int cleanup_goto_error(int n)
    |{
    |    char *buf __free_heap = malloc(32);
    |    int rc = -1;
    |    if (!buf)
    |        goto out;
    |    buf[0] = 'g';
    |    rc = 0;
    |out:
    |    return rc;
    |}
    |
    |/* static storage keeps what the scope moved out first: the store hands over a
    |   block the cleanup variable no longer owns */
    |static char *kept_stolen;
    |
    |int stash_stolen_correct(void)
    |{
    |    char *buf __free_heap = malloc(16);
    |    if (!buf)
    |        return -1;
    |    kept_stolen = no_free_steal(buf);
    |    return 0;
    |}
    |
    |/* the statement expression itself: the slot is emptied in place and the block
    |   leaves through the return */
    |char *cleanup_no_free_steal(void)
    |{
    |    char *buf __free_heap = malloc(16);
    |    if (!buf)
    |        return NULL;
    |    return no_free_steal(buf);
    |}
    |
    |/* the resetting cleanup function leaves the slot empty at every exit */
    |int cleanup_resetting_freep(void)
    |{
    |    char *b __free_reset = malloc(16);
    |    if (!b)
    |        return -1;
    |    b[0] = 'x';
    |    return b[0];
    |}
    |
    |/* ---- the defects ---- */
    |
    |/* freed by hand, then again where the scope ends: the report belongs to the
    |   cleanup call, not to the hand-written free */
    |int cleanup_double_free_bad(int mode)
    |{
    |    char *buf __free_heap = malloc(32);
    |    if (!buf)
    |        return -1;
    |    free(buf);
    |    return 0;
    |}
    |
    |/* the value leaves the frame, then the cleanup releases it: the caller holds a
    |   dangling pointer */
    |char *cleanup_return_dangling(void)
    |{
    |    char *buf __free_heap = malloc(32);
    |    if (!buf)
    |        return NULL;
    |    return buf;
    |}
    |
    |int cleanup_use_after_dangling_return(void)
    |{
    |    char *p = cleanup_return_dangling();
    |    if (!p)
    |        return -1;
    |    p[0] = 'd';
    |    return p[0];
    |}
    |
    |/* the global outlives the scope whose cleanup releases what it keeps */
    |static char *stale_global;
    |
    |int cleanup_stash_dangling(void)
    |{
    |    char *buf __free_heap = malloc(16);
    |    if (!buf)
    |        return -1;
    |    stale_global = buf;
    |    return 0;
    |}
    |""".stripMargin,
    "scope_cleanup.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |
    |/* ---- the steal chain deeper than the definition walk's bound: the returned
    |   identifier's chain of locals runs past where the walk stops, so the method
    |   concludes nothing instead of walking to the stack's end ---- */
    |
    |void *steal_chain_beyond_bound(void **pp)
    |{
    |    void *p0 = *pp;
    |    void *p1 = p0;
    |    void *p2 = p1;
    |    void *p3 = p2;
    |    void *p4 = p3;
    |    void *p5 = p4;
    |    void *p6 = p5;
    |    void *p7 = p6;
    |    void *p8 = p7;
    |    void *p9 = p8;
    |    void *p10 = p9;
    |    void *p11 = p10;
    |    void *p12 = p11;
    |    *pp = NULL;
    |    return p12;
    |}
    |""".stripMargin,
    "steal_chain.c"
  ).moreCode(
    s"""
    |#include <stdlib.h>
    |
    |/* the same shape at a real tree's depth: the walk bounds itself far above
    |   this chain's length and the method stays silent */
    |void *steal_deep(void **pp)
    |{
    |    void *first = *pp;
    |${(0 to DeepStealChainLength).map(i => s"    void *s$i;").mkString("\n")}
    |${(0 to DeepStealChainLength).map(i =>
          if i == 0 then "    s0 = first;" else s"    s$i = s${i - 1};"
      ).mkString("\n")}
    |    *pp = NULL;
    |    return s$DeepStealChainLength;
    |}
    |""".stripMargin,
    "steal_deep_chain.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |
    |/* ---- the binary-exec hand-off: the environment array and the variable block
    |   are released on every error exit, and both are released where the success
    |   path ends. The frees sit on mutually exclusive paths ---- */
    |
    |#define ngx_free(p) free(p)
    |#define ngx_cpymem(dst, src, n) ((char *) memcpy(dst, src, n) + (n))
    |
    |typedef long ngx_pid_t;
    |typedef struct {
    |    char *path;
    |    const char *name;
    |    char **argv;
    |    char **envp;
    |} exec_ctx_t;
    |
    |static char *ngx_log_dummy;
    |
    |void *ngx_alloc(unsigned long size, void *log)
    |{
    |    (void)log;
    |    return malloc(size);
    |}
    |
    |char **ngx_set_environment(unsigned long *n)
    |{
    |    char **e = (char **)calloc(*n + 2, sizeof(*e));
    |    if (e == NULL)
    |        return NULL;
    |    *n = 1;
    |    return e;
    |}
    |
    |int ngx_rename_file(const char *from, const char *to)
    |{
    |    (void)from;
    |    (void)to;
    |    return 0;
    |}
    |
    |long ngx_execute(void *cycle, exec_ctx_t *ctx)
    |{
    |    (void)cycle;
    |    (void)ctx;
    |    return 0;
    |}
    |
    |long ngx_exec_probe(void *cycle, const char *name)
    |{
    |    char **env;
    |    char *var;
    |    unsigned long n = 3;
    |    exec_ctx_t ctx;
    |    ngx_pid_t pid = -1;
    |
    |    env = ngx_set_environment(&n);
    |    if (env == NULL)
    |        return -1;
    |
    |    var = (char *)ngx_alloc(64, ngx_log_dummy);
    |    if (var == NULL) {
    |        ngx_free(env);
    |        return -1;
    |    }
    |
    |    (void)ngx_cpymem(var, name, strlen(name) + 1);
    |    env[1] = var;
    |    env[2] = NULL;
    |    ctx.envp = env;
    |
    |    if (ngx_rename_file(name, "old") != 0) {
    |        ngx_free(env);
    |        ngx_free(var);
    |        return -1;
    |    }
    |
    |    pid = ngx_execute(cycle, &ctx);
    |
    |    ngx_free(env);
    |    ngx_free(var);
    |    return 0;
    |}
    |
    |/* ---- the reference-counted pair the tree defines itself: the release's summary
    |   comes from its body, the decrement and the zero-gated free in one ---- */
    |
    |struct robj {
    |    int refcount;
    |    char *val;
    |};
    |
    |void obj_drop(struct robj *o)
    |{
    |    if (o->refcount == 1) {
    |        free(o->val);
    |        free(o);
    |    } else {
    |        o->refcount--;
    |    }
    |}
    |
    |void obj_take(struct robj *o)
    |{
    |    o->refcount++;
    |}
    |
    |/* ---- the reference-counted pair as real projects spell it: the constructor
    |   stores the first reference into the fresh object's count field, the
    |   acquire is the bare increment statement, and the release frees the
    |   object's members and the object itself behind the zero condition ---- */
    |
    |typedef struct obj {
    |    char *name;
    |    int refs;
    |    int level;
    |} obj_t;
    |
    |obj_t *obj_new(const char *name)
    |{
    |    obj_t *o = (obj_t *)calloc(1, sizeof(*o));
    |    if (o == NULL)
    |        return NULL;
    |    o->name = strdup(name);
    |    o->refs = 1;
    |    return o;
    |}
    |
    |void obj_ref(obj_t *o)
    |{
    |    o->refs++;
    |}
    |
    |void obj_unref(obj_t *o)
    |{
    |    if (--o->refs == 0) {
    |        free(o->name);
    |        free(o);
    |    }
    |}
    |
    |/* an extra reference is held between the two releases, so the read between
    |   them is live: the first release drops the acquired reference, the last
    |   one spends the object's own reference */
    |int good_acquire_release_use_release(void)
    |{
    |    obj_t *o = obj_new("session");
    |    if (o == NULL)
    |        return -1;
    |    obj_ref(o);
    |    obj_unref(o);
    |    int r = o->refs;
    |    obj_unref(o);
    |    return r;
    |}
    |
    |/* the acquire spelled in the caller's own frame: the increment of the count
    |   field is the extra reference, and the two releases net against it */
    |int good_use_after_counter_gated_release(void)
    |{
    |    obj_t *o = obj_new("session");
    |    if (o == NULL)
    |        return -1;
    |    o->refs++;
    |    obj_unref(o);
    |    int r = o->refs;
    |    obj_unref(o);
    |    return r;
    |}
    |
    |/* an increment of a different integer field is not an acquire: the release
    |   still spends the object's own reference */
    |int other_field_increment_ok(void)
    |{
    |    obj_t *o = obj_new("meter");
    |    if (o == NULL)
    |        return -1;
    |    o->level++;
    |    obj_unref(o);
    |    return 0;
    |}
    |
    |/* each object's count field counts for its own object: b's extra reference
    |   balances b's two releases, and a's release is the only one a carries */
    |int other_object_increment_ok(void)
    |{
    |    obj_t *a = obj_new("a");
    |    if (a == NULL)
    |        return -1;
    |    obj_t *b = obj_new("b");
    |    if (b == NULL) {
    |        obj_unref(a);
    |        return -1;
    |    }
    |    b->refs++;
    |    obj_unref(b);
    |    obj_unref(b);
    |    obj_unref(a);
    |    return 0;
    |}
    |
    |/* the release spelled inline in the caller: the decrement under the zero
    |   test is the release, the zero arm's own free models its zero-reach, and
    |   the increment before it is what keeps the object alive past the read */
    |int inline_release_ok(void)
    |{
    |    obj_t *o = obj_new("inline");
    |    if (o == NULL)
    |        return -1;
    |    o->refs++;
    |    int r = o->refs;
    |    if (--o->refs == 0) {
    |        free(o->name);
    |        free(o);
    |    }
    |    return r;
    |}
    |
    |/* ---- the kernel's put with a release callback: the count field's address
    |   names the container, and the callback is the second argument ---- */
    |
    |typedef struct {
    |    int refcount;
    |} kref_t;
    |
    |typedef struct kobj {
    |    kref_t ref;
    |    char *name;
    |} kobj_t;
    |
    |/* the callback's own body is not what the pin exercises: the put's release
    |   summary comes from the put's decrement and its pointer call at zero */
    |static void kobj_release(kref_t *kref)
    |{
    |    (void)kref;
    |}
    |
    |int kref_put(kref_t *kref, void (*release)(kref_t *kref))
    |{
    |    if (--kref->refcount == 0) {
    |        release(kref);
    |        return 1;
    |    }
    |    return 0;
    |}
    |
    |/* the release callback freed the object: the read after the put is the use */
    |int bad_kref_put_then_use(void)
    |{
    |    kobj_t *o = (kobj_t *)calloc(1, sizeof(*o));
    |    if (o == NULL)
    |        return -1;
    |    o->name = strdup("device");
    |    (void)kref_put(&o->ref, kobj_release);
    |    return o->ref.refcount;
    |}
    |
    |/* ---- the negative controls: correct C, no finding ---- */
    |
    |/* the balanced pair on a borrowed parameter: the acquire's reference is the one
    |   the release drops, and the caller's own reference keeps the object alive */
    |int balanced_pair_ok(struct robj *o)
    |{
    |    obj_take(o);
    |    obj_drop(o);
    |    return o->refcount;
    |}
    |
    |/* a release inside a loop over a list: every element drops one reference, and
    |   the next iteration's element is a different one */
    |struct rnode {
    |    struct rnode *next;
    |    struct robj *obj;
    |};
    |
    |void drop_all_ok(struct rnode *head)
    |{
    |    struct rnode *n;
    |    for (n = head; n != NULL; n = n->next)
    |        obj_drop(n->obj);
    |}
    |
    |/* the release on the goto error path: the error path uses nothing after it */
    |int goto_release_ok(struct robj *o, int mode)
    |{
    |    int rc = 0;
    |    if (mode) {
    |        obj_drop(o);
    |        rc = -1;
    |        goto out;
    |    }
    |    rc = o->refcount;
    |out:
    |    return rc;
    |}
    |
    |/* the borrowed release: the method drops the reference it was lent, and the
    |   caller's own reference keeps the object alive; nothing reads it after */
    |int borrowed_release_ok(struct robj *o)
    |{
    |    obj_drop(o);
    |    return 0;
    |}
    |
    |/* a second owner the method counted in itself: the block's own count field says
    |   two, so the one release cannot reach zero */
    |int shared_unref_ok(void)
    |{
    |    struct robj *o = (struct robj *)calloc(1, sizeof(*o));
    |    if (o == NULL)
    |        return -1;
    |    o->refcount = 2;
    |    obj_drop(o);
    |    return o->refcount;
    |}
    |
    |/* the fresh object whose own reference the release spends: the block is gone,
    |   and nothing after it reads it */
    |int drop_new_ok(void)
    |{
    |    struct robj *o = (struct robj *)calloc(1, sizeof(*o));
    |    if (o == NULL)
    |        return -1;
    |    o->refcount = 1;
    |    obj_drop(o);
    |    return 0;
    |}
    |
    |/* ---- the seeded defects ---- */
    |
    |/* a use after the release that spent the block's own reference */
    |int use_after_drop_bad(void)
    |{
    |    struct robj *o = (struct robj *)calloc(1, sizeof(*o));
    |    if (o == NULL)
    |        return -1;
    |    o->refcount = 1;
    |    obj_drop(o);
    |    return o->refcount;
    |}
    |
    |/* a second release of the reference the first one spent */
    |void double_drop_bad(void)
    |{
    |    struct robj *o = (struct robj *)calloc(1, sizeof(*o));
    |    if (o == NULL)
    |        return;
    |    o->refcount = 1;
    |    obj_drop(o);
    |    obj_drop(o);
    |}
    |
    |/* a use after a borrowed release: the object is only maybe gone */
    |int borrowed_use_bad(struct robj *o)
    |{
    |    obj_drop(o);
    |    return o->refcount;
    |}
    |""".stripMargin,
    "refcount_state.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  // The declared region vocabulary, the way a project's in-house config names its pools and
  // contexts, beside an inferred pool pair whose destroy summary comes from its body.
  private val regionConfig =
      """{"version": 1, "apis": [
        |  {"name": "palloc", "len": 1, "alloc": "pgmem",
        |   "region": {"role": "allocate", "context": "CurrentMemoryContext"}},
        |  {"name": "pfree", "free": "pgmem"},
        |  {"name": "apr_palloc", "len": 2, "alloc": "aprpool",
        |   "region": {"role": "allocate", "arg": 1}},
        |  {"name": "apr_pool_create", "region": {"role": "create", "arg": 1}},
        |  {"name": "apr_pool_clear", "region": {"role": "reset", "arg": 1}},
        |  {"name": "apr_pool_destroy", "region": {"role": "destroy", "arg": 1}},
        |  {"name": "MemoryContextDelete", "region": {"role": "destroy", "arg": 1}}
        |]}""".stripMargin

  private val regionCpg = code(
    """
    |#include <stdlib.h>
    |
    |void *palloc(unsigned long size);
    |void pfree(void *p);
    |extern void *CurrentMemoryContext;
    |void MemoryContextDelete(void *ctx);
    |typedef struct apr_pool_t apr_pool_t;
    |void *apr_palloc(apr_pool_t *pool, unsigned long size);
    |void apr_pool_create(apr_pool_t **pool, apr_pool_t *parent);
    |void apr_pool_clear(apr_pool_t *pool);
    |void apr_pool_destroy(apr_pool_t *pool);
    |
    |/* the inferred pool pair: the destroy's summary comes from its body */
    |typedef struct pool { char *base; size_t used; size_t cap; } pool_t;
    |void *pool_alloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return NULL;
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |void pool_destroy(pool_t *p)
    |{
    |    free(p->base);
    |    free(p);
    |}
    |
    |/* the block a region handed out is not this frame's to leak */
    |int region_lives_to_end(apr_pool_t *pool)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    return 0;
    |}
    |
    |/* the destroy tears the block down with the pool */
    |int destroy_then_use(apr_pool_t *pool)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    apr_pool_destroy(pool);
    |    b[0] = 2;
    |    return b[0];
    |}
    |
    |/* the reset only empties the pool: the block is maybe gone */
    |int reset_then_use(apr_pool_t *pool)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    apr_pool_clear(pool);
    |    return b[0];
    |}
    |
    |/* the context-less allocator draws from the named global, which the delete ends */
    |int context_delete_then_use(void)
    |{
    |    char *b = (char *)palloc(16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    MemoryContextDelete(CurrentMemoryContext);
    |    return b[0];
    |}
    |
    |/* the inferred destroy of the pool handle frees the block it handed out */
    |int inferred_destroy_then_use(pool_t *p, size_t n)
    |{
    |    char *s = (char *)pool_alloc(p, n);
    |    if (s == NULL)
    |        return -1;
    |    s[0] = 1;
    |    pool_destroy(p);
    |    return s[0];
    |}
    |
    |/* the inferred pair used correctly: the use sits between alloc and destroy */
    |int inferred_pair_ok(pool_t *p, size_t n)
    |{
    |    char *s = (char *)pool_alloc(p, n);
    |    if (s == NULL)
    |        return -1;
    |    s[0] = 1;
    |    pool_destroy(p);
    |    return 0;
    |}
    |
    |/* the out-pointer create hands the region out; the destroy pairs with it */
    |int created_pool_ok(unsigned long n)
    |{
    |    apr_pool_t *pool = NULL;
    |    char *b;
    |    apr_pool_create(&pool, NULL);
    |    if (pool == NULL)
    |        return -1;
    |    b = (char *)apr_palloc(pool, n);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    apr_pool_destroy(pool);
    |    return 0;
    |}
    |
    |/* the matched palloc/pfree pair releases by hand */
    |int palloc_pfree_ok(void)
    |{
    |    char *b = (char *)palloc(16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    pfree(b);
    |    return 0;
    |}
    |
    |/* the error path destroys the pool and returns NULL, using nothing afterwards */
    |char *goto_destroy_ok(apr_pool_t *pool, unsigned long n)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return NULL;
    |    if (n == 0) {
    |        apr_pool_destroy(pool);
    |        return NULL;
    |    }
    |    b[0] = 1;
    |    return b;
    |}
    |
    |/* every pool of a list is destroyed with its block inside the loop */
    |int loop_destroy_ok(apr_pool_t **pools, int count)
    |{
    |    int i;
    |    for (i = 0; i < count; i++) {
    |        apr_pool_t *p = pools[i];
    |        char *b = (char *)apr_palloc(p, 16);
    |        if (b == NULL)
    |            continue;
    |        b[0] = 1;
    |        apr_pool_destroy(p);
    |    }
    |    return 0;
    |}
    |
    |/* a static holds a region pointer across calls */
    |char *static_region_ok(apr_pool_t *pool)
    |{
    |    static char *keep = NULL;
    |    if (keep == NULL)
    |        keep = (char *)apr_palloc(pool, 16);
    |    return keep;
    |}
    |
    |/* the region-full fallback: the malloc arm freed by hand on the path that
    |   knows the pool was full, the region arm left with the pool */
    |void *pool_alloc_or_malloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return malloc(n);
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |
    |int fallback_ok(pool_t *p, size_t n)
    |{
    |    char *m;
    |    if (p->cap - p->used < n) {
    |        m = (char *)pool_alloc_or_malloc(p, n);
    |        if (m == NULL)
    |            return -1;
    |        m[0] = 1;
    |        free(m);
    |        return -1;
    |    }
    |    m = (char *)pool_alloc_or_malloc(p, n);
    |    if (m == NULL)
    |        return -1;
    |    m[0] = 1;
    |    return 0;
    |}
    |
    |/* ---- the bump array the caller names by its field's address: the array_get
    |   inference reads arithmetic over the field of its parameter, and the call
    |   sites pass the region as &s->directory, a field path ---- */
    |
    |typedef struct varray {
    |    void *ptr;
    |    unsigned long size;
    |    unsigned long n;
    |} varray_t;
    |
    |void *varray_get(varray_t *a, unsigned long i)
    |{
    |    if (i >= a->n)
    |        return NULL;
    |    return a->ptr + i * a->size;
    |}
    |
    |void varray_destroy(varray_t *a)
    |{
    |    free(a->ptr);
    |    free(a);
    |}
    |
    |typedef struct vfat {
    |    varray_t directory;
    |    varray_t fat;
    |} vfat_t;
    |
    |/* the directory array's blocks stay with the directory array */
    |int vvfat_entry_ok(vfat_t *s)
    |{
    |    char *entry = varray_get(&s->directory, 0);
    |    if (entry == NULL)
    |        return -1;
    |    entry[0] = 1;
    |    return 0;
    |}
    |
    |/* the destroy tears the directory array's blocks down: the use after it
    |   reads freed memory */
    |int vvfat_destroy_then_use(vfat_t *s)
    |{
    |    char *entry = varray_get(&s->directory, 0);
    |    varray_destroy(&s->directory);
    |    return entry[0] != 0;
    |}
    |
    |/* the fat array's blocks answer to the fat destroy, not the directory's */
    |int vvfat_fat_ok(vfat_t *s)
    |{
    |    char *entry = varray_get(&s->fat, 0);
    |    if (entry == NULL)
    |        return -1;
    |    varray_destroy(&s->directory);
    |    entry[0] = 1;
    |    return 0;
    |}
    |
    |/* the wrapper over the region-summarised allocator: its result is the
    |   callee's result, and its own parameter names the same region */
    |char *varray_get_next(varray_t *a)
    |{
    |    unsigned long next = a->n;
    |    a->n = next + 1;
    |    return varray_get(a, next);
    |}

    |/* ---- the exact vvfat spellings: the wrapper over the array, the insert's
    |   assignment-in-condition chain, the returned entry, and the first/indexed
    |   reads of one array beside the insert ---- */
    |
    |typedef struct {
    |    void *ptr;
    |    unsigned long next;
    |    unsigned long size;
    |    unsigned long item_size;
    |} qarray_t;
    |
    |void *qarray_get(qarray_t *a, unsigned int index)
    |{
    |    return (char *)a->ptr + index * a->item_size;
    |}
    |
    |/* the array's own maintenance: the storage grows beside the hand-out, the
    |   way the real wrapper's ensure call does */
    |void *qarray_ensure(qarray_t *a, unsigned int index)
    |{
    |    a->ptr = realloc(a->ptr, (index + 1) * a->item_size);
    |    return a->ptr;
    |}
    |
    |void *qarray_get_next(qarray_t *a)
    |{
    |    unsigned int next = a->next;
    |    qarray_ensure(a, next);
    |    a->next = next + 1;
    |    return qarray_get(a, next);
    |}
    |
    |void *qarray_insert(qarray_t *a, unsigned int index, unsigned int count)
    |{
    |    a->ptr = realloc(a->ptr, a->size + count * a->item_size);
    |    return (char *)a->ptr + index * a->item_size;
    |}
    |
    |/* the name creation: the wrapper's result, returned through the local */
    |char *qname_create(qarray_t *names)
    |{
    |    char *entry = qarray_get_next(names);
    |    if (entry == NULL)
    |        return NULL;
    |    entry[0] = 'A';
    |    return entry;
    |}
    |
    |/* the name creation whose every arm hands the block back to the caller:
    |   the local starts NULL, each arm's assignment names the region, and both
    |   exits return the block */
    |char *qname_two_arm_create(qarray_t *names, int is_short)
    |{
    |    char *entry = NULL;
    |    if (is_short) {
    |        entry = qarray_get_next(names);
    |        entry[0] = 'S';
    |        return entry;
    |    }
    |    entry = qarray_get_next(names);
    |    entry[0] = 'L';
    |    return entry;
    |}
    |
    |/* the insert shape: the first and the indexed reads of one array through
    |   the assignment-in-condition chain, with the array's insert beside them;
    |   every block stays with the array */
    |char *qinsert_shape_ok(qarray_t *a, unsigned long begin)
    |{
    |    char *first = qarray_get(a, 0);
    |    char *mapping = NULL;
    |    unsigned long index = 0;
    |
    |    if (index < a->next && (mapping = qarray_get(a, index)) && mapping[0] < begin) {
    |        index++;
    |        mapping = qarray_get(a, index);
    |    }
    |    if (index >= a->next || mapping[0] > begin) {
    |        mapping = qarray_insert(a, index, 1);
    |    }
    |
    |    mapping[0] = begin;
    |    return mapping;
    |}
    |
    |/* the create-name shape: a wrapper whose own summary is empty (it only hands
    |   back the region allocator's result), the local starting NULL, and every
    |   exit returning the block the wrapper handed out */
    |char *qname_via_empty_wrapper(qarray_t *names, int is_short)
    |{
    |    char *entry = NULL;
    |    if (is_short) {
    |        entry = qarray_get_next(names);
    |        entry[0] = 'S';
    |        return entry;
    |    }
    |    entry = qarray_get_next(names);
    |    entry[0] = 'L';
    |    return entry;
    |}
    |
    |/* the same shape with the wrapper's result consumed beside the return */
    |char *qname_via_empty_wrapper_tail(qarray_t *names)
    |{
    |    char *entry = qarray_get_next(names);
    |    if (entry == NULL)
    |        return NULL;
    |    entry[0] = 'L';
    |    return entry;
    |}
    |
    |/* the name-creation shape: the wrapper's result handed back through a local,
    |   consumed at the return */
    |char *varray_name_ok(vfat_t *s)
    |{
    |    char *entry = varray_get_next(&s->directory);
    |    if (entry == NULL)
    |        return NULL;
    |    entry[0] = 'A';
    |    return entry;
    |}
    |
|/* the insert shape: the first and the indexed reads of the same array, with
|   the array's insert beside them */
|char *varray_insert_shape_ok(varray_t *a, unsigned long index)
|{
|    char *first = varray_get(a, 0);
|    char *mapping = varray_get(a, index);
|    if (first == NULL || mapping == NULL)
|        return NULL;
|    first[0] = 'M';
|    mapping[0] = 'M';
|    return mapping;
|}
|
|/* the array's insert: the storage regrows beside the hand-out and the new
|   block comes back as arithmetic over the same field */
|void *varray_insert(varray_t *a, unsigned long index, unsigned long count)
|{
|    a->ptr = realloc(a->ptr, a->size + count * a->size);
|    return a->ptr + index * a->size;
|}
|
|/* the insert's assignment-in-condition chain the way the array helpers spell
|   it: the local starts NULL, the condition draws from the array, the insert
|   hands the new block back, and the method returns the block it holds */
|char *varray_insert_branch_ok(varray_t *a, unsigned long begin)
|{
|    char *first = varray_get(a, 0);
|    char *mapping = NULL;
|    unsigned long index = 0;
|
|    if (index < a->n && (mapping = varray_get(a, index)) && mapping[0] < begin) {
|        index++;
|        mapping = varray_get(a, index);
|    }
|    if (index >= a->n || mapping[0] > begin) {
|        mapping = varray_insert(a, index, 1);
|    }
|
|    mapping[0] = begin;
|    return mapping;
|}
|
|/* the two-arm name creation: the local starts NULL, one arm draws from the
|   array and returns the block straight away, the other draws the returned
|   block beside one that stays with the array */
|char *varray_two_arm_return_ok(vfat_t *s, int is_dot)
|{
|    char *entry = NULL;
|    char *entry_long = NULL;
|
|    if (is_dot) {
|        entry = varray_get_next(&s->directory);
|        entry[0] = '.';
|        return entry;
|    }
|
|    entry_long = varray_get_next(&s->directory);
|    entry = varray_get(&s->directory, 0);
|
|    if (entry_long) {
|        entry_long[0] = entry[0];
|    }
|
|    return entry;
|}
|""".stripMargin,
    "regions_state.c"
  )
  new MemoryApiPass(regionCpg, Some(regionConfig)).createAndApply()
  new AllocationStatePass(regionCpg).createAndApply()

  // The declared reference roles, the way an interpreter's or an engine's in-house config names
  // its reference-counted pair: the release lives in a header outside the analysed tree, so only
  // the declared entry can carry it. The state pass reads it exactly like an inferred one. The
  // interpreter's decref macro is the spelling the declared entry lands on: the macro invocation
  // is the call the entry names, and the dealloc it calls at zero lives outside the tree.
  private val refConfig =
      """{"version": 1, "apis": [
        |  {"name": "obj_keep", "acquire": 1},
        |  {"name": "obj_unref", "release": 1},
        |  {"name": "Py_DECREF", "release": 1}
        |]}""".stripMargin

  private val refCpg = code(
    """
    |#include <stdlib.h>
    |
    |void obj_keep(void *o);
    |void obj_unref(void *o);
    |
    |/* the balanced declared pair on a borrowed parameter */
    |int declared_balanced_ok(void *o)
    |{
    |    obj_keep(o);
    |    obj_unref(o);
    |    return 0;
    |}
    |
    |/* the declared release that spends the block's own reference, then a use */
    |int declared_use_bad(void)
    |{
    |    char *o = (char *)calloc(1, 16);
    |    if (o == NULL)
    |        return -1;
    |    o[0] = 'x';
    |    obj_unref(o);
    |    return o[0];
    |}
    |
    |/* a second declared release of the reference the first one spent */
    |void declared_double_bad(void)
    |{
    |    char *o = (char *)calloc(1, 16);
    |    if (o == NULL)
    |        return;
    |    o[0] = 'x';
    |    obj_unref(o);
    |    obj_unref(o);
    |}
    |
    |/* the declared release of a parameter, nothing after it: the caller's own
    |   reference keeps the object alive */
    |int declared_borrowed_ok(void *o)
    |{
    |    obj_unref(o);
    |    return 0;
    |}
    |
    |/* ---- the interpreter's decref macro: the invocation is the call the
    |   declared entry names, and the dealloc it calls at zero lives outside
    |   the analysed tree ---- */
    |
    |typedef struct pyobject {
    |    long ob_refcnt;
    |    char *ob_type_name;
    |} pyobject_t;
    |
    |void pyobject_dealloc(pyobject_t *o);
    |
    |#define Py_DECREF(op)                               \
    |    do {                                            \
    |        if (--((pyobject_t *)(op))->ob_refcnt == 0) \
    |            pyobject_dealloc((pyobject_t *)(op));   \
    |    } while (0)
    |
    |/* the dealloc freed the object: the read after the macro is the use */
    |int declared_py_decref_use_bad(void)
    |{
    |    pyobject_t *o = (pyobject_t *)calloc(1, sizeof(*o));
    |    if (o == NULL)
    |        return -1;
    |    o->ob_type_name = strdup("Module");
    |    Py_DECREF(o);
    |    return o->ob_refcnt;
    |}
    |""".stripMargin,
    "refcount_declared.c"
  )
  new MemoryApiPass(refCpg, Some(refConfig)).createAndApply()
  new AllocationStatePass(refCpg).createAndApply()
  new MemorySafetyFindingPass(refCpg).createAndApply()

  /** The values one method of the reference-count fixture carries under a state-pass tag. */
  private def refFacts(method: String, tag: String): Set[String] =
      refCpg.method.name(method).ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .flatMap(_.tag.name(tag).value.l).l.toSet

  /** The MS-ALLOC rules one method of the reference-count fixture carries. */
  private def refFindings(method: String): Set[String] =
      refCpg.method.name(method).ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l.toSet
          .filter(_.startsWith("MS-ALLOC"))

  // The corpus arm's exec hand-off, governed by the entries the nginx profile declares for
  // the allocator and its free macro: ngx_alloc is the heap allocator and ngx_free is the
  // plain free, spelled through the project's own macro.
  private val nginxConfig =
      """{"version": 1, "apis": [
        |  {"name": "ngx_alloc", "len": 1, "alloc": "heap", "nullableReturn": true},
        |  {"name": "ngx_free", "free": "heap"}
        |]}""".stripMargin

  private val nginxProbeCpg = code(
    """
    |#include <stdlib.h>
    |
    |#define ngx_free(p) free(p)
    |
    |char **ngx_set_environment(unsigned long *n)
    |{
    |    char **e = (char **)calloc(*n + 2, sizeof(*e));
    |    if (e == NULL)
    |        return NULL;
    |    *n = 1;
    |    return e;
    |}
    |
    |int ngx_rename_file(const char *from, const char *to)
    |{
    |    (void)from;
    |    (void)to;
    |    return 0;
    |}
    |
    |long ngx_execute(void *cycle, exec_ctx_t *ctx)
    |{
    |    (void)cycle;
    |    (void)ctx;
    |    return 0;
    |}
    |
    |typedef struct {
    |    char *path;
    |    const char *name;
    |    char **argv;
    |    char **envp;
    |} exec_ctx_t;
    |
    |/* the binary-exec hand-off: every error exit releases what the success path's
    |   end releases, and the frees sit on mutually exclusive paths */
    |long ngx_exec_probe(void *cycle, const char *name)
    |{
    |    char **env;
    |    char *var;
    |    unsigned long n = 3;
    |    exec_ctx_t ctx;
    |    long pid = -1;
    |
    |    env = ngx_set_environment(&n);
    |    if (env == NULL)
    |        return -1;
    |
    |    var = (char *)ngx_alloc(64, 0);
    |    if (var == NULL) {
    |        ngx_free(env);
    |        return -1;
    |    }
    |
    |    env[1] = var;
    |    env[2] = NULL;
    |    ctx.envp = env;
    |
    |    if (ngx_rename_file(name, "old") != 0) {
    |        ngx_free(env);
    |        ngx_free(var);
    |        return -1;
    |    }
    |
    |    pid = ngx_execute(cycle, &ctx);
    |
    |    ngx_free(env);
    |    ngx_free(var);
    |    return 0;
    |}
    |""".stripMargin,
    "ngx_exec_probe.c"
  )
  new MemoryApiPass(nginxProbeCpg, Some(nginxConfig)).createAndApply()
  new AllocationStatePass(nginxProbeCpg).createAndApply()
  new MemorySafetyFindingPass(nginxProbeCpg, Some(nginxConfig)).createAndApply()

  /** The MS-ALLOC rules one method of the nginx exec fixture carries. */
  private def ngxFindings(method: String): Set[String] =
      nginxProbeCpg.method.name(method).ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l.toSet
          .filter(_.startsWith("MS-ALLOC"))

  /** The values one method of the main fixture carries under a state-pass tag. */
  private def factsIn(method: String, tag: String): Set[String] =
      cpg.method.name(method).ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .flatMap(_.tag.name(tag).value.l).l.toSet

  /** The values one method carries under a state-pass tag. */
  private def regionFacts(method: String, tag: String): Set[String] =
      regionCpg.method.name(method).ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .flatMap(_.tag.name(tag).value.l).l.toSet

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

  /** The per-method effect summaries the pass wrote on the method node. */
  private def effectsOf(method: String): Set[String] =
      cpg.method
          .nameExact(method)
          .flatMap(_.tag.name(AllocationStatePass.TagEffect).value.l)
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
        // `p = realloc(p, 16)` loses the block when realloc fails - that leak is the one finding
        findingsIn("bad_realloc_then_free") shouldBe Set("MS-ALLOC-003")
    }

  "MS-ALLOC-004" should:

    "fire on a double close of a file handle" in {
        findingsIn("bad_double_close") shouldBe Set("MS-ALLOC-004")
    }

    "fire on a double close of a descriptor open returned" in {
        findingsIn("bad_double_close_descriptor") shouldBe Set("MS-ALLOC-004")
    }

    "fire on a double close of a descriptor socket returned" in {
        findingsIn("bad_double_close_socket") shouldBe Set("MS-ALLOC-004")
    }

  "worklist termination" should:

    "converge when two allocation sites merge around a loop" in {
        findingsIn("loop_two_sites") shouldBe empty
    }

  "ownership transfer" should:

    "not report a leak when the pointer is stored into a struct member" in {
        findingsIn("good_stash_into_member") shouldBe empty
    }

  "destroy functions" should:

    "stay silent when a guarded destroy hands the slot to a fresh object" in {
        findingsIn("good_destroy_then_reassign") shouldBe empty
    }

    "stay silent when a flag-gated release leaves a borrowed object in use" in {
        findingsIn("good_use_after_flag_release") shouldBe empty
    }

    "stay silent when the flag says the release is not ours and the caller frees itself" in {
        // a wrong always-frees summary here would read the caller's own free as a double free
        findingsIn("good_owned_release_after_flag") shouldBe empty
    }

    "stay silent when only the member was released and the struct survives" in {
        findingsIn("good_use_after_member_release") shouldBe empty
    }

    "stay silent when a nonzero reference count keeps the object alive" in {
        findingsIn("good_use_after_nonzero_unref") shouldBe empty
    }

    "stay silent when this caller's mode leaves the object alive" in {
        findingsIn("good_use_after_partial_destroy") shouldBe empty
    }

    "stay silent when every path destroys exactly once through a goto error cleanup" in {
        findingsIn("good_goto_error_cleanup") shouldBe empty
    }

    "stay silent when a list, its node and the node's value are all destroyed once" in {
        findingsIn("good_list_destroy_and_discard") shouldBe empty
    }

    "stay silent when a static handle is destroyed, reset and destroyed again" in {
        findingsIn("good_static_destroy_and_reset") shouldBe empty
    }

  "destroy function effect summaries" should:

    "read a free behind only NULL tests of the freed parameter as unconditional" in {
        effectsOf("item_destroy_guarded") shouldBe Set("effect:frees-param:1")
    }

    "keep the unguarded destroy's summary" in {
        effectsOf("item_destroy") should contain("effect:frees-param:1")
    }

    "keep the walking destroy's summary" in {
        effectsOf("word_list_destroy") should contain("effect:frees-param:1")
    }

    "keep the destroy-through-destroy summary" in {
        effectsOf("panel_destroy") should contain("effect:frees-param:1")
    }

    "keep a flag-gated release conditional" in {
        effectsOf("item_release_if_owned") should contain("effect:maybe-frees-param:1")
        effectsOf("item_release_if_owned") should not contain "effect:frees-param:1"
    }

    "keep a some-paths release conditional" in {
        effectsOf("item_destroy_if_loaded") should contain("effect:maybe-frees-param:1")
        effectsOf("item_destroy_if_loaded") should not contain "effect:frees-param:1"
    }

    "keep a reference-counted release conditional" in {
        effectsOf("item_unref") should contain("effect:maybe-frees-param:1")
        effectsOf("item_unref") should not contain "effect:frees-param:1"
    }

    "conclude no release at all when only the member is freed" in {
        effectsOf("item_release_name") should contain noneOf (
          "effect:frees-param:1",
          "effect:maybe-frees-param:1"
        )
    }

    "report a use after a NULL-guarded destroy" in {
        findingsIn("bad_use_after_guarded_destroy") shouldBe Set("MS-ALLOC-002")
    }

    "report a use after the walking destroy" in {
        findingsIn("bad_use_after_list_destroy") shouldBe Set("MS-ALLOC-002")
    }

    "report a use after the destroy that called other destroy functions" in {
        findingsIn("bad_use_after_panel_destroy") shouldBe Set("MS-ALLOC-002")
    }

  "guarded freep wrappers" should:

    "stay silent when the guarded freep leaves the slot null" in {
        findingsIn("good_guarded_freep_reassign") shouldBe empty
    }

    "keep a freep gated by another parameter conditional" in {
        effectsOf("slot_freep_if_owned") should contain("effect:maybe-frees-param:1")
        effectsOf("slot_freep_if_owned") should not contain "effect:frees-param:1"
        effectsOf("slot_freep_if_owned") should not contain "effect:freep-param:1"
    }

    "keep a freep gated by a sentinel comparison conditional" in {
        effectsOf("slot_freep_if_sentinel") should contain("effect:maybe-frees-param:1")
        effectsOf("slot_freep_if_sentinel") should not contain "effect:frees-param:1"
        effectsOf("slot_freep_if_sentinel") should not contain "effect:freep-param:1"
    }

    "read a guarded freep that resets as freep-param" in {
        effectsOf("slot_freep_guarded") should contain("effect:freep-param:1")
        effectsOf("slot_freep_guarded") should not contain "effect:frees-param:1"
        effectsOf("slot_freep_guarded") should not contain "effect:maybe-frees-param:1"
    }

    "read a guarded freep that does not reset as frees-param" in {
        effectsOf("slot_freep_no_reset") should contain("effect:frees-param:1")
        effectsOf("slot_freep_no_reset") should not contain "effect:freep-param:1"
    }

    "report a double free before the non-resetting guarded freep" in {
        findingsIn("bad_double_free_before_guarded_freep") shouldBe Set("MS-ALLOC-001")
    }

  "scope cleanup" should:

    "stay silent for a cleanup variable used and released at every exit" in {
        findingsIn("cleanup_ok") shouldBe empty
    }

    "stay silent when the path that frees by hand resets the slot" in {
        findingsIn("cleanup_conditional_reset") shouldBe empty
    }

    "stay silent when ownership leaves through a steal" in {
        findingsIn("cleanup_return_stolen") shouldBe empty
    }

    "stay silent for the free-and-reset idiom inside a cleanup scope" in {
        findingsIn("cleanup_reset_after_free") shouldBe empty
    }

    "stay silent for a cleanup variable whose block ends each loop iteration" in {
        findingsIn("cleanup_in_loop") shouldBe empty
    }

    "stay silent for a goto exit the cleanup releases" in {
        findingsIn("cleanup_goto_error") shouldBe empty
    }

    "stay silent for static storage keeping a block the scope moved out first" in {
        findingsIn("stash_stolen_correct") shouldBe empty
    }

    "stay silent for a statement expression that empties the slot in place" in {
        findingsIn("cleanup_no_free_steal") shouldBe empty
    }

    "stay silent for the resetting cleanup function" in {
        findingsIn("cleanup_resetting_freep") shouldBe empty
    }

    "read the steal's body as a steal of its pointer-to-pointer parameter" in {
        effectsOf("steal") should contain("effect:steals-param:1")
        effectsOf("steal") should not contain "effect:allocates-return"
    }

    "conclude no steal on a chain deeper than the definition walk's bound" in {
        // the unbounded walk concluded this steal (a chain of thirteen locals reaches the
        // parameter); the bound trades the conclusion for termination, and the method
        // concludes no steal whatever its chain hands back. The pointee read's own
        // derefs summary is the walk's separate conclusion and stays
        effectsOf("steal_chain_beyond_bound") should not contain "effect:steals-param:1"
        effectsOf("steal_chain_beyond_bound") should not contain "effect:allocates-return"
        findingsIn("steal_chain_beyond_bound") shouldBe empty
    }

    "keep the binary-exec hand-off's disjoint frees silent" in {
        findingsIn("ngx_exec_probe") shouldBe empty
    }

    "keep the config-governed exec hand-off's disjoint frees silent" in {
        // the entries the nginx profile declares (ngx_alloc the heap allocator, ngx_free the
        // plain free) govern the probe; the frees sit on mutually exclusive paths and no
        // double free exists
        ngxFindings("ngx_exec_probe") shouldBe empty
    }

    "conclude no steal on a chain at a real tree's depth" in {
        effectsOf("steal_deep") should not contain "effect:steals-param:1"
        effectsOf("steal_deep") should not contain "effect:allocates-return"
        findingsIn("steal_deep") shouldBe empty
    }

    "conclude no steal for a pointee return without the slot's NULL store" in {
        // the slot's NULL store is the steal's own evidence: without it the method is a
        // hand-off to the caller, and the definition walk does not run at all
        effectsOf("returns_pointee_no_steal") should not contain "effect:steals-param:1"
        effectsOf("returns_pointee_no_steal") should not contain "effect:allocates-return"
        findingsIn("returns_pointee_no_steal") shouldBe empty
    }

    "read the non-resetting cleanup function as a releaser of its pointee" in {
        effectsOf("freep") should contain("effect:frees-param:1")
        effectsOf("freep") should not contain "effect:freep-param:1"
    }

    "read the resetting cleanup function as a resetting releaser through the cast" in {
        effectsOf("freep_reset") should contain("effect:freep-param:1")
        effectsOf("freep_reset") should not contain "effect:frees-param:1"
    }

    "report a hand free followed by the scope's release at the cleanup call alone" in {
        val m = cpg.method.nameExact("cleanup_double_free_bad").head
        val sites = m.ast.collectAll[StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-001"))
        // the early return's own cleanup release frees the NULL the guard proved, so
        // the only finding site is the scope's release after the hand-written free
        sites should have size 1
        val retLine  = m.ast.isReturn.l.map(_.lineNumber.map(_.toInt).getOrElse(-1)).max
        val freeLine = m.call.nameExact("free").head.lineNumber.map(_.toInt).getOrElse(-1)
        val site     = sites.head
        site.propertyOption("CODE").map(_.toString).orElse("") shouldBe "buf"
        site.propertyOption("LINE_NUMBER").map(_.toString).orElse("") shouldBe retLine.toString
        (retLine should not).equal(freeLine)
    }

    "carry returns-freed for a cleanup variable the return hands out" in {
        effectsOf("cleanup_return_dangling") should contain("effect:returns-freed")
        effectsOf("cleanup_return_dangling") should not contain "effect:allocates-return"
        findingsIn("cleanup_return_dangling") shouldBe empty
    }

    "report the caller's use of a dangling cleanup return" in {
        findingsIn("cleanup_use_after_dangling_return") shouldBe Set("MS-ALLOC-002")
    }

    "report a cleanup variable stored into a global at the store, at medium" in {
        val m = cpg.method.nameExact("cleanup_stash_dangling").head
        val sites = m.ast.collectAll[StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        sites should have size 1
        sites.head.propertyOption("CODE").map(_.toString).orElse("") should include(
          "stale_global = buf"
        )
        sites.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-002=medium")
    }

  "region memory" should:

    "stay out of the leak facts while the block lives with its region" in {
        regionFacts("region_lives_to_end", "alloc-leak") shouldBe empty
        regionFacts("created_pool_ok", "alloc-leak") shouldBe empty
        regionFacts("palloc_pfree_ok", "alloc-leak") shouldBe empty
        regionFacts("goto_destroy_ok", "alloc-leak") shouldBe empty
        regionFacts("loop_destroy_ok", "alloc-leak") shouldBe empty
        regionFacts("static_region_ok", "alloc-leak") shouldBe empty
        regionFacts("fallback_ok", "alloc-leak") shouldBe empty
        regionFacts("inferred_pair_ok", "alloc-leak") shouldBe empty
    }

    "stay out of the leak facts when the region argument is a field path" in {
        // the bump array the caller names by its field's address: the blocks the array
        // handed out belong to that field's region, and no exit leaks them
        regionFacts("vvfat_entry_ok", "alloc-leak") shouldBe empty
        regionFacts("vvfat_destroy_then_use", "alloc-leak") shouldBe empty
        regionFacts("vvfat_fat_ok", "alloc-leak") shouldBe empty
        regionCpg.call.name("varray_get").tag.name("mem-region").value.l.toSet shouldBe Set(
          "alloc:1"
        )
    }

    "move the field-path region's blocks to freed at its destroy" in {
        regionFacts("vvfat_destroy_then_use", "alloc-state") should contain("freed")
    }

    "keep the other field's region out of the destroy" in {
        // the fat array's blocks answer to the fat destroy, not the directory's: the
        // use after the directory's destroy reads live memory
        regionFacts("vvfat_fat_ok", "alloc-state") shouldBe empty
    }

    "govern the wrapper over the region-summarised allocator by the same key" in {
        // the composition: the wrapper hands back the region-summarised callee's
        // result and passes its own parameter where the callee names its region, so
        // its own conclusion carries the region role and every call site keys the
        // blocks the way the callee's call sites do
        regionCpg.call.name("varray_get_next").tag.name("mem-region").value.l.toSet shouldBe Set(
          "alloc:1"
        )
        regionFacts("varray_name_ok", "alloc-leak") shouldBe empty
        regionFacts("varray_insert_shape_ok", "alloc-leak") shouldBe empty
    }

    "govern the wrapper whose array grows beside the hand-out" in {
        // the real wrapper's ensure call reallocs the array's storage; the composed
        // region survives it, and the wrapper's results stay leak-silent
        regionCpg.call.name("qarray_get_next").tag.name("mem-region").value.l.toSet shouldBe Set(
          "alloc:1"
        )
        regionFacts("qname_create", "alloc-leak") shouldBe empty
        regionFacts("qname_two_arm_create", "alloc-leak") shouldBe empty
        regionFacts("qinsert_shape_ok", "alloc-leak") shouldBe empty
        regionFacts("qname_via_empty_wrapper", "alloc-leak") shouldBe empty
        regionFacts("qname_via_empty_wrapper_tail", "alloc-leak") shouldBe empty
    }

    "govern the insert's condition chain and the exits that hand blocks onward" in {
        // the exact vvfat spellings, the way the array helpers spell them: the local
        // starts NULL and the condition's assignment chain draws from the array, the
        // insert hands the new block back, and the two-arm name creation returns the
        // block from both exits while the beside-block stays with the array. No exit
        // reports a region block lost, and the insert's own summary carries the region
        regionFacts("varray_insert_branch_ok", "alloc-leak") shouldBe empty
        regionFacts("varray_two_arm_return_ok", "alloc-leak") shouldBe empty
        regionCpg.call.name("varray_insert").tag.name("mem-region").value.l.toSet shouldBe Set(
          "alloc:1"
        )
    }

    "move to freed at the region's declared destroy, the use after it reading freed" in {
        regionFacts("destroy_then_use", "alloc-state") should contain("freed")
    }

    "move to freed at the context's declared delete" in {
        regionFacts("context_delete_then_use", "alloc-state") should contain("freed")
    }

    "move to freed at the inferred destroy called with the pool handle" in {
        regionFacts("inferred_destroy_then_use", "alloc-state") should contain("freed")
    }

    "move to maybe-freed at the region's declared reset" in {
        regionFacts("reset_then_use", "alloc-state") should contain("maybe-freed")
    }

    "mark the reset's use so it reports below the rule's own confidence" in {
        regionFacts("reset_then_use", "alloc-reset-use") should contain("1")
        // a destroy's use stays at the rule's own confidence: no such marker there
        regionFacts("destroy_then_use", "alloc-reset-use") shouldBe empty
    }

  "the reference releases" should:

    "keep the balanced acquire and release of a borrowed parameter silent" in {
        findingsIn("balanced_pair_ok") shouldBe empty
        factsIn("balanced_pair_ok", "alloc-state") shouldBe empty
    }

    "keep a release in a loop body over a list silent" in {
        findingsIn("drop_all_ok") shouldBe empty
    }

    "keep the release on a goto error path silent" in {
        findingsIn("goto_release_ok") shouldBe empty
    }

    "keep the borrowed release whose caller holds another reference silent" in {
        findingsIn("borrowed_release_ok") shouldBe empty
    }

    "keep a release whose count does not reach zero silent" in {
        findingsIn("shared_unref_ok") shouldBe empty
        factsIn("shared_unref_ok", "alloc-state") shouldBe empty
    }

    "keep the release that reaches zero with no later use leak-silent" in {
        findingsIn("drop_new_ok") shouldBe empty
        factsIn("drop_new_ok", "alloc-leak") shouldBe empty
    }

    "read the release that spends the block's own reference as the block's freedom" in {
        factsIn("use_after_drop_bad", "alloc-state") should contain("freed")
        factsIn("use_after_drop_bad", "alloc-release-use") should contain("medium")
        // the freedom came from a release, not from a region reset: no region mark
        factsIn("use_after_drop_bad", "alloc-reset-use") shouldBe empty
    }

    "track the borrowed release as maybe freed" in {
        factsIn("borrowed_use_bad", "alloc-state") should contain("maybe-freed")
        factsIn("borrowed_use_bad", "alloc-release-use") should contain("low")
    }

    "keep the acquire, release, use, release run of a fresh object silent" in {
        findingsIn("good_acquire_release_use_release") shouldBe empty
    }

    "keep the caller's own count increment in the balance silent" in {
        findingsIn("good_use_after_counter_gated_release") shouldBe empty
    }

    "keep an increment of a different field out of the balance" in {
        findingsIn("other_field_increment_ok") shouldBe empty
    }

    "count each object's own count field increment for that object" in {
        findingsIn("other_object_increment_ok") shouldBe empty
    }

    "keep the release spelled inline in the caller silent" in {
        findingsIn("inline_release_ok") shouldBe empty
    }

  "the reference release defects" should:

    "report the use after the last release at medium" in {
        findingsIn("use_after_drop_bad") shouldBe Set("MS-ALLOC-002")
        val sites = cpg.method.name("use_after_drop_bad").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        sites should have size 1
        sites.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-002=medium")
    }

    "report the second release below zero at medium" in {
        findingsIn("double_drop_bad") shouldBe Set("MS-ALLOC-001")
        val sites = cpg.method.name("double_drop_bad").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-001"))
        // the second release is the finding site; the first one made the count reach zero
        sites should have size 1
        val dropLines = cpg.method.name("double_drop_bad").call.nameExact("obj_drop").l
            .map(_.lineNumber.map(_.toInt).getOrElse(-1)).sorted
        sites.head match
          case e: io.shiftleft.codepropertygraph.generated.nodes.Expression =>
              e.lineNumber.map(_.toInt).getOrElse(-1) shouldBe dropLines.last
          case _ => fail("the release fact sits on an expression")
        sites.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-001=medium")
    }

    "report the use after a borrowed release at low" in {
        findingsIn("borrowed_use_bad") shouldBe Set("MS-ALLOC-002")
        val sites = cpg.method.name("borrowed_use_bad").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        sites should have size 1
        sites.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-002=low")
    }

    "report the use after the put's release callback at medium" in {
        findingsIn("bad_kref_put_then_use") shouldBe Set("MS-ALLOC-002")
        factsIn("bad_kref_put_then_use", "alloc-release-use") should contain("medium")
        val sites = cpg.method.name("bad_kref_put_then_use").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        sites should have size 1
        sites.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-002=medium")
    }

    "report the use after the decref macro's dealloc at medium" in {
        refFindings("declared_py_decref_use_bad") shouldBe Set("MS-ALLOC-002")
        refFacts("declared_py_decref_use_bad", "alloc-state") should contain("freed")
        refFacts("declared_py_decref_use_bad", "alloc-release-use") should contain("medium")
        val sites = refCpg.method.name("declared_py_decref_use_bad").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        // the read after the macro is the use the pin is for; the expansion's own
        // hand-off of the object to the dealloc reports beside it, both at medium
        val returnLine = refCpg.method.name("declared_py_decref_use_bad").ast.isReturn.l
            .map(_.lineNumber.map(_.toInt).getOrElse(-1)).max
        val readSite = sites.filter { s =>
            s match
              case e: io.shiftleft.codepropertygraph.generated.nodes.Expression =>
                  e.lineNumber.map(_.toInt).getOrElse(-1) == returnLine
              case _ => false
        }
        readSite should have size 1
        readSite.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-002=medium")
    }

  "the declared reference roles" should:

    "keep the balanced declared pair silent" in {
        refFindings("declared_balanced_ok") shouldBe empty
    }

    "keep the declared release of a borrowed parameter silent" in {
        refFindings("declared_borrowed_ok") shouldBe empty
    }

    "report the use after a declared release that reached zero at medium" in {
        refFindings("declared_use_bad") shouldBe Set("MS-ALLOC-002")
        refFacts("declared_use_bad", "alloc-state") should contain("freed")
        refFacts("declared_use_bad", "alloc-release-use") should contain("medium")
        val sites = refCpg.method.name("declared_use_bad").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        sites should have size 1
        sites.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-002=medium")
    }

    "report the second declared release below zero at medium" in {
        refFindings("declared_double_bad") shouldBe Set("MS-ALLOC-001")
        refFacts("declared_double_bad", "alloc-release-use") should contain("medium")
        val sites = refCpg.method.name("declared_double_bad").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-001"))
        sites should have size 1
        sites.head.tag.name("ms-confidence").value.l should contain("MS-ALLOC-001=medium")
    }

end AllocationStatePassTests
