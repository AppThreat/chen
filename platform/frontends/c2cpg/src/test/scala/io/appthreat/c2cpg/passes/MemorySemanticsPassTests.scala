package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** MemorySemanticsPass: the memory facts a hand-written project inventory used to supply, concluded
  * from declarations, bodies and variable storage. Nothing here is named in any inventory - every
  * `my_`/`lib_` function is unknown to the built-in libc list.
  */
class MemorySemanticsPassTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* a library whose bodies are NOT in the tree: only its header */
    |#define lib_malloc_attrib __attribute__((__malloc__))
    |#define lib_alloc_size(...) __attribute__((alloc_size(__VA_ARGS__)))
    |void *lib_malloc(size_t size) lib_malloc_attrib lib_alloc_size(1);
    |void *lib_calloc(size_t n, size_t size) lib_malloc_attrib lib_alloc_size(1, 2);
    |void *lib_realloc_array(void *p, size_t n, size_t size) lib_alloc_size(2, 3);
    |size_t lib_len(const char *s) __attribute__((nonnull(1)));
    |__attribute__((returns_nonnull)) char *lib_name(void);
    |
    |/* wrappers whose bodies ARE in the tree */
    |void my_free(void *p) { free(p); }
    |void my_freep(void **pp) { free(*pp); *pp = NULL; }
    |struct entry { const char *key; struct entry *next; };
    |struct entry *my_find(struct entry *e, const char *key)
    |{
    |    for (; e; e = e->next)
    |        if (!strcmp(e->key, key))
    |            return e;
    |    return NULL;
    |}
    |void my_copy(char *dst, const char *src, size_t n) { memcpy(dst, src, n); }
    |
    |/* storage */
    |static int counter;
    |int storage_shapes(int n)
    |{
    |    static char sbuf[8];
    |    char abuf[8];
    |    int x = n;
    |    char *h = (char *)lib_malloc(8);
    |    char *s = abuf;
    |    char *t = sbuf;
    |    int *a = &x;
    |    const char *lit = "text";
    |    free(h);
    |    return *a + s[0] + t[0] + lit[0] + counter;
    |}
    |
    |/* end to end: facts no inventory declared */
    |void leak_attr_alloc(int n)
    |{
    |    char *p = (char *)lib_malloc(16);
    |    if (!p)
    |        return;
    |    p[0] = (char)n;
    |}
    |void null_through_nonnull(const char *s)
    |{
    |    const char *c = strchr(s, ',');
    |    lib_len(c);
    |}
    |void deref_nullable_getter(struct entry *head)
    |{
    |    struct entry *e = my_find(head, "k");
    |    e->key = "v";
    |}
    |void freep_then_free(void)
    |{
    |    char *p = (char *)lib_malloc(8);
    |    my_freep((void **)&p);
    |    my_free(p);
    |}
    |char *realloc_into_tmp(int n)
    |{
    |    char *p = (char *)malloc(n);
    |    if (!p)
    |        return NULL;
    |    char *t = (char *)realloc(p, 2 * n);
    |    if (!t) {
    |        free(p);
    |        return NULL;
    |    }
    |    p = t;
    |    p[0] = 1;
    |    return p;
    |}
    |""".stripMargin,
    "semantics.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* the destroy idiom: release what the argument owns, then the argument,
    |   with or without a NULL guard, in a loop or through other destroy functions */
    |
    |struct rec {
    |    char *name;
    |    int refs;
    |};
    |
    |/* a callee with no memory role of its own: bookkeeping only */
    |static void note_release(const struct rec *r)
    |{
    |    (void)r->refs;
    |}
    |
    |static struct rec *rec_new(const char *name)
    |{
    |    struct rec *r = (struct rec *)calloc(1, sizeof(*r));
    |    if (r == NULL)
    |        return NULL;
    |    r->name = strdup(name);
    |    r->refs = 1;
    |    return r;
    |}
    |
    |/* member bookkeeping through a no-effect callee, then the release */
    |void rec_destroy(struct rec *r)
    |{
    |    note_release(r);
    |    r->refs = 0;
    |    free(r->name);
    |    free(r);
    |}
    |
    |/* the same release behind a NULL guard on the argument */
    |void rec_destroy_guarded(struct rec *r)
    |{
    |    if (r == NULL)
    |        return;
    |    free(r->name);
    |    free(r);
    |}
    |
    |struct word {
    |    struct word *next;
    |    char *value;
    |};
    |
    |struct word_set {
    |    struct word *head;
    |    size_t count;
    |};
    |
    |/* frees each member in a loop, resets the head, then frees the argument */
    |void word_set_destroy(struct word_set *set)
    |{
    |    struct word *w = set->head;
    |    while (w != NULL) {
    |        struct word *next = w->next;
    |        free(w->value);
    |        free(w);
    |        w = next;
    |    }
    |    set->head = NULL;
    |    set->count = 0;
    |    free(set);
    |}
    |
    |struct folder {
    |    struct rec *owner;
    |    struct word_set *words;
    |    char *path;
    |};
    |
    |/* members released by their own destroy functions, then the argument */
    |void folder_destroy(struct folder *f)
    |{
    |    rec_destroy_guarded(f->owner);
    |    word_set_destroy(f->words);
    |    free(f->path);
    |    free(f);
    |}
    |
    |/* releases only when the flag says the object is ours */
    |void rec_release_if_owned(struct rec *r, int owned)
    |{
    |    if (owned) {
    |        free(r->name);
    |        free(r);
    |    }
    |}
    |
    |/* releases the member and keeps the struct the caller's */
    |void rec_release_name(struct rec *r)
    |{
    |    free(r->name);
    |    r->name = NULL;
    |}
    |
    |/* frees the argument on some paths only */
    |void rec_destroy_if_loaded(struct rec *r, int loaded)
    |{
    |    free(r->name);
    |    if (loaded)
    |        free(r);
    |}
    |
    |/* frees the argument when its reference count reaches zero */
    |void rec_unref(struct rec *r)
    |{
    |    if (--r->refs == 0)
    |        free(r);
    |}
    |
    |/* the caller's half: a use after a guarded destroy is a defect */
    |void bad_use_after_guarded_destroy(void)
    |{
    |    struct rec *r = rec_new("session");
    |    if (r == NULL)
    |        return;
    |    rec_destroy_guarded(r);
    |    (void)r->refs;
    |}
    |
    |/* the caller's half: a fresh object after the destroy is sound */
    |void good_destroy_then_reassign(void)
    |{
    |    struct rec *r = rec_new("old");
    |    if (r == NULL)
    |        return;
    |    rec_destroy_guarded(r);
    |    r = rec_new("new");
    |    if (r == NULL)
    |        return;
    |    (void)r->refs;
    |    rec_destroy(r);
    |}
    |
    |/* ---- freep wrappers behind a guard on the pointee ---- */
    |
    |/* releases the pointee behind a NULL guard on it, and resets the slot */
    |void slot_freep_guarded(char **slot)
    |{
    |    if (*slot) {
    |        free(*slot);
    |        *slot = NULL;
    |    }
    |}
    |
    |/* releases the pointee only when another parameter says so */
    |void slot_freep_if_owned(char **slot, int owned)
    |{
    |    if (owned) {
    |        free(*slot);
    |        *slot = NULL;
    |    }
    |}
    |
    |/* releases the pointee only when it equals a sentinel value, not NULL */
    |void slot_freep_if_sentinel(char **slot, char *sentinel)
    |{
    |    if (*slot == sentinel) {
    |        free(*slot);
    |        *slot = NULL;
    |    }
    |}
    |""".stripMargin,
    "destroy_wrappers.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <sys/mman.h>
    |
    |typedef struct hdr { size_t size; } hdr_t;
    |
    |#define SHORT_PREFIX 4
    |
    |/* An allocator that hands its block out past one size header: every non-NULL
    |   return is a malloc block advanced by sizeof(hdr_t) bytes. */
    |void *my_xalloc(size_t n)
    |{
    |    hdr_t *h = (hdr_t *)malloc(sizeof(hdr_t) + n);
    |    if (h == NULL)
    |        return NULL;
    |    h->size = n;
    |    return (void *)(h + 1);
    |}
    |
    |/* The same contract released with the byte spelling: (char *)p - sizeof(hdr_t)
    |   moves back the bytes (h + 1) moved forward. */
    |void bytes_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - sizeof(hdr_t));
    |}
    |
    |/* The family's own free: the move back onto the header sits in the call. */
    |void hdr_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((hdr_t *)p - 1);
    |}
    |
    |/* A second family: the same shape advancing by a fixed count of bytes. */
    |void *wide_xalloc(size_t n)
    |{
    |    char *p = (char *)malloc(32 + n);
    |    if (p == NULL)
    |        return NULL;
    |    return p + 32;
    |}
    |
    |void wide_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - 32);
    |}
    |
    |/* A third underlying family: the block comes from mmap, not malloc. */
    |void *map_xalloc(size_t n)
    |{
    |    struct hdr *h = (struct hdr *)mmap(NULL, sizeof(struct hdr) + n,
    |                                       PROT_READ | PROT_WRITE,
    |                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    |    if (h == MAP_FAILED)
    |        return NULL;
    |    h->size = n;
    |    return h + 1;
    |}
    |
    |void map_xfree(void *p)
    |{
    |    struct hdr *h;
    |    if (p == NULL)
    |        return;
    |    h = (struct hdr *)p - 1;
    |    (void)munmap(h, h->size);
    |}
    |
    |/* Moves back by an amount no allocator here advances: a family of its own. */
    |void short_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - SHORT_PREFIX);
    |}
    |
    |/* A plain wrapper: the allocation handed out unchanged keeps its family. */
    |void *xmalloc(size_t n)
    |{
    |    return malloc(n);
    |}
    |
    |/* An advance by a variable amount concludes no family. */
    |void *var_offset_alloc(size_t n)
    |{
    |    char *p = (char *)malloc(n + 8);
    |    if (p == NULL)
    |        return NULL;
    |    return p + n;
    |}
    |
    |/* A header whose struct ends in a flexible array has no constant size. */
    |struct tail { size_t size; char data[]; };
    |void *flex_offset_alloc(size_t n)
    |{
    |    struct tail *t = (struct tail *)malloc(sizeof(struct tail) + n);
    |    if (t == NULL)
    |        return NULL;
    |    t->size = n;
    |    return t + 1;
    |}
    |
    |/* Returns advanced by two different amounts conclude no family. */
    |void *mixed_offset_alloc(size_t n)
    |{
    |    char *p = (char *)malloc(n + 16);
    |    if (p == NULL)
    |        return NULL;
    |    if (n == 0)
    |        return p + 8;
    |    return p + 16;
    |}
    |
    |/* A move back by a variable amount concludes no family. */
    |void var_xfree(void *p, size_t n)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - n);
    |}
    |
    |/* Failure handled by abort: no NULL return, so no nullable fact. */
    |void *abort_xalloc(size_t n)
    |{
    |    char *p = (char *)malloc(24 + n);
    |    if (p == NULL)
    |        abort();
    |    return p + 24;
    |}
    |
    |/* The matched pair end to end: the free's name is not the allocator's. */
    |void good_offset_pair(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    hdr_xfree(s);
    |}
    |
    |/* The same release through the byte spelling of the move back. */
    |void good_offset_pair_other_spelling(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    bytes_xfree(s);
    |}
    |
    |/* The matched pair in a loop. */
    |void good_offset_pair_loop(size_t n, unsigned long count)
    |{
    |    unsigned long i;
    |    for (i = 0; i < count; i++)
    |    {
    |        char *s = (char *)my_xalloc(n);
    |        if (s == NULL)
    |            return;
    |        memset(s, 0, n);
    |        hdr_xfree(s);
    |    }
    |}
    |
    |/* The matched pair across a goto error path. */
    |int good_offset_pair_goto(size_t n, int fail)
    |{
    |    char *a = (char *)my_xalloc(n);
    |    char *b;
    |    int rc = 0;
    |    if (a == NULL)
    |        return -1;
    |    b = (char *)my_xalloc(n);
    |    if (b == NULL)
    |    {
    |        hdr_xfree(a);
    |        return -1;
    |    }
    |    memset(a, 0, n);
    |    memset(b, 0, n);
    |    b[0] = 1;
    |    if (fail)
    |    {
    |        rc = -1;
    |        goto out;
    |    }
    |    rc = (int)a[0];
    |out:
    |    hdr_xfree(a);
    |    hdr_xfree(b);
    |    return rc;
    |}
    |
    |/* A static cache holds the block between calls: the first caller
    |   allocates through the family, later callers reuse what it keeps. */
    |char *good_offset_static_cache(size_t n)
    |{
    |    static char *kept = NULL;
    |    if (kept != NULL)
    |        return kept;
    |    kept = (char *)my_xalloc(n);
    |    if (kept == NULL)
    |        return NULL;
    |    return kept;
    |}
    |
    |/* Two families of different amounts, each released by its own free. */
    |void good_two_amounts(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    char *w;
    |    if (s == NULL)
    |        return;
    |    w = (char *)wide_xalloc(n);
    |    if (w == NULL)
    |    {
    |        hdr_xfree(s);
    |        return;
    |    }
    |    memset(s, 0, n);
    |    memset(w, 0, n);
    |    wide_xfree(w);
    |    hdr_xfree(s);
    |}
    |
    |/* The mmap-backed family released by its own free. */
    |void good_map_pair(size_t n)
    |{
    |    char *s = (char *)map_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    map_xfree(s);
    |}
    |
    |/* A plain wrapper's allocation released with free. */
    |void good_plain_pair(size_t n)
    |{
    |    char *p = (char *)xmalloc(n);
    |    if (p == NULL)
    |        return;
    |    memset(p, 0, n);
    |    free(p);
    |}
    |
    |/* A header struct with tail padding: sizeof counts the padding byte, so
    |   the struct spelling of the move back and the byte spelling must stay
    |   one amount and both pair with the allocator. */
    |typedef struct { char flag; size_t size; } padded_t;
    |void *padded_xalloc(size_t n)
    |{
    |    padded_t *h = (padded_t *)malloc(sizeof(padded_t) + n);
    |    if (h == NULL)
    |        return NULL;
    |    h->flag = 1;
    |    h->size = n;
    |    return (void *)(h + 1);
    |}
    |void padded_xfree_struct(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((padded_t *)p - 1);
    |}
    |void padded_xfree_bytes(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - sizeof(padded_t));
    |}
    |void good_padded_pair(size_t n)
    |{
    |    char *s = (char *)padded_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    padded_xfree_struct(s);
    |}
    |void good_padded_pair_bytes(size_t n)
    |{
    |    char *s = (char *)padded_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    padded_xfree_bytes(s);
    |}
    |
    |/* The statement-form pair: the allocator steps the returned pointer
    |   forward (p++) and the free steps it back (p--). Both moves normalise
    |   to the header's bytes, so they share the header-prefixed family. */
    |void *sqlite_mem_malloc(int nByte)
    |{
    |    hdr_t *p = (hdr_t *)malloc(sizeof(hdr_t) + nByte);
    |    if (p == NULL)
    |        return NULL;
    |    p->size = nByte;
    |    p++;
    |    return (void *)p;
    |}
    |void sqlite_mem_free(void *pPrior)
    |{
    |    hdr_t *p;
    |    if (pPrior == NULL)
    |        return;
    |    p = (hdr_t *)pPrior;
    |    p--;
    |    free(p);
    |}
    |void good_sqlite_mem_pair(int nByte)
    |{
    |    char *s = (char *)sqlite_mem_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    sqlite_mem_free(s);
    |}
    |
    |/* An allocator that advances a copy and returns the base: the returned
    |   identifier's own definitions decide, so it stays the plain heap. */
    |void *copy_advance_alloc(size_t n)
    |{
    |    char *base = (char *)malloc(n + 8);
    |    char *t;
    |    if (base == NULL)
    |        return NULL;
    |    t = base;
    |    t++;
    |    (void)t;
    |    return base;
    |}
    |void good_copy_base_pair(size_t n)
    |{
    |    char *b = (char *)copy_advance_alloc(n);
    |    if (b == NULL)
    |        return;
    |    memset(b, 0, n);
    |    free(b);
    |}
    |
    |/* The assignment-form pair: the allocator advances by rebinding the
    |   returned pointer (p = p + 8) and the free steps it back with a
    |   compound assign (p -= 8), both on a char pointer so the eight bytes
    |   are bytes on both sides. */
    |void *sqlite_assign_malloc(int nByte)
    |{
    |    char *p = (char *)malloc(nByte + 8);
    |    if (p == NULL)
    |        return NULL;
    |    p[0] = 0;
    |    p = p + 8;
    |    return (void *)p;
    |}
    |void sqlite_assign_free(void *pPrior)
    |{
    |    char *p;
    |    if (pPrior == NULL)
    |        return;
    |    p = (char *)pPrior;
    |    p -= 8;
    |    free(p);
    |}
    |void good_sqlite_assign_pair(int nByte)
    |{
    |    char *s = (char *)sqlite_assign_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    sqlite_assign_free(s);
    |}
    |
    |/* An allocator that advances a copy by assignment and returns the base:
    |   the returned identifier's own definitions decide, so it stays the
    |   plain heap. */
    |void *copy_assign_advance_alloc(size_t n)
    |{
    |    char *base = (char *)malloc(n + 8);
    |    char *t;
    |    if (base == NULL)
    |        return NULL;
    |    t = base + 8;
    |    (void)t;
    |    return base;
    |}
    |void good_copy_assign_base_pair(size_t n)
    |{
    |    char *b = (char *)copy_assign_advance_alloc(n);
    |    if (b == NULL)
    |        return;
    |    memset(b, 0, n);
    |    free(b);
    |}
    |
    |/* An allocator whose assignment advance steps back (in by sixteen, back
    |   by eight: the value stays inside the block): the advance refuses, the
    |   body concludes the plain heap. */
    |void *back_assign_alloc(size_t n)
    |{
    |    char *p = (char *)malloc(n + 16);
    |    if (p == NULL)
    |        return NULL;
    |    p = p + 16;
    |    p = p - 8;
    |    return (void *)p;
    |}
    |void good_back_assign_pair(size_t n)
    |{
    |    char *p = (char *)back_assign_alloc(n);
    |    if (p == NULL)
    |        return;
    |    memset(p, 0, n);
    |    free(p);
    |}
    |
    |/* Every size a caller hands these functions is a constant, which is what
    |   makes the fixtures' sizes bounded. */
    |void drive_offset_families(void)
    |{
    |    good_offset_pair(32);
    |    good_offset_pair_other_spelling(32);
    |    good_offset_pair_loop(16, 3);
    |    good_offset_pair_goto(24, 1);
    |    good_offset_pair_goto(24, 0);
    |    good_offset_static_cache(20);
    |    good_two_amounts(28);
    |    good_map_pair(36);
    |    good_plain_pair(12);
    |    good_padded_pair(40);
    |    good_padded_pair_bytes(44);
    |    good_sqlite_mem_pair(48);
    |    good_copy_base_pair(52);
    |    good_sqlite_assign_pair(56);
    |    good_copy_assign_base_pair(60);
    |    good_back_assign_pair(64);
    |}
    |""".stripMargin,
    "offsetfamilies.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |
    |/* ---- the region allocator shapes ---- */
    |
    |typedef struct pool { char *base; size_t used; size_t cap; } pool_t;
    |
    |/* The bump allocator: every non-NULL return is pointer arithmetic over a
    |   field of the parameter, and no allocation runs on the path to it. */
    |void *pool_alloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return NULL;
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |
    |/* The same arm, plus a malloc arm for the region-full case: both
    |   summaries. */
    |void *pool_alloc_or_malloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return malloc(n);
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |
    |/* A field handed back unchanged allocates nothing of its own. */
    |void *pool_base(pool_t *p)
    |{
    |    return p->base;
    |}
    |
    |/* Two regions in one body: neither is the one a summary could name. */
    |void *pool_alloc_ambiguous(pool_t *p, pool_t *q)
    |{
    |    if (p->used > q->used)
    |        return p->base + p->used;
    |    return q->base + q->used;
    |}
    |""".stripMargin,
    "regions.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |
    |/* ---- the reference-release shapes ---- */
    |
    |typedef struct refobj { int refs; char *name; } refobj_t;
    |refobj_t *refobj_new(void)
    |{
    |    refobj_t *o = (refobj_t *)calloc(1, sizeof(*o));
    |    if (o)
    |        o->refs = 1;
    |    return o;
    |}
    |void refobj_ref(refobj_t *o) { o->refs++; }
    |
    |/* the decrement sits in the condition that frees the parameter itself */
    |void obj_unref(refobj_t *o)
    |{
    |    if (--o->refs == 0) {
    |        free(o->name);
    |        free(o);
    |    }
    |}
    |
    |/* the count's last unit spent on the other arm of the same comparison */
    |void obj_drop_last(refobj_t *o)
    |{
    |    if (o->refs == 1) {
    |        free(o->name);
    |        free(o);
    |    } else {
    |        o->refs--;
    |    }
    |}
    |
    |/* the zero arm hands the parameter to the release callback argument */
    |int obj_put(refobj_t *o, void (*release)(refobj_t *o))
    |{
    |    if (--o->refs == 0) {
    |        release(o);
    |        return 1;
    |    }
    |    return 0;
    |}
    |
    |/* the acquire: the increment of a parameter's field */
    |void obj_ref_keep(refobj_t *o) { o->refs++; }
    |
    |/* a release a flag gates is no release summary at all */
    |void obj_unref_if_owned(refobj_t *o, int owned)
    |{
    |    if (owned) {
    |        --o->refs;
    |        free(o);
    |    }
    |}
    |
    |/* an uncontrolled free is the plain destroy, never a release */
    |void obj_unref_plain(refobj_t *o)
    |{
    |    o->refs--;
    |    free(o);
    |}
    |
    |/* the zero arm frees only a member: the struct itself survives */
    |void obj_name_drop(refobj_t *o)
    |{
    |    if (--o->refs == 0) {
    |        free(o->name);
    |        o->refs = 0;
    |    }
    |}
    |
    |/* the free sits under a comparison of another variable */
    |void obj_unref_wrong_gate(refobj_t *o, int depth)
    |{
    |    --o->refs;
    |    if (depth == 0)
    |        free(o);
    |}
    |""".stripMargin,
    "refcount_semantics.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def semanticsOf(name: String): Set[String] =
      cpg.method.nameExact(name).tag.nameExact(MemorySemanticsPass.TagSemantic).value.l.toSet

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  private def localTags(method: String, local: String, tag: String): Set[String] =
      cpg.method.nameExact(method).local.nameExact(local).tag.nameExact(tag).value.l.toSet

  "declared attributes" should:
    "make a header-only allocator an allocator with its size roles" in {
        semanticsOf("lib_malloc") shouldBe Set("alloc:heap", "len:1", "nullable-return")
        semanticsOf("lib_calloc") shouldBe Set("alloc:heap", "count:1", "len:2", "nullable-return")
    }
    "make alloc_size without malloc on a pointer-taking function a reallocator" in {
        semanticsOf("lib_realloc_array") shouldBe
            Set("realloc:heap", "count:2", "len:3", "nullable-return")
    }
    "carry nonnull parameters and a non-null return" in {
        semanticsOf("lib_len") shouldBe Set("nonnull-param:1")
        semanticsOf("lib_name") shouldBe Set("nonnull-return")
    }

  "bodies" should:
    "conclude free and freep wrappers" in {
        semanticsOf("my_free") shouldBe Set("free:heap")
        semanticsOf("my_freep") shouldBe Set("free:heap")
    }
    "conclude a nullable return from `return NULL`" in {
        cpg.method.nameExact("my_find").methodReturn.typeFullName.l shouldBe List("entry*")
        semanticsOf("my_find") should contain("nullable-return")
    }
    "inherit a callee's roles through unchanged parameters" in {
        semanticsOf("my_copy") shouldBe Set("dst:1", "src:2", "len:3")
    }

  "storage facts" should:
    "classify where each variable lives" in {
        localTags("storage_shapes", "sbuf", MemorySemanticsPass.TagStorage) shouldBe Set("static")
        localTags("storage_shapes", "abuf", MemorySemanticsPass.TagStorage) shouldBe Set("stack")
        cpg.method.nameExact("storage_shapes").parameter.nameExact("n")
            .tag.nameExact(MemorySemanticsPass.TagStorage).value.l shouldBe List("param")
    }
    "classify what each pointer points at" in {
        localTags("storage_shapes", "h", MemorySemanticsPass.TagPointsTo) shouldBe Set("heap")
        localTags("storage_shapes", "s", MemorySemanticsPass.TagPointsTo) shouldBe Set("stack")
        localTags("storage_shapes", "t", MemorySemanticsPass.TagPointsTo) shouldBe Set("static")
        localTags("storage_shapes", "a", MemorySemanticsPass.TagPointsTo) shouldBe Set("stack")
        localTags("storage_shapes", "lit", MemorySemanticsPass.TagPointsTo) shouldBe Set("static")
    }

  "the findings, with no project inventory" should:
    "report a leak of an attribute-declared allocation" in {
        findingsIn("leak_attr_alloc") should contain("MS-ALLOC-003")
    }
    "report a nullable pointer handed to a declared-nonnull parameter" in {
        findingsIn("null_through_nonnull") should contain("MS-NULL-001")
    }
    "report a dereference of a body-concluded nullable return" in {
        findingsIn("deref_nullable_getter") should contain("MS-NULL-001")
    }
    "not report a free after a freep wrapper nulled the pointer" in {
        findingsIn("freep_then_free") should not contain "MS-ALLOC-001"
        findingsIn("freep_then_free") should not contain "MS-ALLOC-003"
    }
    "not report the free of a realloc input on the failed-realloc path, nor its move as a leak" in {
        findingsIn("realloc_into_tmp") should not contain "MS-ALLOC-001"
        findingsIn("realloc_into_tmp") should not contain "MS-ALLOC-003"
    }

  "destroy functions" should:
    "not conclude a destroy from a flag-gated release" in {
        semanticsOf("rec_release_if_owned") shouldBe empty
    }
    "not conclude a destroy that never frees its argument" in {
        semanticsOf("rec_release_name") shouldBe empty
    }
    "not conclude a destroy that frees its argument on some paths only" in {
        semanticsOf("rec_destroy_if_loaded") shouldBe empty
    }
    "not conclude a destroy behind a reference count" in {
        // the zero-gated free is the reference release's own conclusion now: the destroy
        // summary still refuses, since the free runs only when the count reaches zero
        semanticsOf("rec_unref") should contain("release:1")
        semanticsOf("rec_unref") should not contain "free:heap"
    }
    "stay silent when a guarded destroy hands the slot to a fresh object" in {
        findingsIn("good_destroy_then_reassign") shouldBe empty
    }
    "conclude a destroy that does member work before its argument" in {
        semanticsOf("rec_destroy") shouldBe Set("free:heap")
    }
    "conclude the same destroy behind a NULL guard on the argument" in {
        semanticsOf("rec_destroy_guarded") shouldBe Set("free:heap")
    }
    "conclude a destroy that frees members in a loop" in {
        semanticsOf("word_set_destroy") shouldBe Set("free:heap")
    }
    "conclude a destroy that releases members through other destroy functions" in {
        semanticsOf("folder_destroy") shouldBe Set("free:heap")
    }
    "report a use after a NULL-guarded destroy" in {
        findingsIn("bad_use_after_guarded_destroy") should contain("MS-ALLOC-002")
    }

  "guarded freep wrappers" should:
    "not conclude a freep gated by another parameter" in {
        semanticsOf("slot_freep_if_owned") shouldBe empty
    }
    "not conclude a freep gated by a comparison with a sentinel" in {
        semanticsOf("slot_freep_if_sentinel") shouldBe empty
    }
    "conclude a guarded freep that resets the slot" in {
        semanticsOf("slot_freep_guarded") shouldBe Set("free:heap")
    }

  "offset allocator families" should:
    "summarise an allocator that hands its block out past a header" in {
        semanticsOf("my_xalloc") shouldBe Set("alloc:offset:my_xalloc", "len:1", "nullable-return")
    }
    "pair the family's free by amount and underlying family, not by name" in {
        semanticsOf("hdr_xfree") shouldBe Set("free:offset:my_xalloc")
        semanticsOf("bytes_xfree") shouldBe Set("free:offset:my_xalloc")
    }
    "keep two families of different amounts apart" in {
        semanticsOf("wide_xalloc") shouldBe Set(
          "alloc:offset:wide_xalloc",
          "len:1",
          "nullable-return"
        )
        semanticsOf("wide_xfree") shouldBe Set("free:offset:wide_xalloc")
    }
    "keep a different underlying family apart" in {
        semanticsOf("map_xalloc") shouldBe Set(
          "alloc:offset:map_xalloc",
          "len:1",
          "nullable-return"
        )
        semanticsOf("map_xfree") shouldBe Set("free:offset:map_xalloc")
    }
    "name an unpaired free's family after itself" in {
        semanticsOf("short_xfree") shouldBe Set("free:offset:short_xfree")
    }
    "keep a plain wrapper in its underlying family" in {
        semanticsOf("xmalloc") shouldBe Set("alloc:heap", "len:1", "nullable-return")
    }
    "conclude no family for a variable amount" in {
        semanticsOf("var_offset_alloc") shouldBe Set("nullable-return")
        semanticsOf("var_xfree") shouldBe empty
    }
    "conclude no family for a pointee of no constant size" in {
        semanticsOf("flex_offset_alloc") shouldBe Set("nullable-return")
    }
    "conclude no family for returns advanced by two different amounts" in {
        semanticsOf("mixed_offset_alloc") shouldBe Set("nullable-return")
    }
    "carry no nullable fact when failure aborts instead of returning NULL" in {
        semanticsOf("abort_xalloc") shouldBe Set("alloc:offset:abort_xalloc", "len:1")
    }
    "normalise a padded header through the front ends' sizeof, both spellings one pair" in {
        semanticsOf("padded_xalloc") shouldBe Set(
          "alloc:offset:padded_xalloc",
          "len:1",
          "nullable-return"
        )
        semanticsOf("padded_xfree_struct") shouldBe Set("free:offset:padded_xalloc")
        semanticsOf("padded_xfree_bytes") shouldBe Set("free:offset:padded_xalloc")
    }
    "pair statement-form moves on both sides into the shared key" in {
        // the statement-form pair normalises to the same bytes as the
        // header-prefixed family, so the allocators and frees of both spell
        // one family string, named after the family's first method
        semanticsOf("sqlite_mem_malloc") shouldBe
            Set("alloc:offset:my_xalloc", "len:1", "nullable-return")
        semanticsOf("sqlite_mem_free") shouldBe Set("free:offset:my_xalloc")
    }
    "keep an allocator that advances a copy and returns the base plain" in {
        semanticsOf("copy_advance_alloc") shouldBe Set("alloc:heap", "len:1", "nullable-return")
    }
    "pair assignment-form moves on both sides into the shared key" in {
        semanticsOf("sqlite_assign_malloc") shouldBe
            Set("alloc:offset:my_xalloc", "len:1", "nullable-return")
        semanticsOf("sqlite_assign_free") shouldBe Set("free:offset:my_xalloc")
    }
    "keep an allocator that advances a copy by assignment and returns the base plain" in {
        semanticsOf("copy_assign_advance_alloc") shouldBe
            Set("alloc:heap", "len:1", "nullable-return")
    }
    "keep an allocator whose assignment advance steps back plain" in {
        semanticsOf("back_assign_alloc") shouldBe Set("alloc:heap", "len:1", "nullable-return")
    }
    "stay silent on the matched pairs at every level" in {
        findingsIn("good_offset_pair") shouldBe empty
        findingsIn("good_offset_pair_other_spelling") shouldBe empty
        findingsIn("good_offset_pair_loop") shouldBe empty
        findingsIn("good_offset_pair_goto") shouldBe empty
        findingsIn("good_offset_static_cache") shouldBe empty
        findingsIn("good_two_amounts") shouldBe empty
        findingsIn("good_map_pair") shouldBe empty
        findingsIn("good_plain_pair") shouldBe empty
        findingsIn("good_padded_pair") shouldBe empty
        findingsIn("good_padded_pair_bytes") shouldBe empty
        findingsIn("good_sqlite_mem_pair") shouldBe empty
        findingsIn("good_copy_base_pair") shouldBe empty
        findingsIn("good_sqlite_assign_pair") shouldBe empty
        findingsIn("good_copy_assign_base_pair") shouldBe empty
    }
    "keep the back-stepping assignment advance out of the family at the callers" in {
        findingsIn("good_back_assign_pair") should not contain "MS-ALLOC-007"
        findingsIn("good_back_assign_pair") should not contain "MS-ALLOC-003"
    }

  "region allocators" should:
    "conclude the region allocator from arithmetic over a parameter's field" in {
        semanticsOf("pool_alloc") should contain("region-alloc:1")
        semanticsOf("pool_alloc") should contain("nullable-return")
        // the region summary is the whole story: no allocation family beside it
        semanticsOf("pool_alloc").forall(v => !v.startsWith("alloc:")) shouldBe true
    }
    "record both summaries when the region-full case falls back to malloc" in {
        semanticsOf("pool_alloc_or_malloc") should contain("region-alloc:1")
        semanticsOf("pool_alloc_or_malloc") should contain("alloc:heap")
    }
    "conclude nothing for a field handed back unchanged" in {
        semanticsOf("pool_base") should not contain "region-alloc:1"
    }
    "conclude nothing when two parameters could own the region" in {
        semanticsOf("pool_alloc_ambiguous") should not contain "region-alloc:1"
        semanticsOf("pool_alloc_ambiguous") should not contain "region-alloc:2"
    }

  "reference releases" should:
    "conclude the release of the parameter whose count field the zero condition frees" in {
        // `if (--o->refs == 0) { free(o->name); free(o); }`: the decrement sits in the
        // condition that frees the parameter itself
        semanticsOf("obj_unref") should contain("release:1")
        semanticsOf("obj_unref") should not contain "free:heap"
        // the decrement of the count is not a grow: the release carries no acquire
        semanticsOf("obj_unref") should not contain "grow:1:refs"
    }
    "conclude the release when the count's last unit is spent on the other arm" in {
        // the count-is-one spelling: `if (o->refs == 1) { free(o); } else { o->refs--; }`,
        // the decrement on the survive arm of the same comparison
        semanticsOf("obj_drop_last") should contain("release:1")
        semanticsOf("obj_drop_last") should not contain "free:heap"
    }
    "conclude the release whose zero arm calls the function-pointer argument" in {
        semanticsOf("obj_put") should contain("release:1")
        semanticsOf("obj_put") should not contain "free:heap"
    }
    "keep the acquire on the increment of a parameter's field" in {
        semanticsOf("obj_ref_keep") shouldBe Set("grow:1:refs")
    }
    "conclude nothing for a release a flag gates" in {
        semanticsOf("obj_unref_if_owned") shouldBe empty
    }
    "conclude no release for a free no condition controls" in {
        // the plain destroy: the free is uncontrolled, so no zero condition ever gated it
        semanticsOf("obj_unref_plain") shouldBe Set("free:heap")
        semanticsOf("obj_unref_plain") should not contain "release:1"
    }
    "conclude no release when the zero arm frees only a member" in {
        // the struct survives the zero arm: only its string is released
        semanticsOf("obj_name_drop") should not contain "release:1"
    }
    "conclude no release when the free sits under another variable's comparison" in {
        semanticsOf("obj_unref_wrong_gate") shouldBe empty
    }
end MemorySemanticsPassTests

/** A `libavformat/`-scoped run: the allocator layer's header (`libavutil/mem.h`) is reached through
  * the include path only, so its declarations become no METHOD and its attributes arrive on the
  * CALLs. None of these names is in any inventory.
  */
class ScopedHeaderMemorySemanticsTests extends AnyWordSpec with Matchers:

  private val header =
      """#include <stddef.h>
        |#define AV_GCC_VERSION_AT_LEAST(x,y) (__GNUC__ > (x) || __GNUC__ == (x) && __GNUC_MINOR__ >= (y))
        |#if AV_GCC_VERSION_AT_LEAST(3,1)
        |    #define av_malloc_attrib __attribute__((__malloc__))
        |#else
        |    #define av_malloc_attrib
        |#endif
        |#if AV_GCC_VERSION_AT_LEAST(4,3)
        |    #define av_alloc_size(...) __attribute__((alloc_size(__VA_ARGS__)))
        |#else
        |    #define av_alloc_size(...)
        |#endif
        |void *av_malloc(size_t size) av_malloc_attrib av_alloc_size(1);
        |void *av_mallocz(size_t size) av_malloc_attrib av_alloc_size(1);
        |void *av_calloc(size_t nmemb, size_t size) av_malloc_attrib av_alloc_size(1, 2);
        |av_alloc_size(1, 2) void *av_malloc_array(size_t nmemb, size_t size);
        |av_alloc_size(2, 3) void *av_realloc_array(void *ptr, size_t nmemb, size_t size);
        |char *av_strndup(const char *s, size_t len) av_malloc_attrib;
        |void av_free(void *ptr);
        |void av_freep(void *ptr);
        |void av_freep2(void **ptr);
        |int av_reallocp(void *ptr, size_t size);
        |int av_reallocp_array(void *ptr, size_t nmemb, size_t size);
        |int av_realloc_named(struct node *n, size_t size);
        |struct node { struct node *next; };
        |void free_nodes(struct node *n);
        |void av_free_with_log(void *ptr, int level);
        |void av_opt_free(void *obj);
        |void free(void *ptr);
        |""".stripMargin

  private val source =
      """#include "libavutil/mem.h"
        |void log_it(void *p);
        |/* a body in scope: the heuristic must not override what the body says */
        |void my_freebuf(void *p) { log_it(p); }
        |int my_realloc_buf(void *p, size_t n) { log_it(p); return (int)n; }
        |void uses(int n, void *q, char *s)
        |{
        |    void *a = av_mallocz(n);
        |    void *b = av_calloc(n, 4);
        |    void *c = av_malloc_array(n, 4);
        |    q = av_realloc_array(q, n, 4);
        |    char *d = av_strndup(s, n);
        |    av_free(a); av_freep(&b); av_freep2(&c); av_free(d);
        |    av_reallocp(&q, 8); av_reallocp_array(&q, n + 1, 4); av_realloc_named(0, 4);
        |    my_realloc_buf(q, 4);
        |    free_nodes(0); av_free_with_log(q, 1); my_freebuf(q); av_opt_free(q);
        |}
        |void uaf_through_guessed_free(int n)
        |{
        |    char *p = av_malloc(n);
        |    if (!p)
        |        return;
        |    av_free(p);
        |    p[0] = 1;
        |}
        |void real_double_free(int n)
        |{
        |    char *p = av_malloc(n);
        |    if (!p)
        |        return;
        |    free(p);
        |    free(p);
        |    av_free(p);
        |}
        |""".stripMargin

  private lazy val cpg: Cpg =
    val root = File.newTemporaryDirectory("scopedsem")
    (root / "libavutil").createDirectories()
    (root / "libavformat").createDirectories()
    (root / "libavutil" / "mem.h").write(header)
    (root / "libavformat" / "a.c").write(source)
    val out = File.newTemporaryFile("scopedsem", ".atom")
    out.deleteOnExit()
    val cpg = new C2Cpg().createCpg(
      Config()
          .withInputPath((root / "libavformat").pathAsString)
          .withOutputPath(out.pathAsString)
          .withIncludePaths(Set(root.pathAsString))
          .withAstCache(false)
          .withFunctionBodies(true)
    ).get
    X2Cpg.applyDefaultOverlays(cpg)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(cpg))
    new MemorySemanticsPass(cpg).createAndApply()
    new MemoryApiPass(cpg).createAndApply()
    new ExtentPass(cpg).createAndApply()
    new GuardPass(cpg).createAndApply()
    new ValueOriginPass(cpg).createAndApply()
    new AllocationStatePass(cpg).createAndApply()
    new MemorySafetyFindingPass(cpg).createAndApply()
    root.delete(swallowIOExceptions = true)
    cpg
  end cpg

  private def semanticsOf(name: String): Set[String] =
      cpg.method.nameExact(name).tag.nameExact(MemorySemanticsPass.TagSemantic).value.l.toSet

  private def evidenceOf(name: String): Set[String] =
      cpg.method.nameExact(name).tag.nameExact(MemorySemanticsPass.TagEvidence).value.l.toSet

  "attributes of a header outside the analysed input" should:
    "make the malloc-attributed allocators allocators" in {
        semanticsOf("av_mallocz") shouldBe Set("alloc:heap", "len:1", "nullable-return")
        semanticsOf("av_calloc") shouldBe Set("alloc:heap", "count:1", "len:2", "nullable-return")
        semanticsOf("av_strndup") shouldBe Set("alloc:heap", "nullable-return")
        evidenceOf("av_mallocz") shouldBe Set(MemorySemanticsPass.EvidenceAttribute)
    }
    "make alloc_size without malloc an allocator or a reallocator by the call's signature" in {
        // no parameter is a pointer: a fresh allocation
        semanticsOf("av_malloc_array") shouldBe
            Set("alloc:heap", "count:1", "len:2", "nullable-return")
        // the first parameter is a pointer: it may hand back its input
        semanticsOf("av_realloc_array") shouldBe
            Set("realloc:heap", "count:2", "len:3", "nullable-return")
    }

  "the deallocator heuristic" should:
    "make a void function of one void* or void** named free a heuristic free" in {
        Seq("av_free", "av_freep", "av_freep2").foreach { n =>
          semanticsOf(n) shouldBe Set("free:heap")
          evidenceOf(n) shouldBe Set(MemorySemanticsPass.EvidenceHeuristic)
        }
    }
    "leave other shapes alone" in {
        semanticsOf("free_nodes") shouldBe empty       // a typed pointer, not void*
        semanticsOf("av_free_with_log") shouldBe empty // two parameters
        semanticsOf("av_realloc_named") shouldBe empty // a typed pointer, not void*
        semanticsOf("av_opt_free") shouldBe empty      // frees what the object holds
    }
    "make an untyped-pointer-and-sizes function named realloc a heuristic reallocator" in {
        semanticsOf("av_reallocp") shouldBe Set("realloc:heap", "len:2")
        semanticsOf("av_reallocp_array") shouldBe Set("realloc:heap", "count:2", "len:3")
        evidenceOf("av_reallocp_array") shouldBe Set(MemorySemanticsPass.EvidenceHeuristic)
    }
    "be ignored when a body is in scope" in {
        semanticsOf("my_freebuf") should not contain "free:heap"
        semanticsOf("my_realloc_buf") should not contain "realloc:heap"
    }
    "report what a guessed free triggers at low" in {
        val uses = cpg.method.nameExact("uaf_through_guessed_free").ast.collectAll[StoredNode].l
        uses.flatMap(_.tag.nameExact("ms-finding").value.l) should contain("MS-ALLOC-002")
        uses.flatMap(_.tag.nameExact(MemorySafetyFindingPass.TagConfidence).value.l) should
            contain("MS-ALLOC-002=low")
    }
    "keep a real double free at its confidence though a guessed free follows" in {
        // the second free(p): the av_free(p) after it is itself a double free, rightly at low
        val secondFree = cpg.method.nameExact("real_double_free").call.nameExact("free").l
            .maxBy(_.lineNumber.map(_.toInt).getOrElse(0))
        val nodes = secondFree.ast.collectAll[StoredNode].l
        nodes.flatMap(_.tag.nameExact("ms-finding").value.l) should contain("MS-ALLOC-001")
        nodes.flatMap(_.tag.nameExact(MemorySafetyFindingPass.TagConfidence).value.l) should
            not contain "MS-ALLOC-001=low"
    }
end ScopedHeaderMemorySemanticsTests
