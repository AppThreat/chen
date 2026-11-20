package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.MemoryApiPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The wrapper inference: allocator and free-wrapper roles concluded from what method bodies do.
  * Every positive has its negative beside it - the shapes the inference must NOT conclude.
  */
class MemoryApiInferenceTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |void *my_alloc(int n) {
    |    void *p = malloc(n);
    |    if (!p) return NULL;
    |    return p;
    |}
    |
    |void *wrap_direct(size_t n) {
    |    return malloc(n);
    |}
    |
    |void *wrap_cast(size_t n) {
    |    return (char *)malloc(n * 4);
    |}
    |
    |void *wrap_of_wrap(int n) {
    |    return my_alloc(n);
    |}
    |
    |void my_free(void *p) {
    |    free(p);
    |}
    |
    |void *my_resize(void *p, size_t n) {
    |    return realloc(p, n);
    |}
    |
    |void *returns_param(void *p) {
    |    return p;
    |}
    |
    |void *alloc_then_free(int n) {
    |    void *p = malloc(n);
    |    free(p);
    |    return p;
    |}
    |
    |void *alloc_and_log(int n) {
    |    void *p = malloc(n);
    |    log_ptr(p);
    |    return p;
    |}
    |
    |void *only_literal_return(int n) {
    |    malloc(n);
    |    return 0;
    |}
    |
    |void use_wrappers(void) {
    |    char *a = my_alloc(64);
    |    char *b = wrap_direct(8);
    |    char *c = wrap_cast(8);
    |    char *d = wrap_of_wrap(16);
    |    char *e = returns_param(a);
    |    char *f = alloc_then_free(8);
    |    char *g = alloc_and_log(8);
    |    char *h = only_literal_return(2);
    |    char *r = my_resize(b, 32);
    |    memcpy(a, b, 4);
    |    memcpy(h, g, 4);
    |    memcpy(c, d, 4);
    |    memcpy(e, f, 4);
    |    memcpy(g, a, 4);
    |    my_free(a);
    |    my_free(b);
    |}
    |""".stripMargin,
    "wrappers.c"
  ).moreCode(
    """
    |#include <stdlib.h>
    |
    |/* The pool allocator shapes, seen from their call sites. */
    |typedef struct pool { char *base; size_t used; size_t cap; } pool_t;
    |
    |void *pool_alloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return NULL;
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |
    |void *pool_alloc_or_malloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return malloc(n);
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |
    |void *pool_base(pool_t *p)
    |{
    |    return p->base;
    |}
    |
    |void use_regions(pool_t *p, size_t n)
    |{
    |    char *a = (char *)pool_alloc(p, n);
    |    char *b = (char *)pool_alloc_or_malloc(p, n);
    |    char *c = pool_base(p);
    |    (void)a;
    |    (void)b;
    |    (void)c;
    |}
    |""".stripMargin,
    "region_calls.c"
  )

  new MemoryApiPass(cpg).createAndApply()

  "MemoryApiPass wrapper inference" should:

    "conclude an allocator from a NULL-guarded allocation flow" in {
        cpg.call.name("my_alloc").l should not be empty
        cpg.call.name("my_alloc").l.foreach { site =>
          site.tag.name("mem-alloc").value.l shouldBe List("heap")
          // the size role travels: the parameter feeding malloc's size argument
          site.argument(1).tag.name("mem-len").value.l shouldBe List("my_alloc")
        }
    }

    "conclude an allocator from a direct and a cast-wrapped return" in {
        cpg.call.name("wrap_direct").tag.name("mem-alloc").value.l shouldBe List("heap")
        cpg.call.name("wrap_cast").tag.name("mem-alloc").value.l shouldBe List("heap")
        // the size is `n * 4`, not the parameter alone; one parameter still feeds it
        cpg.call.name("wrap_cast").argument(1).tag.name("mem-len").value.l shouldBe List(
          "wrap_cast"
        )
    }

    "chain a wrapper of an inferred wrapper within the round bound" in {
        cpg.call.name("wrap_of_wrap").tag.name("mem-alloc").value.l shouldBe List("heap")
    }

    "conclude a free wrapper" in {
        cpg.call.name("my_free").l should not be empty
        cpg.call.name("my_free").l.foreach { site =>
            site.tag.name("mem-free").value.l shouldBe List("heap")
        }
    }

    "conclude a realloc wrapper as the third family, not alloc-and-free" in {
        cpg.call.name("my_resize").l should not be empty
        cpg.call.name("my_resize").l.foreach { site =>
          site.tag.name("mem-realloc").value.l shouldBe List("heap")
          site.tag.name("mem-alloc").l shouldBe Nil
          site.tag.name("mem-free").l shouldBe Nil
          // the byte size travels: the parameter feeding realloc's size argument
          site.argument(2).tag.name("mem-len").value.l shouldBe List("my_resize")
        }
    }

    "not conclude an allocator that returns its parameter" in {
        cpg.call.name("returns_param").l.foreach { site =>
            site.tag.name("mem-alloc").l shouldBe Nil
        }
    }

    "not conclude a wrapper whose body frees what it allocates" in {
        cpg.call.name("alloc_then_free").l.foreach { site =>
          site.tag.name("mem-alloc").l shouldBe Nil
          site.tag.name("mem-free").l shouldBe Nil
        }
    }

    "not conclude a wrapper with behaviour beyond the allocation" in {
        cpg.call.name("alloc_and_log").l.foreach { site =>
            site.tag.name("mem-alloc").l shouldBe Nil
        }
    }

    "emit inferred roles as ordinary tags at the call sites, umbrella included" in {
        val site = cpg.call.name("my_alloc").head
        site.tag.name.l should contain("memory-safety")
        // and the mem-len argument node carries it too, exactly like inventory roles
        site.argument(1).tag.name.l should contain("memory-safety")
    }

  "the region allocator inference at the call sites" should:

    "tag a region allocation's calls with the region argument and no family" in {
        cpg.call.name("pool_alloc").l should not be empty
        cpg.call.name("pool_alloc").l.foreach { site =>
          site.tag.name("mem-region").value.l shouldBe List("alloc:1")
          site.tag.name("mem-alloc").l shouldBe Nil
          site.tag.name.l should contain("memory-safety")
        }
    }

    "tag the fallback allocator's calls with both the region and the family" in {
        cpg.call.name("pool_alloc_or_malloc").l.foreach { site =>
          site.tag.name("mem-region").value.l shouldBe List("alloc:1")
          site.tag.name("mem-alloc").value.l shouldBe List("heap")
        }
    }

    "tag no region on a call whose body hands back a field unchanged" in {
        cpg.call.name("pool_base").l.foreach { site =>
            site.tag.name("mem-region").l shouldBe Nil
        }
    }
end MemoryApiInferenceTests

/** Inference against a declared inventory: an agreement changes nothing, and a disagreement is
  * reported with the declaration winning.
  */
class MemoryApiInferenceDisagreementTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <stdlib.h>
    |
    |void *declared_alloc(size_t n) {
    |    return malloc(n);
    |}
    |
    |void *name_says_free(size_t n) {
    |    return malloc(n);
    |}
    |
    |void use_both(void) {
    |    void *a = declared_alloc(4);
    |    void *b = name_says_free(4);
    |    free(a);
    |}
    |""".stripMargin,
    "declared.c"
  )

  new MemoryApiPass(
    cpg,
    Some(
      """{"version": 1, "apis": [
        |  {"name": "declared_alloc", "alloc": "heap"},
        |  {"name": "name_says_free", "free": "heap"}
        |]}""".stripMargin
    )
  ).createAndApply()

  "MemoryApiPass inference vs a declared inventory" should:

    "leave an agreed function tagged exactly once, by the declaration" in {
        val sites = cpg.call.name("declared_alloc").l
        sites should not be empty
        sites.foreach { site =>
            site.tag.name("mem-alloc").value.l shouldBe List("heap")
        }
    }

    "keep the declaration when inference concludes the opposite" in {
        val sites = cpg.call.name("name_says_free").l
        sites should not be empty
        // the body is a clean allocation flow, so inference concludes allocator; the declared
        // free role wins and no allocator tag may appear beside it
        sites.foreach { site =>
          site.tag.name("mem-free").value.l shouldBe List("heap")
          site.tag.name("mem-alloc").l shouldBe Nil
        }
    }
end MemoryApiInferenceDisagreementTests

/** The offset families: an allocator whose every non-NULL return hands out a known allocation
  * advanced by one constant amount is a family of its own, and the free that moves its parameter
  * back by the same normalised amount joins it. The pairing is by amount and underlying family: the
  * allocator and the free here carry different names, two families of different amounts stay apart,
  * and a free under a different underlying family pairs with its own allocator only.
  */
class OffsetFamilyInferenceTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
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
    |/* A move back by a variable amount concludes no family. */
    |void var_xfree(void *p, size_t n)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - n);
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
    |/* Two families of different amounts, each released by its own free. */
    |void good_two_amounts(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    char *w = (char *)wide_xalloc(n);
    |    if (s == NULL || w == NULL)
    |        return;
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
    |/* The offset free moved back by a different amount than the allocator
    |   advanced: no pairing, the family is the free's own. */
    |void bad_offset_wrong_amount(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    short_xfree(s);
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
    |
    |/* An allocator whose assignment advance steps back: the advance refuses,
    |   the body concludes the plain heap. */
    |void *back_assign_alloc(size_t n)
    |{
    |    char *p = (char *)malloc(n + 16);
    |    if (p == NULL)
    |        return NULL;
    |    p = p + 16;
    |    p = p - 8;
    |    return (void *)p;
    |}
    |
    |/* A wrapper returning the offset allocator's result unchanged keeps the
    |   offset family. */
    |void *wrap_xalloc(size_t n)
    |{
    |    return my_xalloc(n);
    |}
    |
    |/* A wrapper around mmap keeps the mmap family. */
    |void *wrap_map_alloc(size_t n)
    |{
    |    return mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    |}
    |void wrap_map_free(void *p, size_t n)
    |{
    |    if (p == NULL)
    |        return;
    |    munmap(p, n);
    |}
    |
    |/* The statement-form pair end to end. */
    |void good_sqlite_mem_pair(int nByte)
    |{
    |    char *s = (char *)sqlite_mem_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    sqlite_mem_free(s);
    |}
    |
    |/* The assignment-form pair end to end. */
    |void good_sqlite_assign_pair(int nByte)
    |{
    |    char *s = (char *)sqlite_assign_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    sqlite_assign_free(s);
    |}
    |
    |/* An allocator that advances a copy by assignment and returns the base,
    |   released with free: the plain pair. */
    |void good_copy_assign_base_pair(size_t n)
    |{
    |    char *b = (char *)copy_assign_advance_alloc(n);
    |    if (b == NULL)
    |        return;
    |    memset(b, 0, n);
    |    free(b);
    |}
    |
    |/* An allocator whose assignment advance steps back, released with free. */
    |void good_back_assign_pair(size_t n)
    |{
    |    char *p = (char *)back_assign_alloc(n);
    |    if (p == NULL)
    |        return;
    |    memset(p, 0, n);
    |    free(p);
    |}
    |
    |/* An allocator that advances a copy and returns the base, released with
    |   free: the plain pair. */
    |void good_copy_base_pair(size_t n)
    |{
    |    char *b = (char *)copy_advance_alloc(n);
    |    if (b == NULL)
    |        return;
    |    memset(b, 0, n);
    |    free(b);
    |}
    |
    |/* Call sites for the shapes that conclude nothing. */
    |void uses_unconcluded(void)
    |{
    |    (void)var_offset_alloc(8);
    |    var_xfree(NULL, 4);
    |    (void)wrap_xalloc(8);
    |    (void)wrap_map_alloc(16);
    |    wrap_map_free(NULL, 8);
    |}
    |""".stripMargin,
    "offsetfamilies.c"
  )

  new MemoryApiPass(cpg).createAndApply()

  private def allocFamilies(name: String): List[String] =
      cpg.call.name(name).l.flatMap(_.tag.name("mem-alloc").value.l).distinct.sorted

  private def freeFamilies(name: String): List[String] =
      cpg.call.name(name).l.flatMap(_.tag.name("mem-free").value.l).distinct.sorted

  "the offset family inference at the call sites" should:

    "tag an offset allocator's calls with its family and carry the size role" in {
        allocFamilies("my_xalloc") shouldBe List("offset:my_xalloc")
        cpg.call.name("my_xalloc").l.foreach { site =>
          site.argument(1).tag.name("mem-len").value.l shouldBe List("my_xalloc")
          site.tag.name.l should contain("memory-safety")
        }
    }

    "tag the paired frees with the allocator's family, across different names" in {
        freeFamilies("hdr_xfree") shouldBe List("offset:my_xalloc")
        freeFamilies("bytes_xfree") shouldBe List("offset:my_xalloc")
    }

    "keep the two amounts' families apart" in {
        allocFamilies("wide_xalloc") shouldBe List("offset:wide_xalloc")
        freeFamilies("wide_xfree") shouldBe List("offset:wide_xalloc")
    }

    "keep a different underlying family apart" in {
        allocFamilies("map_xalloc") shouldBe List("offset:map_xalloc")
        freeFamilies("map_xfree") shouldBe List("offset:map_xalloc")
    }

    "name an unpaired free's family after itself" in {
        freeFamilies("short_xfree") shouldBe List("offset:short_xfree")
    }

    "keep a plain wrapper in the underlying family" in {
        allocFamilies("xmalloc") shouldBe List("heap")
    }

    "keep an offset family through a wrapper returning the result unchanged" in {
        allocFamilies("wrap_xalloc") shouldBe List("offset:my_xalloc")
    }

    "keep the mmap family through a wrapper around mmap" in {
        allocFamilies("wrap_map_alloc") shouldBe List("mmap")
        freeFamilies("wrap_map_free") shouldBe List("mmap")
    }

    "pair statement-form moves on both sides into the shared key" in {
        allocFamilies("sqlite_mem_malloc") shouldBe List("offset:my_xalloc")
        freeFamilies("sqlite_mem_free") shouldBe List("offset:my_xalloc")
    }

    "keep an allocator that advances a copy and returns the base plain" in {
        allocFamilies("copy_advance_alloc") shouldBe List("heap")
    }

    "pair assignment-form moves on both sides into the shared key" in {
        allocFamilies("sqlite_assign_malloc") shouldBe List("offset:my_xalloc")
        freeFamilies("sqlite_assign_free") shouldBe List("offset:my_xalloc")
    }

    "keep an allocator that advances a copy by assignment and returns the base plain" in {
        allocFamilies("copy_assign_advance_alloc") shouldBe List("heap")
    }

    "keep an allocator whose assignment advance steps back plain" in {
        allocFamilies("back_assign_alloc") shouldBe List("heap")
    }

    "conclude no family for a variable amount" in {
        allocFamilies("var_offset_alloc") shouldBe empty
        freeFamilies("var_xfree") shouldBe empty
    }
end OffsetFamilyInferenceTests
