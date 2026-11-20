package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    MemorySemanticsPass,
    ValueOriginPass
}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** The shapes at the edges of the allocation styles, each a defect beside the correct code it looks
  * like: an index one past a variable that sized the allocation, reference counts across loops and
  * joins, a scope-cleanup variable stored on one path and released on another, offset releases that
  * cancel or follow a block held in a field, a region handle rebound before its destroy, and the
  * method summaries a destroy, an offset allocator and a reference release draw from their bodies.
  */
class AllocationStyleEdgeCaseTests extends DataFlowCodeToCpgSuite:

  /** Runs the memory-safety overlay in the order the memory-safety command runs it. */
  private def overlay(cpg: Cpg): Cpg =
    new MemorySemanticsPass(cpg).createAndApply()
    new MemoryApiPass(cpg).createAndApply()
    new ExtentPass(cpg).createAndApply()
    new GuardPass(cpg).createAndApply()
    new ValueOriginPass(cpg).createAndApply()
    new IntegerWidthPass(cpg).createAndApply()
    new AllocationStatePass(cpg).createAndApply()
    new MemorySafetyFindingPass(cpg).createAndApply()
    cpg

  /** (rule, line, confidence) of every finding inside `method`. */
  private def findings(cpg: Cpg, method: String): Set[(String, Int, String)] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode].l.flatMap { node =>
        val line = node.propertiesMap.get("LINE_NUMBER") match
          case i: Integer => i.intValue
          case _          => -1
        val confidences = node.tag.name("ms-confidence").value.l
            .map(_.split("=", 2)).collect { case Array(r, c) => r -> c }.toMap
        node.tag.name("ms-finding").value.l.map(rule =>
            (rule, line, confidences.getOrElse(rule, ""))
        )
      }.toSet

  private def rules(cpg: Cpg, method: String): Set[String] = findings(cpg, method).map(_._1)

  "an index equal to the variable that sized a byte buffer" should {

      val cpg = overlay(code(
        """#include <stdlib.h>
          |#include <string.h>
          |void bump(size_t *x);
          |struct pair { int a, b; };
          |
          |char *good_terminator(const char *s, size_t n) {
          |    char *buf = malloc(n + 1);
          |    if (!buf) return 0;
          |    memcpy(buf, s, n);
          |    buf[n] = 0;
          |    return buf;
          |}
          |int *bad_int_elements(size_t n) {
          |    int *a = malloc(n + 1);
          |    if (!a) return 0;
          |    a[n] = 0;
          |    return a;
          |}
          |struct pair *bad_struct_elements(size_t n) {
          |    struct pair *s = malloc(n + 1);
          |    if (!s) return 0;
          |    s[n].a = 0;
          |    return s;
          |}
          |char *bad_incremented(size_t n) {
          |    char *buf = malloc(n + 1);
          |    if (!buf) return 0;
          |    n++;
          |    buf[n] = 0;
          |    return buf;
          |}
          |char *bad_grown_in_loop(size_t n, int c) {
          |    char *buf = malloc(n + 1);
          |    if (!buf) return 0;
          |    while (c--) n++;
          |    buf[n] = 0;
          |    return buf;
          |}
          |char *bad_changed_through_address(size_t n) {
          |    char *buf = malloc(n + 1);
          |    if (!buf) return 0;
          |    bump(&n);
          |    buf[n] = 0;
          |    return buf;
          |}
          |""".stripMargin,
        "terminators.c"
      ))

      "stay silent on the terminator write" in {
          rules(cpg, "good_terminator").filter(_.startsWith("MS-BOUND-")) shouldBe empty
      }

      "report it when the elements are wider than a byte" in {
          List("bad_int_elements", "bad_struct_elements").foreach { m =>
              withClue(s"$m: ")(rules(cpg, m).exists(_.startsWith("MS-BOUND-")) shouldBe true)
          }
      }

      "report it when the variable changed after the allocation" in {
          List("bad_incremented", "bad_grown_in_loop", "bad_changed_through_address").foreach { m =>
              withClue(s"$m: ")(rules(cpg, m).exists(_.startsWith("MS-BOUND-")) shouldBe true)
          }
      }
  }

  "an offset release" should {

      val cpg = overlay(code(
        """#include <stdlib.h>
          |#include <string.h>
          |struct holder { char *buf; };
          |
          |void good_advanced_and_moved_back(void) {
          |    char *p = malloc(16);
          |    if (!p) return;
          |    p += 4;
          |    p[0] = 1;
          |    free(p - 4);
          |}
          |void good_prefixed_in_place(void) {
          |    char *raw = malloc(32);
          |    if (!raw) return;
          |    char *p = raw + 8;
          |    p[0] = 1;
          |    free(p - 8);
          |}
          |void bad_moved_back_too_little(void) {
          |    char *p = malloc(16);
          |    if (!p) return;
          |    p += 4;
          |    free(p - 2);
          |}
          |void bad_field_block(struct holder *s) {
          |    s->buf = malloc(16);
          |    if (!s->buf) return;
          |    free(s->buf + 1);
          |}
          |void bad_either_allocator(int c) {
          |    char *p = c ? malloc(16) : calloc(1, 16);
          |    if (!p) return;
          |    free(p + 1);
          |}
          |void bad_walk_over_field_block(struct holder *s, const char *src) {
          |    s->buf = strdup(src);
          |    char *p = s->buf;
          |    if (!p) return;
          |    while (*p) p++;
          |    free(p);
          |}
          |void good_header_of_parameter(void *ptr) {
          |    free((char *)ptr - 16);
          |}
          |""".stripMargin,
        "offsets.c"
      ))

      "stay silent when the pointer is moved back by what advanced it" in {
          rules(cpg, "good_advanced_and_moved_back") should not contain "MS-ALLOC-006"
          rules(cpg, "good_prefixed_in_place") should not contain "MS-ALLOC-006"
          rules(cpg, "good_header_of_parameter") should not contain "MS-ALLOC-006"
      }

      "report a pointer moved back by less than advanced it" in {
          rules(cpg, "bad_moved_back_too_little") should contain("MS-ALLOC-006")
      }

      "report an offset into a block held in a field or chosen between allocators" in {
          rules(cpg, "bad_field_block") should contain("MS-ALLOC-006")
          rules(cpg, "bad_either_allocator") should contain("MS-ALLOC-006")
          rules(cpg, "bad_walk_over_field_block") should contain("MS-ALLOC-006")
      }
  }

  "a scope-cleanup variable stored on one path" should {

      val cpg = overlay(code(
        """#include <stdlib.h>
          |static void freep(void *pp) { free(*(void **)pp); }
          |#define _cleanup_free_ __attribute__((cleanup(freep)))
          |char *g_keep;
          |
          |void good_stored_then_reset(int c) {
          |    _cleanup_free_ char *p = malloc(8);
          |    if (!p) return;
          |    if (c) {
          |        g_keep = p;
          |        p = NULL;
          |        return;
          |    }
          |    p[0] = 1;
          |}
          |void bad_stored_and_released(void) {
          |    _cleanup_free_ char *p = malloc(8);
          |    if (!p) return;
          |    g_keep = p;
          |}
          |""".stripMargin,
        "cleanup_store.c"
      ))

      "stay silent when that path resets the variable and the releasing path never stored it" in {
          rules(cpg, "good_stored_then_reset") should not contain "MS-ALLOC-002"
      }

      "report a store the release then frees" in {
          rules(cpg, "bad_stored_and_released") should contain("MS-ALLOC-002")
      }
  }

  "a declared region handle" should {

      val cpg = overlay(
        code(
          """#include "apr_pools.h"
            |
            |void good_rebound_before_destroy(apr_pool_t *a, apr_pool_t *b) {
            |    apr_pool_t *pool = a;
            |    char *p = apr_palloc(pool, 8);
            |    if (!p) return;
            |    pool = b;
            |    apr_pool_destroy(pool);
            |    p[0] = 1;
            |}
            |void good_null_or_pool_block(apr_pool_t **pools, int k, int c) {
            |    char *name = NULL;
            |    if (c) {
            |        name = apr_palloc(pools[k], 8);
            |        if (!name) return;
            |        name[0] = 1;
            |    }
            |}
            |void bad_use_after_destroy(apr_pool_t *a) {
            |    apr_pool_t *pool = a;
            |    char *p = apr_palloc(pool, 8);
            |    if (!p) return;
            |    apr_pool_destroy(pool);
            |    p[0] = 1;
            |}
            |""".stripMargin,
          "regions.c"
        ).moreCode(
          """typedef struct apr_pool_t apr_pool_t;
            |void *apr_palloc(apr_pool_t *p, unsigned long size);
            |void apr_pool_destroy(apr_pool_t *p);
            |""".stripMargin,
          "apr_pools.h"
        )
      )

      "keep a pool block that one path left NULL out of the leak facts" in {
          rules(cpg, "good_null_or_pool_block") should not contain "MS-ALLOC-003"
      }

      "follow the region the handle held at the allocation" in {
          rules(cpg, "good_rebound_before_destroy") should not contain "MS-ALLOC-002"
          rules(cpg, "bad_use_after_destroy") should contain("MS-ALLOC-002")
      }
  }

  "reference counts across loops and joins" should {

      val cpg = overlay(
        code(
          """#include <stdlib.h>
            |#include "object.h"
            |void sink(PyObject *);
            |static PyObject *mk(void) { PyObject *o = PyMem_Malloc(sizeof(PyObject)); return o; }
            |
            |void good_balanced_loops(int n) {
            |    PyObject *o = mk();
            |    if (!o) return;
            |    for (int i = 0; i < n; i++) Py_INCREF(o);
            |    for (int i = 0; i < n; i++) Py_DECREF(o);
            |    Py_DECREF(o);
            |}
            |void good_conditional_extra_reference(int c) {
            |    PyObject *o = mk();
            |    if (!o) return;
            |    if (c) Py_INCREF(o);
            |    Py_DECREF(o);
            |    if (c) {
            |        o->v = 1;
            |        Py_DECREF(o);
            |    }
            |}
            |void good_null_or_two_references(int c) {
            |    PyObject *o = NULL;
            |    if (c) {
            |        o = mk();
            |        if (!o) return;
            |        Py_INCREF(o);
            |    }
            |    if (o) {
            |        sink(o);
            |        Py_DECREF(o);
            |        o->v = 1;
            |        Py_DECREF(o);
            |    }
            |}
            |void good_borrowed_release_in_loop(PyObject *o, int n) {
            |    for (int i = 0; i < n; i++) {
            |        if (i == n - 1) Py_DECREF(o);
            |    }
            |}
            |void bad_use_after_last_release(void) {
            |    PyObject *o = mk();
            |    if (!o) return;
            |    Py_DECREF(o);
            |    o->v = 1;
            |}
            |void bad_double_release(void) {
            |    PyObject *o = mk();
            |    if (!o) return;
            |    Py_DECREF(o);
            |    Py_DECREF(o);
            |}
            |void bad_use_after_borrowed_release(PyObject *o) {
            |    Py_DECREF(o);
            |    o->v = 1;
            |}
            |""".stripMargin,
          "refcounts.c"
        ).moreCode(
          """typedef struct _object { long ob_refcnt; int v; } PyObject;
            |void Py_INCREF(PyObject *o);
            |void Py_DECREF(PyObject *o);
            |void *PyMem_Malloc(unsigned long n);
            |void PyMem_Free(void *p);
            |""".stripMargin,
          "object.h"
        )
      )

      "stay silent on balanced counts across loops, branches and a NULL path" in {
          List(
            "good_balanced_loops",
            "good_conditional_extra_reference",
            "good_null_or_two_references",
            "good_borrowed_release_in_loop"
          ).foreach { m =>
              withClue(s"$m: ") {
                  rules(cpg, m) should not contain "MS-ALLOC-001"
                  rules(cpg, m) should not contain "MS-ALLOC-002"
              }
          }
      }

      "report the use after the last release and the release below zero at medium" in {
          findings(cpg, "bad_use_after_last_release").map(f => (f._1, f._3)) should contain(
            ("MS-ALLOC-002", "medium")
          )
          findings(cpg, "bad_double_release").map(f => (f._1, f._3)) should contain(
            ("MS-ALLOC-001", "medium")
          )
      }

      "report the use after a borrowed release at low, in a method with no other memory call" in {
          findings(cpg, "bad_use_after_borrowed_release").map(f => (f._1, f._3)) should contain(
            ("MS-ALLOC-002", "low")
          )
      }
  }

  "a method summary" should {

      val cpg = overlay(code(
        """#include <stdlib.h>
          |#define PREFIX_SIZE 8
          |struct node { struct node *next; int v; };
          |struct obj { int refs; int owned; };
          |struct hdr { char tag; char name[3]; int size; };
          |struct zhdr { int len; char data[0]; };
          |
          |void *zmalloc(size_t n) {
          |    char *p = malloc(n + PREFIX_SIZE);
          |    if (!p) return NULL;
          |    return p + PREFIX_SIZE;
          |}
          |void zfree(void *ptr) {
          |    if (ptr == NULL) return;
          |    ptr = (char *)ptr - PREFIX_SIZE;
          |    free(ptr);
          |}
          |void good_zpair(size_t n) {
          |    void *p = zmalloc(n);
          |    zfree(p);
          |}
          |void bad_heap_free_of_zmalloc(size_t n) {
          |    void *p = zmalloc(n);
          |    free(p);
          |}
          |
          |void skip_free(struct node *p) {
          |    p = p->next;
          |    free(p);
          |}
          |void good_free_after_skip(void) {
          |    struct node *a = malloc(sizeof(struct node));
          |    if (!a) return;
          |    a->next = malloc(sizeof(struct node));
          |    skip_free(a);
          |    free(a);
          |}
          |
          |void *halloc(size_t n) {
          |    struct hdr *h = malloc(n + 8);
          |    if (!h) return NULL;
          |    return h + 1;
          |}
          |void hfree(void *p) {
          |    free((char *)p - 8);
          |}
          |void good_hpair(size_t n) {
          |    void *p = halloc(n);
          |    hfree(p);
          |}
          |
          |void *zl_alloc(size_t n) {
          |    struct zhdr *h = malloc(n + 4);
          |    if (!h) return NULL;
          |    h->len = (int)n;
          |    return h + 1;
          |}
          |
          |void *swap_alloc(int n) {
          |    void *p = 0, *q = 0;
          |    while (n-- > 0) { q = p; p = q; }
          |    if (n == -5) p = malloc(4);
          |    return p;
          |}
          |
          |void put_if_owned(struct obj *o) {
          |    if (--o->refs == 0 && o->owned) free(o);
          |}
          |void put_when_nonzero(struct obj *o) {
          |    if (--o->refs != 0) free(o);
          |}
          |void guard_backwards(struct node *p) {
          |    if (p != NULL) return;
          |    free(p);
          |}
          |void good_after_gated_releases(struct obj *o, struct node *n) {
          |    put_if_owned(o);
          |    o->refs = 1;
          |    put_when_nonzero(o);
          |    o->refs = 2;
          |    guard_backwards(n);
          |    free(n);
          |}
          |""".stripMargin,
        "summaries.c"
      ))

      "pair an offset allocator with the free that moves its parameter back" in {
          rules(cpg, "good_zpair") should not contain "MS-ALLOC-007"
          rules(cpg, "bad_heap_free_of_zmalloc") should contain("MS-ALLOC-007")
          rules(cpg, "good_hpair") should not contain "MS-ALLOC-007"
      }

      "not read the free of a reassigned parameter as a destroy of the argument" in {
          rules(cpg, "good_free_after_skip") should not contain "MS-ALLOC-001"
      }

      "not conclude a release from a gated, inverted or misplaced zero test" in {
          rules(cpg, "good_after_gated_releases") should not contain "MS-ALLOC-001"
          rules(cpg, "good_after_gated_releases") should not contain "MS-ALLOC-002"
      }

      "not report an offset allocator's own return as a leak" in {
          rules(cpg, "zmalloc") should not contain "MS-ALLOC-003"
          rules(cpg, "halloc") should not contain "MS-ALLOC-003"
      }

      "survive a zero-length member and a copy cycle in an allocator's body" in {
          cpg.method.nameExact("zl_alloc").l should not be empty
          cpg.method.nameExact("swap_alloc").l should not be empty
      }
  }

  "a library's declared steal and cleanup functions" should {

      val cpg = overlay(
        code(
          """#include "glib.h"
            |
            |void good_stolen_then_freed(void) {
            |    char *p = g_new0(1, 8);
            |    if (!p) return;
            |    char *q = g_steal_pointer(&p);
            |    g_free(q);
            |}
            |void good_declared_cleanup(void) {
            |    char *p __attribute__((cleanup(g_autoptr_cleanup_generic_gfree))) = g_new0(1, 8);
            |    if (!p) return;
            |    p[0] = 1;
            |}
            |void bad_freed_then_cleaned(void) {
            |    char *p __attribute__((cleanup(g_autoptr_cleanup_generic_gfree))) = g_new0(1, 8);
            |    if (!p) return;
            |    g_free(p);
            |}
            |""".stripMargin,
          "glib_roles.c"
        ).moreCode(
          """void *g_new0(unsigned long size, unsigned long n);
            |void g_free(void *p);
            |void *g_steal_pointer(void *pp);
            |void g_autoptr_cleanup_generic_gfree(void *pp);
            |""".stripMargin,
          "glib.h"
        )
      )

      "move the block out of the slot a declared steal is handed" in {
          rules(cpg, "good_stolen_then_freed") shouldBe empty
      }

      "release the variable at a declared cleanup function's call" in {
          rules(cpg, "good_declared_cleanup") should not contain "MS-ALLOC-003"
          rules(cpg, "bad_freed_then_cleaned") should contain("MS-ALLOC-001")
      }
  }

  "a variable a later block or a callee gives a new value" should {

      val cpg = overlay(code(
        """#include <stdlib.h>
          |#include <string.h>
          |struct entry { char *name; };
          |struct manifest { int n; };
          |struct server { struct manifest *manifest; };
          |struct server srv;
          |
          |char *fill(const char *s, char **out) {
          |    *out = strdup(s);
          |    return *out;
          |}
          |void load_manifest(void) {
          |    srv.manifest = malloc(sizeof(struct manifest));
          |}
          |
          |void good_refilled_each_iteration(const char **names, int n) {
          |    for (int i = 0; i < n; i++) {
          |        char *tmp;
          |        fill(names[i], &tmp);
          |        if (tmp != NULL) free(tmp);
          |    }
          |}
          |void good_walk_frees_each_element(struct entry *e) {
          |    while (e->name != NULL) {
          |        free(e->name);
          |        e++;
          |    }
          |}
          |void good_reloaded_global(void) {
          |    if (srv.manifest) free(srv.manifest);
          |    load_manifest();
          |    srv.manifest->n = 1;
          |}
          |struct attn { char *data; int status; };
          |int next_attn(struct attn *out);
          |void good_refilled_struct(void) {
          |    struct attn a = {0};
          |    int count;
          |    do {
          |        count = next_attn(&a);
          |        if (count) {
          |            free(a.data);
          |        }
          |    } while (count);
          |}
          |void good_counter_of_another_block(unsigned long size) {
          |    {
          |        char *idx = malloc(size);
          |        if (idx) idx[0] = 0;
          |        free(idx);
          |    }
          |    {
          |        unsigned long idx;
          |        for (idx = 0; idx < size; idx++) {}
          |    }
          |}
          |""".stripMargin,
        "rebound.c"
      ))

      "not read the freed value into the new one" in {
          List(
            "good_refilled_each_iteration",
            "good_walk_frees_each_element",
            "good_reloaded_global",
            "good_counter_of_another_block",
            "good_refilled_struct"
          ).foreach { m =>
              withClue(s"$m: ") {
                  // the allocation-state rules; a size question (MS-ALLOC-008) is not this one
                  rules(cpg, m).intersect(
                    Set("MS-ALLOC-001", "MS-ALLOC-002", "MS-ALLOC-003", "MS-ALLOC-006")
                  ) shouldBe empty
              }
          }
      }
  }

  "a descriptor handed to fdopen" should {

      val cpg = overlay(code(
        """#include <stdio.h>
          |#include <fcntl.h>
          |#include <unistd.h>
          |
          |int good_fdopen_owns_descriptor(const char *path) {
          |    int fd = open(path, O_RDONLY);
          |    if (fd < 0) return -1;
          |    FILE *s = fdopen(fd, "r");
          |    if (!s) { close(fd); return -1; }
          |    int c = fgetc(s);
          |    fclose(s);
          |    return c;
          |}
          |""".stripMargin,
        "fdopen.c"
      ))

      "not report the descriptor as leaked" in {
          rules(cpg, "good_fdopen_owns_descriptor") should not contain "MS-ALLOC-003"
      }
  }

end AllocationStyleEdgeCaseTests
