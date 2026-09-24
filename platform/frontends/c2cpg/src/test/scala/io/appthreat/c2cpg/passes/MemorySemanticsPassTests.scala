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
    |""".stripMargin,
    "semantics.c"
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
        |    free_nodes(0); av_free_with_log(q, 1); my_freebuf(q);
        |}
        |void uaf_through_guessed_free(int n)
        |{
        |    char *p = av_malloc(n);
        |    if (!p)
        |        return;
        |    av_free(p);
        |    p[0] = 1;
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
end ScopedHeaderMemorySemanticsTests
