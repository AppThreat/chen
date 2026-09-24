package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

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
