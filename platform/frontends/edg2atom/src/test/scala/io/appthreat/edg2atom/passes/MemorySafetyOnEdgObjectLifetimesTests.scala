package io.appthreat.edg2atom.passes

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

/** The object-lifetime shapes a front end that writes destructor calls, constructor bodies and
  * resolved move parameters gives the rules: the class that releases its member in the wrong form,
  * the copy that shares the member two destructors free, the moved-from source read through, the
  * view of a temporary, and the attribute-installed scope-exit release.
  */
class MemorySafetyOnEdgObjectLifetimesTests extends Code2CpgFixture(() =>
        new DefaultTestCpgWithEdg(".cpp")
    ):

  private val edgaAvailable       = EdgaRunner.locate().isDefined
  private def requireEdga(): Unit = assume(edgaAvailable, "edga is not installed")

  private lazy val cpg =
    val graph = code(
      """
      |#include <cstdio>
      |#include <cstdlib>
      |#include <cstring>
      |#include <memory>
      |#include <string>
      |#include <string_view>
      |#include <utility>
      |
      |struct owner {
      |    char *p;
      |    owner() : p(new char[16]) {}
      |    ~owner() { delete[] p; }
      |};
      |struct sloppy_owner {
      |    char *p;
      |    sloppy_owner() : p(new char[16]) {}
      |    ~sloppy_owner() { delete p; }
      |};
      |
      |void bad_copy_owner(void) {
      |    owner a;
      |    owner b = a;
      |    (void)b;
      |}
      |struct deep_owner {
      |    char *p;
      |    deep_owner() : p(new char[16]) {}
      |    deep_owner(const deep_owner &o) : p(new char[16]) { memcpy(p, o.p, 16); }
      |    ~deep_owner() { delete[] p; }
      |};
      |void good_deep_copy(void) {
      |    deep_owner a;
      |    deep_owner b = a;
      |    (void)b;
      |}
      |
      |void bad_literal_index(void) {
      |    char a[16];
      |    a[16] = 'x';
      |}
      |void bad_literal_index_through_view(void) {
      |    char buf[16] = {0};
      |    auto p = buf;
      |    p[20] = 'x';
      |}
      |void good_literal_index_into_pointer(void) {
      |    char *p = (char *)malloc(17);
      |    if (!p) return;
      |    p[16] = 'x';
      |    free(p);
      |}
      |void good_wide_union(void) {
      |    union { long bn[8]; int ui[16]; } buf;
      |    buf.bn[5] = 0;
      |    (void)buf.ui[0];
      |}
      |void good_narrow_union(void) {
      |    union { long bn[2]; int ui[4]; } buf;
      |    buf.bn[1] = 0;
      |    (void)buf.ui[0];
      |}
      |char *good_last_row(char (*t)[6]) {
      |    static char table[9][6];
      |    (void)t;
      |    return &(table[8][0]);
      |}
      |void good_scoped_owner(void) {
      |    owner a;
      |    a.p[0] = 'x';
      |}
      |
      |void bad_moved_read(void) {
      |    auto p = std::unique_ptr<char[]>(new char[8]);
      |    auto q = std::move(p);
      |    p[0] = 'x';
      |    (void)q;
      |}
      |void good_moved_target(void) {
      |    auto p = std::unique_ptr<char[]>(new char[8]);
      |    auto q = std::move(p);
      |    q[0] = 'x';
      |}
      |void reassigned_source_is_live(void) {
      |    auto p = std::unique_ptr<char[]>(new char[8]);
      |    auto q = std::move(p);
      |    p = std::unique_ptr<char[]>(new char[8]);
      |    p[0] = 'x';
      |    (void)q;
      |}
      |
      |static std::string make_name(int id) {
      |    char tmp[16];
      |    snprintf(tmp, sizeof(tmp), "name-%d", id);
      |    return std::string(tmp);
      |}
      |std::string_view bad_view_of_temporary(int id) {
      |    std::string_view v = make_name(id);
      |    return v;
      |}
      |void use_text(const char *);
      |void bad_c_str_of_temporary(int id) {
      |    const char *p = make_name(id).c_str();
      |    use_text(p);
      |}
      |char bad_view_of_concatenation(const std::string &a) {
      |    std::string_view v = a + "-suffix";
      |    return v[0];
      |}
      |void good_reference_extends(int id) {
      |    const std::string &kept = make_name(id);
      |    use_text(kept.c_str());
      |}
      |void good_inside_full_expression(int id) {
      |    use_text(make_name(id).c_str());
      |}
      |std::string_view good_view_of_lvalue(const std::string &s) {
      |    std::string_view v = s;
      |    return v;
      |}
      |
      |static void release(char **p) {
      |    free(*p);
      |    *p = NULL;
      |}
      |void bad_cleanup_explicit_free(void) {
      |    char *q __attribute__((cleanup(release))) = (char*)malloc(32);
      |    if (!q) return;
      |    free(q);
      |}
      |void good_cleanup_only(void) {
      |    char *p __attribute__((cleanup(release))) = (char*)malloc(32);
      |    if (!p) return;
      |    p[0] = 'x';
      |}
      |struct tree_node { int depth; };
      |static tree_node *build_from(std::string spec) {
      |    tree_node *n = new tree_node;
      |    n->depth = (int)spec.size();
      |    return n;
      |}
      |int good_new_object_from_temporary_argument(int id) {
      |    tree_node *n = build_from(make_name(id));
      |    int d = n->depth;
      |    delete n;
      |    return d;
      |}
      |struct named_value { const char *name; int value; };
      |static const named_value known_values[] = { {"a", 1}, {"b", 2}, {nullptr, 0} };
      |int good_global_table_walk(int wanted) {
      |    const named_value *nv;
      |    for (nv = known_values; nv->name; nv++)
      |        if (nv->value == wanted) return 1;
      |    return nv->value;
      |}
      |struct sink {
      |    char buf[64];
      |    char *pos = buf;
      |    void fill(size_t n, char c) {
      |        auto put = [&](size_t count) { memset(pos, c, count); pos += count; };
      |        if (n <= sizeof(buf)) put(n);
      |    }
      |};
      |void good_closure_kept_in_frame(sink &s) { s.fill(3, 'x'); }
      |""".stripMargin,
      "object_lifetimes.cpp"
    )
    X2Cpg.applyDefaultOverlays(graph)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(graph))
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    new GuardPass(graph).createAndApply()
    new ValueOriginPass(graph).createAndApply()
    new IntegerWidthPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    new MemorySafetyFindingPass(graph).createAndApply()
    graph
  end cpg

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "a class whose constructor array-news its member" should {
      "report the destructor's scalar delete of it" in {
          requireEdga()
          findingsIn("~sloppy_owner") should contain("MS-ALLOC-007")
      }
  }

  "a copy-initialised pair of a class with a freeing destructor" should {
      "report the double delete at the copy" in {
          requireEdga()
          findingsIn("bad_copy_owner") should contain("MS-ALLOC-001")
      }
      "stay silent for one scoped owner" in {
          requireEdga()
          findingsIn("good_scoped_owner") shouldBe Set.empty
      }
  }

  "a copy of a class that declares its own copy constructor" should {
      "stay silent: the copy owns fresh storage" in {
          requireEdga()
          findingsIn("good_deep_copy") shouldBe Set.empty
      }
  }

  "a literal index against a declared count" should {
      "report the index one past a declared array" in {
          requireEdga()
          findingsIn("bad_literal_index").exists(_.startsWith("MS-BOUND-")) shouldBe true
      }
      "report the index past the array a pointer views" in {
          requireEdga()
          findingsIn("bad_literal_index_through_view").exists(_.startsWith("MS-BOUND-")) shouldBe
              true
      }
      "stay silent for a pointer whose capacity comes through its definition" in {
          requireEdga()
          findingsIn("good_literal_index_into_pointer").filter(_.startsWith("MS-BOUND-")) shouldBe
              Set.empty
      }
      "stay silent for a member of one of several same-named anonymous unions" in {
          requireEdga()
          findingsIn("good_wide_union").filter(_.startsWith("MS-BOUND-")) shouldBe Set.empty
      }
      "stay silent for the last row of a two-dimensional table" in {
          requireEdga()
          findingsIn("good_last_row").filter(_.startsWith("MS-BOUND-")) shouldBe Set.empty
      }
  }

  "a read through a moved-from unique_ptr" should {
      "report the null dereference" in {
          requireEdga()
          findingsIn("bad_moved_read") should contain("MS-NULL-001")
      }
      "stay silent for the move's target" in {
          requireEdga()
          findingsIn("good_moved_target") shouldBe Set.empty
      }
      "stay silent for a source reassigned after the move" in {
          requireEdga()
          findingsIn("reassigned_source_is_live") shouldBe Set.empty
      }
  }

  "a view bound to a call's by-value result" should {
      "report the returned dangling view at the binding" in {
          requireEdga()
          findingsIn("bad_view_of_temporary") should contain("MS-ESC-001")
      }
      "stay silent for a view of an lvalue" in {
          requireEdga()
          findingsIn("good_view_of_lvalue") shouldBe Set.empty
      }
  }

  "a pointer or view borrowed from a temporary" should {
      "report its read after the temporary's statement" in {
          requireEdga()
          findingsIn("bad_c_str_of_temporary") should contain("MS-ALLOC-002")
          findingsIn("bad_view_of_concatenation") should contain("MS-ALLOC-002")
      }
      "stay silent for an extended temporary and a use inside the statement" in {
          requireEdga()
          findingsIn("good_reference_extends") should not contain "MS-ALLOC-002"
          findingsIn("good_inside_full_expression") should not contain "MS-ALLOC-002"
      }
      "stay silent for a new object a call builds from a temporary argument" in {
          requireEdga()
          findingsIn("good_new_object_from_temporary_argument") should not contain "MS-ALLOC-002"
      }
  }

  "a pointer walking a global table" should {
      "stay silent: the table's storage is the program's" in {
          requireEdga()
          findingsIn("good_global_table_walk") should not contain "MS-ALLOC-002"
      }
  }

  "a closure a member function keeps in a local" should {
      "not escape its frame" in {
          requireEdga()
          findingsIn("fill") should not contain "MS-ESC-001"
      }
  }

  "an explicit free the scope-exit cleanup releases again" should {
      "report the double free" in {
          requireEdga()
          findingsIn("bad_cleanup_explicit_free") should contain("MS-ALLOC-001")
      }
      "stay silent when the attribute owns the single release" in {
          requireEdga()
          findingsIn("good_cleanup_only") shouldBe Set.empty
      }
  }
end MemorySafetyOnEdgObjectLifetimesTests
