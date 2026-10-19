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
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A temporary is destroyed at the end of the full-expression that makes it, unless a reference
  * binds it: what it hands out - a pointer to its storage - does not outlive the statement.
  */
class TemporaryLifetimeTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |struct text {
      |  text(const char *s);
      |  text(const text &other);
      |  ~text();
      |  const char *c_str() const;
      |};
      |text make_name(int id);
      |void use(const char *);
      |
      |void bad_c_str_of_temporary(int id) {
      |  const char *p = make_name(id).c_str();
      |  use(p);
      |}
      |void good_reference_extends(int id) {
      |  const text &kept = make_name(id);
      |  use(kept.c_str());
      |}
      |void good_named_copy(int id) {
      |  text kept = make_name(id);
      |  const char *p = kept.c_str();
      |  use(p);
      |}
      |void good_inside_full_expression(int id) {
      |  use(make_name(id).c_str());
      |}
      |struct piece { const char *data() const; };
      |struct rope {
      |  struct cursor {
      |    using reference = const piece&;
      |    reference operator*() const;
      |  };
      |  cursor begin() const;
      |};
      |struct node;
      |node *build(text spec);
      |void keep(node *);
      |void good_iterator_dereference(const rope &r) {
      |  piece first;
      |  first = *r.begin();
      |  use(first.data());
      |}
      |void good_new_object_from_temporary_argument(int id) {
      |  node *n = build(make_name(id));
      |  keep(n);
      |}
      |""".stripMargin,
    "temporaries.cpp"
  )

  private lazy val cpg =
    val graph = sourceCpg
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    new GuardPass(graph).createAndApply()
    new ValueOriginPass(graph).createAndApply()
    new IntegerWidthPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    new MemorySafetyFindingPass(graph).createAndApply()
    graph

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "a temporary a full-expression destroys" should {
      "be marked where it is made" in {
          cpg.method.nameExact("bad_c_str_of_temporary").call.nameExact("make_name").tag
              .nameExact("lifetime-end").value.l shouldBe List("full-expression")
      }
      "not be marked when a reference extends it" in {
          cpg.method.nameExact("good_reference_extends").call.nameExact("make_name").tag
              .nameExact("lifetime-end").l shouldBe empty
      }
      "report a pointer to its storage read after the statement" in {
          findingsIn("bad_c_str_of_temporary") should contain("MS-ALLOC-002")
      }
      "stay silent for an extended temporary, a named copy and a use inside the statement" in {
          Seq("good_reference_extends", "good_named_copy", "good_inside_full_expression").foreach {
              m => withClue(m) { findingsIn(m) should not contain "MS-ALLOC-002" }
          }
      }
      "stay silent where the borrowed storage is not the temporary's" in {
          // an iterator's referent is the sequence's, and a call that takes the temporary as an
          // argument returns its own object
          Seq("good_iterator_dereference", "good_new_object_from_temporary_argument").foreach {
              m => withClue(m) { findingsIn(m) should not contain "MS-ALLOC-002" }
          }
      }
  }
end TemporaryLifetimeTests
