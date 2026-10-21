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

/** An inner block's automatic objects - address-taken locals, decayed arrays, compound literals -
  * end with the block; an access through a pointer into one, where the block has been left, reads a
  * dead object. A `static` local, and an object of a block still open, stay live.
  */
class UseAfterScopeTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <stdio.h>
      |int bad_inner_block_address(int flag)
      |{
      |    int *p = NULL;
      |    if (flag) {
      |        int inner = 42;
      |        p = &inner;
      |    }
      |    return p ? *p : 0; 
      |}
      |int bad_inner_array(int i)
      |{
      |    char *view;
      |    {
      |        char buf[16] = "scoped";
      |        view = buf;
      |    }
      |    return view[i & 7]; 
      |}
      |int bad_inner_compound_literal(int x)
      |{
      |    int *pair;
      |    {
      |        pair = (int[]){x, x + 1};
      |    }
      |    return pair[1]; 
      |}
      |int good_same_block(int flag)
      |{
      |    int outer = 7;
      |    int *p = &outer;
      |    if (flag) {
      |        int inner = 42;
      |        p = &inner;
      |        return *p; 
      |    }
      |    return *p; 
      |}
      |int good_outer_array(int i)
      |{
      |    char buf[16] = "outer";
      |    char *view;
      |    {
      |        view = buf;
      |    }
      |    return view[i & 7]; 
      |}
      |char *bad_element_address_returned(void) {
      |    char text[] = "helper string";
      |    char *p;
      |    p = &text[1];
      |    return p;
      |}
      |int good_static_inner(int flag) {
      |    int *p = NULL;
      |    if (flag) {
      |        static int kept = 3;
      |        p = &kept;
      |    }
      |    return p ? *p : 0;
      |}
      |static const char *names[] = { "a", "b", 0 };
      |int table[4];
      |int good_global_array_walk(void) {
      |    const char **name;
      |    int n = 0;
      |    for (name = &names[1]; *name != NULL; name++)
      |        n++;
      |    int *q = table;
      |    *q = n;
      |    return q[1];
      |}
      |int *kept_address;
      |int main(void) {
      |    int counter = 3;
      |    kept_address = &counter;
      |    return *kept_address;
      |}
      |""".stripMargin,
    "scopes.c"
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

  "a pointer to an element of a local" should {
      "leave the frame when returned" in {
          findingsIn("bad_element_address_returned") should contain("MS-ESC-001")
      }
  }

  "an access through a pointer into an inner block's object" should {
      "report the dead object read after the block" in {
          Seq("bad_inner_block_address", "bad_inner_array", "bad_inner_compound_literal").foreach {
              m => withClue(m) { findingsIn(m) should contain("MS-ALLOC-002") }
          }
      }
      "stay silent while the object's block is open, for an outer object, and for a static" in {
          Seq("good_same_block", "good_outer_array", "good_static_inner").foreach { m =>
              withClue(m) { findingsIn(m) should not contain "MS-ALLOC-002" }
          }
      }
      "stay silent on a global array, whose block is the file's and never ends" in {
          findingsIn("good_global_array_walk") shouldBe empty
      }
  }

  "main's local kept in a global" should {
      "not escape: main's frame lives until the program ends" in {
          findingsIn("main") should not contain "MS-ESC-001"
      }
  }
end UseAfterScopeTests
