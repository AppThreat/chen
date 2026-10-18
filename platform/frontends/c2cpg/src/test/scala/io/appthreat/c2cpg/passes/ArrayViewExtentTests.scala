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

/** A pointer whose every definition is an array identifier views that array: the array's element
  * count is the pointer's extent, the way a `char buf[16]` local's is. A compound literal's
  * initializer list is its element count, and its address is an unnamed frame object's address (C99
  * 6.5.2.5p5).
  */
class ArrayViewExtentTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <cstring>
      |#include <cstdio>
      |
      |void bad_decayed_write(void) {
      |    char buf[16] = {0};
      |    char *p = buf;
      |    p[20] = 'x';
      |}
      |void good_decayed_write(void) {
      |    char buf[16] = {0};
      |    char *p = buf;
      |    p[15] = 'x';
      |}
      |void bad_two_views_differ(void) {
      |    char a[16] = {0};
      |    char b[32] = {0};
      |    char *p = a;
      |    p = b;
      |    p[20] = 'x';
      |}
      |
      |char good_derived_pointer(const char *list, int n) {
      |    char a[4] = {0};
      |    const char *q = a;
      |    const char *p = strchr(list, q[0]);
      |    return p ? p[n] : 0;
      |}
      |
      |struct point { int x, y; };
      |struct point *bad_literal_address(int x, int y) {
      |    return &(struct point){ x, y };
      |}
      |int bad_literal_overread(int x) {
      |    int *pair = (int[]){ x, 0 };
      |    return pair[4];
      |}
      |int good_literal_read(int x) {
      |    int *pair = (int[]){ x, 0 };
      |    return pair[1];
      |}
      |int *good_literal_stored(void) {
      |    static int *kept;
      |    kept = (int[]){ 1, 2 };
      |    return kept;
      |}
      |""".stripMargin,
    "array_views.c"
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

  "a write through a pointer that views an array" should {
      "read the array's extent" in {
          findingsIn("bad_decayed_write") should contain("MS-BOUND-004")
      }
      "stay silent at the last in-bounds element" in {
          findingsIn("good_decayed_write") shouldBe Set.empty
      }
  }

  "a pointer redefined to a different array" should {
      // no single capacity: the definitions disagree (16 and 32), and 20 is inside the larger
      // one - the view has no extent to read
      "carry no extent" in {
          findingsIn("bad_two_views_differ") shouldBe Set.empty
      }
  }

  "a pointer a call derives from a view" should {
      "not inherit the viewed array's extent" in {
          findingsIn("good_derived_pointer").filter(_.startsWith("MS-BOUND-")) shouldBe Set.empty
      }
  }

  "the address of a block-scope compound literal" should {
      "leave the frame when returned" in {
          findingsIn("bad_literal_address") should contain("MS-ESC-001")
      }
  }

  "an index into a compound literal" should {
      "read the initializer's element count" in {
          findingsIn("bad_literal_overread") should contain("MS-BOUND-003")
      }
      "stay silent inside the count" in {
          findingsIn("good_literal_read") shouldBe Set.empty
      }
  }

  "a literal's address stored into static storage" should {
      // the destination's own duration decides that store; the return is of `kept`, not of
      // the literal's address
      "stay silent" in {
          findingsIn("good_literal_stored") shouldBe Set.empty
      }
  }
end ArrayViewExtentTests
