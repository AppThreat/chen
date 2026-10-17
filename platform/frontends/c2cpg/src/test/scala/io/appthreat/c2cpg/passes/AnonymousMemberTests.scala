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

/** A member of an anonymous struct or union member is a member of the enclosing type (C11
  * 6.7.2.1p13): `f.small` resolves to the union's `small` with its declared extent.
  */
class AnonymousMemberTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <string.h>
      |struct frame {
      |    int kind;
      |    union {
      |        char small[8];
      |        long aligned;
      |    };
      |};
      |void bad_anon_copy(const char *user) {
      |    struct frame f;
      |    strcpy(f.small, user);
      |}
      |void good_anon_copy(const char *user) {
      |    struct frame f;
      |    strncpy(f.small, user, sizeof(f.small));
      |}
      |struct named {
      |    int kind;
      |    union {
      |        char small[8];
      |        long aligned;
      |    } u;
      |};
      |void named_still_resolves(const char *user) {
      |    struct named n;
      |    strcpy(n.u.small, user);
      |}
      |""".stripMargin,
    "anon_members.c"
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

  "a copy into a member of an anonymous union" should {
      "overrun the member's own extent" in {
          findingsIn("bad_anon_copy") should contain("MS-BOUND-006")
      }
      "honour a length bounded by the member's size" in {
          findingsIn("good_anon_copy") should not contain "MS-BOUND-006"
      }
  }

  "a copy into a member of a NAMED union member" should {
      "be a write into the member, not an uninitialised read of it" in {
          // the array member decays where it is handed over, a named union's as much as an
          // anonymous one's: the read the rule used to report on this shape was a false one
          findingsIn("named_still_resolves") should not contain "MS-INIT-001"
      }
  }
end AnonymousMemberTests
