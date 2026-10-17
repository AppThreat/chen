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

/** GNU's zero-length trailing array is the flexible member written before C99: the allocation sizes
  * its storage, so its declared 0 is no capacity to overrun. A trailing array with a real extent
  * still is one.
  */
class ZeroLengthMemberTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <stdlib.h>
      |#include <string.h>
      |struct packet {
      |    int kind;
      |    char body[0];
      |};
      |struct framed {
      |    int kind;
      |    char body[4];
      |};
      |void zero_tail_sized_by_allocation(const char *user) {
      |    struct packet *p = malloc(sizeof(*p) + strlen(user) + 1);
      |    if (!p) return;
      |    strcpy(p->body, user);
      |    free(p);
      |}
      |void fixed_tail_overrun(const char *user) {
      |    struct framed *f = malloc(sizeof(*f));
      |    if (!f) return;
      |    strcpy(f->body, user);
      |    free(f);
      |}
      |""".stripMargin,
    "tails.c"
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

  "a string copy into a zero-length trailing member" should {
      "not be held to the declared zero extent" in {
          findingsIn("zero_tail_sized_by_allocation") should not contain "MS-BOUND-006"
      }
  }

  "a string copy into a trailing member with an extent" should {
      "still overrun it" in {
          findingsIn("fixed_tail_overrun") should contain("MS-BOUND-006")
      }
  }
end ZeroLengthMemberTests
