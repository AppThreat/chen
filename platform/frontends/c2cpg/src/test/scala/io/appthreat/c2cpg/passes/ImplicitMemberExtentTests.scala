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

/** A member read without `this->` carries the owner's class as its type: the member's declared
  * array extent is the buffer's extent, both for an index base inside an operator the caller bounds
  * or not, and for a copy destination.
  */
class ImplicitMemberExtentTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <cstdlib>
      |#include <cstring>
      |
      |struct table_t {
      |    char slots[4];
      |    char &operator[](int i) { return slots[i]; }
      |};
      |void bad_table_index(const char *user) {
      |    table_t t;
      |    int idx = atoi(user);
      |    t[idx] = 'x';
      |}
      |void good_table_index(const char *user) {
      |    table_t t;
      |    int idx = atoi(user);
      |    if (idx >= 0 && idx < 4) {
      |        t[idx] = 'x';
      |    }
      |}
      |
      |struct narrow_sink {
      |    char scratch[8];
      |    void put(const char *src) { strcpy(scratch, src); }
      |};
      |void bad_sink_copy(const char *user) {
      |    narrow_sink s;
      |    s.put(user);
      |}
      |
      |struct level_node {
      |    int key;
      |    char next_[1];
      |    char &next(int n) { return next_[n]; }
      |};
      |""".stripMargin,
    "implicit_members.cpp"
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

  "an operator's member index with an unbounded caller" should {
      "read out of bounds inside the operator" in {
          findingsIn("operator []") should contain("MS-BOUND-003")
      }
  }

  "an operator whose every caller bounds the index" should {
      // the guarded caller bounds only its own call; the shared operator is judged by the
      // unbounded one, so this method is the same METHOD - the negative control is the guard's
      // own copy, which stays silent at its own site (no finding in the caller)
      "keep the caller's own site silent" in {
          findingsIn("good_table_index") shouldBe Set.empty
      }
  }

  "a trailing one-element member read without this->" should {
      "be the flexible idiom, with no extent to index past" in {
          findingsIn("next") should not contain "MS-BOUND-003"
      }
  }

  "a copy into an implicit member of a fixed extent" should {
      "overrun it inside the callee" in {
          findingsIn("put") should contain("MS-BOUND-006")
      }
  }
end ImplicitMemberExtentTests
