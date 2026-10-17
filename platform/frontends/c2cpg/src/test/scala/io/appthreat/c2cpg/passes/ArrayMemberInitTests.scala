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

/** A struct with an array member is still an uninitialised-read candidate: the array member is
  * initialised element-wise (a store `s.buf[i] = x` counts) or whole (an aggregate initialiser,
  * which also zeroes the members the list leaves out), so a bare declaration read is the defect.
  */
class ArrayMemberInitTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <stdio.h>
      |struct sample {
      |    int a;
      |    int b;
      |    char rest[8];
      |};
      |void bad_uninit_member(void) {
      |    struct sample s;
      |    printf("%d\n", s.b);
      |}
      |void good_braced_member(void) {
      |    struct sample s = {};
      |    printf("%d\n", s.b);
      |}
      |void good_element_filled(void) {
      |    struct sample s;
      |    for (int i = 0; i < 8; i++) s.rest[i] = 0;
      |    printf("%d\n", s.rest[0]);
      |}
      |void good_member_handed_out(const char *user) {
      |    struct sample s;
      |    strncpy(s.rest, user, sizeof(s.rest));
      |    printf("%d\n", s.rest[0]);
      |}
      |struct host {
      |    char small[8];
      |    void put(const char *src) { strcpy(small, src); }
      |};
      |void good_member_call_target(const char *user) {
      |    host h;
      |    h.put(user);
      |    printf("%d\n", h.small[0]);
      |}
      |typedef struct { int x; int y; } point_s, point_t[1];
      |void fill_point(point_t out);
      |void use_point(point_t in);
      |void good_array_typedef_filled(void) {
      |    point_t pt;
      |    fill_point(pt);
      |    use_point(pt);
      |}
      |""".stripMargin,
    "array_members.c"
  ).moreCode(
    """
      |typedef struct { int x; int y; } niels_s, niels_t[1];
      |void fill_niels(niels_t out);
      |void use_niels(niels_t in);
      |""".stripMargin,
    "niels.h"
  ).moreCode(
    """
      |#include "niels.h"
      |void good_header_array_typedef_filled(void) {
      |    niels_t n;
      |    fill_niels(n);
      |    use_niels(n);
      |}
      |""".stripMargin,
    "niels_user.c"
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

  "a read of a never-written member of a struct with an array member" should {
      "be an uninitialised read" in {
          findingsIn("bad_uninit_member") should contain("MS-INIT-001")
      }
  }

  "an aggregate initialiser" should {
      "count as initialising the whole object" in {
          findingsIn("good_braced_member") should not contain "MS-INIT-001"
      }
  }

  "an element-wise fill of the array member" should {
      "initialise that member" in {
          findingsIn("good_element_filled") should not contain "MS-INIT-001"
      }
  }

  "an array member handed to a call" should {
      "be the callee's to write, not an uninitialised read" in {
          findingsIn("good_member_handed_out") should not contain "MS-INIT-001"
      }
  }

  "the object a member call is made on" should {
      "be its callee's to write" in {
          findingsIn("good_member_call_target") should not contain "MS-INIT-001"
      }
  }

  "a local of an array typedef handed to a call" should {
      "decay to storage the callee fills, not be read" in {
          findingsIn("good_array_typedef_filled") should not contain "MS-INIT-001"
          findingsIn("good_header_array_typedef_filled") should not contain "MS-INIT-001"
      }
  }
end ArrayMemberInitTests
