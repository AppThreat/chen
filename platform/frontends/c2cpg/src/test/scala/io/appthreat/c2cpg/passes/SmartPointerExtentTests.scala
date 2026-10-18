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

/** The storage a smart pointer owns has the count its construction states: `unique_ptr<T[]>(new
  * T[n])` takes the array new's extent, `make_unique<T[]>(n)` the factory's count, and
  * `std::array<T, N>` the instance's constant N. The construction-call arms are exercised on the
  * language corpus (the suite's parser leaves the template-id construction unparsed); the
  * instance-type arm is testable here.
  */
class SmartPointerExtentTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <cstdlib>
      |#include <cstring>
      |#include <cstdio>
      |#include <memory>
      |#include <array>
      |
      |void bad_unique_index(const char *user) {
      |    auto p = std::unique_ptr<char[]>(new char[8]);
      |    int idx = atoi(user);
      |    printf("%c\n", p[idx]);
      |}
      |void good_unique_index(const char *user) {
      |    auto p = std::unique_ptr<char[]>(new char[8]);
      |    int idx = atoi(user);
      |    if (idx >= 0 && idx < 8) {
      |        printf("%c\n", p[idx]);
      |    }
      |}
      |void bad_make_unique_write(const char *user) {
      |    auto p = std::make_unique<char[]>(8);
      |    int idx = atoi(user);
      |    p[idx] = 'x';
      |}
      |void bad_array_member_index(const char *user) {
      |    std::array<char, 8> a;
      |    int idx = atoi(user);
      |    a[idx] = 'x';
      |}
      |void good_array_member_index(const char *user) {
      |    std::array<char, 8> a;
      |    int idx = atoi(user);
      |    if (idx >= 0 && idx < 8) {
      |        a[idx] = 'x';
      |    }
      |}
      |""".stripMargin,
    "smart_pointer_extents.cpp"
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

  "an index into a unique_ptr's owned array" should {
      "read the new[] count" in {
          findingsIn("bad_unique_index") should contain("MS-BOUND-003")
      }
      "stay silent inside the count" in {
          findingsIn("good_unique_index") shouldBe Set.empty
      }
  }

  "an index into a make_unique array" should {
      "read the factory's count" in {
          findingsIn("bad_make_unique_write") should contain("MS-BOUND-004")
      }
  }

  "an index into a std::array" should {
      "read the instance's constant count" in {
          findingsIn("bad_array_member_index") should contain("MS-BOUND-004")
      }
      "stay silent inside the count" in {
          findingsIn("good_array_member_index") shouldBe Set.empty
      }
  }
end SmartPointerExtentTests
