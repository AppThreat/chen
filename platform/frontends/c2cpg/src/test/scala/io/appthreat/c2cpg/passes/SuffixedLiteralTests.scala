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

/** An integer literal written with the standard's suffixes - the C++23 size suffix among them - or
  * with digit separators is the constant it spells, for the copy rules as for any literal.
  */
class SuffixedLiteralTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <string.h>
      |void sized_copy(const char *src) {
      |    char buf[8];
      |    memcpy(buf, src, 16uz);
      |}
      |void fitting_copy(const char *src) {
      |    char buf[8];
      |    memcpy(buf, src, 8uz);
      |}
      |void separated_copy(const char *src) {
      |    char buf[8];
      |    memcpy(buf, src, 1'6);
      |}
      |void char_count(const char *src) {
      |    char buf[8];
      |    memcpy(buf, src, 'A');
      |}
      |""".stripMargin,
    "literals.cpp"
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

  "an integer literal with a size suffix" should {
      "be a constant the extent rules read: an overrunning count fires" in {
          findingsIn("sized_copy") should contain("MS-BOUND-006")
      }

      "not fire when the count fits the buffer" in {
          findingsIn("fitting_copy") should not contain "MS-BOUND-006"
      }
  }

  "an integer literal with digit separators" should {
      "read as the count it spells" in {
          findingsIn("separated_copy") should contain("MS-BOUND-006")
      }
  }

  // a regression guard: a character literal was already read as its code point
  "a character literal as a count" should {
      "still be its code point" in {
          findingsIn("char_count") should contain("MS-BOUND-006")
      }
  }
end SuffixedLiteralTests
