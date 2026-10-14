package io.appthreat.edg2atom.passes

import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A typedef a header no unit of the project writes declares - an external library's - is a name
  * the graph knows only as a stub. Its target (`uint_least64_t` is an unsigned 64-bit type) is a
  * fact the width and signedness rules read off the declaration, the way the spelled-out type
  * carries it.
  */
class ResignThroughHeaderTypedefTests extends Code2CpgFixture(() =>
        new DefaultTestCpgWithEdg(".cpp")
    ):

  private val edgaAvailable = EdgaRunner.locate().isDefined

  private lazy val cpg =
    val graph = code(
      """
        |#include <cstdint>
        |#include <cstring>
        |int resign_wide_spelled(unsigned long long wide, long limit, unsigned char *dst) {
        |  unsigned char buf[16];
        |  if ((long)wide > limit)
        |    return -1;
        |  memcpy(buf, dst, wide);
        |  return 0;
        |}
        |int resign_wide_header_typedef(uint_least64_t wide, long limit, unsigned char *dst) {
        |  unsigned char buf[16];
        |  if ((long)wide > limit)
        |    return -1;
        |  memcpy(buf, dst, wide);
        |  return 0;
        |}
        |int resign_constant_through_header_typedef(int len, unsigned char *dst) {
        |  unsigned char magic[4];
        |  unsigned int pos;
        |  if ((int_least64_t)len < (int_least64_t)sizeof(magic))
        |    return -1;
        |  pos = magic[0] + magic[1];
        |  return (int)pos;
        |}
        |""".stripMargin,
      "resign.cpp"
    )
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

  "a guard over a re-signing cast of a header's typedef" should {
      "fire on the spelled-out type" in {
          assume(edgaAvailable, "edga is not installed")
          findingsIn("resign_wide_spelled") should contain("MS-INT-002")
      }
      "cross signedness through the header's typedef as through the spelled-out type" in {
          assume(edgaAvailable, "edga is not installed")
          findingsIn("resign_wide_header_typedef") should contain("MS-INT-002")
      }
      "not fire on a cast of a constant that fits the type the header's typedef names" in {
          assume(edgaAvailable, "edga is not installed")
          findingsIn("resign_constant_through_header_typedef") shouldBe Set()
      }
  }
end ResignThroughHeaderTypedefTests
