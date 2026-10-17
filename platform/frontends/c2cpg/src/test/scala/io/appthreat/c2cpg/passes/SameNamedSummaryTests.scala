package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{AllocationStatePass, MemoryApiPass, MemorySemanticsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** Same-named static functions in different units, one reading through its parameter and one not: a
  * call by that name cannot tell which it reaches, so neither one's conclusion is the name's,
  * whichever of them the graph lists last.
  */
class SameNamedSummaryTests extends DataFlowCodeToCpgSuite:

  private val reads =
      """
        |static int sink(int *data) { return data[0]; }
        |int use_reading(int *p) { return sink(p); }
        |""".stripMargin
  private val ignores =
      """
        |static int sink(int *data) { return data == 0; }
        |int use_ignoring(int *p) { return sink(p); }
        |""".stripMargin

  private def withPasses(graph: Cpg): Cpg =
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    graph

  private lazy val readerFirst  = withPasses(code(reads, "a.c").moreCode(ignores, "b.c"))
  private lazy val readerSecond = withPasses(code(ignores, "a.c").moreCode(reads, "b.c"))

  private def derefSummaries(cpg: Cpg): List[String] =
      cpg.method.nameExact("sink").tag.name(AllocationStatePass.TagEffect).value.l
          .filter(_.contains("derefs-param"))

  "a name two units' static functions share" should {
      "carry no dereference summary when they disagree, in either order" in {
          derefSummaries(readerFirst) shouldBe empty
          derefSummaries(readerSecond) shouldBe empty
      }
  }
end SameNamedSummaryTests
