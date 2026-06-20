package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryComputer
import _root_.io.appthreat.dataflowengineoss.semanticsloader.{
    FlowSemantic,
    FlowMapping,
    PassThroughMapping,
    Semantics
}
import _root_.io.shiftleft.semanticcpg.language.*

/** Validates that a declared flow semantic makes a method's own summary authoritative: a sanitizer
  * (a semantic with no mappings) summarises as carrying nothing to its return, a pass-through
  * forwards every non-receiver argument, and an explicit mapping records exactly that flow. These
  * facts override whatever the method body would otherwise imply.
  */
class FlowSummarySemanticsTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |int propagate(int p, int q) { return p; }   // body: p -> return
      |""".stripMargin)

  private val fqn  = cpg.method.name("propagate").fullName.head
  private val pIdx = cpg.method.name("propagate").parameter.name("p").index.head
  private val qIdx = cpg.method.name("propagate").parameter.name("q").index.head

  "A declared flow semantic" should:
    "make the body-derived flow visible when no semantic is declared" in:
      val summaries = FlowSummaryComputer.computeAll(cpg)
      summaries(fqn).paramToReturn should contain(pIdx)

    "summarise a declared sanitizer as carrying nothing to the return" in:
      val semantics = Semantics.fromList(List(FlowSemantic(fqn, List.empty)))
      val summary   = FlowSummaryComputer.computeAll(cpg, semantics)(fqn)
      summary.paramToReturn shouldBe empty
      summary.returnTaintable shouldBe false

    "forward every non-receiver argument for a pass-through semantic" in:
      val semantics = Semantics.fromList(List(FlowSemantic(fqn, List(PassThroughMapping))))
      val summary   = FlowSummaryComputer.computeAll(cpg, semantics)(fqn)
      summary.paramToReturn should contain(pIdx)
      summary.paramToReturn should contain(qIdx)

    "record exactly the declared explicit mapping" in:
      // Only q -> return is declared, so p must not appear even though the body returns p.
      val semantics = Semantics.fromList(List(FlowSemantic(fqn, List(FlowMapping(qIdx, -1)))))
      val summary   = FlowSummaryComputer.computeAll(cpg, semantics)(fqn)
      summary.paramToReturn shouldBe Set(qIdx)
end FlowSummarySemanticsTests
