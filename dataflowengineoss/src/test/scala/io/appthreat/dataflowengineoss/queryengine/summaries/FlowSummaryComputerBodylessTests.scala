package io.appthreat.dataflowengineoss.queryengine.summaries

import io.shiftleft.codepropertygraph.generated.nodes.{NewBlock, NewMethod, NewMethodReturn}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import overflowdb.BatchedUpdate.{DiffGraphBuilder, applyDiff}

/** A frontend may leave a bodyless METHOD (a native or stubbed one) without a BLOCK child. Picking
  * the method that speaks for a full name must not assume one (`method.block` throws "next on empty
  * iterator").
  */
class FlowSummaryComputerBodylessTests extends AnyWordSpec with Matchers:

  /** Adds a METHOD with a METHOD_RETURN and, optionally, a BLOCK holding one child. */
  private def addMethod(
    diff: DiffGraphBuilder,
    fullName: String,
    withBlock: Boolean,
    withBody: Boolean = false,
    line: Option[Int] = None
  ): NewMethod =
    val method = NewMethod().name(fullName.takeWhile(_ != ':')).fullName(fullName)
        .isExternal(false).filename("Demo.java")
    line.foreach(l => method.lineNumber(l))
    diff.addNode(method)
    if withBlock then
      val block = NewBlock().typeFullName("void")
      line.foreach(l => block.lineNumber(l))
      diff.addNode(block)
      diff.addEdge(method, block, EdgeTypes.AST)
      if withBody then
        val inner = NewBlock().typeFullName("void")
        diff.addNode(inner)
        diff.addEdge(block, inner, EdgeTypes.AST)
    val ret = NewMethodReturn().typeFullName("void").code("RET").evaluationStrategy("BY_VALUE")
    diff.addNode(ret)
    diff.addEdge(method, ret, EdgeTypes.AST)
    method
  end addMethod

  "FlowSummaryComputer.computeAll" should {
      "summarise a method that has no BLOCK" in {
          val cpg  = Cpg.emptyCpg
          val diff = new DiffGraphBuilder
          addMethod(diff, "demo.Bridge.stringFromJNI:java.lang.String()", withBlock = false)
          addMethod(diff, "demo.Bridge.verify:int()", withBlock = true, withBody = true)
          applyDiff(cpg.graph, diff)
          try
            val summaries = FlowSummaryComputer.computeAll(cpg)
            summaries.keySet shouldBe Set(
              "demo.Bridge.stringFromJNI:java.lang.String()",
              "demo.Bridge.verify:int()"
            )
            summaries("demo.Bridge.stringFromJNI:java.lang.String()").paramToReturn shouldBe empty
          finally cpg.close()
      }

      "prefer the definition over a BLOCK-less declaration of the same full name" in {
          val cpg  = Cpg.emptyCpg
          val diff = new DiffGraphBuilder
          addMethod(diff, "f:int(int)", withBlock = false)
          addMethod(diff, "f:int(int)", withBlock = true, withBody = true, line = Some(7))
          applyDiff(cpg.graph, diff)
          try FlowSummaryComputer.computeAll(cpg).keySet shouldBe Set("f:int(int)")
          finally cpg.close()
      }
  }
end FlowSummaryComputerBodylessTests
