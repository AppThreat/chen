package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.language.*
import _root_.io.shiftleft.semanticcpg.language.*

/** Validates the node-predicate flow filters `passesThrough` / `doesNotPassThrough`, which are the
  * friendly form of the older `passes` / `passesNot` traversal combinators.
  */
class FlowFilterTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |int sanitize(int x) { return x & 0xff; }
      |
      |int flow(int p0) {
      |  int a = sanitize(p0);   // this flow passes through sanitize()
      |  return a;
      |}
      |
      |int direct(int p1) {
      |  int b = p1;             // this flow does not
      |  return b;
      |}
      |""".stripMargin)

  private val sanitizeCallIds =
      cpg.call.name("sanitize").argument.id.toSet

  "doesNotPassThrough" should:
    "drop flows that pass through the sanitiser and keep the others" in:
      val allFlows =
          cpg.method.methodReturn.reachableByFlows(cpg.method.parameter).toList
      val sanitized = allFlows.iterator.passesThrough(n => sanitizeCallIds.contains(n.id)).toList
      val unsanitized =
          allFlows.iterator.doesNotPassThrough(n => sanitizeCallIds.contains(n.id)).toList

      sanitized should not be empty
      unsanitized should not be empty
      // The two are complementary partitions of the original flows.
      (sanitized.size + unsanitized.size) shouldBe allFlows.size
      // The p0 -> return flow goes through sanitize(); the p1 -> return flow does not.
      sanitized.exists(_.elements.exists(_.code.contains("p0"))) shouldBe true
      unsanitized.exists(_.elements.exists(_.code.contains("p1"))) shouldBe true
end FlowFilterTests
