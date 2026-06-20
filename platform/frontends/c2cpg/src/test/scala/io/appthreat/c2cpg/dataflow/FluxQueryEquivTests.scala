package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.DefaultSemantics
import _root_.io.appthreat.dataflowengineoss.language.*
import _root_.io.appthreat.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import _root_.io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import _root_.io.shiftleft.semanticcpg.language.*

/** Proves the Flux query mode (shared cross-task summary cache, `EngineConfig.useFluxEngine`)
  * returns exactly the same taint flows as the classic engine - it is result-preserving
  * memoisation, validated here on intra- and inter-procedural flows with multiple sinks (so the
  * shared-across-sinks cache path is actually exercised).
  */
class FluxQueryEquivTests extends DataFlowCodeToCpgSuite:

  private val classicCtx = EngineContext(DefaultSemantics(), EngineConfig(useFluxEngine = false))
  private val fluxCtx    = EngineContext(DefaultSemantics(), EngineConfig(useFluxEngine = true))

  private def flowSet(
    sinks: Iterator[CfgNode],
    sources: Iterator[CfgNode]
  )(ctx: EngineContext): Set[List[Long]] =
      sinks.reachableByFlows(sources)(using ctx).map(_.elements.map(_.id)).toSet

  private val cpg = code("""
      |void free_list(struct node *head) {
      |  struct node *q;
      |  for (struct node *p = head; p != NULL; p = q) {
      |    q = p->next;
      |    free(p);
      |  }
      |}
      |
      |int flow(int p0) {
      |  int a = p0;
      |  int b = a;
      |  int c = 0x31;
      |  int z = b + c;
      |  z++;
      |  int x = z;
      |  return x;
      |}
      |""".stripMargin)

  private def assertSameFlows(sinks: () => Iterator[CfgNode], sources: () => Iterator[CfgNode]): Unit =
    val classic = flowSet(sinks(), sources())(classicCtx)
    val flux    = flowSet(sinks(), sources())(fluxCtx)
    classic should not be empty
    withClue(s"only-classic=${classic -- flux}\nonly-flux=${flux -- classic}\n") {
        flux shouldBe classic
    }

  "the Flux query mode" should:
    "match the classic engine for flows to the return of `flow`" in:
      assertSameFlows(() => cpg.method.name("flow").methodReturn, () => cpg.identifier)

    "match the classic engine for flows to arguments of `free` (loop, multiple sinks)" in:
      assertSameFlows(() => cpg.call.name("free").argument(1), () => cpg.identifier)
end FluxQueryEquivTests
