package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.DefaultSemantics
import _root_.io.appthreat.dataflowengineoss.passes.reachingdef.{FluxReachingDefPass, ReachingDefPass}
import _root_.io.appthreat.dataflowengineoss.semanticsloader.Semantics
import _root_.io.shiftleft.codepropertygraph.Cpg
import _root_.io.shiftleft.codepropertygraph.generated.{EdgeTypes, PropertyNames}
import _root_.io.shiftleft.passes.CpgPassBase
import overflowdb.BatchedUpdate.{CreateEdge, DiffGraphBuilder}

import scala.jdk.CollectionConverters.*

/** Proves the Flux reaching-def engine ([[FluxReachingDefPass]]) produces exactly the same
  * `REACHING_DEF` edges as the classic [[ReachingDefPass]].
  *
  * Both passes run via `runWithBuilder` against the same, unmutated CPG, so the existing node IDs
  * are identical and the produced edges can be compared directly as `(srcId, dstId, variable)`
  * tuples.
  */
class FluxReachingDefEquivTests extends CCodeToCpgSuite:

  private given Semantics = Semantics.fromList(DefaultSemantics().elements)

  private def reachingDefEdges(cpg: Cpg, pass: CpgPassBase): Set[(Long, Long, String)] =
    val diff = new DiffGraphBuilder
    pass.runWithBuilder(diff)
    diff.iterator().asScala.collect {
        case e: CreateEdge if e.label == EdgeTypes.REACHING_DEF =>
            val src = e.src.asInstanceOf[overflowdb.Node].id()
            val dst = e.dst.asInstanceOf[overflowdb.Node].id()
            val variable = Option(e.propertiesAndKeys)
                .flatMap {
                    _.grouped(2).collectFirst {
                        case Array(k, v) if k == PropertyNames.VARIABLE => String.valueOf(v)
                    }
                }
                .getOrElse("")
            (src, dst, variable)
    }.toSet

  "the Flux reaching-def engine" should:
    "produce identical REACHING_DEF edges to the classic engine" in:
      val cpg = code("""
          |int foo(int a, int b) {
          |  int x = a;
          |  if (b > 0) { x = b; }
          |  int y = x + 1;
          |  while (y < 100) { y = y + x; a = a + 1; }
          |  return y + a;
          |}
          |""".stripMargin)

      val classic = reachingDefEdges(cpg, new ReachingDefPass(cpg))
      val flux    = reachingDefEdges(cpg, new FluxReachingDefPass(cpg))

      flux should not be empty
      withClue(
        s"only-classic=${(classic -- flux).toList.sorted}\nonly-flux=${(flux -- classic).toList.sorted}\n"
      ) {
          flux shouldBe classic
      }
end FluxReachingDefEquivTests
