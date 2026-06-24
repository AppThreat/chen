package io.appthreat.x2cpg

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes}
import overflowdb.BatchedUpdate
import overflowdb.BatchedUpdate.DiffGraphBuilder
import overflowdb.util.DiffTool
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.jdk.CollectionConverters.*

/** Validates the [[AstFragment]] codec (the GraphFragmentCodec-backed successor to [[AstCache]]):
  * a frontend diff + `usedTypes` round-trips losslessly, reconstruction into a diff graph matches a
  * direct apply (DiffTool), and corrupt/incompatible bytes are rejected so the caller recomputes.
  */
class AstFragmentTests extends AnyWordSpec with Matchers:

  private def unit(): DiffGraphBuilder =
    val diff = new DiffGraphBuilder
    val m     = NewMethod().name("foo").fullName("foo").signature("sig").order(1)
    val block = NewBlock().typeFullName("ANY").order(1)
    val call  = NewCall().name("bar").methodFullName("bar").signature("s")
        .dispatchType(DispatchTypes.STATIC_DISPATCH).code("bar(x)").order(2)
    // a long > 2^53 exercises the lossless typed value codec
    val lit = NewLiteral().code("9007199254740993").typeFullName("long").order(1)
    diff.addNode(m); diff.addNode(block); diff.addNode(call); diff.addNode(lit)
    diff.addEdge(m, block, EdgeTypes.AST)
    diff.addEdge(block, call, EdgeTypes.AST)
    diff.addEdge(call, lit, EdgeTypes.AST)
    diff.addEdge(call, lit, EdgeTypes.ARGUMENT)
    diff
  end unit

  "AstFragment" should:

    "round-trip a diff + usedTypes (decode into diff graph == direct apply)" in:
      val usedTypes = Seq("int", "com.example.MyType")
      val bytes     = AstFragment.encode(unit(), usedTypes)
      bytes shouldBe defined

      val restored = new DiffGraphBuilder
      AstFragment.decodeIntoDiffGraph(bytes.get, restored) shouldBe Some(usedTypes)

      val direct = Cpg.emptyCpg
      BatchedUpdate.applyDiff(direct.graph, unit())
      val viaFragment = Cpg.emptyCpg
      BatchedUpdate.applyDiff(viaFragment.graph, restored)

      val diff = DiffTool.compare(direct.graph, viaFragment.graph).asScala.toList
      withClue(diff.mkString("\n")) { diff shouldBe empty }

    "reject corrupt bytes so the caller recomputes" in:
      AstFragment.decodeIntoDiffGraph(Array[Byte](1, 2, 3, 4), new DiffGraphBuilder) shouldBe None
end AstFragmentTests
