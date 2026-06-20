package io.appthreat.x2cpg.passes.linking

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.SchemaInfo
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate
import overflowdb.BatchedUpdate.DiffGraphBuilder
import overflowdb.storage.GraphFragmentCodec
import overflowdb.util.DiffTool
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.jdk.CollectionConverters.*

/** Validates that the overflowdb2 3.0.2 fragment foundation (GraphFragmentCodec / applyFragment)
  * works for chen's cpg2 schema and node types - the substrate for serialized mini-graph stitching
  * (CHEN3_PLAN §3):
  *   - a self-contained frontend diff round-trips through encode -> applyFragment, producing a
  *     graph identical (DiffTool) to directly applying the diff;
  *   - a cross-unit boundary edge is recorded with a symbolic key and resolved back to the live
  *     target node via a [[SymbolIndex]]-backed [[SymbolIndexBoundaryResolver]].
  */
class FragmentStitchTests extends AnyWordSpec with Matchers:

  private val schemaHash = SchemaInfo.schemaHash

  /** A self-contained unit: method `foo` with a block, a call and an argument; all edges are
    * intra-fragment.
    */
  private def selfContainedUnit(): DiffGraphBuilder =
    val diff = new DiffGraphBuilder
    val m     = NewMethod().name("foo").fullName("foo").signature("sig").order(1)
    val block = NewBlock().typeFullName("ANY").order(1)
    val call  = NewCall().name("bar").methodFullName("bar").signature("s")
        .dispatchType(DispatchTypes.STATIC_DISPATCH).code("bar(x)").order(1)
    val arg = NewIdentifier().name("x").code("x").argumentIndex(1).order(1)
    diff.addNode(m); diff.addNode(block); diff.addNode(call); diff.addNode(arg)
    diff.addEdge(m, block, EdgeTypes.AST)
    diff.addEdge(block, call, EdgeTypes.AST)
    diff.addEdge(call, arg, EdgeTypes.AST)
    diff.addEdge(call, arg, EdgeTypes.ARGUMENT)
    diff
  end selfContainedUnit

  "the fragment foundation" should:

    "round-trip a chen frontend diff (encode -> applyFragment == direct apply)" in:
      val bytes = GraphFragmentCodec.encode(selfContainedUnit(), NoBoundaryResolver, schemaHash)
      bytes.isPresent shouldBe true

      val direct = Cpg.emptyCpg
      BatchedUpdate.applyDiff(direct.graph, selfContainedUnit())

      val viaFragment = Cpg.emptyCpg
      BatchedUpdate.applyFragment(viaFragment.graph, bytes.get, schemaHash, NoBoundaryResolver, null)

      val diff = DiffTool.compare(direct.graph, viaFragment.graph).asScala.toList
      withClue(diff.mkString("\n")) { diff shouldBe empty }

    "resolve a cross-unit boundary edge to a live node via the SymbolIndex" in:
      // Target graph already exports method `bar`.
      val cpg  = Cpg.emptyCpg
      val seed = new DiffGraphBuilder
      seed.addNode(NewMethod().name("bar").fullName("bar").signature("s").order(1))
      BatchedUpdate.applyDiff(cpg.graph, seed)
      val index     = SymbolIndex(cpg)
      val barStored = cpg.method.fullNameExact("bar").head

      // A unit fragment whose call edges out to the external `bar` (not part of this fragment).
      val unit = new DiffGraphBuilder
      val foo  = NewMethod().name("foo").fullName("foo").signature("sig").order(1)
      val call = NewCall().name("bar").methodFullName("bar").signature("s")
          .dispatchType(DispatchTypes.STATIC_DISPATCH).code("bar()").order(1)
      unit.addNode(foo); unit.addNode(call)
      unit.addEdge(foo, call, EdgeTypes.AST)
      unit.addEdge(call, barStored, EdgeTypes.CALL) // boundary: dst is external

      val resolver = new SymbolIndexBoundaryResolver(index)
      val bytes    = GraphFragmentCodec.encode(unit, resolver, schemaHash)
      bytes.isPresent shouldBe true

      BatchedUpdate.applyFragment(cpg.graph, bytes.get, schemaHash, resolver, null)

      // The spliced call resolved its boundary edge back to the live `bar`.
      cpg.method.fullNameExact("foo").size shouldBe 1
      cpg.call.name("bar").out(EdgeTypes.CALL).collectAll[Method].fullName.toList should contain(
        "bar"
      )
end FragmentStitchTests
