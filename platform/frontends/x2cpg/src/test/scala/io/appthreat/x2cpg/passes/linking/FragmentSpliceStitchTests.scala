package io.appthreat.x2cpg.passes.linking

import io.appthreat.x2cpg.AstFragment
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.collection.mutable

/** End-to-end "fastest splice" (CHEN3_PLAN §3.4): two per-unit mini-graphs are serialized as
  * fragments, spliced STRAIGHT into a fresh graph via [[FragmentSplicePass]] (no re-parse, no diff
  * rebuild), and then linked across units by [[StitchPass]] - the serialized analogue of the
  * in-memory modular build.
  */
class FragmentSpliceStitchTests extends AnyWordSpec with Matchers:

  /** Unit a.c: `foo` makes a static call to `bar` (cross-unit; expressed as a methodFullName
    * property, resolved later by StitchPass - the fragment itself is self-contained).
    */
  private def unitFoo(): DiffGraphBuilder =
    val diff  = new DiffGraphBuilder
    val m     = NewMethod().name("foo").fullName("foo").signature("sig").filename("a.c").order(1)
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
  end unitFoo

  /** Unit b.c: declares `bar`. */
  private def unitBar(): DiffGraphBuilder =
    val diff  = new DiffGraphBuilder
    val m     = NewMethod().name("bar").fullName("bar").signature("s").filename("b.c").order(1)
    val block = NewBlock().typeFullName("ANY").order(1)
    diff.addNode(m); diff.addNode(block)
    diff.addEdge(m, block, EdgeTypes.AST)
    diff
  end unitBar

  "FragmentSplicePass + StitchPass" should:
    "restore units from fragments by direct splice and link them across units" in:
      val fragFoo = AstFragment.encode(unitFoo(), Seq("int")).get
      val fragBar = AstFragment.encode(unitBar(), Seq("com.example.Bar")).get

      val cpg            = Cpg.emptyCpg
      val registeredType = mutable.ArrayBuffer.empty[String]
      val splice =
          new FragmentSplicePass(cpg, Seq(fragFoo, fragBar), ts => registeredType ++= ts)
      splice.createAndApply()

      splice.splicedCount shouldBe 2
      cpg.method.fullNameExact("foo").size shouldBe 1
      cpg.method.fullNameExact("bar").size shouldBe 1
      registeredType.toSet shouldBe Set("int", "com.example.Bar")

      // No cross-unit CALL edge yet - it is the StitchPass's job.
      cpg.call.name("bar").out(EdgeTypes.CALL).size shouldBe 0

      new StitchPass(cpg).createAndApply()

      cpg.call.name("bar").out(EdgeTypes.CALL).collectAll[Method].fullName.toList should contain(
        "bar"
      )
end FragmentSpliceStitchTests
