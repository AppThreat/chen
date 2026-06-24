package io.appthreat.x2cpg.passes.linking

import io.appthreat.x2cpg.passes.base.MethodStubCreator
import io.appthreat.x2cpg.passes.callgraph.{DynamicCallLinker, MethodRefLinker, StaticCallLinker}
import io.appthreat.x2cpg.passes.typerelations.{AliasLinkerPass, TypeHierarchyPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes, PropertyNames}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder
import overflowdb.util.DiffTool
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.jdk.CollectionConverters.*

/** Proves the modular link phase ([[StitchPass]]) produces the same graph as the whole-graph
  * linking it replaces (`MethodStubCreator` + `StaticCallLinker` + `MethodRefLinker` +
  * `TypeHierarchyPass` + `AliasLinkerPass`) - the graph-equivalence oracle of CHEN3_PLAN §8 - and
  * that it can be scoped to dirty units for incremental re-stitch.
  */
class StitchPassTests extends AnyWordSpec with Matchers:

  /** A small two-unit CPG exercising every edge kind StitchPass realizes:
    *   - file a.c declares `foo`, file b.c declares `bar`;
    *   - `foo` calls `bar` (resolvable cross-unit, static), `ext` (unresolved, static) and `dyn`
    *     (unresolved, dynamic), and holds a `METHOD_REF` to `bar`;
    *   - a `Derived` type decl inherits from TYPE `Base` and aliases TYPE `Aliased`.
    */
  private def buildBase(): Cpg =
    val cpg  = Cpg.emptyCpg
    val diff = new DiffGraphBuilder

    def method(name: String, file: String): (NewMethod, NewBlock) =
      val m     = NewMethod().name(name).fullName(name).signature(s"sig_$name").filename(file).order(1)
      val block = NewBlock().typeFullName("ANY").order(1)
      val file0 = NewFile().name(file)
      diff.addNode(m); diff.addNode(block); diff.addNode(file0)
      diff.addEdge(m, block, EdgeTypes.AST)
      diff.addEdge(m, file0, EdgeTypes.SOURCE_FILE)
      (m, block)

    val (foo, fooBlock) = method("foo", "a.c")
    method("bar", "b.c")

    def callInFoo(name: String, dispatch: String, argCount: Int): NewCall =
      val call = NewCall()
          .name(name)
          .methodFullName(name)
          .signature(s"sig_$name")
          .dispatchType(dispatch)
          .code(s"$name()")
          .order(1)
      diff.addNode(call)
      diff.addEdge(fooBlock, call, EdgeTypes.AST)
      diff.addEdge(foo, call, EdgeTypes.CONTAINS)
      (1 to argCount).foreach { i =>
          val arg = NewIdentifier().name(s"a$i").code(s"a$i").argumentIndex(i).order(i)
          diff.addNode(arg)
          diff.addEdge(call, arg, EdgeTypes.AST)
          diff.addEdge(call, arg, EdgeTypes.ARGUMENT)
      }
      call

    callInFoo("bar", DispatchTypes.STATIC_DISPATCH, 1)
    callInFoo("ext", DispatchTypes.STATIC_DISPATCH, 2)
    callInFoo("dyn", DispatchTypes.DYNAMIC_DISPATCH, 1)

    // A METHOD_REF to bar (for REF linking).
    val ref = NewMethodRef().methodFullName("bar").typeFullName("ANY").code("&bar").order(2)
    diff.addNode(ref)
    diff.addEdge(fooBlock, ref, EdgeTypes.AST)

    // Type relations: Derived inherits from / aliases types declared elsewhere.
    val baseType    = NewType().name("Base").fullName("Base")
    val aliasedType = NewType().name("Aliased").fullName("Aliased")
    val derived = NewTypeDecl()
        .name("Derived")
        .fullName("Derived")
        .filename("b.c")
        .inheritsFromTypeFullName(Seq("Base"))
        .aliasTypeFullName("Aliased")
    diff.addNode(baseType); diff.addNode(aliasedType); diff.addNode(derived)

    overflowdb.BatchedUpdate.applyDiff(cpg.graph, diff)
    cpg
  end buildBase

  "StitchPass" should:

    "produce the same graph as the whole-graph linking passes" in:
      val viaPasses = buildBase()
      // The Base overlay creates this index before the LinkingUtil-based passes run.
      viaPasses.graph.indexManager.createNodePropertyIndex(PropertyNames.FULL_NAME)
      new MethodStubCreator(viaPasses).createAndApply()
      new TypeHierarchyPass(viaPasses).createAndApply()
      new AliasLinkerPass(viaPasses).createAndApply()
      new MethodRefLinker(viaPasses).createAndApply()
      new StaticCallLinker(viaPasses).createAndApply()
      new DynamicCallLinker(viaPasses).createAndApply()

      val viaStitch = buildBase()
      new StitchPass(viaStitch).createAndApply()

      val diff = DiffTool.compare(viaPasses.graph, viaStitch.graph).asScala.toList
      withClue(diff.mkString("\n")) {
          diff shouldBe empty
      }

    "realize calls, refs, inheritance, aliases and synthesize external stubs" in:
      val cpg  = buildBase()
      val pass = new StitchPass(cpg)
      pass.createAndApply()

      cpg.method.fullNameExact("ext").isExternal.headOption shouldBe Some(true)
      cpg.method.fullNameExact("dyn").isExternal.headOption shouldBe Some(true)
      cpg.method.fullNameExact("bar").isExternal.headOption shouldBe Some(false)

      cpg.call.name("bar").out(EdgeTypes.CALL).size shouldBe 1
      cpg.call.name("ext").out(EdgeTypes.CALL).size shouldBe 1
      // the dynamic call resolves to its synthesized stub via DynamicCallLinker's fallback
      cpg.call.name("dyn").out(EdgeTypes.CALL).size shouldBe 1
      cpg.methodRef.out(EdgeTypes.REF).size shouldBe 1
      cpg.typeDecl.name("Derived").out(EdgeTypes.INHERITS_FROM).size shouldBe 1
      cpg.typeDecl.name("Derived").out(EdgeTypes.ALIAS_OF).size shouldBe 1

      pass.synthesizedStubs shouldBe 2
      pass.realizedEdges shouldBe 2 // static CALL edges (bar, ext)

    "scope work to dirty units when given" in:
      val clean = new StitchPass(buildBase(), dirtyUnits = Some(Set("b.c")))
      clean.createAndApply()
      clean.realizedEdges shouldBe 0
      clean.synthesizedStubs shouldBe 0

      val dirty = new StitchPass(buildBase(), dirtyUnits = Some(Set("a.c")))
      dirty.createAndApply()
      dirty.realizedEdges shouldBe 2
      dirty.synthesizedStubs shouldBe 2
end StitchPassTests
