package io.appthreat.x2cpg.passes.linking

import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.passes.base.MethodStubCreator.createMethodStub
import io.appthreat.x2cpg.passes.callgraph.DynamicCallLinker
import io.appthreat.x2cpg.passes.frontend.Dereference
import io.appthreat.x2cpg.utils.LinkingUtil
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{
    AstNode,
    Call,
    Method,
    MethodRef,
    Type,
    TypeDecl
}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes, NodeTypes, PropertyNames}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable

/** The link phase (CHEN3_PLAN §3.2) for the in-memory CPG.
  *
  * A single, [[SymbolIndex]]-backed orchestrator that resolves the cross-unit references whose cost
  * is dominated by FQN lookups into real edges, and synthesizes external stubs for unresolved
  * targets. It is a drop-in replacement for the combination of
  *
  *   - [[io.appthreat.x2cpg.passes.base.MethodStubCreator]] (external method stubs),
  *   - [[io.appthreat.x2cpg.passes.callgraph.StaticCallLinker]] (static/inlined `CALL`),
  *   - [[io.appthreat.x2cpg.passes.callgraph.MethodRefLinker]] (`METHOD_REF` → `REF`),
  *   - [[io.appthreat.x2cpg.passes.typerelations.TypeHierarchyPass]] (`INHERITS_FROM`),
  *   - [[io.appthreat.x2cpg.passes.typerelations.AliasLinkerPass]] (`ALIAS_OF`).
  *
  * Each of those passes independently re-scans the graph and resolves destinations through the
  * `FULL_NAME` index one lookup at a time; this pass builds one [[SymbolIndex]] and reuses it for
  * all of them. To stay byte-for-byte equivalent it reuses the very same `LinkingUtil` routines for
  * the type/ref edges (so dereferencing, the `hasOut` guard, default-value filtering and the
  * fallback lookup all match exactly) - only the per-lookup `FULL_NAME` index access is replaced by
  * the prebuilt map.
  *
  * It runs in two phases, mirroring the current pipeline, where `MethodStubCreator` (Base overlay)
  * commits its stubs before the call/ref linkers (CallGraph overlay) run and resolve against them:
  *   1. '''Stub synthesis''' - commit external method stubs, then fold them into the index.
  *   1. '''Edge realization''' - static `CALL`, `REF`, `INHERITS_FROM`, `ALIAS_OF`.
  *
  * Dynamic dispatch is intentionally left to
  * [[io.appthreat.x2cpg.passes.callgraph.DynamicCallLinker]]: its cost is inheritance-hierarchy
  * traversal, not FQN lookup, so the index does not help it.
  *
  * '''Incremental mode.''' When `dirtyUnits` is given, only call sites whose enclosing unit (source
  * file) is dirty are (re)stitched, and the whole-graph type/ref relinking is skipped - the work is
  * then proportional to the change (CHEN3_PLAN §4). Leave it `None` for a full stitch.
  */
class StitchPass(cpg: Cpg, dirtyUnits: Option[Set[String]] = None):

  /** Number of static `CALL` edges realized in the last run; useful for incremental telemetry. */
  @volatile var realizedEdges: Int = 0

  /** Number of external stubs synthesized in the last run. */
  @volatile var synthesizedStubs: Int = 0

  def createAndApply(): Unit =
    val index = SymbolIndex(cpg)

    val stubPass = new StitchPass.StubSynthesisPass(cpg, index, dirtyUnits)
    stubPass.createAndApply()
    synthesizedStubs = stubPass.synthesizedStubs

    // Fold the just-committed stubs into the index so the edge phase resolves to them exactly as
    // StaticCallLinker / MethodRefLinker would once MethodStubCreator's stubs are committed.
    stubPass.synthesizedFullNames.foreach { fn =>
        cpg.method.fullNameExact(fn).foreach(m => index.addMethod(fn, m))
    }

    val edgePass = new StitchPass.EdgeRealizationPass(cpg, index, dirtyUnits)
    edgePass.createAndApply()
    realizedEdges = edgePass.realizedEdges

    // Phase 3: virtual dispatch. Its cost is hierarchy traversal, but it still consumes the shared
    // index for its type/method maps, avoiding two more whole-graph scans. Full stitch only.
    if dirtyUnits.isEmpty then
      new DynamicCallLinker(cpg, Some(index)).createAndApply()
  end createAndApply
end StitchPass

object StitchPass:

  private case class StubKey(
    name: String,
    signature: String,
    fullName: String,
    dispatchType: String
  )

  /** The unit (source file) an AST node belongs to, resolved by walking AST parents to the
    * enclosing method. This works on a raw frontend CPG, unlike `Call.method`, which needs the
    * `CONTAINS` edges only added by the Base overlay.
    */
  private def unitOf(node: AstNode): Option[String] =
      node.inAst.collectFirst { case m: Method => m }
          .map(_.filename)
          .filter(f => f != null && f.nonEmpty)

  private def callsToConsider(cpg: Cpg, dirtyUnits: Option[Set[String]]): Iterator[Call] =
      dirtyUnits match
        case None        => cpg.call.iterator
        case Some(dirty) => cpg.call.iterator.filter(c => unitOf(c).exists(dirty.contains))

  /** Phase 1: synthesize an external stub per distinct `(name, signature, fullName, dispatchType)`
    * whose full name is not a declared method - matching `MethodStubCreator`'s keying exactly.
    */
  private class StubSynthesisPass(
    cpg: Cpg,
    index: SymbolIndex,
    dirtyUnits: Option[Set[String]]
  ) extends CpgPass(cpg):

    var synthesizedStubs: Int = 0
    val synthesizedFullNames  = mutable.LinkedHashSet.empty[String]

    override def run(dstGraph: DiffGraphBuilder): Unit =
      val summaries = mutable.LinkedHashMap.empty[StubKey, Int]
      callsToConsider(cpg, dirtyUnits).foreach { call =>
          if call.methodFullName != Defines.DynamicCallUnknownFullName then
            summaries.put(
              StubKey(call.name, call.signature, call.methodFullName, call.dispatchType),
              call.argument.size
            )
      }
      summaries.foreach { case (key, parameterCount) =>
          if !index.hasMethod(key.fullName) then
            createMethodStub(
              key.name,
              key.fullName,
              key.signature,
              key.dispatchType,
              parameterCount,
              dstGraph
            )
            synthesizedFullNames += key.fullName
            synthesizedStubs += 1
      }
    end run
  end StubSynthesisPass

  /** Phase 2: realize static `CALL` edges (index-backed) and, in a full stitch, the `REF`,
    * `INHERITS_FROM` and `ALIAS_OF` edges via the shared `LinkingUtil` routines.
    */
  private class EdgeRealizationPass(
    cpg: Cpg,
    index: SymbolIndex,
    dirtyUnits: Option[Set[String]]
  ) extends CpgPass(cpg) with LinkingUtil:

    var realizedEdges: Int = 0

    override def run(dstGraph: DiffGraphBuilder): Unit =
      // Static / inlined dispatch (replaces StaticCallLinker).
      callsToConsider(cpg, dirtyUnits).foreach { call =>
          call.dispatchType match
            case DispatchTypes.STATIC_DISPATCH | DispatchTypes.INLINED =>
                index.methods(call.methodFullName).foreach { dst =>
                  dstGraph.addEdge(call, dst, EdgeTypes.CALL)
                  realizedEdges += 1
                }
            case _ =>
      }

      dirtyUnits match
        case None        => linkTypeAndRefEdgesFull(dstGraph)
        case Some(dirty) => linkTypeAndRefEdgesDirty(dstGraph, dirty)

    /** Full stitch: reuse the shared `LinkingUtil` routines verbatim (so dereferencing, the
      * `hasOut` guard, default-value filtering and the fallback lookup all match the original
      * passes exactly), with only the per-lookup `FULL_NAME` index access replaced by the index.
      */
    private def linkTypeAndRefEdgesFull(dstGraph: DiffGraphBuilder): Unit =
      // METHOD_REF -> REF (replaces MethodRefLinker).
      linkToSingle(
        cpg,
        srcLabels = List(NodeTypes.METHOD_REF),
        dstNodeLabel = NodeTypes.METHOD,
        edgeType = EdgeTypes.REF,
        dstNodeMap = index.methodNode,
        dstFullNameKey = PropertyNames.METHOD_FULL_NAME,
        dstGraph,
        None
      )

      // TYPE_DECL -> TYPE INHERITS_FROM (replaces TypeHierarchyPass).
      linkToMultiple[TypeDecl](
        cpg,
        srcLabels = List(NodeTypes.TYPE_DECL),
        dstNodeLabel = NodeTypes.TYPE,
        edgeType = EdgeTypes.INHERITS_FROM,
        dstNodeMap = index.typeNode,
        getDstFullNames = (td: TypeDecl) =>
            if td.inheritsFromTypeFullName != null then td.inheritsFromTypeFullName else Seq.empty,
        dstFullNameKey = PropertyNames.INHERITS_FROM_TYPE_FULL_NAME,
        dstGraph
      )

      // TYPE_DECL -> TYPE ALIAS_OF (replaces AliasLinkerPass).
      linkToMultiple[TypeDecl](
        cpg,
        srcLabels = List(NodeTypes.TYPE_DECL),
        dstNodeLabel = NodeTypes.TYPE,
        edgeType = EdgeTypes.ALIAS_OF,
        dstNodeMap = index.typeNode,
        getDstFullNames = (td: TypeDecl) => td.aliasTypeFullName,
        dstFullNameKey = PropertyNames.ALIAS_TYPE_FULL_NAME,
        dstGraph
      )
    end linkTypeAndRefEdgesFull

    /** Incremental stitch: realize REF / INHERITS_FROM / ALIAS_OF only for source nodes located in
      * a dirty unit, so the work is proportional to the change. Uses the index for resolution and
      * the same dereference rule as the full path.
      */
    private def linkTypeAndRefEdgesDirty(dstGraph: DiffGraphBuilder, dirty: Set[String]): Unit =
      val dereference = Dereference(cpg)
      def resolveType(raw: String): Option[Type] =
        val deref = dereference.dereferenceTypeFullName(raw)
        index.types(deref).headOption.orElse(index.types(raw).headOption)

      cpg.methodRef.foreach { mr =>
          if mr.out(EdgeTypes.REF).isEmpty && unitOf(mr).exists(dirty.contains) then
            val raw   = mr.methodFullName
            val deref = dereference.dereferenceTypeFullName(raw)
            index.methods(deref).headOption.orElse(index.methods(raw).headOption).foreach { m =>
                dstGraph.addEdge(mr, m, EdgeTypes.REF)
            }
      }

      cpg.typeDecl.foreach { td =>
          if td.filename != null && dirty.contains(td.filename) then
            if td.out(EdgeTypes.INHERITS_FROM).isEmpty && td.inheritsFromTypeFullName != null then
              td.inheritsFromTypeFullName.foreach { raw =>
                  resolveType(raw).foreach(t => dstGraph.addEdge(td, t, EdgeTypes.INHERITS_FROM))
              }
            if td.out(EdgeTypes.ALIAS_OF).isEmpty then
              td.aliasTypeFullName.foreach { raw =>
                  resolveType(raw).foreach(t => dstGraph.addEdge(td, t, EdgeTypes.ALIAS_OF))
              }
      }
    end linkTypeAndRefEdgesDirty
  end EdgeRealizationPass
end StitchPass
