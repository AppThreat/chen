package io.appthreat.x2cpg.passes.linking

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Method, StoredNode, Type, TypeDecl}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Symbol kinds that can appear at a unit/fragment boundary. Mirrors the `SymbolicKey.kind` of the
  * overflowdb2 fragment foundation, so the in-memory stitch and a future serialized stitch share
  * one address space.
  */
object SymbolKind:
  final val Method         = "METHOD"
  final val TypeDecl       = "TYPE_DECL"
  final val Type           = "TYPE"
  final val NamespaceBlock = "NAMESPACE_BLOCK"

/** Stable, ID-independent address of a symbol exported by a unit.
  *
  * `(kind, fqName, arity)` is intentionally the same shape as the overflowdb2 `SymbolicKey`, so
  * cross-unit references survive ID-space changes and cache reuse. `arity` is `-1` when not
  * applicable (e.g. types).
  */
case class SymbolicKey(kind: String, fqName: String, arity: Int = -1)

/** A global, FQN-keyed view of every symbol a set of mini-graphs (units) export.
  *
  * Built once from the live CPG and consumed by [[StitchPass]] for cross-unit edge realization,
  * replacing the per-pass, repeated `cpg.graph.indexManager.lookup(FULL_NAME, ...)` /
  * `cpg.method.fullNameExact(...)` calls that each linking pass performs independently today.
  *
  * Besides the lookup maps it records, per unit (source file), the set of FQNs that unit exports.
  * That `unitExports` table is the boundary interface needed for incremental re-stitching
  * (CHEN3_PLAN §3.2/§4): when a file changes, only call sites in dirty units and edges that
  * targeted symbols whose defining unit changed need to be re-resolved.
  */
class SymbolIndex private (
  private val methodsByFullName: mutable.Map[String, mutable.ArrayBuffer[Method]],
  private val typeDeclsByFullName: mutable.Map[String, mutable.ArrayBuffer[TypeDecl]],
  private val typesByFullName: mutable.Map[String, mutable.ArrayBuffer[Type]],
  val unitExports: Map[String, Set[String]]
):

  /** Methods declared with this exact full name (usually one; fuzzy frontends may yield several).
    */
  def methods(fullName: String): Seq[Method] =
      methodsByFullName.get(fullName).map(_.toSeq).getOrElse(Seq.empty)

  def hasMethod(fullName: String): Boolean = methodsByFullName.contains(fullName)

  def typeDecls(fullName: String): Seq[TypeDecl] =
      typeDeclsByFullName.get(fullName).map(_.toSeq).getOrElse(Seq.empty)

  def types(fullName: String): Seq[Type] =
      typesByFullName.get(fullName).map(_.toSeq).getOrElse(Seq.empty)

  def methodFullNames: collection.Set[String] = methodsByFullName.keySet

  /** Resolve a method full name to a single node (the first declared), as a `StoredNode` - the
    * shape `LinkingUtil.linkToSingle` / `linkToMultiple` expect for their `dstNodeMap`.
    */
  def methodNode(fullName: String): Option[StoredNode] = methods(fullName).headOption

  /** Resolve a type full name to a single TYPE node, for `linkToMultiple`'s `dstNodeMap`. */
  def typeNode(fullName: String): Option[StoredNode] = types(fullName).headOption

  /** Register a symbol created during stitching (e.g. an external method stub committed in an
    * earlier phase) so subsequent lookups in the same stitch resolve to it, mirroring how a
    * committed stub is visible to a later linking pass in the current pipeline.
    */
  def addMethod(fullName: String, method: Method): Unit =
      methodsByFullName.getOrElseUpdate(fullName, mutable.ArrayBuffer.empty) += method

  /** `fullName -> TypeDecl`, last declaration winning - exactly what `cpg.typeDecl.map(td =>
    * td.fullName -> td).toMap` produces, but without re-traversing the graph. Consumed by
    * [[io.appthreat.x2cpg.passes.callgraph.DynamicCallLinker]] when it is run as part of a shared
    * stitch.
    */
  def typeDeclMap: Map[String, TypeDecl] =
      typeDeclsByFullName.view.mapValues(_.last).toMap

  /** `fullName -> Method` excluding `<operator>` methods, last declaration winning - matching
    * `cpg.method.filterNot(_.name.startsWith("<operator>")).map(m => m.fullName -> m).toMap`
    * without re-traversing the graph. A full name with only operator methods is absent.
    */
  def nonOperatorMethodMap: Map[String, Method] =
    val builder = Map.newBuilder[String, Method]
    methodsByFullName.foreach { case (fullName, ms) =>
        ms.reverseIterator.find(m => !m.name.startsWith("<operator>")).foreach { m =>
            builder += fullName -> m
        }
    }
    builder.result()
end SymbolIndex

object SymbolIndex:

  /** Build the index from the live CPG in a single scan over methods, type declarations and types.
    */
  def apply(cpg: Cpg): SymbolIndex =
    val methodsByFullName   = mutable.Map.empty[String, mutable.ArrayBuffer[Method]]
    val typeDeclsByFullName = mutable.Map.empty[String, mutable.ArrayBuffer[TypeDecl]]
    val typesByFullName     = mutable.Map.empty[String, mutable.ArrayBuffer[Type]]
    val exports             = mutable.Map.empty[String, mutable.Set[String]]

    def recordExport(filename: String, fqName: String): Unit =
        if filename != null && filename.nonEmpty then
          exports.getOrElseUpdate(filename, mutable.Set.empty) += fqName

    cpg.method.foreach { m =>
      val fullName = m.fullName
      methodsByFullName.getOrElseUpdate(fullName, mutable.ArrayBuffer.empty) += m
      recordExport(m.filename, fullName)
    }
    cpg.typeDecl.foreach { td =>
      val fullName = td.fullName
      typeDeclsByFullName.getOrElseUpdate(fullName, mutable.ArrayBuffer.empty) += td
      recordExport(td.filename, fullName)
    }
    cpg.typ.foreach { t =>
        typesByFullName.getOrElseUpdate(t.fullName, mutable.ArrayBuffer.empty) += t
    }

    new SymbolIndex(
      methodsByFullName,
      typeDeclsByFullName,
      typesByFullName,
      exports.view.mapValues(_.toSet).toMap
    )
  end apply
end SymbolIndex
