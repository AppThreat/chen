package io.appthreat.x2cpg.passes.linking

import io.shiftleft.codepropertygraph.generated.nodes.{Method, Type, TypeDecl}
import io.shiftleft.semanticcpg.language.*
import overflowdb.{BoundaryResolver, Node, NodeOrDetachedNode, SymbolicKey}

import java.util.Optional

/** Codec between chen's structured symbol address `(kind, fqName, arity)` and the opaque
  * `overflowdb.SymbolicKey` string used by the fragment foundation (`GraphFragmentCodec` /
  * `applyFragment`). Keeping the structure on the chen side, and the key opaque in overflowdb,
  * keeps overflowdb free of any knowledge of chen's symbol model.
  *
  * A NUL separator is used so it never collides with characters that appear in fully-qualified
  * names (`.`, `:`, `|`, etc.).
  */
object ChenSymbolicKeys:

  private final val Sep = '\u0000'

  def encode(kind: String, fqName: String, arity: Int = -1): SymbolicKey =
      new SymbolicKey(s"$kind$Sep$fqName$Sep$arity")

  def decode(key: SymbolicKey): Option[(String, String, Int)] =
      key.key.split(Sep) match
        case Array(kind, fqName, arity) => arity.toIntOption.map((kind, fqName, _))
        case _                          => None

  /** The symbolic key for a named symbol node (method / type-decl / type), or empty for nodes that
    * are not cross-unit addressable.
    */
  def keyForNode(node: NodeOrDetachedNode): Optional[SymbolicKey] = node match
    case m: Method   => Optional.of(encode(SymbolKind.Method, m.fullName, m.parameter.size))
    case t: TypeDecl => Optional.of(encode(SymbolKind.TypeDecl, t.fullName))
    case t: Type     => Optional.of(encode(SymbolKind.Type, t.fullName))
    case _           => Optional.empty()
end ChenSymbolicKeys

/** A [[overflowdb.BoundaryResolver]] that treats named symbols (methods/type-decls/types) as the
  * cross-unit boundary and resolves them through a [[SymbolIndex]].
  *
  *   - encode side (`getSymbolicKey`): a fragment's edges to an external named symbol are recorded
  *     as boundary refs keyed by `(kind, fqName, arity)`; nodes the fragment itself defines become
  *     exports.
  *   - decode/apply side (`resolve`): a boundary key is mapped back to the live node the
  *     `SymbolIndex` currently knows for that fully-qualified name, materialising the real edge.
  *
  * This is the bridge that lets a cached/serialised mini-graph be spliced (`applyFragment`) and its
  * dangling cross-unit edges realised without re-parsing - the serialised analogue of the in-memory
  * [[StitchPass]].
  */
class SymbolIndexBoundaryResolver(index: SymbolIndex) extends BoundaryResolver:

  override def getSymbolicKey(node: NodeOrDetachedNode): Optional[SymbolicKey] =
      ChenSymbolicKeys.keyForNode(node)

  override def resolve(key: SymbolicKey): Optional[Node] =
    val resolved: Option[Node] = ChenSymbolicKeys.decode(key).flatMap {
        case (SymbolKind.Method, fqName, _)   => index.methods(fqName).headOption
        case (SymbolKind.TypeDecl, fqName, _) => index.typeDecls(fqName).headOption
        case (SymbolKind.Type, fqName, _)     => index.types(fqName).headOption
        case _                                => None
    }
    resolved match
      case Some(n) => Optional.of(n)
      case None    => Optional.empty()

/** A resolver that classifies nothing as a boundary - used to serialise a fully self-contained
  * mini-graph (all edges intra-fragment), where cross-unit linking is deferred to a later
  * [[StitchPass]] over the spliced graph.
  */
object NoBoundaryResolver extends BoundaryResolver:
  override def getSymbolicKey(node: NodeOrDetachedNode): Optional[SymbolicKey] = Optional.empty()
  override def resolve(key: SymbolicKey): Optional[Node]                       = Optional.empty()
