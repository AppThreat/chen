package io.appthreat.x2cpg

import overflowdb.BatchedUpdate.{CreateEdge, DiffGraphBuilder}
import overflowdb.{DetachedNodeData, DetachedNodeGeneric}
import io.shiftleft.codepropertygraph.generated.nodes.NewNode
import upickle.default.*

import scala.collection.immutable.ArraySeq
import scala.collection.mutable
import scala.jdk.CollectionConverters.*

/** On-disk representation ("bitcode") of a frontend's local diff graph, used to cache parse results
  * between runs.
  *
  * The cache operates on the complete `DiffGraphBuilder` a frontend produces for one file, not on
  * the narrower [[Ast]] structure. This means every node and edge the frontend created - including
  * ones that do not belong to the AST tree, such as dependency nodes and `IMPORTS` edges - is
  * captured, so a cache hit reproduces exactly what a fresh parse would have written.
  *
  * Two properties matter for correctness:
  *   - Values round-trip without loss of type or precision. Property values carry an explicit type
  *     tag rather than being funnelled through a JSON value model, so e.g. a `Long` larger than
  *     2^53, a `Char` or a `Byte` survives a save/load cycle unchanged.
  *   - Caches written by an incompatible build are rejected rather than silently producing a
  *     corrupt graph. Every bitcode carries a format tag that is validated on load.
  *
  * Nodes are reconstructed as generic detached nodes and written straight into the diff graph,
  * which applies their properties through exactly the same path as freshly parsed nodes - without
  * any reflection.
  */
object AstCache:

  /** Bump whenever the on-disk layout changes; mismatching caches are then transparently discarded
    * and recomputed.
    */
  final val FormatVersion: Int = 2
  final val FormatTag: String  = "chen-ast"

  /** Type-tagged property value, so that serialization is lossless. */
  enum CachedValue derives ReadWriter:
    case Str(value: String)
    case Bool(value: Boolean)
    case I32(value: Int)
    case I64(value: Long)
    case F64(value: Double)
    case F32(value: Float)
    case Chr(value: Char)
    case I8(value: Byte)
    case I16(value: Short)
    case StrList(value: Vector[String])
    case I32List(value: Vector[Int])

  case class CachedProperty(key: String, value: CachedValue) derives ReadWriter

  case class AstNodeBitcode(label: String, properties: List[CachedProperty]) derives ReadWriter

  case class AstEdgeBitcode(
    srcId: Int,
    dstId: Int,
    label: String,
    properties: List[CachedProperty]
  ) derives ReadWriter

  /** Serialized representation of a frontend's local diff graph.
    *
    * `usedTypes` records type names the frontend registered in its global type table while parsing
    * the file (consumed later by the type node pass). These are not part of the diff graph, so they
    * are captured separately and re-registered on a cache hit - otherwise a cached run would be
    * missing the corresponding TYPE nodes.
    */
  case class AstBitcode(
    formatTag: String,
    formatVersion: Int,
    nodes: List[AstNodeBitcode],
    edges: List[AstEdgeBitcode],
    usedTypes: List[String] = Nil
  ) derives ReadWriter

  /** Serialize a frontend's local diff graph.
    *
    * Returns `None` (the diff is then simply not cached) if it contains change kinds that cannot be
    * represented as a self-contained fragment - property updates or removals, generated
    * `CreateNode` changes, or an edge that references a node outside this diff. Frontend AST
    * creation only adds nodes and edges, so in practice this always succeeds.
    */
  def toBitcode(diff: DiffGraphBuilder): Option[AstBitcode] =
    // identity (not value) based, so structurally-equal New nodes are kept distinct
    val nodeIndex    = new java.util.IdentityHashMap[AnyRef, Integer]()
    val nodeBitcodes = mutable.ArrayBuffer.empty[AstNodeBitcode]
    var unsupported  = false

    diff.iterator().asScala.foreach {
        case _: CreateEdge => // handled in the second pass
        case n: DetachedNodeData =>
            if !nodeIndex.containsKey(n) then
              nodeIndex.put(n, nodeBitcodes.size)
              nodeBitcodes += AstNodeBitcode(n.label(), propertiesOf(n))
        case _ => unsupported = true
    }

    val edgeBitcodes = mutable.ArrayBuffer.empty[AstEdgeBitcode]
    if !unsupported then
      diff.iterator().asScala.foreach {
          case e: CreateEdge =>
              val src = nodeIndex.get(e.src)
              val dst = nodeIndex.get(e.dst)
              if src == null || dst == null then unsupported = true
              else
                edgeBitcodes += AstEdgeBitcode(
                  src,
                  dst,
                  e.label,
                  keyValuesToProperties(e.propertiesAndKeys)
                )
          case _ =>
      }

    if unsupported then None
    else Some(AstBitcode(FormatTag, FormatVersion, nodeBitcodes.toList, edgeBitcodes.toList))
  end toBitcode

  /** True if the bitcode was produced by a compatible build and is safe to load. */
  def isCompatible(bitcode: AstBitcode): Boolean =
      bitcode.formatTag == FormatTag && bitcode.formatVersion == FormatVersion

  /** Reconstruct the cached nodes and edges directly into the diff graph.
    *
    * Nodes are materialized as `DetachedNodeGeneric` instances, whose properties are applied by the
    * diff graph through the same code path used for freshly parsed nodes; no reflection is
    * involved. Returns false (without mutating the diff graph) if the bitcode is incompatible.
    */
  def storeInDiffGraph(bitcode: AstBitcode, diffGraph: DiffGraphBuilder): Boolean =
      if !isCompatible(bitcode) then false
      else
        val detachedNodes = bitcode.nodes.map { n =>
            new DetachedNodeGeneric(n.label, toKeyValues(n.properties)*)
        }.toArray[DetachedNodeGeneric]

        detachedNodes.foreach(diffGraph.addNode)
        bitcode.edges.foreach { e =>
          val src = detachedNodes(e.srcId)
          val dst = detachedNodes(e.dstId)
          if e.properties.isEmpty then diffGraph.addEdge(src, dst, e.label)
          else diffGraph.addEdge(src, dst, e.label, toKeyValues(e.properties)*)
        }
        true
  end storeInDiffGraph

  private def propertiesOf(node: DetachedNodeData): List[CachedProperty] = node match
    case g: DetachedNodeGeneric => keyValuesToProperties(g.keyvalues)
    case n: NewNode =>
        n.properties.iterator.map { case (key, value) =>
            CachedProperty(key, toCachedValue(value))
        }.toList
    case _ => Nil

  private def keyValuesToProperties(keyValues: Array[Object]): List[CachedProperty] =
      if keyValues == null then Nil
      else
        val builder = List.newBuilder[CachedProperty]
        var i       = 0
        while i + 1 < keyValues.length do
          builder += CachedProperty(keyValues(i).toString, toCachedValue(keyValues(i + 1)))
          i += 2
        builder.result()

  private def toKeyValues(properties: List[CachedProperty]): Array[Object] =
    val kvs = new Array[Object](properties.size * 2)
    var i   = 0
    properties.foreach { p =>
      kvs(i) = p.key
      kvs(i + 1) = fromCachedValue(p.value)
      i += 2
    }
    kvs

  private def toCachedValue(v: Any): CachedValue = v match
    case s: String  => CachedValue.Str(s)
    case b: Boolean => CachedValue.Bool(b)
    case i: Int     => CachedValue.I32(i)
    case l: Long    => CachedValue.I64(l)
    case d: Double  => CachedValue.F64(d)
    case f: Float   => CachedValue.F32(f)
    case c: Char    => CachedValue.Chr(c)
    case b: Byte    => CachedValue.I8(b)
    case s: Short   => CachedValue.I16(s)
    case xs: IterableOnce[?] =>
        val items = xs.iterator.toVector
        items.headOption match
          case Some(_: Int) => CachedValue.I32List(items.map(_.asInstanceOf[Int]))
          case _            => CachedValue.StrList(items.map(stringify))
    case other => CachedValue.Str(stringify(other))

  private def fromCachedValue(v: CachedValue): Object = v match
    case CachedValue.Str(value)     => value
    case CachedValue.Bool(value)    => java.lang.Boolean.valueOf(value)
    case CachedValue.I32(value)     => java.lang.Integer.valueOf(value)
    case CachedValue.I64(value)     => java.lang.Long.valueOf(value)
    case CachedValue.F64(value)     => java.lang.Double.valueOf(value)
    case CachedValue.F32(value)     => java.lang.Float.valueOf(value)
    case CachedValue.Chr(value)     => java.lang.Character.valueOf(value)
    case CachedValue.I8(value)      => java.lang.Byte.valueOf(value)
    case CachedValue.I16(value)     => java.lang.Short.valueOf(value)
    case CachedValue.StrList(value) => ArraySeq.from(value)
    case CachedValue.I32List(value) => ArraySeq.from(value)

  private def stringify(v: Any): String = v match
    case s: String => s
    case other     => String.valueOf(other)

end AstCache
