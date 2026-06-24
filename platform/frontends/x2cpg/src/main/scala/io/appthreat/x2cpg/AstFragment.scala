package io.appthreat.x2cpg

import io.appthreat.x2cpg.passes.linking.NoBoundaryResolver
import io.shiftleft.codepropertygraph.generated.SchemaInfo
import overflowdb.BatchedUpdate.DiffGraphBuilder
import overflowdb.{BatchedUpdate, BoundaryResolver, DetachedNodeData, DetachedNodeGeneric, Graph}
import overflowdb.storage.{DecodedFragment, GraphFragmentCodec}

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, DataInputStream, DataOutputStream}
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** Fragment-based codec for a frontend's local diff graph (CHEN3_PLAN §3/§4 - the successor to
  * [[AstCache]]'s bespoke upickle bitcode).
  *
  * It serializes a self-contained, add-only diff graph with overflowdb2's `GraphFragmentCodec`,
  * which gives us, for free: a typed lossless value codec (the shared `ValueTypes` path), a
  * per-fragment string glossary, and a self-describing header carrying the cpg2 `schemaHash` + a
  * CRC. A schema or format change is therefore detected on load and the entry is recomputed rather
  * than corrupting a graph.
  *
  * chen-specific `usedTypes` (the global-type-table names a frontend registered while parsing) are
  * not part of the graph, so they are stored as a small sidecar around the fragment bytes.
  *
  * Like [[AstCache]], reconstruction is done into a [[DiffGraphBuilder]] (so a frontend keeps its
  * existing streaming-pass apply model); the faster `applyFragment`-straight-into-the-graph path is
  * a separate, later optimization.
  */
object AstFragment:

  /** Serialize a frontend's local diff graph plus its `usedTypes` sidecar, or `None` if the diff is
    * not a self-contained add-only fragment (property updates/removals, or an edge whose endpoint
    * is outside the diff) - exactly the cases `GraphFragmentCodec.encode` rejects.
    */
  def encode(diff: DiffGraphBuilder, usedTypes: Seq[String]): Option[Array[Byte]] =
      // Never throw: an unsupported property value (or any codec error) simply means this unit is
      // not cached and will be reparsed, rather than aborting the whole frontend run.
      Try {
          Option(
            GraphFragmentCodec.encode(diff, NoBoundaryResolver, SchemaInfo.schemaHash).orElse(null)
          ).map { fragmentBytes =>
            val baos = new ByteArrayOutputStream()
            val out  = new DataOutputStream(baos)
            out.writeInt(usedTypes.size)
            usedTypes.foreach(out.writeUTF)
            out.writeInt(fragmentBytes.length)
            out.write(fragmentBytes)
            out.flush()
            baos.toByteArray
          }
      }.toOption.flatten

  /** Reconstruct the cached nodes and edges into `diffGraph` and return the `usedTypes` sidecar.
    *
    * Returns `None` (leaving `diffGraph` untouched) if the bytes are corrupt, truncated, or were
    * written for a different cpg2 schema (the `schemaHash` in the fragment header does not match
    * the current schema) - the caller then recomputes.
    */
  def decodeIntoDiffGraph(bytes: Array[Byte], diffGraph: DiffGraphBuilder): Option[Seq[String]] =
      Try {
          val in        = new DataInputStream(new ByteArrayInputStream(bytes))
          val typeCount = in.readInt()
          val usedTypes = (0 until typeCount).map(_ => in.readUTF()).toList
          val fragLen   = in.readInt()
          val fragment  = in.readNBytes(fragLen)

          // Reject fragments from an incompatible schema before decoding.
          val header = GraphFragmentCodec.peek(fragment)
          if header.schemaHash != SchemaInfo.schemaHash then None
          else
            storeInDiffGraph(GraphFragmentCodec.decode(fragment), diffGraph)
            Some(usedTypes)
      }.toOption.flatten

  /** Fastest splice: apply the cached fragment STRAIGHT into the live graph via
    * `BatchedUpdate.applyFragment` (ID-remapped), skipping the Scala diff-graph rebuild that
    * [[decodeIntoDiffGraph]] performs. Returns the `usedTypes` sidecar on success, or `None` if the
    * bytes are corrupt / written for a different schema.
    *
    * IMPORTANT: this mutates `graph` directly, so it is only safe single-threaded (e.g. from a
    * [[io.appthreat.x2cpg.passes.linking.FragmentSplicePass]]), NOT from a parallel producer of a
    * streaming pass. Cross-unit boundary edges are realised via `resolver`; for self-contained AST
    * fragments (property-based cross-unit refs resolved later by a StitchPass) pass
    * [[io.appthreat.x2cpg.passes.linking.NoBoundaryResolver]].
    */
  def applyToGraph(
    bytes: Array[Byte],
    graph: Graph,
    resolver: BoundaryResolver = NoBoundaryResolver,
    keyPool: BatchedUpdate.KeyPool = null
  ): Option[Seq[String]] =
      Try {
          val in        = new DataInputStream(new ByteArrayInputStream(bytes))
          val typeCount = in.readInt()
          val usedTypes = (0 until typeCount).map(_ => in.readUTF()).toList
          val fragLen   = in.readInt()
          val fragment  = in.readNBytes(fragLen)

          val header = GraphFragmentCodec.peek(fragment)
          if header.schemaHash != SchemaInfo.schemaHash then None
          else
            BatchedUpdate.applyFragment(graph, fragment, SchemaInfo.schemaHash, resolver, keyPool)
            Some(usedTypes)
      }.toOption.flatten

  /** Rebuild decoded nodes/edges into the diff graph as generic detached nodes - the same code path
    * fresh parse output takes, no reflection. Boundary refs are not expected for a self-contained
    * AST fragment and are ignored here (cross-unit linking is a later [[passes.linking.StitchPass]]
    * concern).
    */
  private def storeInDiffGraph(decoded: DecodedFragment, diffGraph: DiffGraphBuilder): Unit =
    val detached: Array[DetachedNodeData] = decoded.nodes.asScala.map { n =>
        new DetachedNodeGeneric(n.label, toKeyValues(n.properties)*)
    }.toArray
    detached.foreach(diffGraph.addNode)
    decoded.edges.asScala.foreach { e =>
      val src = detached(e.srcLocal)
      val dst = detached(e.dstLocal)
      if e.properties.isEmpty then diffGraph.addEdge(src, dst, e.label)
      else diffGraph.addEdge(src, dst, e.label, toKeyValues(e.properties)*)
    }

  private def toKeyValues(properties: java.util.Map[String, Object]): Array[Object] =
    val kvs = new Array[Object](properties.size * 2)
    var i   = 0
    properties.asScala.foreach { case (k, v) =>
        kvs(i) = k
        kvs(i + 1) = v
        i += 2
    }
    kvs
end AstFragment
