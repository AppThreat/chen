package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.passes.frontend.XTypeRecovery
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Guarantees that only actual types appear in the graph's type fields.
  *
  * Python's type recovery reaches its answers through strings that are not types, and both kinds
  * leak into `TYPE_FULL_NAME` and `DYNAMIC_TYPE_HINT_FULL_NAME`.
  *
  * ==Operator names==
  * Candidates are built by appending segments to a receiver type, which for subscript chains
  * produced `<operator>.indexAccess`, `__builtin.str.<operator>.indexAccess` or
  * `__builtin.list.<operator>.indexAccess.__iter__`. These are call names. They are always removed
  * \- no configuration makes them meaningful as types.
  *
  * ==Dummy/placeholder types==
  * `<returnValue>`, `<member>(x)` and `<indexAccess>`, invented for chains the recovery cannot
  * resolve. These are removed only when the frontend asked for `enabledDummyTypes = false`, which
  * is what `--no-dummy-types` sets.
  *
  * ==Why this is a pass and not a filter inside the recovery==
  * Every frontend rewrites `enabledDummyTypes` per iteration as `isFinalIteration &&
  * enabledDummyTypes`, so inside the recovery the flag means "may emit placeholders during this
  * iteration" - it is false in earlier iterations even when the user enabled them. Filtering on it
  * at the recovery's write paths therefore removes the placeholders that intermediate iterations
  * depend on to keep chaining, and measurably breaks resolution: doing so turned
  * `boto.<returnValue>.getS3Object` into a differently-rooted chain and lost the pymongo `find_one`
  * candidate. Suppression is a property of the *finished* graph, so it is enforced here - after the
  * recovery, the call linker and call-site return-type propagation have all had their use of the
  * placeholders.
  *
  * ==Scope: types, not names==
  * Only type-bearing properties are cleaned. A placeholder that reached a CALL's
  * `METHOD_FULL_NAME`, or the `FULL_NAME` of a stub the call linker minted from it, is a
  * name-resolution artifact rather than a type: it gives an otherwise-unresolvable callee a stable
  * identity and a call-graph edge, and nothing downstream in chen or atom pattern-matches on it.
  * Removing those would cost call-graph edges and buy nothing.
  */
class PythonPseudoTypeSanityPass(cpg: Cpg, removeDummyTypes: Boolean = false)
    extends ForkJoinParallelCpgPass[StoredNode](cpg):

  private def isPseudoType(t: String): Boolean =
      t.contains("<operator>.") || (removeDummyTypes && XTypeRecovery.isDummyType(t))

  private def hintsOf(n: StoredNode): Seq[String] =
      n.property[Seq[String]](PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME, Seq.empty)

  /** A node needs cleaning if its primary type *or* any of its dynamic type hints is a pseudo type.
    * Selecting on the primary type alone misses the commonest shape: the recovery leaves the
    * primary `ANY` and parks every candidate in the hints, and `dynamicTypeHintFullName` is what
    * the type-hint call linker and `atom reachables` read.
    */
  override def generateParts(): Array[StoredNode] =
    val parts = scala.collection.mutable.ArrayBuffer.empty[StoredNode]
    val it    = cpg.graph.nodes()
    while it.hasNext do
      it.next() match
        case s: StoredNode =>
            val tfn = s.property[String](PropertyNames.TYPE_FULL_NAME, null)
            if (tfn != null && isPseudoType(tfn)) || hintsOf(s).exists(isPseudoType) then
              parts += s
        case _ =>
    parts.toArray

  override def runOnPart(builder: DiffGraphBuilder, part: StoredNode): Unit =
    val tfn = part.property[String](PropertyNames.TYPE_FULL_NAME, null)
    // Only drop the primary type when it is itself a pseudo type - a node selected for its hints
    // may carry a perfectly good primary type.
    if tfn != null && isPseudoType(tfn) then
      builder.setNodeProperty(part, PropertyNames.TYPE_FULL_NAME, Constants.ANY)
    val hints      = hintsOf(part)
    val cleanHints = hints.filterNot(isPseudoType)
    if cleanHints.size != hints.size then
      builder.setNodeProperty(
        part,
        PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME,
        cleanHints
      )
end PythonPseudoTypeSanityPass
