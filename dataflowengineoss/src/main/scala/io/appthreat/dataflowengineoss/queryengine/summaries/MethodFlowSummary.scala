package io.appthreat.dataflowengineoss.queryengine.summaries

import io.appthreat.dataflowengineoss.semanticsloader.{
    FlowMapping,
    FlowSemantic,
    ParameterNode,
    PassThroughMapping,
    Semantics
}
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable
import scala.jdk.CollectionConverters.*

/** A context-independent flow summary for a single method (CHEN3_PLAN §5).
  *
  * Unlike a `ReachableByResult` (which is tied to a specific query/sink/call-stack and therefore
  * cannot be reused across call sites), a summary records only facts that hold for the method in
  * isolation:
  *   - `paramToReturn`: indices of formal parameters whose value can flow to the method's return.
  *   - `paramToParamOut`: for each formal parameter index, the output-parameter indices its value
  *     can flow to (i.e. the method mutates that argument from this parameter).
  *
  * Because these facts are expressed over formal-parameter / return positions - not over concrete
  * nodes of a particular call - a summary can be soundly reused at every call site by mapping
  * actual arguments onto formals. That is what makes summary reuse safe where raw result-sharing
  * was not.
  *
  * The summary is derived purely from the intra-procedural data-dependence graph (`REACHING_DEF`
  * edges), so it is deterministic and independent of any query.
  */
case class MethodFlowSummary(
  methodFullName: String,
  paramToReturn: Set[Int],
  paramToParamOut: Map[Int, Set[Int]],
  returnFromInternal: Boolean,
  paramOutFromInternal: Set[Int]
):
  /** True if a tainted actual at `paramIndex` can reach the method's return value. */
  def reachesReturn(paramIndex: Int): Boolean = paramToReturn.contains(paramIndex)

  /** Output-parameter indices reachable from the given formal parameter index. */
  def reachedParamOuts(paramIndex: Int): Set[Int] =
      paramToParamOut.getOrElse(paramIndex, Set.empty)

  /** True if the method's return value can carry taint from any origin: a formal parameter, or an
    * internal origin such as a literal-independent computation or a source inside the body. When
    * this is false the return is provably taint-free and a query need not explore the callee for
    * it.
    */
  def returnTaintable: Boolean = paramToReturn.nonEmpty || returnFromInternal

  /** True if the given output parameter index can carry taint from any origin (a formal parameter
    * or an internal origin). When false, the output parameter is provably taint-free.
    */
  def paramOutTaintable(outIndex: Int): Boolean =
      paramOutFromInternal.contains(outIndex) ||
          paramToParamOut.values.exists(_.contains(outIndex))

  /** Encode the context-independent facts as a compact, single-line string suitable for a CPG tag
    * value (`flow-summary`). The `methodFullName` is not encoded - it is the identity of the tagged
    * method node and is supplied again on decode. Sections are `;`-separated; within `o`, parameter
    * entries are `/`-separated as `src:out,out`.
    *
    * Example: `r=1,2;o=0:1,2/3:4;ri=1;pi=0,3`
    */
  def encode: String =
    val r = paramToReturn.toSeq.sorted.mkString(",")
    val o = paramToParamOut.toSeq.sortBy(_._1).map { case (src, outs) =>
        s"$src:${outs.toSeq.sorted.mkString(",")}"
    }.mkString("/")
    val ri = if returnFromInternal then "1" else "0"
    val pi = paramOutFromInternal.toSeq.sorted.mkString(",")
    s"r=$r;o=$o;ri=$ri;pi=$pi"
end MethodFlowSummary

object MethodFlowSummary:

  /** A lookup of already-computed summaries by method full name. Returning `None` means the callee
    * has no summary yet (an external method, or one not computed during a fixpoint), in which case
    * the call is treated as opaque.
    */
  type SummaryLookup = String => Option[MethodFlowSummary]

  /** The empty summary: nothing flows from a parameter to the return or to an output parameter. */
  def empty(methodFullName: String): MethodFlowSummary =
      MethodFlowSummary(methodFullName, Set.empty, Map.empty, returnFromInternal = false, Set.empty)

  /** Decode a summary previously produced by [[MethodFlowSummary.encode]]. Malformed or missing
    * sections decode to empty facts, so a corrupt tag degrades to an opaque (no-fact) summary
    * rather than throwing. Returns `None` only when the value is not in the expected `k=v;...`
    * shape at all.
    */
  def decode(methodFullName: String, encoded: String): Option[MethodFlowSummary] =
      if encoded == null || !encoded.contains('=') then None
      else
        val sections = encoded.split(';').iterator.collect {
            case s if s.contains('=') =>
                val idx = s.indexOf('=')
                s.substring(0, idx) -> s.substring(idx + 1)
        }.toMap
        def ints(s: String): Set[Int] =
            if s == null || s.isEmpty then Set.empty
            else s.split(',').iterator.flatMap(_.toIntOption).toSet
        val paramToReturn = ints(sections.getOrElse("r", ""))
        val paramToParamOut = sections.getOrElse("o", "") match
          case "" => Map.empty[Int, Set[Int]]
          case o => o.split('/').iterator.flatMap { entry =>
                  entry.split(':') match
                    case Array(src, outs) => src.toIntOption.map(_ -> ints(outs))
                    case Array(src)       => src.toIntOption.map(_ -> Set.empty[Int])
                    case _                => None
              }.toMap
        val returnFromInternal   = sections.getOrElse("ri", "0") == "1"
        val paramOutFromInternal = ints(sections.getOrElse("pi", ""))
        Some(MethodFlowSummary(
          methodFullName,
          paramToReturn,
          paramToParamOut,
          returnFromInternal,
          paramOutFromInternal
        ))
  end decode

  /** Derive a summary directly from a declared flow semantic rather than from the method body. When
    * a method has a semantic, that semantic is authoritative: only the declared parameter-to-return
    * and parameter-to-output mappings propagate taint, so a parameter that is not a declared source
    * is treated as sanitized. `PassThroughMapping` flows every non-receiver parameter to the return
    * and to itself. Because the behaviour is fully declared, there is no internal origin.
    */
  def fromSemantic(method: Method, semantic: FlowSemantic): MethodFlowSummary =
    val paramIndices = method.parameter.index.l
    val toReturn     = mutable.SortedSet.empty[Int]
    val toParamOut   = mutable.Map.empty[Int, mutable.SortedSet[Int]]
    semantic.mappings.foreach {
        case PassThroughMapping =>
            paramIndices.filter(_ != 0).foreach { i =>
              toReturn += i
              toParamOut.getOrElseUpdate(i, mutable.SortedSet.empty) += i
            }
        case FlowMapping(ParameterNode(srcIdx, _), ParameterNode(dstIdx, _)) =>
            if dstIdx == ReturnIndex then toReturn += srcIdx
            else toParamOut.getOrElseUpdate(srcIdx, mutable.SortedSet.empty) += dstIdx
        case _ =>
    }
    MethodFlowSummary(
      method.fullName,
      toReturn.toSet,
      toParamOut.view.mapValues(_.toSet).toMap,
      returnFromInternal = false,
      Set.empty
    )
  end fromSemantic

  /** The destination index used by a flow semantic to denote the method's return value. */
  private val ReturnIndex = -1

  /** Compute an intra-procedural-only summary, treating every call as opaque. */
  def of(method: Method): MethodFlowSummary = of(method, _ => None, Semantics.empty)

  /** Compute a summary plugging in callee body summaries, with no flow semantics. */
  def of(method: Method, lookup: SummaryLookup): MethodFlowSummary =
      of(method, lookup, Semantics.empty)

  /** Compute the summary for `method` by forward-propagating each formal parameter along
    * intra-procedural `REACHING_DEF` edges and recording which method-return / output-parameter
    * boundary nodes it reaches.
    *
    * When the propagation reaches an argument of a call whose callee already has a summary
    * (provided by `lookup`), the callee summary is plugged in: if the callee passes that argument
    * position to its return, the call's result becomes tainted; if it passes the argument to one of
    * its output parameters, the matching actual argument at the call site becomes tainted. This is
    * what makes the summary interprocedural while remaining context independent.
    */
  def of(method: Method, lookup: SummaryLookup, semantics: Semantics): MethodFlowSummary =
    val methodReturn = method.methodReturn
    val returnId     = methodReturn.id

    // Output-parameter boundary nodes, indexed by their parameter index.
    val paramOutIdToIndex: Map[Long, Int] =
        method.parameter.asOutput.map(p => p.id -> p.index).toMap

    val params        = method.parameter.l
    val toReturn      = mutable.SortedSet.empty[Int]
    val toParamOutAcc = mutable.Map.empty[Int, mutable.SortedSet[Int]]

    // Everything reachable forward from any formal parameter. A boundary node fed only by nodes
    // outside this set is influenced by an internal origin (a literal-independent computation or a
    // source inside the body) rather than by a parameter.
    val unionParamReach = mutable.HashSet.empty[Long]

    params.foreach { param =>
      val reached = forwardReach(param, lookup, semantics)
      unionParamReach ++= reached
      if reached.contains(returnId) then toReturn += param.index
      reached.foreach { rid =>
          paramOutIdToIndex.get(rid).foreach { outIdx =>
              toParamOutAcc.getOrElseUpdate(param.index, mutable.SortedSet.empty) += outIdx
          }
      }
    }

    val returnFromInternal = hasInternalPredecessor(methodReturn, unionParamReach)
    val paramOutFromInternal = method.parameter.asOutput.l.collect {
        case p if hasInternalPredecessor(p, unionParamReach) => p.index
    }.toSet

    MethodFlowSummary(
      method.fullName,
      toReturn.toSet,
      toParamOutAcc.view.mapValues(_.toSet).toMap,
      returnFromInternal,
      paramOutFromInternal
    )
  end of

  /** True if `boundary` has an incoming `REACHING_DEF` predecessor that no parameter reaches, i.e.
    * the boundary is influenced by an origin internal to the method.
    */
  private def hasInternalPredecessor(
    boundary: StoredNode,
    paramReachable: mutable.Set[Long]
  ): Boolean =
      boundary.in(EdgeTypes.REACHING_DEF).asScala.exists {
          case pred: StoredNode => !paramReachable.contains(pred.id)
          case _                => false
      }

  /** Ids of all nodes reachable from `start` over outgoing `REACHING_DEF` edges (the intra-method
    * data-dependence graph), extended with callee-summary jumps at call sites. BFS over node ids.
    */
  private def forwardReach(
    start: StoredNode,
    lookup: SummaryLookup,
    semantics: Semantics
  ): mutable.Set[Long] =
    val visited = mutable.HashSet[Long](start.id)
    val queue   = mutable.ArrayDeque[StoredNode](start)
    while queue.nonEmpty do
      val n         = queue.removeHead()
      val intraNext = n.out(EdgeTypes.REACHING_DEF).asScala.collect { case s: StoredNode => s }
      (intraNext ++ calleeJumps(n, lookup, semantics)).foreach { next =>
          if !visited.contains(next.id) then
            visited += next.id
            queue.append(next)
      }
    visited

  /** Interprocedural successors of `n` obtained by crossing a call. If `n` is an argument at index
    * `i` of a call, the call result and/or output arguments that the value can reach become
    * reachable. A declared flow semantic for the callee is authoritative (it encodes sanitizers and
    * pass-through, so undeclared arguments are blocked); otherwise the callee's computed body
    * summary is plugged in. With neither, the call is opaque.
    */
  private def calleeJumps(
    n: StoredNode,
    lookup: SummaryLookup,
    semantics: Semantics
  ): Seq[StoredNode] =
      n match
        case expr: Expression =>
            val argIndex = expr.argumentIndex
            if argIndex < 0 then Seq.empty
            else
              expr.inCall.l.flatMap { call =>
                  calleeNames(call).distinct.flatMap { fullName =>
                      semantics.forMethod(fullName) match
                        case Some(semantic) => semanticJumps(call, argIndex, semantic)
                        case None => lookup(fullName).toSeq.flatMap(summaryJumps(call, argIndex, _))
                  }
              }
        case _ => Seq.empty

  /** Full names of the resolved callees of `call`, falling back to the call's own method full name
    * when no callee is linked (so semantics for unresolved external methods still apply).
    */
  private def calleeNames(call: Call): Seq[String] =
    val resolved = call.out(EdgeTypes.CALL).asScala.collect { case m: Method => m.fullName }.toSeq
    if resolved.nonEmpty then resolved else Seq(call.methodFullName)

  /** Jumps implied by a callee's computed body summary. */
  private def summaryJumps(call: Call, argIndex: Int, summary: MethodFlowSummary): Seq[StoredNode] =
    val toReturn: Seq[StoredNode] =
        if summary.reachesReturn(argIndex) then Seq(call) else Seq.empty
    val toOutArgs: Seq[StoredNode] =
        summary.reachedParamOuts(argIndex).toSeq.flatMap(out => call.argument.argumentIndex(out).l)
    toReturn ++ toOutArgs

  /** Jumps implied by a declared flow semantic. Only the declared mappings propagate, so an
    * argument absent from every mapping is sanitized.
    */
  private def semanticJumps(
    call: Call,
    argIndex: Int,
    semantic: FlowSemantic
  ): Seq[StoredNode] =
      semantic.mappings.flatMap {
          case PassThroughMapping if argIndex != 0 =>
              // The value flows to the return (and to itself, which is already visited).
              Seq(call)
          case FlowMapping(ParameterNode(srcIdx, _), ParameterNode(dstIdx, _))
              if srcIdx == argIndex =>
              if dstIdx == ReturnIndex then Seq(call)
              else call.argument.argumentIndex(dstIdx).l
          case _ => Seq.empty
      }
end MethodFlowSummary
