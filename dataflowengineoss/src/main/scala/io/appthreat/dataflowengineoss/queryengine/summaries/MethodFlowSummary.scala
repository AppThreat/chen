package io.appthreat.dataflowengineoss.queryengine.summaries

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
  paramToParamOut: Map[Int, Set[Int]]
):
  /** True if a tainted actual at `paramIndex` can reach the method's return value. */
  def reachesReturn(paramIndex: Int): Boolean = paramToReturn.contains(paramIndex)

  /** Output-parameter indices reachable from the given formal parameter index. */
  def reachedParamOuts(paramIndex: Int): Set[Int] =
      paramToParamOut.getOrElse(paramIndex, Set.empty)

object MethodFlowSummary:

  /** Compute the summary for `method` by forward-propagating each formal parameter along
    * intra-procedural `REACHING_DEF` edges and recording which method-return / output-parameter
    * boundary nodes it reaches.
    */
  def of(method: Method): MethodFlowSummary =
    val methodReturn = method.methodReturn
    val returnId     = methodReturn.id

    // Output-parameter boundary nodes, indexed by their parameter index.
    val paramOutIdToIndex: Map[Long, Int] =
        method.parameter.asOutput.map(p => p.id -> p.index).toMap

    val params        = method.parameter.l
    val toReturn      = mutable.SortedSet.empty[Int]
    val toParamOutAcc = mutable.Map.empty[Int, mutable.SortedSet[Int]]

    params.foreach { param =>
      val reached = forwardReach(param)
      if reached.contains(returnId) then toReturn += param.index
      reached.foreach { rid =>
          paramOutIdToIndex.get(rid).foreach { outIdx =>
              toParamOutAcc.getOrElseUpdate(param.index, mutable.SortedSet.empty) += outIdx
          }
      }
    }

    MethodFlowSummary(
      method.fullName,
      toReturn.toSet,
      toParamOutAcc.view.mapValues(_.toSet).toMap
    )
  end of

  /** Ids of all nodes reachable from `start` over outgoing `REACHING_DEF` edges (the intra-method
    * data-dependence graph). BFS over node ids.
    */
  private def forwardReach(start: StoredNode): mutable.Set[Long] =
    val visited = mutable.HashSet[Long](start.id)
    val queue   = mutable.ArrayDeque[StoredNode](start)
    while queue.nonEmpty do
      val n = queue.removeHead()
      n.out(EdgeTypes.REACHING_DEF).asScala.foreach {
          case next: StoredNode if !visited.contains(next.id) =>
              visited += next.id
              queue.append(next)
          case _ =>
      }
    visited
end MethodFlowSummary
