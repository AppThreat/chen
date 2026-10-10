package io.appthreat.dataflowengineoss

import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, CfgNode}

package object queryengine:

  /** The TaskFingerprint uniquely identifies a task.
    */
  /** @param fieldContext
    *   the field whose read brought the walk here, when it entered a callee because the caller read
    *   one field of an object the callee had written. Part of the fingerprint because the same node
    *   reached through a read of a different field is a different question with a different answer.
    */
  case class TaskFingerprint(
    sink: CfgNode,
    callSiteStack: List[Call],
    callDepth: Int,
    fieldContext: Option[String] = None
  )

  /** A (partial) result, informing about a path that exists from a source to another node in the
    * graph.
    *
    * @param taskStack
    *   The list of tasks that was solved to arrive at this task
    *
    * @param path
    *   A path to the sink.
    *
    * @param partial
    *   indicate whether this result stands on its own or requires further analysis, e.g., by
    *   expanding output arguments backwards into method output parameters.
    */
  case class ReachableByResult(
    taskStack: List[TaskFingerprint],
    path: Vector[PathElement],
    partial: Boolean = false
  ):

    def fingerprint: TaskFingerprint = taskStack.last
    def sink: CfgNode                = fingerprint.sink
    def callSiteStack: List[Call]    = fingerprint.callSiteStack

    def callDepth: Int = fingerprint.callDepth

    /** Grouping key of `TaskSolver.deduplicateWithinTask`, cached so that repeated hashing does not
      * re-walk the endpoints' call-site stacks. See [[ResultKey]] for why the hash must be exactly
      * the bare tuple's.
      */
    private[queryengine] lazy val resultDedupKey: ResultKey = ResultKey(
      path.headOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get,
      path.lastOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get,
      partial,
      callDepth
    )

    def startingPoint: CfgNode = path.head.node.asInstanceOf[CfgNode]

    /** If the result begins in an output argument, return it.
      */
    def outputArgument: Option[CfgNode] =
        path.headOption.collect {
            case elem: PathElement if elem.isOutputArg =>
                elem.node.asInstanceOf[CfgNode]
        }
  end ReachableByResult

  /** We represent data flows as sequences of path elements, where each path element consists of a
    * node, flags and the label of its outgoing edge.
    *
    * @param node
    *   The parent node. This is actually always a CfgNode during data flow computation, however,
    *   since the source may be an arbitrary AST node, we may add an AST node to the start of the
    *   flow right before returning flows to the user.
    *
    * @param callSiteStack
    *   The call stack when this path element was created. Since we may enter the same function via
    *   two different call sites, path elements should only be treated as the same if they are the
    *   same node and we've reached them via the same call sequence.
    *
    * @param visible
    *   whether this path element should be shown in the flow
    * @param isOutputArg
    *   input and output arguments are the same node in the CPG, so, we need this additional flag to
    *   determine whether we are on an input or output argument. By default, we consider arguments
    *   to be input arguments, meaning that when tracking `x` at `f(x)`, we do not expand into `f`
    *   but rather upwards to producers of `x`.
    * @param outEdgeLabel
    *   label of the outgoing DDG edge
    */
  case class PathElement(
    node: AstNode,
    callSiteStack: List[Call] = List(),
    visible: Boolean = true,
    isOutputArg: Boolean = false,
    outEdgeLabel: String = ""
  )

  /** @param taskStack
    *   The list of tasks that was solved to arrive at this task, including the current task, which
    *   is to be solved. The current task is the last element of the list.
    *
    * @param initialPath
    *   The path from the current sink downwards to previous sinks.
    */
  case class ReachableByTask(taskStack: List[TaskFingerprint], initialPath: Vector[PathElement]):

    /** This tasks fingerprint: if two tasks have the same fingerprint, then the TaskSolver MUST
      * return the same result for them. This is the basis of our caching scheme.
      */
    def fingerprint: TaskFingerprint = taskStack.last

    /** The sink at which we start the analysis (upwards)
      */
    def sink: CfgNode = fingerprint.sink

    /** The call sites we have expanded downwards during this analysis. We need to keep track of
      * this so that we do not end up expanding one call site and then returning to a different call
      * site, which would produce an unreachable path.
      */
    def callSiteStack: List[Call] = fingerprint.callSiteStack

    /** The call depth at which this task was created.
      */
    def callDepth: Int = fingerprint.callDepth
  end ReachableByTask

  case class TaskSummary(
    tableEntries: Vector[(TaskFingerprint, TableEntry)],
    followupTasks: Vector[ReachableByTask]
  )
  case class TableEntry(path: Vector[PathElement]):
    /** Grouping key of the result-table deduplication, shared by every re-deduplication round. A
      * wrapper class rather than the bare tuple only so that the tuple's hash is computed once per
      * entry: the result table is regrouped on every round of held-task completion, and re-hashing
      * walked each endpoint's call-site stack again every time. The hash is exactly the tuple's -
      * the iteration order of the grouped map, and with it the order of the deduplicated list,
      * depends on the key hashes.
      */
    private[queryengine] lazy val dedupKey: TableEntryKey = TableEntryKey(
      path.headOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get,
      path.lastOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get
    )

  /** The grouping key of `HeldTaskCompletion.deduplicateTableEntries`: the path's head and last
    * (node, call-site stack, is-output-arg) tuples. A wrapper class rather than the bare tuple so
    * that the tuple's hash is computed once per entry instead of on every regrouping: the result
    * table is re-deduplicated on every round of held-task completion. The hash is exactly the
    * tuple's because the iteration order of the grouped map - and with it the order of the
    * deduplicated list - depends on the key hashes.
    */
  private[queryengine] final class TableEntryKey(
    val head: (AstNode, List[Call], Boolean),
    val last: (AstNode, List[Call], Boolean)
  ):
    override val hashCode: Int = (head, last).hashCode
    override def equals(other: Any): Boolean = other match
      case that: TableEntryKey => this.head == that.head && this.last == that.last
      case _                   => false

  /** The grouping key of `TaskSolver.deduplicateWithinTask`: a result's path endpoints plus its
    * partial flag and call depth. Same rationale as [[TableEntryKey]]: the hash is the bare
    * tuple's, computed once per result.
    */
  private[queryengine] final class ResultKey(
    val head: (AstNode, List[Call], Boolean),
    val last: (AstNode, List[Call], Boolean),
    val partial: Boolean,
    val callDepth: Int
  ):
    override val hashCode: Int = (head, last, partial, callDepth).hashCode
    override def equals(other: Any): Boolean = other match
      case that: ResultKey =>
          this.head == that.head && this.last == that.last && this.partial == that.partial && this
              .callDepth == that.callDepth
      case _ => false
end queryengine
