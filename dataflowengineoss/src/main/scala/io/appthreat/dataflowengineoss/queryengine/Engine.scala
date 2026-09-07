package io.appthreat.dataflowengineoss.queryengine

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.passes.reachingdef.EdgeValidator
import io.appthreat.dataflowengineoss.queryengine.summaries.MethodFlowSummary
import io.appthreat.dataflowengineoss.semanticsloader.{FlowSemantic, Semantics}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Properties}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve
import overflowdb.Edge

import java.util.concurrent.*
import org.slf4j.LoggerFactory
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.control.NonFatal
import scala.util.{Failure, Success, Try}

/** The data flow engine allows determining paths to a set of sinks from a set of sources. To this
  * end, it solves tasks in parallel, creating and submitting new tasks upon completion of tasks.
  * This class deals only with task scheduling, while the creation of new tasks from existing tasks
  * is handled by the class `TaskCreator`, and solving of tasks is taken care of by the
  * `TaskSolver`.
  */
class Engine(context: EngineContext):

  import Engine.*

  private val logger: org.slf4j.Logger = LoggerFactory.getLogger(getClass)

  private val executorService: ExecutorService =
      Executors.newVirtualThreadPerTaskExecutor()
  private val completionService =
      new ExecutorCompletionService[TaskSummary](executorService)

  /** All results of tasks are accumulated in this table. At the end of the analysis, we extract
    * results from the table and return them.
    */
  private val mainResultTable: mutable.Map[TaskFingerprint, List[TableEntry]] = mutable.Map()
  private var numberOfTasksRunning: Int                                       = 0
  private val started: mutable.HashSet[TaskFingerprint] = mutable.HashSet[TaskFingerprint]()
  private val held: mutable.Buffer[ReachableByTask]     = mutable.Buffer()

  /** Determine flows from sources to sinks by exploring the graph backwards from sinks to sources.
    * Returns the list of results along with a ResultTable, a cache of known paths created during
    * the analysis.
    */
  def backwards(sinks: List[CfgNode], sources: List[CfgNode]): List[TableEntry] =
    reset()
    val sourcesSet = sources.toSet
    val tasks      = createOneTaskPerSink(sinks)
    solveTasks(tasks, sourcesSet, sinks)

  private def reset(): Unit =
    mainResultTable.clear()
    numberOfTasksRunning = 0
    started.clear()
    held.clear()

  private def createOneTaskPerSink(sinks: List[CfgNode]) =
      sinks.map(sink => ReachableByTask(List(TaskFingerprint(sink, List(), 0)), Vector()))

  /** Submit tasks to a worker pool, solving them in parallel. Upon receiving results for a task,
    * new tasks are submitted accordingly. Once no more tasks can be created, the list of results is
    * returned.
    */
  private def solveTasks(
    tasks: List[ReachableByTask],
    sources: Set[CfgNode],
    sinks: List[CfgNode]
  ): List[TableEntry] =

    /** Solving a task produces a list of summaries. The following method is called for each of
      * these summaries. It submits new tasks and adds results to the result table.
      */
    def handleSummary(taskSummary: TaskSummary): Unit =
      val newTasks = taskSummary.followupTasks
      submitTasks(newTasks, sources)
      val newResults = taskSummary.tableEntries
      addEntriesToMainTable(newResults)

    def addEntriesToMainTable(entries: Vector[(TaskFingerprint, TableEntry)]): Unit =
        entries.groupBy(_._1).foreach { case (fingerprint, entryList) =>
            val entries = entryList.map(_._2).toList
            mainResultTable.updateWith(fingerprint) {
                case Some(list) => Some(list ++ entries)
                case None       => Some(entries)
            }
        }

    def runUntilAllTasksAreSolved(): Unit =
        while numberOfTasksRunning > 0 do
          Try {
              completionService.take.get
          } match
            case Success(resultsOfTask) =>
                numberOfTasksRunning -= 1
                handleSummary(resultsOfTask)
            case Failure(exception) =>
                numberOfTasksRunning -= 1
                // A task that fails twice has still failed: its results are lost, which is why
                // this is logged rather than swallowed. Historically this branch was silent, and
                // transient adjacency-read races under the virtual-thread pool were quietly
                // dropping a different handful of tasks per run - a measured 2888-2937
                // reachables spread on one fixture from task loss alone (task 12 part B).
                logger.warn(
                  s"Data flow task failed (its results are not in the analysis): $exception"
                )

    submitTasks(tasks.toVector, sources)
    runUntilAllTasksAreSolved()
    new HeldTaskCompletion(held.toList, mainResultTable).completeHeldTasks()
    // Deal with duplicates in downstream tools
    extractResultsFromTable(sinks)
  end solveTasks

  private def submitTasks(tasks: Vector[ReachableByTask], sources: Set[CfgNode]): Unit =
      tasks.foreach { task =>
          if started.contains(task.fingerprint) then
            held ++= Vector(task)
          else
            started.add(task.fingerprint)
            numberOfTasksRunning += 1
            completionService.submit(new RetryingTaskSolver(task, context, sources))
      }

  /** A [[TaskSolver]] with one built-in retry. Task solving only READS the graph, and the pool
    * solves on virtual threads, so a task can transiently lose a race against another thread's lazy
    * deserialization of the same adjacency (a ClassCastException or an NPE out of overflowdb's
    * adjacent-node access). Rerunning the identical task is safe and idempotent, and without the
    * retry those transient races silently removed a different set of results on every run. A task
    * that fails the second attempt propagates the failure to the engine, which logs it - a
    * persistent failure loses the same results every run, which is at least deterministic, and
    * visible.
    *
    * Only NON-FATAL failures are retried. `Throwable` would also catch the three that must never be
    * retried: an `InterruptedException` (retrying defeats the cancellation that raised it), an
    * `OutOfMemoryError` (a second attempt asks a starved heap for the same allocation), and a
    * `StackOverflowError` (deterministic in a deep traversal - retrying only pays the cost twice
    * before failing identically). Those propagate on the first attempt, as they should.
    */
  private class RetryingTaskSolver(
    task: ReachableByTask,
    context: EngineContext,
    sources: Set[CfgNode]
  ) extends Callable[TaskSummary]:
    override def call(): TaskSummary =
        try new TaskSolver(task, context, sources).call()
        catch
          case NonFatal(first) =>
              // Logged at debug, not warn: a retry that then SUCCEEDS costs nothing and is
              // expected on a cold graph, but "how often does this fire" is the first question
              // asked when residual nondeterminism is being chased, and it must be answerable
              // without a rebuild.
              logger.debug(
                s"Data flow task failed; retrying once synchronously: $first"
              )
              new TaskSolver(task, context, sources).call()

  private def extractResultsFromTable(sinks: List[CfgNode]): List[TableEntry] =
      sinks.flatMap { sink =>
          mainResultTable.get(TaskFingerprint(sink, List(), 0)) match
            case Some(results) => results
            case _             => Vector()
      }

  /** This must be called when one is done using the engine.
    */
  def shutdown(): Unit =
      executorService.shutdown()
end Engine

object Engine:

  /** Traverse from a node to incoming DDG nodes, taking into account semantics. This method is
    * exposed via the `ddgIn` step, but is also called by the engine internally by the `TaskSolver`.
    *
    * @param curNode
    *   the node to expand
    * @param path
    *   the path that has been expanded to reach the `curNode`
    */
  def expandIn(
    curNode: CfgNode,
    path: Vector[PathElement],
    callSiteStack: List[Call] = List()
  )(implicit semantics: Semantics): Vector[PathElement] =
      ddgInE(curNode, path, callSiteStack).flatMap(x => elemForEdge(x, callSiteStack))

  private def elemForEdge(e: Edge, callSiteStack: List[Call] = List())(implicit
    semantics: Semantics
  ): Option[PathElement] =
    val curNode  = e.inNode().asInstanceOf[CfgNode]
    val parNode  = e.outNode().asInstanceOf[CfgNode]
    val outLabel = Some(e.property(Properties.VARIABLE)).getOrElse("")

    if !EdgeValidator.isValidEdge(curNode, parNode) then
      return None

    curNode match
      case childNode: Expression =>
          parNode match
            case parentNode: Expression =>
                val parentNodeCall = parentNode.inCall.l
                val sameCallSite   = parentNode.inCall.l == childNode.start.inCall.l
                val visible = if sameCallSite then
                  val semanticExists = parentNode.semanticsForCallByArg.nonEmpty
                  // Methods the walk treats as a descendable callee (internal, or external
                  // with a body): the call site is a boundary the walk reports at, rather than
                  // an opaque call whose permissive in-edges are followed.
                  val internalMethodsForCall =
                      parentNodeCall.flatMap(methodsForCall)
                          .filter(MethodExplorability.stopsWalkAtCallSite)
                  (semanticExists && parentNode.isDefined) || internalMethodsForCall.isEmpty
                else
                  parentNode.isDefined
                val isOutputArg = isOutputArgOfInternalMethod(parentNode)
                Some(PathElement(
                  parentNode,
                  callSiteStack,
                  visible,
                  isOutputArg,
                  outEdgeLabel = outLabel
                ))
            case parentNode if parentNode != null =>
                Some(PathElement(parentNode, callSiteStack, outEdgeLabel = outLabel))
            case null =>
                None
      case _ =>
          Some(PathElement(parNode, callSiteStack, outEdgeLabel = outLabel))
    end match
  end elemForEdge

  /** The argument is (an implicit `this`/receiver aside) an argument of a call to a method whose
    * body the engine explores: the sibling-argument taint that the reaching-def pass manufactures
    * for every opaque call must not stand, because the callee's real statements decide what reaches
    * what. Explorability, not internality: an external method parsed with its body
    * (`python-deps=full`) is explored just the same.
    */
  def isOutputArgOfInternalMethod(arg: Expression)(implicit semantics: Semantics): Boolean =
      arg.inCall.l match
        case List(call) =>
            methodsForCall(call)
                .filter(MethodExplorability.isExplorable)
                .nonEmpty && semanticsForCall(call).isEmpty
        case _ =>
            false

  /** For a given node `node`, return all incoming reaching definition edges, unless the source node
    * is (a) a METHOD node, (b) already present on `path`, or (c) a CALL node to a method where the
    * semantic indicates that taint is propagated to it.
    */
  private def ddgInE(
    node: CfgNode,
    path: Vector[PathElement],
    callSiteStack: List[Call] = List()
  ): Vector[Edge] =
      node
          .inE(EdgeTypes.REACHING_DEF)
          .asScala
          .filter { e =>
              e.outNode() match
                case srcNode: CfgNode =>
                    // `path.exists(_.node == srcNode)` avoids materialising a fresh Vector of the
                    // whole path on every incoming edge (this is one of the hottest loops in the
                    // backward query).
                    !srcNode.isInstanceOf[Method] && !path.exists(_.node == srcNode)
                case _ => false
          }
          .toVector

  def argToOutputParams(arg: Expression): Iterator[MethodParameterOut] =
      argToMethods(arg).parameter
          .index(arg.argumentIndex)
          .asOutput

  def argToMethods(arg: Expression): List[Method] =
      arg.inCall.l.flatMap { call =>
          methodsForCall(call)
      }

  def methodsForCall(call: Call): List[Method] =
      NoResolve.getCalledMethods(call).toList

  /** True when the call resolves to a callee the walk treats as a boundary it reports at (see
    * [[MethodExplorability.stopsWalkAtCallSite]]): internal code, or external code that arrived
    * with a body. An opaque external callee keeps the permissive walk.
    */
  def isCallToInternalMethod(call: Call): Boolean =
      methodsForCall(call).exists(MethodExplorability.stopsWalkAtCallSite)
  def isCallToInternalMethodWithoutSemantic(call: Call)(implicit semantics: Semantics): Boolean =
      isCallToInternalMethod(call) && semanticsForCall(call).isEmpty

  def semanticsForCall(call: Call)(implicit semantics: Semantics): List[FlowSemantic] =
      Engine.methodsForCall(call).flatMap { method =>
          semantics.forMethod(method.fullName)
      }
end Engine

/** The execution context for the data flow engine.
  * @param semantics
  *   pre-determined semantic models for method calls e.g., logical operators, operators for common
  *   data structures.
  * @param config
  *   additional configurations for the data flow engine.
  */
case class EngineContext(
  semantics: Semantics = DefaultSemantics(),
  config: EngineConfig = EngineConfig()
)

/** Various configurations for the data flow engine.
  * @param maxCallDepth
  *   the k-limit for calls and field accesses.
  * @param initialTable
  *   an initial (starting node) -> (path-edges) cache to initiate data flow queries with.
  * @param shareCacheBetweenTasks
  *   enables sharing of previously calculated paths among other tasks.
  * @param maxArgsToAllow
  *   max limit to determine all corresponding arguments at all call sites to the method
  * @param maxOutputArgsExpansion
  *   max limit on number arguments for which tasks will be created for unresolved arguments
  */
case class EngineConfig(
  var maxCallDepth: Int = 3,
  initialTable: Option[mutable.Map[TaskFingerprint, Vector[ReachableByResult]]] = None,
  shareCacheBetweenTasks: Boolean = true,
  maxArgsToAllow: Int = 100,
  maxOutputArgsExpansion: Int = 100,
  // Opt-in (atom `--summaries`). When enabled and `summaries` is populated, the engine prunes
  // cross-call tasks that a method flow summary proves cannot carry taint (for example an output
  // argument the callee never writes). This only removes provably empty work, so results are
  // unchanged; it is off by default.
  var useSummaries: Boolean = false,
  summaries: Map[String, MethodFlowSummary] = Map.empty
)

/** Tracks various performance characteristics of the query engine.
  */
object QueryEngineStatistics extends Enumeration:

  type QueryEngineStatistic = Value

  val PATH_CACHE_HITS, PATH_CACHE_MISSES = Value

  private val statistics = new ConcurrentHashMap[QueryEngineStatistic, Long]()

  reset()

  /** Adds the given value to the associated value to the given [[QueryEngineStatistics]] key.
    * @param key
    *   the key associated with the value to transform.
    * @param value
    *   the value to add to the statistic. Can be negative.
    */
  def incrementBy(key: QueryEngineStatistic, value: Long): Unit =
      statistics.put(key, statistics.getOrDefault(key, 0L) + value)

  /** The results of the measured statistics.
    * @return
    *   a map of each [[QueryEngineStatistic]] and the associated value measurement.
    */
  def results(): Map[QueryEngineStatistic, Long] = statistics.asScala.toMap

  /** Sets all the tracked values back to 0.
    */
  def reset(): Unit =
      QueryEngineStatistics.values.map((_, 0L)).foreach { case (v, t) => statistics.put(v, t) }
end QueryEngineStatistics
