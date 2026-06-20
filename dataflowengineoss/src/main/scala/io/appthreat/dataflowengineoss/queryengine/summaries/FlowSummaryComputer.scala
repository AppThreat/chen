package io.appthreat.dataflowengineoss.queryengine.summaries

import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.CpgAlgorithms.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*
import overflowdb.Node

import scala.collection.mutable
import scala.jdk.CollectionConverters.*

/** Computes [[MethodFlowSummary]] facts for every internal method in a graph.
  *
  * Summaries are built callee-before-caller so that, by the time a method is processed, the
  * summaries of the methods it calls are already available to be plugged in. Recursion would make a
  * strict ordering impossible, so methods are first grouped into strongly connected components of
  * the call graph; the components form an acyclic condensation that is processed callee-first, and
  * each recursive component is iterated to a fixpoint (summaries only grow, so this terminates).
  *
  * The result is returned as an immutable map and can be used as a
  * [[MethodFlowSummary.SummaryLookup]] by any consumer that wants context-independent flow facts
  * without running the full query engine.
  */
object FlowSummaryComputer:

  /** Return summaries for all internal methods, restoring them from `cacheDir` when an entry for
    * the current graph already exists and storing freshly computed summaries otherwise. The cache
    * is gated by `CacheControl.Summary`; when it is disabled this simply computes the summaries.
    */
  def loadOrCompute(
    cpg: Cpg,
    cacheDir: String,
    semantics: Semantics = Semantics.empty
  ): Map[String, MethodFlowSummary] =
    val store       = new FlowSummaryStore(cacheDir)
    val fingerprint = FlowSummaryStore.fingerprint(cpg, semantics)
    store.restore(fingerprint) match
      case Some(summaries) => summaries
      case None =>
          val summaries = computeAll(cpg, semantics)
          store.store(fingerprint, summaries)
          summaries

  /** Compute summaries for all internal methods in `cpg`. A method that has a declared flow
    * semantic gets its summary from that semantic (sanitizer / pass-through aware); other methods
    * are computed from their body, plugging in already-computed callee summaries and respecting the
    * semantics of any callees that have them.
    */
  def computeAll(
    cpg: Cpg,
    semantics: Semantics = Semantics.empty
  ): Map[String, MethodFlowSummary] =
    val methods    = cpg.method.internal.l
    val byFullName = methods.groupBy(_.fullName)
    val cache      = mutable.Map.empty[String, MethodFlowSummary]
    def lookup(name: String): Option[MethodFlowSummary] = cache.get(name)

    def summaryOf(m: Method): MethodFlowSummary =
        semantics.forMethod(m.fullName) match
          case Some(semantic) => MethodFlowSummary.fromSemantic(m, semantic)
          case None           => MethodFlowSummary.of(m, lookup, semantics)

    val nodes      = methods.map(_.asInstanceOf[Node])
    val components = nodes.stronglyConnectedComponents(calleesOf(byFullName.keySet))

    calleeFirstOrder(components, byFullName.keySet).foreach { component =>
      val componentMethods = component.toSeq.collect { case m: Method => m }
      val recursive        = component.size > 1 || componentMethods.exists(isSelfRecursive)
      if !recursive then
        componentMethods.foreach(m => cache(m.fullName) = summaryOf(m))
      else
        componentMethods.foreach(m =>
            cache.getOrElseUpdate(m.fullName, MethodFlowSummary.empty(m.fullName))
        )
        var changed = true
        while changed do
          changed = false
          componentMethods.foreach { m =>
            val next = summaryOf(m)
            if !cache.get(m.fullName).contains(next) then
              cache(m.fullName) = next
              changed = true
          }
    }
    cache.toMap
  end computeAll

  /** Successor function over the call graph restricted to the internal methods we summarise. */
  private def calleesOf(internalNames: Set[String])(node: Node): Iterator[Node] =
      node match
        case m: Method =>
            m.call
                .flatMap(_.out(EdgeTypes.CALL).asScala.collect { case c: Method => c })
                .filter(c => internalNames.contains(c.fullName))
                .iterator
        case _ => Iterator.empty

  private def isSelfRecursive(method: Method): Boolean =
      method.call.flatMap(_.out(EdgeTypes.CALL).asScala.collect { case c: Method => c })
          .exists(_.fullName == method.fullName)

  /** Orders the strongly connected components so that callees come before callers, by topologically
    * sorting the (acyclic) condensation and reversing it.
    */
  private def calleeFirstOrder(
    components: Seq[Set[Node]],
    internalNames: Set[String]
  ): Seq[Set[Node]] =
    val componentOfNode = mutable.HashMap.empty[Long, Int]
    components.zipWithIndex.foreach { case (component, index) =>
        component.foreach(node => componentOfNode(node.id()) = index)
    }
    val callees    = calleesOf(internalNames)
    val size       = components.size
    val successors = Array.fill(size)(mutable.Set.empty[Int])
    val inDegree   = Array.fill(size)(0)
    components.foreach { component =>
        component.foreach { node =>
          val from = componentOfNode(node.id())
          callees(node).foreach { callee =>
              componentOfNode.get(callee.id()).foreach { to =>
                  if to != from && !successors(from).contains(to) then
                    successors(from) += to
                    inDegree(to) += 1
              }
          }
        }
    }
    val queue = mutable.Queue.empty[Int]
    (0 until size).foreach(index => if inDegree(index) == 0 then queue.enqueue(index))
    val callerFirst = mutable.ArrayBuffer.empty[Int]
    while queue.nonEmpty do
      val current = queue.dequeue()
      callerFirst += current
      successors(current).foreach { to =>
        inDegree(to) -= 1
        if inDegree(to) == 0 then queue.enqueue(to)
      }
    callerFirst.reverse.map(components).toSeq
  end calleeFirstOrder
end FlowSummaryComputer
