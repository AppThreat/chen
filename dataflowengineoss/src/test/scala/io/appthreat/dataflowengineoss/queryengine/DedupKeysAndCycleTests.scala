package io.appthreat.dataflowengineoss.queryengine

import io.shiftleft.OverflowDbTestInstance
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, NodeTypes, Properties}
import io.shiftleft.semanticcpg.language.MethodExplorability
import org.scalatest.matchers.should.Matchers.*
import org.scalatest.wordspec.AnyWordSpec
import overflowdb.*

import scala.collection.mutable
import scala.util.Random

/** The perf batch replaced three implementations with cheaper ones whose answers must be
  * indistinguishable from the previous versions: the per-entry cycle check, the two grouping keys
  * of the result deduplicators, and the per-call explorability predicates. These tests keep the
  * previous implementations as oracles and compare the two on hand-written and randomized cases.
  *
  * The grouping keys additionally pin their hash VALUES to the bare tuples': the iteration order of
  * the grouped map, and with it the order of the deduplicated list, depends on the hashes.
  */
class DedupKeysAndCycleTests extends AnyWordSpec:

  private val g = OverflowDbTestInstance.create

  private def genID(payload: String): Identifier =
    val ret = g + NodeTypes.IDENTIFIER
    ret.setProperty(Properties.NAME, payload)
    ret.asInstanceOf[Identifier]

  private def genCALL(payload: String): Call =
    val ret = g + NodeTypes.CALL
    ret.setProperty(Properties.NAME, payload)
    ret.asInstanceOf[Call]

  // A small alphabet, so that repeated nodes, shared call-site stacks and genuinely equal
  // elements all occur with reasonable probability.
  private val identifiers = (1 to 6).map(i => genID(s"i$i"))
  private val calls       = (1 to 6).map(i => genCALL(s"c$i"))
  private val rnd         = new Random(42)

  private def randomPath(maxLen: Int): Vector[PathElement] =
      Vector.fill(1 + rnd.nextInt(maxLen)):
        PathElement(
          node =
              if rnd.nextBoolean() then identifiers(rnd.nextInt(identifiers.size))
              else calls(rnd.nextInt(calls.size)),
          callSiteStack = List.fill(rnd.nextInt(3))(calls(rnd.nextInt(calls.size))),
          visible = rnd.nextBoolean(),
          isOutputArg = rnd.nextBoolean(),
          outEdgeLabel = if rnd.nextBoolean() then "" else "REACHING_DEF"
        )

  private def endpoint(path: Vector[PathElement], atStart: Boolean) =
    val x = (if atStart then path.headOption else path.lastOption).get
    (x.node, x.callSiteStack, x.isOutputArg)

  // The previous cycle-check implementation, kept verbatim as the oracle.
  private def oldContainsCycle(tableEntry: TableEntry): Boolean =
    val path    = tableEntry.path
    val nodeIds = new java.util.HashSet[java.lang.Long](path.size * 2)
    if path.forall(x => nodeIds.add(x.node.id())) then true
    else
      val pathSeq = path.map(x => (x.node, x.callSiteStack, x.isOutputArg, x.outEdgeLabel))
      pathSeq.distinct.size == pathSeq.size

  private val hc = HeldTaskCompletion(List(), mutable.Map())

  "containsCycle" should {
      "answer all-distinct paths as acyclic" in {
          hc.containsCycle(TableEntry(Vector(PathElement(identifiers(0))))) shouldBe true
          hc.containsCycle(
            TableEntry(identifiers.take(3).toVector.map(PathElement(_)))
          ) shouldBe true
      }

      "answer a repeated node with distinct elements as acyclic (the precise check decides)" in {
          val element = PathElement(identifiers(0), calls.take(2).toList)
          hc.containsCycle(TableEntry(Vector(element, PathElement(identifiers(0))))) shouldBe true
      }

      "answer a repeated identical element as a cycle" in {
          val element = PathElement(identifiers(0), calls.take(2).toList)
          hc.containsCycle(TableEntry(Vector(element, element))) shouldBe false
      }

      "agree with the previous implementation on randomized short paths" in {
          (1 to 300).foreach(_ =>
            val t = TableEntry(randomPath(8))
            hc.containsCycle(t) shouldBe oldContainsCycle(t)
          )
      }

      "agree with the previous implementation on long paths (the hash-set branch)" in {
          (1 to 20).foreach(_ =>
            val t = TableEntry(randomPath(120))
            hc.containsCycle(t) shouldBe oldContainsCycle(t)
          )
      }
  }

  "table entry grouping keys" should {
      "match the previous tuple equality and hash" in {
          (1 to 300).foreach(_ =>
            val a    = TableEntry(randomPath(8))
            val b    = TableEntry(randomPath(8))
            val oldA = (endpoint(a.path, atStart = true), endpoint(a.path, atStart = false))
            val oldB = (endpoint(b.path, atStart = true), endpoint(b.path, atStart = false))
            (a.dedupKey == b.dedupKey) shouldBe (oldA == oldB)
            a.dedupKey.hashCode shouldBe oldA.hashCode
            b.dedupKey.hashCode shouldBe oldB.hashCode
          )
      }

      "treat an entry as equal to itself via a second key instance" in {
          val a = TableEntry(randomPath(6))
          val keyAgain = TableEntryKey(
            endpoint(a.path, atStart = true),
            endpoint(a.path, atStart = false)
          )
          a.dedupKey shouldBe keyAgain
          a.dedupKey.hashCode shouldBe keyAgain.hashCode
      }
  }

  "result grouping keys" should {
      def randomResult(): ReachableByResult =
        val fingerprint = TaskFingerprint(
          calls(rnd.nextInt(calls.size)),
          List.fill(rnd.nextInt(3))(calls(rnd.nextInt(calls.size))),
          rnd.nextInt(5)
        )
        ReachableByResult(List(fingerprint), randomPath(8), partial = rnd.nextBoolean())

      def oldKey(r: ReachableByResult) =
          (
            endpoint(r.path, atStart = true),
            endpoint(
              r.path,
              atStart =
                  false
            ),
            r.partial,
            r.callDepth
          )

      "match the previous tuple equality and hash" in {
          (1 to 300).foreach(_ =>
            val a = randomResult()
            val b = randomResult()
            (a.resultDedupKey == b.resultDedupKey) shouldBe (oldKey(a) == oldKey(b))
            a.resultDedupKey.hashCode shouldBe oldKey(a).hashCode
          )
      }
  }

  "the explorability cache" should {
      def externalMethod(graph: Graph, withReturn: Boolean): Method =
        val m = (graph + NodeTypes.METHOD).asInstanceOf[Method]
        m.setProperty(Properties.IS_EXTERNAL, true)
        if withReturn then
          val r = (graph + NodeTypes.RETURN).asInstanceOf[Node]
          m --- EdgeTypes.CONTAINS --> r
        m

      def internalStub(graph: Graph): Method =
        // Internal and bodyless: `isStub` keeps it out of isExplorable, while every internal
        // method stops the walk at its call site. The engine asks both questions of the same
        // method in one query, so the two predicates' caches must not share answers.
        val m = (graph + NodeTypes.METHOD).asInstanceOf[Method]
        m.setProperty(Properties.IS_EXTERNAL, false)
        m

      "answer explorable from the method own graph, repeatedly" in {
          val g1  = OverflowDbTestInstance.create
          val m1  = externalMethod(g1, withReturn = true)
          val m1b = externalMethod(g1, withReturn = false)
          MethodExplorability.isExplorable(m1) shouldBe true
          MethodExplorability.isExplorable(m1) shouldBe true
          MethodExplorability.isExplorable(m1b) shouldBe false
          MethodExplorability.stopsWalkAtCallSite(m1) shouldBe true
          MethodExplorability.stopsWalkAtCallSite(m1b) shouldBe false
      }

      "answer the two predicates of one internal stub differently, in either ask order" in {
          val g1                       = OverflowDbTestInstance.create
          val g2                       = OverflowDbTestInstance.create
          val stubAskedStopsFirst      = internalStub(g1)
          val stubAskedExplorableFirst = internalStub(g2)
          MethodExplorability.stopsWalkAtCallSite(stubAskedStopsFirst) shouldBe true
          MethodExplorability.isExplorable(stubAskedStopsFirst) shouldBe false
          MethodExplorability.isExplorable(stubAskedExplorableFirst) shouldBe false
          MethodExplorability.stopsWalkAtCallSite(stubAskedExplorableFirst) shouldBe true
      }

      "not leak an answer into a second graph whose method has the same id" in {
          val g1            = OverflowDbTestInstance.create
          val g2            = OverflowDbTestInstance.create
          val withReturn    = externalMethod(g1, withReturn = true)
          val withoutReturn = externalMethod(g2, withReturn = false)
          withReturn.id shouldBe withoutReturn.id
          MethodExplorability.isExplorable(withReturn) shouldBe true
          MethodExplorability.isExplorable(withoutReturn) shouldBe false
          MethodExplorability.stopsWalkAtCallSite(withReturn) shouldBe true
          MethodExplorability.stopsWalkAtCallSite(withoutReturn) shouldBe false
      }
  }
end DedupKeysAndCycleTests
