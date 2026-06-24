package io.appthreat.dataflowengineoss.passes.reachingdef

import io.shiftleft.codepropertygraph.generated.nodes.StoredNode

import scala.collection.mutable

/** Flux - a fast, low-allocation reaching-definitions solver.
  *
  * It computes the exact same forward MOP solution as
  * [[DataFlowSolver.calculateMopSolutionForwards]] (the classic engine) but is engineered to keep
  * the fixpoint loop allocation-free, which is where the classic solver hurts on very large (e.g.
  * transpiled JavaScript) methods.
  *
  * Why it is equivalent: the reaching-def lattice is the powerset of `Definition`s, every
  * definition is already a dense integer (the node number assigned by [[ReachingDefFlowGraph]]),
  * and `meet` is set union - a monotone, distributive framework. The least fixpoint of such a
  * framework is independent of worklist visit order, so a node-numbered worklist with in-place
  * bitset operations reaches the identical `in`/`out` solution as the classic round-based solver.
  *
  * Why it is cheaper: the classic solver keeps `in`/`out` as `Map[Node, BitSet]` rebuilt with `+=`
  * every round and, per node per visit, allocates fresh bitsets (`gen(n).union(x.diff(kill(n)))`)
  * plus a `.distinct` over the worklist. Flux stores `out` as a dense `Array[BitSet]` indexed by
  * node number and mutates a single reusable scratch bitset in place (`|=`, `&~=`), so the steady
  * state of the loop performs no allocation at all.
  *
  * [[DdgGenerator]] only consumes `Solution.in` (its `.keys` and `UsageAnalyzer`), so producing an
  * identical `in` map - keyed, as in the classic solver, by `allNodesReversePostOrder` - makes the
  * resulting `REACHING_DEF` edges byte-for-byte identical.
  */
class FluxSolver:

  def calculateMopSolutionForwards(
    problem: DataFlowProblem[StoredNode, mutable.BitSet]
  ): Solution[StoredNode, mutable.BitSet] =
    val flowGraph    = problem.flowGraph.asInstanceOf[ReachingDefFlowGraph]
    val transfer     = problem.transferFunction.asInstanceOf[ReachingDefTransferFunction]
    val nodeToNumber = flowGraph.nodeToNumber
    val numberToNode = flowGraph.numberToNode
    val m            = numberToNode.size

    // Dense, node-number-indexed state. `gen`/`kill` are read-only. `out` follows the classic
    // solver's copy-on-write discipline (`initOut = gen`): each `out(i)` starts as the *shared*
    // `gen(i)` reference and is only replaced by a freshly allocated set when its value actually
    // changes. This is critical for large transpiled-JS CFGs, where most nodes have an empty `gen`
    // and never change - eagerly cloning a BitSet per node would allocate millions of distinct
    // (mostly empty) sets and exhaust the heap.
    val gen   = new Array[mutable.BitSet](m)
    val kill  = new Array[mutable.BitSet](m)
    val out   = new Array[mutable.BitSet](m)
    val isRpo = new Array[Boolean](m)
    var i     = 0
    while i < m do
      val node = numberToNode(i)
      gen(i) = transfer.gen(node)   // shared default-empty bitset when absent; read-only
      kill(i) = transfer.kill(node) // ditto
      out(i) = gen(i)               // shared until first change (copy-on-write below)
      i += 1

    // Only reachable nodes (those the classic solver puts on its initial worklist) are processed,
    // so the `in` keyset matches exactly. Predecessor/successor adjacency is precomputed as node
    // numbers to avoid map lookups in the loop.
    val rpoNodes = flowGraph.allNodesReversePostOrder
    val preds    = new Array[Array[Int]](m)
    val succs    = new Array[Array[Int]](m)
    rpoNodes.foreach { node =>
      val idx = nodeToNumber(node)
      isRpo(idx) = true
      preds(idx) = flowGraph.pred(node).iterator.collect {
          case p if nodeToNumber.contains(p) => nodeToNumber(p)
      }.toArray
      succs(idx) = flowGraph.succ(node).iterator.collect {
          case s if nodeToNumber.contains(s) => nodeToNumber(s)
      }.toArray
    }

    // Worklist fixpoint. Reverse-postorder seeding gives fast convergence on forward problems.
    val inQueue = new Array[Boolean](m)
    val queue   = mutable.ArrayDeque.empty[Int]
    rpoNodes.foreach { node =>
      val idx = nodeToNumber(node)
      queue.append(idx)
      inQueue(idx) = true
    }

    val scratch = mutable.BitSet()
    while queue.nonEmpty do
      val idx = queue.removeHead()
      inQueue(idx) = false

      // scratch := gen(idx) | (in(idx) \ kill(idx)), where in(idx) = union of out over predecessors
      scratch.clear()
      val ps = preds(idx)
      var k  = 0
      while k < ps.length do
        scratch |= out(ps(k))
        k += 1
      scratch &~= kill(idx)
      scratch |= gen(idx)

      if scratch != out(idx) then
        // Copy-on-write: replace the (possibly shared) set with a right-sized snapshot. Only nodes
        // that actually change ever allocate, so unchanged empty-`gen` nodes keep sharing one set.
        out(idx) = scratch.clone()
        val ss = succs(idx)
        var j  = 0
        while j < ss.length do
          val s = ss(j)
          if isRpo(s) && !inQueue(s) then
            queue.append(s)
            inQueue(s) = true
          j += 1
    end while
    // Materialise the solution once. `in(n)` is the union of `out` over n's predecessors at the
    // fixpoint - equivalent to the classic solver's last-visit `in`. `DdgGenerator` ignores `out`,
    // but we provide it for a complete `Solution`.
    //
    // Memory note: the classic solver's `reduceOption(meet)` returns the single predecessor's `out`
    // set *by reference* when a node has exactly one predecessor, so long linear chains (the common
    // shape of transpiled JavaScript) share one BitSet object across the whole chain instead of
    // allocating a distinct copy per node. We replicate that structural sharing here - only nodes
    // with >= 2 predecessors allocate a fresh union - to keep peak memory in line with the classic
    // engine (a fresh-copy-per-node materialisation OOMs on large methods).
    val emptyShared = mutable.BitSet()
    val inMap       = Map.newBuilder[StoredNode, mutable.BitSet]
    val outMap      = Map.newBuilder[StoredNode, mutable.BitSet]
    rpoNodes.foreach { node =>
      val idx = nodeToNumber(node)
      val ps  = preds(idx)
      val inSet =
          if ps.length == 0 then emptyShared
          else if ps.length == 1 then out(ps(0)) // share predecessor's `out` by reference
          else
            val s = mutable.BitSet()
            var k = 0
            while k < ps.length do
              s |= out(ps(k))
              k += 1
            s
      inMap += node  -> inSet
      outMap += node -> out(idx)
    }

    Solution(
      inMap.result().withDefaultValue(mutable.BitSet()),
      outMap.result().withDefaultValue(mutable.BitSet()),
      problem
    )
  end calculateMopSolutionForwards
end FluxSolver
