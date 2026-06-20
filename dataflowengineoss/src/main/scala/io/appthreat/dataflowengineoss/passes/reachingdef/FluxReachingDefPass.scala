package io.appthreat.dataflowengineoss.passes.reachingdef

import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Reaching-definitions pass backed by the [[FluxSolver]] (the "Flux" engine).
  *
  * A drop-in alternative to [[ReachingDefPass]]: same problem construction, same bail-out, same
  * [[DdgGenerator]], hence identical `REACHING_DEF` edges - only the fixpoint solver differs. It is
  * opt-in (see `OssDataFlowOptions.useFluxEngine`) so the classic engine remains the default.
  */
class FluxReachingDefPass(cpg: Cpg, maxNumberOfDefinitions: Int = 4000)(implicit s: Semantics)
    extends ForkJoinParallelCpgPass[Method](cpg):

  s.loadRegexSemantics(cpg)

  override def generateParts(): Array[Method] = cpg.method.toArray

  override def runOnPart(dstGraph: DiffGraphBuilder, method: Method): Unit =
    val problem = ReachingDefProblem.create(method)
    if shouldBailOut(method, problem) then
      return

    val solution     = new FluxSolver().calculateMopSolutionForwards(problem)
    val ddgGenerator = new DdgGenerator(s)
    ddgGenerator.addReachingDefEdges(dstGraph, method, problem, solution)

  private def shouldBailOut(
    method: Method,
    problem: DataFlowProblem[StoredNode, mutable.BitSet]
  ): Boolean =
    val transferFunction    = problem.transferFunction.asInstanceOf[ReachingDefTransferFunction]
    val numberOfDefinitions = transferFunction.gen.foldLeft(0)(_ + _._2.size)
    numberOfDefinitions > maxNumberOfDefinitions
end FluxReachingDefPass
