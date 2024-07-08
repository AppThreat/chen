package io.appthreat.dataflowengineoss.passes.reachingdef

import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.{Logger, LoggerFactory}

import scala.collection.mutable

/** A pass that calculates reaching definitions ("data dependencies").
  */
class ReachingDefPass(cpg: Cpg, maxNumberOfDefinitions: Int = 4000)(implicit s: Semantics)
    extends ForkJoinParallelCpgPass[Method](cpg):

  private val logger: Logger = LoggerFactory.getLogger(this.getClass)
  // If there are any regex method full names, load them early
  s.loadRegexSemantics(cpg)

  override def generateParts(): Array[Method] = cpg.method.toArray

  override def runOnPart(dstGraph: DiffGraphBuilder, method: Method): Unit =
    logger.debug(
      "Calculating reaching definitions for: {} in {}",
      method.fullName,
      method.filename
    )
    val problem = ReachingDefProblem.create(method)
    if shouldBailOut(method, problem) then
      logger.warn("Skipping.")
      return

    val solution     = new DataFlowSolver().calculateMopSolutionForwards(problem)
    val ddgGenerator = new DdgGenerator(s)
    ddgGenerator.addReachingDefEdges(dstGraph, method, problem, solution)

  /** Before we start propagating definitions in the graph, which is the bulk of the work, we check
    * how many definitions were are dealing with in total. If a threshold is reached, we bail out
    * instead, leaving reaching definitions uncalculated for the method in question. Users can
    * increase the threshold if desired.
    */
  private def shouldBailOut(
    method: Method,
    problem: DataFlowProblem[StoredNode, mutable.BitSet]
  ): Boolean =
    val transferFunction = problem.transferFunction.asInstanceOf[ReachingDefTransferFunction]
    // For each node, the `gen` map contains the list of definitions it generates
    // We add up the sizes of these lists to obtain the total number of definitions
    val numberOfDefinitions = transferFunction.gen.foldLeft(0)(_ + _._2.size)
    logger.debug("Number of definitions for {}: {}", method.fullName, numberOfDefinitions)
    if numberOfDefinitions > maxNumberOfDefinitions then
      logger.warn("{} has more than {} definitions", method.fullName, maxNumberOfDefinitions)
      true
    else
      false
end ReachingDefPass
