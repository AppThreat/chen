package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.passes.reachingdef.{
    DataFlowSolver,
    FluxSolver,
    ReachingDefProblem
}
import _root_.io.shiftleft.codepropertygraph.Cpg
import _root_.io.shiftleft.semanticcpg.language.*

import java.lang.management.ManagementFactory

/** Measures the allocation/time difference between the classic [[DataFlowSolver]] and the Flux
  * engine ([[FluxSolver]]) on a deliberately large method - the shape (one giant method with many
  * interdependent definitions and loops) that makes the classic solver allocate heavily, mirroring
  * the transpiled-JavaScript megamethods seen on juice-shop.
  *
  * Runs single-threaded so per-thread allocation is directly comparable.
  */
class FluxReachingDefBenchmark extends CCodeToCpgSuite:

  private val threadMx =
      ManagementFactory.getThreadMXBean.asInstanceOf[com.sun.management.ThreadMXBean]

  private def allocatedBytes: Long =
      threadMx.getThreadAllocatedBytes(Thread.currentThread().getId)

  /** A single big method: many locals, an initialisation chain, two loops whose bodies reassign the
    * locals in terms of one another (loop-carried dependencies force fixpoint iteration), and a
    * large return expression keeping everything live.
    */
  private def bigMethod(nVars: Int): String =
    val decls = (0 until nVars).map(i => s"  int v$i = a + $i;").mkString("\n")
    val loop1 = (0 until nVars - 1).map(i => s"    v$i = v${i + 1} + v$i;").mkString("\n")
    val loop2 = (1 until nVars).map(i => s"    v$i = v${i - 1} + a;").mkString("\n")
    val ret   = (0 until nVars).map(i => s"v$i").mkString(" + ")
    s"""
       |int big(int a) {
       |$decls
       |  for (int i = 0; i < 50; i++) {
       |$loop1
       |  }
       |  while (a > 0) {
       |$loop2
       |    a = a - 1;
       |  }
       |  return $ret;
       |}
       |""".stripMargin

  "the Flux reaching-def engine" should:
    "use far less memory than the classic engine on a large method" in:
      val cpg: Cpg = code(bigMethod(200))
      val method   = cpg.method.name("big").head

      // Build the problem outside the measured region: its construction (gen/kill maps, flow graph)
      // is identical for both engines and would otherwise mask the solver's own allocation.
      def runClassic(): Int =
          new DataFlowSolver()
              .calculateMopSolutionForwards(ReachingDefProblem.create(method)).in.size
      def runFlux(): Int =
          new FluxSolver()
              .calculateMopSolutionForwards(ReachingDefProblem.create(method)).in.size

      // Warm up the JIT and confirm both solvers visit the same node set.
      runClassic(); runClassic()
      runFlux(); runFlux()
      runFlux() shouldBe runClassic()

      // Measure the solver only, on a pre-built problem.
      val classicProblem = ReachingDefProblem.create(method)
      System.gc()
      var a0 = allocatedBytes
      var t0 = System.nanoTime()
      new DataFlowSolver().calculateMopSolutionForwards(classicProblem)
      val classicNanos = System.nanoTime() - t0
      val classicAlloc = allocatedBytes - a0

      val fluxProblem = ReachingDefProblem.create(method)
      System.gc()
      a0 = allocatedBytes
      t0 = System.nanoTime()
      new FluxSolver().calculateMopSolutionForwards(fluxProblem)
      val fluxNanos = System.nanoTime() - t0
      val fluxAlloc = allocatedBytes - a0

      info(f"classic: ${classicAlloc / 1e6}%.1f MB allocated, ${classicNanos / 1e6}%.1f ms")
      info(f"flux:    ${fluxAlloc / 1e6}%.1f MB allocated, ${fluxNanos / 1e6}%.1f ms")
      info(f"alloc reduction: ${classicAlloc.toDouble / math.max(fluxAlloc, 1)}%.1fx")

      fluxAlloc should be < classicAlloc
end FluxReachingDefBenchmark
