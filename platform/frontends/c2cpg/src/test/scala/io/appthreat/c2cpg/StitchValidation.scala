package io.appthreat.c2cpg

import _root_.io.appthreat.x2cpg.passes.base.MethodStubCreator
import _root_.io.appthreat.x2cpg.passes.callgraph.{DynamicCallLinker, MethodRefLinker, StaticCallLinker}
import _root_.io.appthreat.x2cpg.passes.typerelations.{AliasLinkerPass, TypeHierarchyPass}
import _root_.io.appthreat.x2cpg.passes.linking.StitchPass
import _root_.io.shiftleft.codepropertygraph.Cpg
import _root_.io.shiftleft.codepropertygraph.generated.PropertyNames
import _root_.io.shiftleft.semanticcpg.language.*
import overflowdb.util.DiffTool

import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import scala.jdk.CollectionConverters.*

/** End-to-end validation harness for the modular link phase (CHEN3_PLAN §3 / §8) on a real C
  * codebase (openssl by default).
  *
  * It demonstrates, on the same persisted base graph (so node IDs are stable and comparable):
  *   - '''AST-cache benefit''' - cold vs warm frontend build time.
  *   - '''Graph equivalence''' - StitchPass produces the same graph as the whole-graph
  *     MethodStubCreator + StaticCallLinker (DiffTool reports no differences).
  *   - '''Incremental stitch''' - restitching a single dirty unit does work proportional to that
  *     unit, not the whole program.
  *
  * Run with:
  * {{{
  * sbt "c2cpg/Test/runMain io.appthreat.c2cpg.StitchValidation [inputDir] [workDir]"
  * }}}
  */
object StitchValidation:

  private def time[T](label: String)(body: => T): T =
    val t0  = System.nanoTime()
    val res = body
    println(f"[time] $label%-44s ${(System.nanoTime() - t0) / 1e6}%9.1f ms")
    res

  private def deleteRecursively(p: Path): Unit =
      if Files.exists(p) then
        Files.walk(p).sorted(java.util.Comparator.reverseOrder()).iterator().asScala
            .foreach(Files.deleteIfExists)

  private def buildTo(input: String, out: String): Unit =
    Files.deleteIfExists(Paths.get(out))
    val cfg = Config().withInputPath(input).withOutputPath(out)
    val cpg = new C2Cpg().createCpg(cfg).get
    cpg.close()

  def main(args: Array[String]): Unit =
    val input = if args.nonEmpty then args(0) else "/Users/prabhu/sandbox/openssl-4.0.0/ssl"
    val work  = Paths.get(if args.length > 1 then args(1) else "/tmp/stitchval")
    Files.createDirectories(work)
    val base = work.resolve("base.bin").toString

    println(s"== Stitch validation on $input ==")

    // --- AST cache: cold vs warm frontend build ---
    deleteRecursively(Paths.get(input, ".chen"))
    time("cold frontend build (AST cache empty)")(buildTo(input, base))
    time("warm frontend build (AST cache hit)")(buildTo(input, work.resolve("warm.bin").toString))

    // --- Graph equivalence: trio vs StitchPass on identical base copies ---
    val a = work.resolve("a.bin")
    val b = work.resolve("b.bin")
    Files.copy(Paths.get(base), a, StandardCopyOption.REPLACE_EXISTING)
    Files.copy(Paths.get(base), b, StandardCopyOption.REPLACE_EXISTING)

    val cpgA = Cpg.withStorage(a.toString)
    time("whole-graph linkers (6 passes)") {
        cpgA.graph.indexManager.createNodePropertyIndex(PropertyNames.FULL_NAME)
        new MethodStubCreator(cpgA).createAndApply()
        new TypeHierarchyPass(cpgA).createAndApply()
        new AliasLinkerPass(cpgA).createAndApply()
        new MethodRefLinker(cpgA).createAndApply()
        new StaticCallLinker(cpgA).createAndApply()
        new DynamicCallLinker(cpgA).createAndApply()
    }

    val cpgB   = Cpg.withStorage(b.toString)
    val stitch = new StitchPass(cpgB)
    time("StitchPass (full)")(stitch.createAndApply())
    println(s"[stitch] realizedEdges=${stitch.realizedEdges} synthesizedStubs=${stitch.synthesizedStubs}")

    val diff = DiffTool.compare(cpgA.graph, cpgB.graph).asScala.toList
    println(s"[equivalence] DiffTool difference entries = ${diff.size}")
    diff.take(20).foreach(d => println("   " + d))

    cpgA.close()
    cpgB.close()

    // --- Incremental: restitch only one dirty unit ---
    val c = work.resolve("c.bin")
    Files.copy(Paths.get(base), c, StandardCopyOption.REPLACE_EXISTING)
    val cpgC = Cpg.withStorage(c.toString)
    // Pick the source file that declares the most methods as the single "dirty" unit.
    val dirtyFile = cpgC.method.filename
        .filter(f => f != null && f.nonEmpty)
        .l
        .groupBy(identity)
        .view
        .mapValues(_.size)
        .toList
        .sortBy(-_._2)
        .headOption
        .map(_._1)
    dirtyFile match
      case Some(f) =>
          val inc = new StitchPass(cpgC, dirtyUnits = Some(Set(f)))
          time(s"StitchPass (incremental: 1 unit)")(inc.createAndApply())
          println(
            s"[incremental] dirty=$f realizedEdges=${inc.realizedEdges} " +
                s"synthesizedStubs=${inc.synthesizedStubs} (full was ${stitch.realizedEdges})"
          )
      case None =>
          println("[incremental] no call site with a filename found; skipped")
    cpgC.close()
    println("== done ==")
  end main
end StitchValidation
