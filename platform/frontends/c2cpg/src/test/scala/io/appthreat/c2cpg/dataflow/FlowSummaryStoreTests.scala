package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.queryengine.summaries.{
    FlowSummaryComputer,
    FlowSummaryStore
}
import _root_.io.appthreat.x2cpg.passes.frontend.CacheControl
import _root_.io.shiftleft.semanticcpg.language.*

import java.nio.file.Files

/** Validates persistence of method flow summaries: serialization round-trips, the fingerprint is
  * stable, and a stored set is restored on a second request.
  */
class FlowSummaryStoreTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |int id(int p) { return p; }
      |int wrapper(int a, int b) { return id(a); }
      |""".stripMargin)

  "FlowSummaryStore" should:
    "round-trip summaries through JSON" in:
      val summaries = FlowSummaryComputer.computeAll(cpg)
      val json      = FlowSummaryStore.serialize(summaries)
      val restored  = FlowSummaryStore.deserialize(json)
      restored shouldBe Right(summaries)

    "produce a stable fingerprint for the same graph" in:
      FlowSummaryStore.fingerprint(cpg) shouldBe FlowSummaryStore.fingerprint(cpg)

    "restore a stored summary set instead of recomputing" in:
      val cacheDir = Files.createTempDirectory("flowsummary-cache")
      CacheControl.enable(CacheControl.Summary)
      try
        val first  = FlowSummaryComputer.loadOrCompute(cpg, cacheDir.toString)
        val stored = cacheDir.resolve(s"flowsummary-${FlowSummaryStore.fingerprint(cpg)}.json")
        Files.exists(stored) shouldBe true
        val second = FlowSummaryComputer.loadOrCompute(cpg, cacheDir.toString)
        second shouldBe first
      finally
        CacheControl.disable(CacheControl.Summary)

    "skip the cache when the summary kind is disabled" in:
      val cacheDir = Files.createTempDirectory("flowsummary-nocache")
      CacheControl.disable(CacheControl.Summary)
      val summaries = FlowSummaryComputer.loadOrCompute(cpg, cacheDir.toString)
      summaries shouldBe FlowSummaryComputer.computeAll(cpg)
      // Nothing should have been written while the cache kind is disabled.
      Files.list(cacheDir).count() shouldBe 0L
end FlowSummaryStoreTests
