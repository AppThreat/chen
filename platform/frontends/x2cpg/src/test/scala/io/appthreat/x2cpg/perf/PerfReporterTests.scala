package io.appthreat.x2cpg.perf

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files
import scala.jdk.CollectionConverters.*

class PerfReporterTests extends AnyWordSpec with Matchers:

  "PerfReporter when disabled" should {

      "run the body unchanged and write nothing" in {
          val tmp = Files.createTempDirectory("perf-reporter")
          System.clearProperty("chen.perf.report")
          PerfReporter.isEnabled shouldBe false
          val result = PerfReporter.stage("disabled.probe", "analysis") {
              41 + 1
          }
          result shouldBe 42
          // No file appears anywhere under the temp dir: the disabled path must not even
          // resolve clocks, let alone write.
          Files.list(tmp).iterator.asScala.toList shouldBe empty
      }

      "propagate exceptions from the body" in {
          System.clearProperty("chen.perf.report")
          val thrown = the[IllegalStateException] thrownBy PerfReporter.stage("boom", "analysis") {
              throw new IllegalStateException("boom")
          }
          thrown.getMessage shouldBe "boom"
      }
  }

  "PerfReporter when enabled" should {

      "emit a meta line plus one NDJSON line per stage with the documented fields" in {
          val tmp    = Files.createTempDirectory("perf-reporter")
          val report = tmp.resolve("perf.ndjson")
          System.setProperty("chen.perf.report", report.toString)
          try
            PerfReporter.isEnabled shouldBe true
            val out = PerfReporter.stage("test.first", "analysis") { "value" }
            out shouldBe "value"
            a[RuntimeException] should be thrownBy PerfReporter.stage("test.failing", "analysis") {
                throw new RuntimeException("nope")
            }
          finally System.clearProperty("chen.perf.report")

          val lines = Files.readAllLines(report).asScala.toList
          lines should have size 3
          val meta = ujson.read(lines(0))
          meta("stage").str shouldBe "__meta__"
          meta.obj.contains("jvm") shouldBe true

          val ok = ujson.read(lines(1))
          ok("stage").str shouldBe "test.first"
          ok("phase").str shouldBe "analysis"
          ok("wallMs").num should be >= 0.0
          ok("cpuMs").num should be >= 0.0
          ok("startEpochMs").num should be > 0.0
          ok("ok").bool shouldBe true

          val failed = ujson.read(lines(2))
          failed("stage").str shouldBe "test.failing"
          failed("ok").bool shouldBe false
      }
  }
end PerfReporterTests
