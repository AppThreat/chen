package io.appthreat.jssrc2cpg.config

import io.appthreat.jssrc2cpg.{Config, Main}

import org.scalatest.wordspec.AnyWordSpec
import org.scalatest.matchers.should.Matchers
import io.appthreat.x2cpg.X2Cpg
import org.scalatest.Inside

class ConfigTests extends AnyWordSpec with Matchers with Inside {

  private def getSuffix(s: String, n: Int): String = s.takeRight(n)

  "parsing the jssrc2cpg config" should {

    "handle command line args correctly" in {
      val parser = Main.cmdLineParser
      val args = Array(
        // Common args
        "INPUT",
        "--output",
        "OUTPUT",
        "--exclude",
        "1EXCLUDE_FILE,2EXCLUDE_FILE",
        "--exclude-regex",
        "EXCLUDE_REGEX",
        // Frontend-specific args
        "--no-tsTypes",
        "--no-dummyTypes"
      )

      inside(X2Cpg.parseCommandLine(args, parser, Config())) { case Some(config) =>
        config.inputPath.endsWith("INPUT") shouldBe true
        config.outputPath shouldBe "OUTPUT"
        config.ignoredFiles.map(getSuffix(_, 13)).toSet shouldBe Set("1EXCLUDE_FILE", "2EXCLUDE_FILE")
        config.ignoredFilesRegex.toString shouldBe "EXCLUDE_REGEX"
        config.tsTypes shouldBe false
        config.disableDummyTypes shouldBe true
      }
    }
  }

}
