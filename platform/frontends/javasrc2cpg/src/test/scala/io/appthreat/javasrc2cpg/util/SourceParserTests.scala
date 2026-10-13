package io.appthreat.javasrc2cpg.util

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class SourceParserTests extends AnyWordSpec with Matchers:

  "the roots to analyse" should {
      "be the original sources where delombok could not run" in {
          // atom's native image has no class path to fork delombok with
          SourceParser.analysisAndTypesDirs("/src", "", None, hasLombokDependency = true) shouldBe
              ("/src", "/src")
          SourceParser.analysisAndTypesDirs("/src", "", Some("run-delombok"), false) shouldBe
              ("/src", "/src")
          SourceParser.analysisAndTypesDirs("/src", "", Some("types-only"), false) shouldBe
              ("/src", "/src")
      }
      "follow the delombok mode where it ran" in {
          SourceParser.analysisAndTypesDirs("/src", "/d", None, hasLombokDependency = true) shouldBe
              ("/d", "/d")
          SourceParser.analysisAndTypesDirs("/src", "/d", None, false) shouldBe ("/src", "/src")
          SourceParser.analysisAndTypesDirs("/src", "/d", Some("no-delombok"), true) shouldBe
              ("/src", "/src")
          SourceParser.analysisAndTypesDirs("/src", "/d", Some("types-only"), true) shouldBe
              ("/src", "/d")
          SourceParser.analysisAndTypesDirs("/src", "/d", Some("run-delombok"), false) shouldBe
              ("/d", "/d")
      }
  }
end SourceParserTests
