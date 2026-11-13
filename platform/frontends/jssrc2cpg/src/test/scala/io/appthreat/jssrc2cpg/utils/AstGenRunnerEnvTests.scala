package io.appthreat.jssrc2cpg.utils

import io.appthreat.jssrc2cpg.Config
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class AstGenRunnerEnvTests extends AnyWordSpec with Matchers:

  "the astgen cache fingerprint" should {
      "differ by the type map engine, so a cached parse is not restored for another engine" in {
          // the version probe runs astgen in the input directory, so it has to exist
          val dir = java.nio.file.Files.createTempDirectory("astgenFingerprint").toString
          def inputs(c: Config) =
              new AstGenRunner(c.withInputPath(dir)).astGenFingerprintInputs
                  .filter(_.startsWith("astgen-types="))
          inputs(Config()) shouldBe Seq(s"astgen-types=${Config().effectiveAstGenTypes()}")
          inputs(Config().withAstGenTypes("native")) shouldBe Seq("astgen-types=native")
          inputs(Config().withAstGenTypes("ts6")) shouldBe Seq("astgen-types=ts6")
      }
  }

  "the astgen-types setting" should {
      "be passed to astgen as ASTGEN_TYPES" in {
          new AstGenRunner(Config().withAstGenTypes("native")).astGenEnv shouldBe Map(
            "ASTGEN_TYPES" -> "native"
          )
          new AstGenRunner(Config().withAstGenTypes("ts6")).astGenEnv shouldBe Map(
            "ASTGEN_TYPES" -> "ts6"
          )
      }

      "leave the environment alone when it is not set" in {
          new AstGenRunner(Config()).astGenEnv shouldBe Map.empty
      }

      "fall back to an inherited ASTGEN_TYPES, read as astgen reads it" in {
          Config().effectiveAstGenTypes(Map.empty) shouldBe "ts6"
          Config().effectiveAstGenTypes(Map("ASTGEN_TYPES" -> " Native ")) shouldBe "native"
          Config().effectiveAstGenTypes(Map("ASTGEN_TYPES" -> "fast")) shouldBe "ts6"
          Config().withAstGenTypes("ts6").effectiveAstGenTypes(
            Map("ASTGEN_TYPES" -> "native")
          ) shouldBe "ts6"
      }

      "be normalized to lower case and ignored when blank" in {
          Config().withAstGenTypes("NATIVE").astGenTypes shouldBe Some("native")
          Config().withAstGenTypes("  ").astGenTypes shouldBe None
      }
  }

  "the astgen command" should {
      "be plain astgen unless a test setting names another one" in {
          val fromEnv = sys.env.get("JSSRC2CPG_TEST_ASTGEN_CMD").map(_.trim).filter(_.nonEmpty)
          if fromEnv.isEmpty then AstGenRunner.astGenCommand shouldBe "astgen"
          System.setProperty("jssrc2cpg.test.astgenCmd", "node /somewhere/astgen.js")
          try AstGenRunner.astGenCommand shouldBe "node /somewhere/astgen.js"
          finally System.clearProperty("jssrc2cpg.test.astgenCmd")
          System.setProperty("jssrc2cpg.test.astgenCmd", "   ")
          try AstGenRunner.astGenCommand shouldBe fromEnv.getOrElse("astgen")
          finally System.clearProperty("jssrc2cpg.test.astgenCmd")
      }
  }
  "astgen's arguments" should {
      "reach it as they are, with no shell" in {
          assume(!scala.util.Properties.isWin)
          better.files.File.usingTemporaryDirectory("astgen") { tools =>
              better.files.File.usingTemporaryDirectory("project $(touch marker1)") { project =>
                val fake = tools / "astgen"
                fake.writeText("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n")
                fake.toJava.setExecutable(true)
                val out    = tools / "astgen-out; touch marker2"
                val runner = new AstGenRunner(Config().withInputPath(project.pathAsString))
                val args   = runner.astGenArgs("ts", out)
                args.takeRight(2) shouldBe Seq("-o", out.pathAsString)
                runner.runAstGen(project, args, (fake.pathAsString, Seq("--prefix"))).get shouldBe
                    "--prefix" +: args
                project.list.map(_.name).toSeq shouldBe empty
                tools.list.map(_.name).filter(_.startsWith("marker")).toSeq shouldBe empty
              }
          }
      }

      "split a test command into the program and its leading arguments" in {
          System.setProperty("jssrc2cpg.test.astgenCmd", "node   /somewhere/astgen.js")
          try AstGenRunner.astGenProgram shouldBe ("node", Seq("/somewhere/astgen.js"))
          finally System.clearProperty("jssrc2cpg.test.astgenCmd")
      }
  }
end AstGenRunnerEnvTests
