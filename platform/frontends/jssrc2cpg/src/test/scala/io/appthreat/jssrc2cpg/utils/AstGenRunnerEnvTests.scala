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
          inputs(Config()) shouldBe Seq("astgen-types=default")
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

      "be normalized to lower case and ignored when blank" in {
          Config().withAstGenTypes("NATIVE").astGenTypes shouldBe Some("native")
          Config().withAstGenTypes("  ").astGenTypes shouldBe None
      }
  }
end AstGenRunnerEnvTests
