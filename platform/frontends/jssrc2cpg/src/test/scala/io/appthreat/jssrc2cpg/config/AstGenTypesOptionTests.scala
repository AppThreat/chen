package io.appthreat.jssrc2cpg.config

import io.appthreat.jssrc2cpg.{Config, Main}
import io.appthreat.x2cpg.X2Cpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class AstGenTypesOptionTests extends AnyWordSpec with Matchers:

  private def parse(extra: String*): Option[Config] =
      X2Cpg.parseCommandLine(
        Array("INPUT", "--output", "OUTPUT") ++ extra,
        Main.cmdLineParser,
        Config()
      )

  "the --astgen-types option" should {
      "accept native and ts6" in {
          parse("--astgen-types", "native").flatMap(_.astGenTypes) shouldBe Some("native")
          parse("--astgen-types", "ts6").flatMap(_.astGenTypes) shouldBe Some("ts6")
      }
      "accept upper case" in {
          parse("--astgen-types", "NATIVE").flatMap(_.astGenTypes) shouldBe Some("native")
      }
      "reject any other value" in {
          parse("--astgen-types", "tsgo") shouldBe None
      }
      "default to not set" in {
          parse().flatMap(_.astGenTypes) shouldBe None
      }
  }
end AstGenTypesOptionTests
