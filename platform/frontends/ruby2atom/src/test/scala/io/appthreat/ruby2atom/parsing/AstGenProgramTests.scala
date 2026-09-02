package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.parser.RubyAstGenRunner
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The generator binary can be overridden without touching `PATH`, so a custom `rbastgen` build
  * can be used when ruby2atom runs inside another process (atom loads it as a library, so it
  * inherits that process's `PATH` and cannot be pointed at a different binary otherwise).
  */
class AstGenProgramTests extends AnyWordSpec with Matchers:

  "the generator program" should {

      "default to the PATH lookup" in {
        RubyAstGenRunner.resolveProgram(None, None) shouldBe "rbastgen"
      }

      "prefer the system property over the environment" in {
        RubyAstGenRunner.resolveProgram(
          Some("/opt/custom/rbastgen"),
          Some("/usr/bin/rbastgen")
        ) shouldBe "/opt/custom/rbastgen"
      }

      "fall back to the environment variable" in {
        RubyAstGenRunner.resolveProgram(None, Some("/usr/bin/rbastgen")) shouldBe "/usr/bin/rbastgen"
      }

      "treat blank values as unset" in {
        RubyAstGenRunner.resolveProgram(Some("  "), Some("")) shouldBe "rbastgen"
      }
  }
end AstGenProgramTests
