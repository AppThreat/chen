package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Literal-level fixtures: heredocs and percent-array literals (plan 04 §5). */
class LiteralTests extends RubyCode2CpgFixture:

  "heredoc content reaches the CPG through the node value" in {
    val cpg = fixtureWithoutUnknowns("heredoc")
    // The heredoc body is NOT covered by meta_data/offsets (those cover only the `<<~SQL`
    // marker); the content is reachable via the node's `value`.
    cpg.literal.code.l.exists(_.contains("select * from users")) shouldBe true
    cpg.local.name.l should contain("sql")
  }

  "percent arrays keep their element types" in {
    val cpg = fixtureWithoutUnknowns("percent_array")
    // %w[...] elements are strings, %i[...] elements are symbols.
    cpg.literal.code.l should contain("alice")
    cpg.literal.code.l should contain(":on")
    cpg.local.name.l should contain("names")
    cpg.local.name.l should contain("flags")
    // A plain array is not a percent array.
    cpg.literal.code.l should contain("1")
  }
