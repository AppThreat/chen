package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Call syntax comes from the generator's syntax facts (`call_operator`, `has_parentheses`,
  * `percent_array`, `heredoc`) instead of text heuristics over the whitespace-normalized `code`
  * string (plan 04 §5).
  *
  * Measured scope of that migration, by reverting each fact read to the heuristic it replaced and
  * re-running this suite: only the `heredoc` fact changes an observable outcome (the multiline
  * string case below). `has_parentheses` and `call_operator` agree with the old text checks on
  * every fixture here, and on realistic Ruby generally - `usesParenthesis` is only consulted for
  * calls with no arguments, which is why plan 04 §5's `log foo(bar)` example is a misread of the
  * text but not a misclassified call. The facts are still the right input: they are exact, they do
  * not depend on `code` being un-normalized, and they cost nothing to read. The tests below
  * therefore pin the *outcomes* - the shapes the CPG must have - and only the heredoc one is a
  * regression test in the strict sense.
  */
class CallSyntaxFactTests extends RubyCode2CpgFixture:

  "a no-paren command call over a parenthesized inner call keeps both calls" in {
      val cpg = fixtureWithoutUnknowns("no_paren_call")

      // `log foo(bar)` - no-paren command call over a parenthesized inner call.
      cpg.call.nameExact("log").l should not be empty
      cpg.call.nameExact("foo").l should not be empty
      // `puts "literal)"` - a string ending in a paren must not change the call shape.
      cpg.call.nameExact("puts").l should not be empty
  }

  "safe navigation keeps the &. operator" in {
      val cpg = fixtureWithoutUnknowns("safe_navigation")
      // `user&.address&.street` - the generator emits call_operator "&." on both csend nodes.
      cpg.fieldAccess.code.l should contain("user&.address")
  }

  "scoped constants keep their :: operator" in {
      val cpg = fixtureWithoutUnknowns("scoped_const")
      cpg.fieldAccess.code.l should contain("Outer::Inner")
      // Chained scopes get split through a tmp variable; the :: operator is preserved.
      cpg.fieldAccess.code.l.exists(_.contains("::MAX")) shouldBe true
      cpg.method.name.l should contain("ping")
  }

  "percent arrays keep their element types" in {
      val cpg = fixtureWithoutUnknowns("percent_array")
      cpg.literal.code.l should contain("alice") // %w -> strings
      cpg.literal.code.l should contain(":on")   // %i -> symbols
  }

  "heredoc content is taken from the node value" in {
      val cpg = fixtureWithoutUnknowns("heredoc")
      cpg.literal.code.l.exists(_.contains("select * from users")) shouldBe true
  }

  /** The one case where the fact and the heuristic it replaced disagree. A multiline plain string
    * arrives as `dstr` with one `str` child per line whose `value` keeps the newline while its
    * `code` does not, so the old `!code.contains(value)` fallback classified it as a heredoc and
    * replaced the literal's text with the raw value. The `heredoc` fact is absent here, so the
    * literal keeps its source text; the real heredoc in the same fixture still yields its body.
    */
  "a multiline plain string is not mistaken for a heredoc" in {
      val cpg = fixtureWithoutUnknowns("multiline_string")

      val literals = cpg.literal.code.l
      literals should contain("line one")
      literals should not contain "line one\n"
      // The heredoc in the same file still reaches the CPG through its value.
      literals.exists(_.contains("select * from users")) shouldBe true
  }
end CallSyntaxFactTests
