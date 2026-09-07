package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Baseline lowering over generated fixtures: methods, calls and safe navigation. */
class MethodAndCallTests extends RubyCode2CpgFixture:

  "a method definition becomes a METHOD node with its parameters" in {
      val cpg = fixtureWithoutUnknowns("safe_navigation")
      cpg.method.name.l should contain("street")
      cpg.method.name.l should contain("<main>")
      cpg.method.parameter.name.l should contain("user")
  }

  "safe navigation lowers to field accesses with the &. operator" in {
      val cpg = fixtureWithoutUnknowns("safe_navigation")
      cpg.fieldAccess.code.l should contain("user&.address")
      cpg.fieldAccess.code.l.exists(_.endsWith("&.street")) shouldBe true
      cpg.identifier.name.l should contain("user")
  }

  "a no-paren call whose code ends with a closing paren is a plain call" in {
      val cpg = fixtureWithoutUnknowns("no_paren_call")

      // `log foo(bar)` is a no-paren command call: `log` with one argument (the `foo(bar)` call).
      // Its whitespace-normalized code ends with `)`, which the pre-fact text heuristic
      // (`text.endsWith(")")`) misread as a parenthesized call.
      val logCalls = cpg.call.nameExact("log").l
      logCalls should have size 1
      val logCall = logCalls.head
      logCall.code shouldBe "log foo(bar)"
      logCall.argument.isCall.name.l should contain("foo")

      // The inner parenthesized call is a call with its own argument.
      cpg.call.nameExact("foo").l should have size 1
      cpg.call.nameExact("bar").l should have size 1

      // `puts "literal)"` — a string argument ending in a paren must not affect the call.
      cpg.call.nameExact("puts").l should have size 1
  }

  "a member command call keeps its receiver and argument" in {
      val cpg = fixtureWithoutUnknowns("no_paren_call")
      inside(cpg.call.nameExact("bar").l) { case List(bar) =>
          bar.code shouldBe "(<tmp-0> = x).bar(y(z))"
          bar.argument.isCall.name.l should contain("y")
      }
  }
end MethodAndCallTests
