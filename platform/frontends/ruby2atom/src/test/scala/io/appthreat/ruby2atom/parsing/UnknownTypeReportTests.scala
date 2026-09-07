package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** The per-run unknown-type report: instead of one warn log per offending node, the count is
  * aggregated per type (plan 04 §1's last paragraph).
  */
class UnknownTypeReportTests extends RubyCode2CpgFixture:

  "lowered node types leave an empty report (itblock closed by plan 04 §3)" in {
      // it_block.rb contains two `itblock` nodes; they used to be counted as unknown
      // (plan 04 §1) and now lower fully (plan 04 §3).
      val (cpg, unknowns) = fixtureWithReport("it_block")

      unknowns shouldBe Map.empty
      cpg.local.name.l should contain("items")
      cpg.literal.code.l should contain("1")
  }

  "files without unknown types produce an empty report" in {
      val (cpg, unknowns) = fixtureWithReport("safe_navigation", "percent_array")
      unknowns shouldBe Map.empty
      cpg.local.name.l should contain("names")
  }
