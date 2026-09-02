package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** A file whose JSON contains depth-truncated nodes (generated with `rbastgen --max-depth 3`,
  * see `resources/ruby/nested/truncated.rb.json`) must degrade one node per truncation point —
  * not lose the whole file. Before the truncated-node guard this fixture threw in
  * `visitArray` (missing `children` key) and the exception escaped as a swallowed `Failure`,
  * silently dropping the file from the CPG.
  */
class TruncatedNodeTests extends RubyCode2CpgFixture:

  "a file with truncated nodes survives ingestion" in {
    val (cpg, unknowns) = fixtureWithReport("nested/truncated")

    // The untruncated parts of the file are still present.
    cpg.local.name.l should contain("v")
    cpg.identifier.name.l should contain("v")
    // The innermost untruncated literal survives as well.
    cpg.literal.code.l should contain("0")

    // Each truncation point becomes exactly one placeholder node, counted per type.
    unknowns shouldBe Map("truncated:int" -> 1, "truncated:array" -> 1)
  }
