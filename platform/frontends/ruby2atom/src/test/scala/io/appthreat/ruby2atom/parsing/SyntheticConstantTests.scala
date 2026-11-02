package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** The parser makes some constants up while it lowers: `Array` for `Array(value)`, `StandardError`
  * for `raise "text"`, `Float::INFINITY` for an endless range. Nobody wrote them, so they have no
  * position, and a written constant of the same name still has its own.
  */
class SyntheticConstantTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture("callsites/synthetic")

  private def positions(name: String) =
      cpg.typeRef.filter(_.typeFullName == name).map(_.lineNumber.map(_.intValue)).l

  "a constant the lowering borrows for a Kernel function has no position" in {
      positions("__core.Array").sortBy(_.getOrElse(0)) shouldBe List(None, None, Some(6))
      positions("__core.Hash") shouldBe List(None, None)
  }

  "the class a bare raise of text makes up has no position" in {
      positions("__core.StandardError") shouldBe List(None)
  }

  "the Float of an endless range is no reference" in {
      cpg.typeRef.filter(_.typeFullName.contains("INFINITY")).l shouldBe empty
      cpg.typeRef.filter(_.typeFullName == "Float.INFINITY").l shouldBe empty
  }
end SyntheticConstantTests
