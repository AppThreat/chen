package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** A constant is a reference wherever it is the base of something: of an index (`Migration[7.2]` as
  * a superclass or `CONFIG[:key]`), of a chain of attribute calls (`Rails.logger.info`), or of an
  * instantiation in a superclass expression.
  */
class ConstantChainTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture("callsites/chains")

  private def refs(name: String) = cpg.typeRef.filter(_.typeFullName == name).l

  "a constant indexed in a superclass expression is a reference with the index as its user" in {
      val ref = refs("ActiveRecord.Migration")
      ref.map(t => (t.lineNumber.get: Int, t.columnNumber.get: Int)) shouldBe List((1, 16))
      val users =
          ref.flatMap(r => cpg.call.nameExact(Operators.indexAccess).argument.filter(_.id == r.id))
      users.size shouldBe 1
  }

  "an instantiation in a superclass expression references the class it instantiates" in {
      // Struct is a bundled core class, which has its own reference node
      refs("__core.Struct").map(t => (t.lineNumber.get: Int, t.columnNumber.get: Int)) shouldBe
          List((4, 13))
  }

  "a constant at the base of a chain of calls is one reference per written constant" in {
      refs("Rails").map(t => t.lineNumber.get: Int) shouldBe List(9, 10)
  }

  "an indexed constant path is one reference, used by the index access" in {
      val ref = refs("Faraday.Utils.CONFIG")
      ref.map(t => (t.lineNumber.get: Int, t.columnNumber.get: Int)) shouldBe List((11, 4))
      val indexed = cpg.call.nameExact(Operators.indexAccess).lineNumber(11).argument.isTypeRef.l
      indexed.map(_.typeFullName) shouldBe List("Faraday.Utils.CONFIG")
  }

  "a bundled core class as a superclass has its own reference at its position" in {
      refs("__core.StandardError").map(t =>
          (t.lineNumber.get: Int, t.columnNumber.get: Int)
      ) shouldBe
          List((15, 16))
  }

  "an absolute core class is a reference of its own, written with the leading ::" in {
      cpg.typeRef.code("::Thread").map(t =>
          (t.lineNumber.get: Int, t.columnNumber.get: Int, t.typeFullName)
      ).l shouldBe
          List((20, 4, "Thread"))
  }
end ConstantChainTests
