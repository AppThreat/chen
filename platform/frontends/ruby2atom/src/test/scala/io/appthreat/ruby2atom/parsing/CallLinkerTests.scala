package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** RubyCallLinker names the callee of a call to a method of the project
  * (`resources/ruby/calls.rb`).
  */
class CallLinkerTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture("calls")

  private def calleeOf(name: String): List[String] = cpg.call.nameExact(name).methodFullName.l

  "calls to the project's methods" should {
      "be named after a class method of a constant receiver" in {
          calleeOf("save") shouldBe List(cpg.method.nameExact("save").fullName.head)
          calleeOf("find_by_token") shouldBe List(
            cpg.method.nameExact("find_by_token").fullName.head
          )
      }

      "be named after the method of the class they are in" in {
          calleeOf("helper") shouldBe List(cpg.method.nameExact("helper").fullName.head)
      }

      "stay unnamed for a method the project does not declare" in {
          calleeOf("find_by") shouldBe List("<unknownFullName>")
      }
  }
end CallLinkerTests
