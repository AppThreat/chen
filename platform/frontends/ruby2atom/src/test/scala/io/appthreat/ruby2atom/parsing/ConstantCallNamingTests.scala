package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Calls on a constant that resolves outside the project are named after the constant, spelled as
  * the graph spells project calls (`Faraday.Utils.escape`), an instantiation is a constructor call
  * of that class, and a local bound exactly once to such an instance carries the class to its
  * calls. Anything that rebinds the name takes the type away.
  */
class ConstantCallNamingTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture("callsites/constant_calls", "callsites/constants")

  private def client = cpg.method.fullName(".*constant_calls.rb:.*").l

  "a call on a dependency constant is named after it" in {
      val escape = cpg.call.nameExact("escape").l
      escape.map(_.methodFullName) shouldBe List("Faraday.Utils.escape")
      cpg.call.nameExact("check").methodFullName.l shouldBe List("Json.Schema.check")
  }

  "an instantiation of a dependency class is a constructor call of that class" in {
      val inits = cpg.call.nameExact("initialize").filter(_.methodFullName.startsWith("Faraday")).l
      inits.map(_.methodFullName) shouldBe
          List("Faraday.Connection.initialize", "Faraday.Connection.initialize")
      inits.map(_.lineNumber.get: Int) shouldBe List(4, 5)
  }

  "a call on a project constant keeps the project name" in {
      cpg.call.nameExact("initialize").lineNumber(29).methodFullName.l shouldBe
          List("callsites/constant_calls.rb:<main>.Local.initialize")
      cpg.call.nameExact("initialize").filter(_.file.name.exists(_.endsWith("constants.rb")))
          .lineNumber(23).methodFullName.l shouldBe
          List("callsites/constants.rb:<main>.Shop.Cart.initialize")
  }

  "a local bound once to an instance carries the class to its calls" in {
      val get = cpg.call.nameExact("get").l
      get.flatMap(_.possibleTypes) shouldBe List("Faraday.Connection.get")
      get.argument(0).isIdentifier.typeFullName.l shouldBe List("Faraday.Connection")
  }

  "operators, indexing and setters on that local are not typed" in {
      cpg.identifier.nameExact("conn").lineNumber(7).typeFullName.l shouldBe List("ANY")
      cpg.identifier.nameExact("conn").lineNumber(8).typeFullName.l shouldBe List("ANY", "ANY")
  }

  "a local bound twice is not typed" in {
      cpg.identifier.nameExact("client").lineNumber(14).typeFullName.l shouldBe List("ANY")
  }

  "a parameter of the same name takes the type away" in {
      cpg.identifier.nameExact("client").lineNumber(19).typeFullName.l shouldBe List("ANY")
  }

  "a block parameter of the same name takes the type away" in {
      cpg.identifier.nameExact("http").lineNumber(25).typeFullName.l shouldBe List("ANY")
      cpg.identifier.nameExact("http").lineNumber(24).typeFullName.l shouldBe List("ANY")
  }
end ConstantCallNamingTests
