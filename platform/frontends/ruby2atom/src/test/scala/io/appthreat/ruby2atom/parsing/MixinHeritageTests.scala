package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** `class A < Faraday::Middleware`, `include Rack::Utils`, `prepend` and `extend` become heritage
  * facts: the superclass and the included modules are ancestors of the class, an extended module is
  * an ancestor of its singleton class, each constant is a reference at its own position.
  */
class MixinHeritageTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture("callsites/mixins")

  private def inherits(name: String) =
      cpg.typeDecl.nameExact(name).filterNot(_.isExternal).inheritsFromTypeFullName.l

  "a superclass from a gem is an ancestor with its own position" in {
      inherits("Handler").head shouldBe "Faraday.Middleware"
      val ref = cpg.typeRef.code("Faraday::Middleware").l
      ref.map(_.typeFullName) shouldBe List("Faraday.Middleware")
      (ref.head.lineNumber.get: Int, ref.head.columnNumber.get: Int) shouldBe (4, 16)
  }

  "include and prepend make the module an ancestor of the class, in any argument position" in {
      inherits("Handler") shouldBe
          List("Faraday.Middleware", "Rack.Utils", "Helpers", "Observable", "Left", "Right.Mixin")
  }

  "extend makes the module an ancestor of the singleton class" in {
      inherits("Handler<class>") shouldBe List("Faraday.Middleware<class>", "Forwardable")
  }

  "each dependency module is a reference at its own position" in {
      cpg.typeRef.filter(_.typeFullName == "Rack.Utils").map(t =>
          (t.lineNumber.get: Int, t.columnNumber.get: Int)
      ).l shouldBe List((5, 10))
      cpg.typeRef.filter(_.typeFullName == "Right.Mixin").map(t =>
          (t.lineNumber.get: Int, t.columnNumber.get: Int)
      ).l shouldBe List((9, 16))
      cpg.typeRef.filter(_.typeFullName == "Left").map(t => t.lineNumber.get: Int).l shouldBe List(
        9
      )
  }

  "a project module or class in the same positions is an ancestor but not a dependency reference" in {
      inherits("Project") shouldBe List("Base", "Helpers")
      cpg.typeRef.filter(t => Set("Base", "Helpers").contains(t.typeFullName)).l shouldBe empty
  }

  "include inside a method is not a mixin of the class" in {
      inherits("Handler") should not contain "Late"
      cpg.typeRef.filter(_.typeFullName == "Late").map(t => t.lineNumber.get: Int).l shouldBe List(
        12
      )
  }
end MixinHeritageTests
