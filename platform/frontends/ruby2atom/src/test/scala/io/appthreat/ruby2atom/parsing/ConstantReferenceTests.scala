package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.TypeRef
import io.shiftleft.semanticcpg.language.*

/** A constant that resolves outside the project is a `TYPE_REF` at the start of the written
  * constant, named with its written path (`.` as separator). Constants the project defines keep
  * their earlier lowering and get no such node. Ruby looks a constant up lexically, innermost scope
  * first, so the same written name can be a project constant in one module and a gem's in another.
  */
class ConstantReferenceTests extends RubyCode2CpgFixture:

  /** The references to dependency constants as (line, written code, name), in source order. */
  private def external(cpg: Cpg, file: String): List[(Int, String, String)] =
      cpg.typeRef
          .filter(isConstantReference)
          .filter(_.file.name.exists(_.endsWith(file)))
          .l
          .sortBy(t => (t.lineNumber.get: Int, t.columnNumber.get: Int))
          .map(t => (t.lineNumber.get, t.code, t.typeFullName))

  // The pointers to a class or module body end in `<class>`, bundled core classes live under
  // `__core`, block pointers are named after their lambda
  private def isConstantReference(t: TypeRef): Boolean =
      !t.typeFullName.endsWith("<class>") && !t.typeFullName.startsWith("__core") &&
          !t.typeFullName.contains("<lambda>")

  private lazy val cpg = fixture(
    "callsites/constants",
    "app/models/user_profile",
    "app/services/profile_loader"
  )

  "a nested module that defines the constant resolves to the project, one that does not to a gem" in {
      val refs = external(cpg, "callsites/constants.rb")
      // Shop::build: `Cart` is Shop::Cart (project), `Receipt` is nobody's
      refs.filter(_._1 == 7) shouldBe empty
      refs should contain((8, "Receipt", "Receipt"))
      // Shop::Inner sees Shop::Cart through the lexical scope, but not a Cache
      refs.filter(_._1 == 15) shouldBe empty
      refs should contain((16, "Cache", "Cache"))
  }

  "a name nested in a module is also claimed by its bare name" in {
      // Other does not see Shop::Cart lexically, but a bare `Cart` may still reach it (an `include`
      // of Shop, `const_missing`), so it is not reported as a dependency's
      external(cpg, "callsites/constants.rb").filter(_._1 == 23) shouldBe empty
  }

  "a constant assigned by the project is not a dependency" in {
      external(cpg, "callsites/constants.rb").filter(_._1 == 9) shouldBe empty
  }

  "a path keeps the written separators as dots, and a leading :: is dropped from the name" in {
      val refs = external(cpg, "callsites/constants.rb")
      refs should contain((10, "Json::Schema", "Json.Schema"))
      refs should contain((29, "::Absolute", "Absolute"))
      refs should contain((30, "Absolute", "Absolute"))
  }

  "the other names Ruby would try first are listed innermost first" in {
      def hints(code: String) = cpg.typeRef.code(code).dynamicTypeHintFullName.l
      hints("Cache") shouldBe List("Shop.Inner.Cache", "Shop.Cache")
      hints("Receipt") shouldBe List("Shop.Receipt")
      // a path inside the same lexical scopes is tried the same way
      hints("Json::Schema") shouldBe List("Shop.Json.Schema")
      // outside any module there is nothing else to try, and an absolute path is not looked up
      hints("::Absolute") shouldBe empty
      hints("Absolute").sorted shouldBe List("Reopened.Absolute")
  }

  "a constant read outside a call keeps its whole path" in {
      val refs = external(cpg, "callsites/constants.rb")
      // the last expression of a method, as an argument, and in a rescue list
      refs should contain((36, "Settings::LEVEL", "Settings.LEVEL"))
      refs should contain((49, "Faraday::Error", "Faraday.Error"))
      refs should contain((50, "Foo::Bar::BAZ", "Foo.Bar.BAZ"))
  }

  "a rescue list names its dependency classes at their own positions" in {
      val refs = external(cpg, "callsites/constants.rb")
      refs should contain((42, "Net::ReadTimeout", "Net.ReadTimeout"))
      refs should contain((42, "::Timeout::Error", "Timeout.Error"))
      // `rescue Shop::Cart` names a project class
      refs.filter(_._1 == 45) shouldBe empty
      val columns = cpg.typeRef.lineNumber(42).map(_.columnNumber.get: Int).l.sorted
      columns shouldBe List(7, 25)
  }

  "a bundled core class in a rescue list has its own reference at its position" in {
      val bundled = cpg.typeRef.filter(_.typeFullName.startsWith("__core")).filter(
        _.lineNumber.exists(_ == 59)
      ).l
      bundled.map(t => (t.code, t.typeFullName, t.columnNumber.get: Int)) shouldBe List(
        ("__core.StandardError", "__core.StandardError", 7),
        ("__core.ArgumentError", "__core.ArgumentError", 22)
      )
  }

  "a reopened core class is a project constant, what it refers to is still checked" in {
      val refs = external(cpg, "callsites/constants.rb")
      refs.filter(_._2 == "String") shouldBe empty
      refs should contain((36, "Settings::LEVEL", "Settings.LEVEL"))
  }

  "a constant a file path implies under app/ is a project constant" in {
      val refs = external(cpg, "app/services/profile_loader.rb")
      // `UserProfile` is defined by Zeitwerk from app/models/user_profile.rb, `Missing` by nobody
      refs shouldBe List((4, "Missing", "Missing"))
  }

  "a reference is created once, also in the last expression of a method" in {
      val refs = external(cpg, "callsites/constants.rb")
      refs should contain((54, "Rails", "Rails"))
      val positions = cpg.typeRef.filter(isConstantReference).map(t =>
          (t.file.name.l, t.lineNumber.get: Int, t.columnNumber.get: Int)
      ).l
      positions.distinct.size shouldBe positions.size
  }

  "every reference sits on its own line, none before line 1" in {
      cpg.typeRef.filter(isConstantReference).filter(_.lineNumber.exists(_ < 1)).l shouldBe empty
  }
end ConstantReferenceTests
