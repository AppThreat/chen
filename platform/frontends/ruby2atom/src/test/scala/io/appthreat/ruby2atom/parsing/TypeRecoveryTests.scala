package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.datastructures.RubyProgramSummaryBuilder
import io.appthreat.ruby2atom.testfixtures.Ruby2AtomFixture
import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Type recovery (plan 04 §6): `RubyProgramSummary` is populated from the parsed ASTs of all
  * files before AST creation, `require` calls pull the required types into scope, and the
  * previously unscheduled `ImportsPass`/`ImplicitRequirePass` run. Fixtures: `models/user.rb`
  * defines `User`, `app.rb` requires and instantiates it, `cli.rb` instantiates `User` without a
  * require (zeitwerk-style autoload), `models/report.rb` is a `Data.define` class.
  */
class TypeRecoveryTests extends RubyCode2CpgFixture:

  "the summary builder inventories classes, methods, fields and Data.define members" in {
    val programs  = Ruby2AtomFixture.parse("models/user", "models/report")
    val summary   = RubyProgramSummaryBuilder.build(programs)

    val userTypes = summary.matchingTypes("User")
    userTypes should not be empty
    userTypes.exists(_.name == "User") shouldBe true
    userTypes.flatMap(_.methods).map(_.name) should contain("name")
    userTypes.flatMap(_.fields).map(_.name) should contain("email")

    summary.pathToType.keySet should contain("models/user")
    summary.pathToType.keySet should contain("models/report")

    val report = summary.matchingTypes("Report")
    report.flatMap(_.fields).map(_.name) should contain("title")
    report.flatMap(_.fields).map(_.name) should contain("rows")
  }

  "a require pulls the required type into scope, typing its constructor" in {
    val cpg = fixtureWithoutUnknowns("app", "models/user")

    // The require becomes an IMPORT node.
    cpg.imports.importedEntity.l should contain("models/user")

    // `User.new` resolves against the summary-informed scope: the receiver variable and the
    // constructor tmp carry the resolved type hint instead of ANY.
    cpg.local.dynamicTypeHintFullName.l.exists(_.contains("User")) shouldBe true
    cpg.local.name("admin").dynamicTypeHintFullName.l should contain("User")
  }

  "an explicit require is not duplicated by a synthetic one" in {
    // app.rb requires models/user explicitly; the implicit require pass must leave it alone.
    val cpg = fixtureWithoutUnknowns("app", "models/user")
    cpg.call.nameExact("require").code.l shouldBe List("require \"models/user\"")
  }

  "the implicit require pass materializes zeitwerk-style autoloads" in {
    // cli.rb uses User.new without any require; models/user.rb matches the zeitwerk rule.
    val cpg = fixtureWithoutUnknowns("cli", "models/user")
    val requireCalls = cpg.call.nameExact("require").l
    requireCalls should not be empty
    requireCalls.map(_.code) should contain("require 'models/user'")
  }
