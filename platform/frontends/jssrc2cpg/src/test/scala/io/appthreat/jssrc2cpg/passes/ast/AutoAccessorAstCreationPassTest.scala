package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.AbstractPassTest
import io.shiftleft.semanticcpg.language.*

/** A TC39 auto-accessor (`accessor x = v`, atom-parsetools#34) arrives as a `ClassAccessorProperty`
  * node. jssrc2cpg treats it as a property: named by its key, carrying its decorators, with its
  * initialiser as the usual `this.key = value` assignment. The committed astgen output is consumed
  * via `AstJsonFixture`, so no astgen invocation (see the fixture `README.md` for how it was
  * generated).
  */
class AutoAccessorAstCreationPassTest extends AbstractPassTest:

  "AST generation for TC39 auto-accessors" should {
      "name each accessor by its key, like a class property" in AstJsonFixture("auto-accessor") {
          cpg =>
            // the class's four members: the three accessors and the describe method
            cpg.typeDecl.nameExact("Session").member.name.l.toSet shouldBe Set(
              "id",
              "limit",
              "plain",
              "describe"
            )
            cpg.typeDecl.nameExact("Session").member.nameExact("id").code.l shouldBe List(
              "@logged accessor id: string = uuidv4();"
            )
            cpg.typeDecl.nameExact("Session").member.nameExact("plain").code.l shouldBe List(
              "accessor plain: number = 7;"
            )
      }

      "keep the accessor's decorators" in AstJsonFixture("auto-accessor") { cpg =>
          cpg.typeDecl.nameExact("Session").member.name("id").annotation.name.l shouldBe List(
            "logged"
          )
          cpg.typeDecl.nameExact("Session").member.name("limit").annotation.name.l shouldBe List(
            "logged"
          )
          cpg.typeDecl.nameExact("Session").member.name("plain").annotation.l shouldBe empty
      }

      "keep the static flag of an accessor" in AstJsonFixture("auto-accessor") { cpg =>
          val session = cpg.typeDecl.nameExact("Session").head
          session.member.isStatic.l shouldBe session.member.name("limit").l
      }

      "lower the initialiser as the field's assignment, at the accessor's line" in AstJsonFixture(
        "auto-accessor"
      ) { cpg =>
          // `@logged accessor id: string = uuidv4();` assigns to this.id, and the initialiser's
          // call keeps its own position in the file
          val uuidCalls = cpg.call.codeExact("uuidv4()").l
          uuidCalls.size shouldBe 1
          uuidCalls.head.lineNumber shouldBe Some(8)
          val assignments = cpg.call.nameExact(
            io.shiftleft.codepropertygraph.generated.Operators.assignment
          ).lineNumber(8).l
          assignments.size shouldBe 1
          assignments.head.code shouldBe "@logged accessor id: string = uuidv4();"
      }

      "read the accessor through its field, like a property read" in AstJsonFixture(
        "auto-accessor"
      ) { cpg =>
          // `return this.id;` in describe(): a field access on this, not a call to an accessor
          // method
          val reads = cpg.method.nameExact("describe").ast.isCall
              .nameExact(io.shiftleft.codepropertygraph.generated.Operators.fieldAccess).l
          reads.size shouldBe 1
          reads.head.code shouldBe "this.id"
      }
  }
end AutoAccessorAstCreationPassTest
