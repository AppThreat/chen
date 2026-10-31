package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.AbstractPassTest
import io.shiftleft.codepropertygraph.generated.nodes.Identifier
import io.shiftleft.semanticcpg.language.*

class DestructuredArrowParamsTest extends AbstractPassTest:

  "AST generation for destructured parameters of arrow functions" should {

      "parent every identifier of an object-pattern parameter of an arrow in an object literal" in
          AstFixture("""
          |import { t } from "i18next";
          |const actions = {
          |  name: ({ t, isMenu }) => t("x"),
          |};
          |""".stripMargin) { cpg =>
            cpg.identifier.filter(_._astIn.isEmpty).l shouldBe empty
            cpg.identifier.nameExact("t").whereNot(_.refsTo).l shouldBe empty
            // the arrow's use of `t` REFs the destructured local, not a name match
            val List(tLocal) = cpg.local.nameExact("t").where(_.method.nameExact("anonymous")).l
            val List(tUse) = cpg.call.nameExact("t").receiver.collect { case i: Identifier => i }.l
            tUse.refsTo.map(_.id).l shouldBe List(tLocal.id)
          }

      "parent every identifier of an object-pattern parameter of an arrow as a class property initialiser" in
          AstFixture("""
          |class Menu {
          |  handler = ({ t, isMenu }) => t("x");
          |}
          |""".stripMargin) { cpg =>
            cpg.identifier.filter(_._astIn.isEmpty).l shouldBe empty
            cpg.identifier.nameExact("t").whereNot(_.refsTo).l shouldBe empty
          }

      "parent every identifier of an array-pattern parameter of an arrow" in AstFixture("""
        |const handlers = {
        |  run: ([first, second]) => first(second),
        |};
        |""".stripMargin) { cpg =>
        cpg.identifier.filter(_._astIn.isEmpty).l shouldBe empty
        val List(first) = cpg.local.nameExact("first").l
        cpg.identifier.nameExact("first").refsTo.name.l.distinct shouldBe List("first")
      }

      "lower a method's object-pattern parameter like a function declaration's" in AstFixture("""
        |class C {
        |  run({ t }) { return t("x"); }
        |}
        |""".stripMargin) { cpg =>
          cpg.identifier.filter(_._astIn.isEmpty).l shouldBe empty
      }

      "keep the good twin, a function declaration, free of orphans and with one REF per identifier" in
          AstFixture("""
          |function f({ t, isMenu }) { return t("x"); }
          |""".stripMargin) { cpg =>
            cpg.identifier.filter(_._astIn.isEmpty).l shouldBe empty
            cpg.identifier.count(_.refsTo.size > 1) shouldBe 0
            cpg.identifier.whereNot(_.refsTo).size shouldBe 0
            cpg.typeDecl.nameExact("_anon_cdecl").member.name.l should contain theSameElementsAs List(
              "t",
              "isMenu"
            )
          }
  }
end DestructuredArrowParamsTest
