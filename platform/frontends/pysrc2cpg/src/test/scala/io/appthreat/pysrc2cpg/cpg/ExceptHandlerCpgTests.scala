package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.FieldIdentifier

class ExceptHandlerCpgTests extends PySrc2CpgFixture:

  "except handler classes" should {

      "lower the handler class of `except X` to a reference at the handler's line" in {
          val cpg = code(
            """import requests
              |
              |def f():
              |    try:
              |        g()
              |    except requests.ConnectionError:
              |        pass""".stripMargin,
            "test.py"
          )
          val List(handlerUse) =
              cpg.identifier.nameExact("requests").whereNot(_.method.nameExact("<module>")).l
          handlerUse.lineNumber shouldBe cpg.call.nameExact("<operator>.fieldAccess").filter(
            _.code == "requests.ConnectionError"
          ).lineNumber.headOption
          // the use resolves to the import binding through the closure chain
          handlerUse.refsTo.nonEmpty shouldBe true
          cpg.all.collectAll[FieldIdentifier].map(_.canonicalName).l should contain(
            "ConnectionError"
          )
      }

      "lower each member of a tuple of handler classes to a reference" in {
          val cpg = code(
            """import a
              |
              |def f():
              |    try:
              |        g()
              |    except (a.E1, a.E2):
              |        pass""".stripMargin,
            "test.py"
          )
          val handlerUses = cpg.identifier.nameExact("a").whereNot(_.method.nameExact("<module>")).l
          // the handler clause is on line 6; both tuple members sit on it
          handlerUses.map(_.lineNumber.get).toSet shouldBe Set(6)
          handlerUses.filterNot(_.refsTo.nonEmpty) shouldBe empty
          val fields = cpg.all.collectAll[FieldIdentifier].map(_.canonicalName).l
          fields should contain("E1")
          fields should contain("E2")
      }

      "lower the handler class of `except* X` to a reference (good twin, star handler)" in {
          val cpg = code(
            """import grp
              |
              |def f():
              |    try:
              |        g()
              |    except* grp.GroupError:
              |        pass""".stripMargin,
            "test.py"
          )
          val handlerUses =
              cpg.identifier.nameExact("grp").whereNot(_.method.nameExact("<module>")).l
          handlerUses should not be empty
          handlerUses.filterNot(_.refsTo.nonEmpty) shouldBe empty
      }

      "keep the handler's `as` target and body untouched (good twin)" in {
          val cpg = code(
            """import grp
              |
              |def f():
              |    try:
              |        g()
              |    except grp.GroupError as e:
              |        sink(e)""".stripMargin,
            "test.py"
          )
          cpg.local.nameExact("e").l should not be empty
          val List(sinkCall) = cpg.call.nameExact("sink").l
          sinkCall.argument.isIdentifier.name.l shouldBe List("e")
      }

      "evaluate the handler class before the handler body" in {
          val cpg = code(
            """import grp
              |
              |def f():
              |    try:
              |        g()
              |    except grp.GroupError as e:
              |        h(e)
              |        k()""".stripMargin,
            "test.py"
          )
          val List(handlerBlock) = cpg.call.nameExact("k").astParent.isBlock.l
          handlerBlock.astChildren.isCall.sortBy(_.order).code.l shouldBe List(
            "grp.GroupError",
            "h(e)",
            "k()"
          )
          handlerBlock.astChildren.isCall.order.l.distinct.size shouldBe 3
      }
  }
end ExceptHandlerCpgTests
