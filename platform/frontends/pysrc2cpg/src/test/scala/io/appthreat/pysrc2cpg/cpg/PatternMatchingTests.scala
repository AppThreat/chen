package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.codepropertygraph.generated.NodeTypes
import io.shiftleft.codepropertygraph.generated.nodes.JumpTarget
import io.shiftleft.semanticcpg.language.*

/** `match` lowers to a C-style SWITCH: the subject is assigned to a temporary, the SWITCH condition
  * reads that temporary, and one body block (order 2) holds a JUMP_TARGET per arm followed by the
  * arm's pattern captures and statements. `case _:` arms use the name "default". Guards wrap the
  * arm body in an IF.
  */
class PatternMatchingTests extends PySrc2CpgFixture():
  "pattern matching" should {
      "be correct" in {
          val cpg = code("""match [1, 2]:
          |  case [a, b]:
          |    print(1)
          |  case _:
          |    print(2)
          |""".stripMargin)
          val switch = cpg.controlStructure.head
          switch.controlStructureType shouldBe ControlStructureTypes.SWITCH

          // subject assigned to a temporary; condition reads the temporary
          val condition = switch.astChildren.order(1).head
          condition.label shouldBe NodeTypes.IDENTIFIER
          (condition.code should fullyMatch).regex("""matchSubject_tmp\d+""")
          val subjectAssign = cpg.call.name("<operator>.assignment").l
          subjectAssign.map(_.code).exists(_.startsWith("matchSubject_tmp")) shouldBe true
          subjectAssign.map(_.code).exists(_.contains("[1, 2]")) shouldBe true

          // single body block with one JUMP_TARGET per arm; `case _:` is "default"
          val body = switch.astChildren.order(2).head
          body.label shouldBe NodeTypes.BLOCK
          val jumpTargets = body.astChildren.l.collect { case j: JumpTarget => j }
          jumpTargets.size shouldBe 2
          jumpTargets.map(_.name).sorted shouldBe List("case", "default")

          // both arm bodies are inside the switch body and reachable
          body.astChildren.isCall.nameExact("print").size shouldBe 2
      }

      "match statement with value pattern" in {
          val cpg = code("""def process_value(value):
                       |    match value:
                       |        case 1:
                       |            result = "one"
                       |        case 2:
                       |            result = "two"
                       |        case _:
                       |            result = "other"
                       |    sink(result)""".stripMargin)
          val switch = cpg.controlStructure.head
          val body   = switch.astChildren.order(2).head
          body.label shouldBe NodeTypes.BLOCK
          val jumpTargets = body.astChildren.l.collect { case j: JumpTarget => j }
          jumpTargets.size shouldBe 3
          jumpTargets.count(_.name == "default") shouldBe 1
          body.astChildren.isCall.nameExact("<operator>.assignment").size shouldBe 3
      }

      "match statement with capture pattern" in {
          val cpg = code("""def process_value(value):
                       |    match value:
                       |        case x:
                       |            sink(x)""".stripMargin)
          val switch      = cpg.controlStructure.head
          val body        = switch.astChildren.order(2).head
          val jumpTargets = body.astChildren.l.collect { case j: JumpTarget => j }
          jumpTargets.size shouldBe 1
          jumpTargets.head.name shouldBe "case"

          // `case x:` binds x from the subject: a local, an assignment, and a REF edge
          val localX = cpg.local.nameExact("x").l
          localX.size shouldBe 1
          val captureAssign = body.astChildren.isCall.nameExact("<operator>.assignment").l
          captureAssign.size shouldBe 1
          captureAssign.head.code should startWith("x = matchSubject")
          val identX = cpg.identifier.nameExact("x").l
          identX.size shouldBe 2 // capture definition + use in sink(x)
          identX.head.refsTo.size shouldBe 1
      }

      "match statement with sequence pattern" in {
          val cpg = code("""def process_sequence(seq):
                       |    match seq:
                       |        case [x, y]:
                       |            sink(x, y)""".stripMargin)
          val switch = cpg.controlStructure.head
          val body   = switch.astChildren.order(2).head
          body.astChildren.filter(_.isInstanceOf[JumpTarget]).size shouldBe 1

          // every element of the sequence pattern is a capture fed by the subject
          val captureAssigns = body.astChildren.isCall.nameExact("<operator>.assignment").l
          captureAssigns.size shouldBe 2
          captureAssigns.count(_.code.startsWith("x = matchSubject")) shouldBe 1
          captureAssigns.count(_.code.startsWith("y = matchSubject")) shouldBe 1
          cpg.local.name("x").size shouldBe 1
          cpg.local.name("y").size shouldBe 1
      }

      "complex match statement with multiple patterns" in {
          val cpg = code("""def process_complex_data(data):
                       |    match data:
                       |        case {"status": "success", "result": result}:
                       |            sink(result)
                       |        case {"status": "error", "errors": [err1, err2]}:
                       |            sink(err1, err2)
                       |        case {"status": "pending", "details": {"id": id, "message": msg}}:
                       |            sink(id, msg)""".stripMargin)
          val switch = cpg.controlStructure.head
          val body   = switch.astChildren.order(2).head
          body.astChildren.filter(_.isInstanceOf[JumpTarget]).size shouldBe 3

          // nested captures: result, err1, err2, id, msg
          val captures = body.astChildren.isCall.nameExact("<operator>.assignment").map(_.code).l
          captures.count(_.startsWith("result = matchSubject")) shouldBe 1
          captures.count(_.startsWith("err1 = matchSubject")) shouldBe 1
          captures.count(_.startsWith("err2 = matchSubject")) shouldBe 1
          captures.count(_.startsWith("id = matchSubject")) shouldBe 1
          captures.count(_.startsWith("msg = matchSubject")) shouldBe 1

          // every arm body is present in the single switch body block
          body.astChildren.isCall.nameExact("sink").size shouldBe 3
      }

      "complex match statement with walrus operator" in {
          val cpg = code("""def process_complex_data(data):
                       |    match data:
                       |        case [x, y] if (sum := x + y) > 10:
                       |            sink(result)
                       |        case {"status": "error", "errors": [err1, err2]}:
                       |            sink(err1, err2)
                       |        case {"status": "pending", "details": {"id": id, "message": msg}}:
                       |            sink(id, msg)""".stripMargin)
          val switch = cpg.controlStructure.head
          val body   = switch.astChildren.order(2).head
          body.astChildren.filter(_.isInstanceOf[JumpTarget]).size shouldBe 3

          // the guard wraps the first arm's body in an IF whose condition carries the walrus
          val guardIf = body.astChildren.isControlStructure
              .controlStructureTypeExact(ControlStructureTypes.IF).l
          guardIf.size shouldBe 1
          // the guard condition carries the walrus assignment in its code; the exact
          // bracket shape is not load-bearing so we only assert the substance
          guardIf.head.condition.head.code should include("sum = x + y")
          guardIf.head.condition.head.code should include("> 10")
          guardIf.head.ast.isCall.nameExact("sink").size shouldBe 1

          // all three arm bodies are inside the switch body (the guarded one nested in its IF)
          body.ast.isCall.nameExact("sink").size shouldBe 3
      }
  }
end PatternMatchingTests
