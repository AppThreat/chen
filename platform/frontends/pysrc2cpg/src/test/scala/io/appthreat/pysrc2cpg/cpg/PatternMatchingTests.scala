package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.codepropertygraph.generated.NodeTypes
import io.shiftleft.semanticcpg.language._

class PatternMatchingTests extends PySrc2CpgFixture() {
  "pattern matching" should {
    "be correct" in {
      val cpg = code("""match [1, 2]:
          |  case [a, b]:
          |    print(1)
          |  case _:
          |    print(2)
          |""".stripMargin)
      val switch    = cpg.controlStructure.head
      val condition = switch.astChildren.order(1).head
      condition.code shouldBe "[1, 2]"
      condition.lineNumber shouldBe Some(1)

      val case1 = switch.astChildren.order(2).head
      case1.label shouldBe NodeTypes.BLOCK
      case1.code shouldBe "print(1)"

      val case2 = switch.astChildren.order(3).head
      case2.label shouldBe NodeTypes.BLOCK
      case2.code shouldBe "print(2)"
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
      val switch    = cpg.controlStructure.head
      val condition = switch.astChildren.order(1).head
      condition.code shouldBe "value"
      condition.lineNumber shouldBe Some(2)

      val case1 = switch.astChildren.order(2).head
      case1.label shouldBe NodeTypes.BLOCK
      case1.code shouldBe "result = \"one\""

      val case2 = switch.astChildren.order(3).head
      case2.label shouldBe NodeTypes.BLOCK
      case2.code shouldBe "result = \"two\""
    }

    "match statement with capture pattern" in {
      val cpg = code("""def process_value(value):
                       |    match value:
                       |        case x:
                       |            sink(x)""".stripMargin)
      val switch    = cpg.controlStructure.head
      val condition = switch.astChildren.order(1).head
      condition.code shouldBe "value"
      condition.lineNumber shouldBe Some(2)

      val case1 = switch.astChildren.order(2).head
      case1.label shouldBe NodeTypes.BLOCK
      case1.code shouldBe "sink(x)"
    }

    "match statement with sequence pattern" in {
      val cpg = code("""def process_sequence(seq):
                       |    match seq:
                       |        case [x, y]:
                       |            sink(x, y)""".stripMargin)
      val switch    = cpg.controlStructure.head
      val condition = switch.astChildren.order(1).head
      condition.code shouldBe "seq"
      condition.lineNumber shouldBe Some(2)
      val case1 = switch.astChildren.order(2).head
      case1.label shouldBe NodeTypes.BLOCK
      case1.code shouldBe "sink(x, y)"
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
      val switch    = cpg.controlStructure.head
      val condition = switch.astChildren.order(1).head
      condition.code shouldBe "data"
      condition.lineNumber shouldBe Some(2)
      val case1 = switch.astChildren.order(2).head
      case1.label shouldBe NodeTypes.BLOCK
      case1.code shouldBe "sink(result)"
      val case2 = switch.astChildren.order(3).head
      case2.label shouldBe NodeTypes.BLOCK
      case2.code shouldBe "sink(err1, err2)"
      val case3 = switch.astChildren.order(4).head
      case3.label shouldBe NodeTypes.BLOCK
      case3.code shouldBe "sink(id, msg)"
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
      val switch    = cpg.controlStructure.head
      val condition = switch.astChildren.order(1).head
      condition.code shouldBe "data"
      condition.lineNumber shouldBe Some(2)
      val case1 = switch.astChildren.order(2).head
      case1.label shouldBe NodeTypes.BLOCK
      case1.code shouldBe "sink(result)"
      val case2 = switch.astChildren.order(3).head
      case2.label shouldBe NodeTypes.BLOCK
      case2.code shouldBe "sink(err1, err2)"
      val case3 = switch.astChildren.order(4).head
      case3.label shouldBe NodeTypes.BLOCK
      case3.code shouldBe "sink(id, msg)"
    }
  }
}
