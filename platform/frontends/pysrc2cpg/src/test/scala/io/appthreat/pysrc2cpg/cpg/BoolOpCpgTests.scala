package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.Py2CpgTestContext
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import io.shiftleft.semanticcpg.language.*
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

/** `a or b or c` lowers to nested BINARY logical calls ((a or b) or c): the shared CFG creator's
  * or/and expression handling wires two-argument logical calls only, so an n-ary call would leave
  * the 3rd+ operands CFG-disconnected.
  */
class BoolOpCpgTests extends AnyFreeSpec with Matchers:
  lazy val cpg = Py2CpgTestContext.buildCpg("""if x or y or z:
      |    sink(1)""".stripMargin)

  "test boolOp 'or' call node properties" in {
      val orCalls = cpg.call.methodFullName(Operators.logicalOr).l
      orCalls.size shouldBe 2 // (x or y) and ((x or y) or z)
      val outer = orCalls.find(_.code == "x or y or z").get
      outer.dispatchType shouldBe DispatchTypes.STATIC_DISPATCH
      outer.lineNumber shouldBe Some(1)
      orCalls.map(_.code).toSet shouldBe Set("x or y", "x or y or z")
  }

  "test boolOp 'or' ast children" in {
      val inner = cpg.call.methodFullName(Operators.logicalOr).code("x or y").head
      inner.astChildren.order(1).isIdentifier.head.code shouldBe "x"
      inner.astChildren.order(2).isIdentifier.head.code shouldBe "y"
      val outer = cpg.call.methodFullName(Operators.logicalOr).code("x or y or z").head
      outer.astChildren.order(1).isCall.head.code shouldBe "x or y"
      outer.astChildren.order(2).isIdentifier.head.code shouldBe "z"
  }

  "test boolOp 'or' arguments" in {
      val inner = cpg.call.methodFullName(Operators.logicalOr).code("x or y").head
      inner.argument.argumentIndex(1).isIdentifier.head.code shouldBe "x"
      inner.argument.argumentIndex(2).isIdentifier.head.code shouldBe "y"
      val outer = cpg.call.methodFullName(Operators.logicalOr).code("x or y or z").head
      outer.argument.argumentIndex(1).isCall.head.code shouldBe "x or y"
      outer.argument.argumentIndex(2).isIdentifier.head.code shouldBe "z"
  }

  "every operand of an n-ary bool op is CFG-wired" in {
      // with the old n-ary lowering the third operand (z) had no CFG edges at all
      val z = cpg.identifier.nameExact("z").head
      (z.cfgIn.nonEmpty || z.cfgOut.nonEmpty) shouldBe true
      val y = cpg.identifier.nameExact("y").head
      (y.cfgIn.nonEmpty || y.cfgOut.nonEmpty) shouldBe true
  }
end BoolOpCpgTests
