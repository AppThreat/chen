package io.appthreat.jimple2cpg.querying

import io.appthreat.jimple2cpg.testfixtures.JimpleCode2CpgFixture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Literal}
import io.shiftleft.semanticcpg.language._
import org.scalatest.Failed

class ArrayTests extends JimpleCode2CpgFixture {

  lazy val cpg: Cpg = code("""
      |class Foo {
      |  public void foo() {
      |    int[] x = {0, 1, 2};
      |  }
      |
      |  public void bar() {
      |    int[][] x = new int[5][2];
      |  }
      |
      |  public void baz() {
      |    int[] x = new int[2];
      |    x[0] = 1;
      |    x[1] = x[0] + 2;
      |  }
      |}
      |""".stripMargin).cpg

  "should initialize array with three address code initialization expressions" in {
    def m = cpg.method(".*foo.*")

    val List(arrayInit: Call) = m.call.nameExact(Operators.alloc).code("new int\\[3\\]").l: @unchecked

    arrayInit.code shouldBe "new int[3]"
    arrayInit.methodFullName shouldBe Operators.alloc
    arrayInit.astChildren.headOption match {
      case Some(alloc) =>
        alloc shouldBe a[Literal]
        alloc.code shouldBe "3"
      case None => Failed("arrayInitializer should have a literal with the value of 3")
    }

    val List(stackAt0: Call, arg0: Literal) = m.assignment.code(".*\\[0\\] = 0").argument.l: @unchecked

    arg0.code shouldBe "0"
    arg0.typeFullName shouldBe "int"

    stackAt0.code.endsWith("[0]") shouldBe true
    stackAt0.methodFullName shouldBe Operators.indexAccess
    val List(stackPointerAt0: Identifier, zero: Literal) = stackAt0.astChildren.l: @unchecked
    stackPointerAt0.typeFullName shouldBe "int[]"
    zero.code shouldBe "0"

    val List(stackAt1: Call, arg1: Literal) = m.assignment.code(".*\\[1\\] = 1").argument.l: @unchecked

    arg1.code shouldBe "1"
    arg1.typeFullName shouldBe "int"

    stackAt1.code.endsWith("[1]") shouldBe true
    stackAt1.methodFullName shouldBe Operators.indexAccess
    val List(stackPointerAt1: Identifier, one: Literal) = stackAt1.astChildren.l: @unchecked
    stackPointerAt1.typeFullName shouldBe "int[]"
    one.code shouldBe "1"

    val List(stackAt2: Call, arg2: Literal) = m.assignment.code(".*\\[2\\] = 2").argument.l: @unchecked

    arg2.code shouldBe "2"
    arg2.typeFullName shouldBe "int"

    stackAt2.code.endsWith("[2]") shouldBe true
    stackAt2.methodFullName shouldBe Operators.indexAccess
    val List(stackPointerAt2: Identifier, two: Literal) = stackAt2.astChildren.l: @unchecked
    stackPointerAt2.typeFullName shouldBe "int[]"
    two.code shouldBe "2"
  }

  "should initialize an array with empty initialization expression" in {
    def m = cpg.method(".*bar.*")

    val List(arg1: Identifier, arg2: Call) =
      m.assignment.codeExact("x = new int[5][2]").argument.l: @unchecked

    arg1.typeFullName shouldBe "int[][]"

    arg2.code shouldBe "new int[5][2]"
    val List(lvl1: Literal, lvl2: Literal) = arg2.argument.l: @unchecked
    lvl1.code shouldBe "5"
    lvl2.code shouldBe "2"
  }

  "should handle arrayIndexAccesses correctly (3-address code form)" in {
    def m = cpg.method(".*baz.*")

    val targetAssigns =
      m.assignment
        .where(
          _.argument(1)
            .isCall
            .nameExact(Operators.indexAccess)
            .where(_.argument(1).isIdentifier.nameExact("x"))
            .where(_.argument(2).isLiteral.codeExact("1"))
        )
        .l

    targetAssigns.size shouldBe 1
    val List(indexAccess: Call, rhsNode) = targetAssigns.head.argument.l: @unchecked
    indexAccess.name shouldBe Operators.indexAccess
    indexAccess.methodFullName shouldBe Operators.indexAccess

    withClue("indexAccess on LHS of assignment") {
      val List(arg1: Identifier, arg2: Literal) = indexAccess.argument.l: @unchecked
      arg1.code shouldBe "x"
      arg1.name shouldBe "x"
      arg1.typeFullName shouldBe "int[]"
      arg2.code shouldBe "1"
    }

    withClue("expr on RHS of assignment preserves x[0] + 2 semantics") {
      rhsNode match {
        case rhsCall: Call =>
          rhsCall.name shouldBe Operators.addition
          rhsCall.argument.isLiteral.codeExact("2").size shouldBe 1
          rhsCall.argument
            .isCall
            .nameExact(Operators.indexAccess)
            .where(_.argument(1).isIdentifier.nameExact("x"))
            .where(_.argument(2).isLiteral.codeExact("0"))
            .size shouldBe 1

        case rhsStub: Identifier =>
          rhsStub.typeFullName shouldBe "int"
          val producerCalls =
            m.assignment
              .where(_.argument(1).isIdentifier.nameExact(rhsStub.name))
              .argument(2)
              .isCall
              .nameExact(Operators.addition)
              .l

          producerCalls.size shouldBe 1
          val producer = producerCalls.head
          producer.code should include("+")
          producer.code should include("2")

        case other => Failed(s"unexpected RHS node type: ${other.label}")
      }
    }
  }
}
