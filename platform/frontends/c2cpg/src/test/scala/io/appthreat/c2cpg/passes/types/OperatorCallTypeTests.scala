package io.appthreat.c2cpg.passes.types

import io.appthreat.c2cpg.astcreation.Defines
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

/** Operator calls carry the type CDT gives the expression, so a pass reading an arithmetic, member,
  * element or cast expression finds its type on the call itself.
  */
class OperatorCallTypeTests extends CCodeToCpgSuite:

  "operator calls in C" should {
      val cpg = code("""
          |struct S { unsigned short n; char name[8]; };
          |long f(int a, unsigned u, struct S *p, struct S s) {
          |  int x = a + 1;
          |  unsigned v = u >> 2;
          |  int w = a >> 1;
          |  u >>= 1;
          |  char c = p->name[1];
          |  unsigned short m = s.n;
          |  long l = (long)a;
          |  long k = a ? l : a;
          |  int *q = &x;
          |  return k + *q + m + c + v + w;
          |}
          |""".stripMargin)
      def callIn(code: String): Call = cpg.method.nameExact("f").call.codeExact(code).head

      "type arithmetic, comparison-free expressions and assignments" in {
          callIn("a + 1").typeFullName shouldBe "int"
          callIn("&x").typeFullName shouldBe "int*"
          callIn("*q").typeFullName shouldBe "int"
          cpg.method.nameExact("f").call.nameExact(Operators.assignment).codeExact("x = a + 1")
              .typeFullName.l shouldBe List("int")
      }

      "type member and element accesses with the member's and the element's type" in {
          callIn("p->name").typeFullName shouldBe "char[8]"
          callIn("p->name[1]").typeFullName shouldBe "char"
          callIn("s.n").typeFullName shouldBe "unsigned short int"
      }

      "type a cast with its target type, and a conditional with its result type" in {
          callIn("(long)a").typeFullName shouldBe "long int"
          callIn("a ? l : a").typeFullName shouldBe "long int"
      }

      "shift an unsigned operand right logically and a signed one arithmetically" in {
          callIn("u >> 2").name shouldBe Operators.logicalShiftRight
          callIn("a >> 1").name shouldBe Operators.arithmeticShiftRight
          callIn("u >>= 1").name shouldBe Operators.assignmentLogicalShiftRight
      }
  }

  "pointer-to-member access in C++" should {
      val cpg = code(
        """
          |struct P { int v; };
          |int f(P obj, P *ptr) {
          |  int P::*pm = &P::v;
          |  return obj.*pm + ptr->*pm;
          |}
          |""".stripMargin,
        "pm.cpp"
      )

      "use the pointer-to-member operators, not a named field access" in {
          cpg.call.codeExact("obj.*pm").name.l shouldBe List(Defines.operatorPointerToMember)
          cpg.call.codeExact("ptr->*pm").name.l shouldBe List(
            Defines.operatorIndirectPointerToMember
          )
          cpg.call.codeExact("obj.*pm").typeFullName.l shouldBe List("int")
      }
  }
end OperatorCallTypeTests
