package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** Arithmetic that moves a pointer says so, with the operand that is the pointer. */
class PointerArithmeticTests extends CCodeToCpgSuite:

  "pointer arithmetic" should {
      val cpg = code(
        """
          |typedef char *cursor;
          |long run(char *p, char *q, cursor c, int n, int a, int b) {
          |  char buf[16];
          |  char *r = p + n;
          |  r = n + p;
          |  r = buf + 2;
          |  r = c + 1;
          |  long d = p - q;
          |  r = p - n;
          |  p += n;
          |  q -= 2;
          |  p++;
          |  --q;
          |  a++;
          |  int s = a + b;
          |  return 1[buf] + d + s;
          |}
          |""".stripMargin,
        "arith.c"
      )

      def tagOf(code: String): List[String] =
          cpg.call.codeExact(code).tag.nameExact(Defines.PointerArithmeticTag).value.l

      "name the pointer operand of an addition" in {
          tagOf("p + n") shouldBe List("add:1")
          tagOf("n + p") shouldBe List("add:2")
          tagOf("buf + 2") shouldBe List("add:1")
          tagOf("c + 1") shouldBe List("add:1")
      }

      "tell a pointer difference from a pointer moved back" in {
          tagOf("p - q") shouldBe List("diff")
          tagOf("p - n") shouldBe List("sub:1")
      }

      "cover compound assignments and increments" in {
          tagOf("p += n") shouldBe List("add:1")
          tagOf("q -= 2") shouldBe List("sub:1")
          tagOf("p++") shouldBe List("add:1")
          tagOf("--q") shouldBe List("sub:1")
      }

      "leave integer arithmetic alone" in {
          tagOf("a++") shouldBe empty
          tagOf("a + b") shouldBe empty
      }

      "index with the array as the base however it is written" in {
          val List(access) = cpg.call.nameExact(Operators.indirectIndexAccess).codeExact("1[buf]").l
          access.argument(1).code shouldBe "buf"
          access.argument(2).code shouldBe "1"
      }
  }
end PointerArithmeticTests
