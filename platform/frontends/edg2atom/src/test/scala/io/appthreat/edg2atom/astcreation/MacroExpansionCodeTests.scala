package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** A node a macro expanded has the code of the expression, composed from its operands, and an
  * expression that ends in a macro invocation covers the invocation's arguments.
  */
class MacroExpansionCodeTests extends EdgCodeToCpgSuite(".c"):

  "a function that uses macros" should {
      val cpg = code(
        """#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
        |#define SWAPL(p) do { if (sizeof(*(p)) != 4) bad(); *(p) = swap32(*(p)); } while (0)
        |#define FIELD(q) ((struct s *)(q))->f[(q)->g] = (int) -(q)->g
        |#define PICK(c, a, b) ((c) ? &(a) : &(b))
        |struct s { int f[3]; int g; };
        |void bad(void); unsigned swap32(unsigned);
        |int g(unsigned short *w, unsigned *n, struct s *q) {
        |    int size;
        |    size = ALIGN(*w, 4);
        |    SWAPL(n);
        |    FIELD(q);
        |    int *r = PICK(size > 1, size, q->g);
        |    q->g = (*r)++;
        |    return size;
        |}
        |""".stripMargin
      )

      "have no expression without code" in {
          requireEdga()
          val method = cpg.method.nameExact("g")
          method.ast.isCall.filter(_.code.isEmpty).name.l shouldBe empty
          method.ast.isIdentifier.filter(_.code.isEmpty).name.l shouldBe empty
          method.ast.isLiteral.filter(_.code.isEmpty).l shouldBe empty
          method.ast.isTypeRef.filter(_.code.isEmpty).l shouldBe empty
      }

      "compose the code of the expansion from its operands" in {
          requireEdga()
          val codes = cpg.method.nameExact("g").ast.isCall.map(c => c.name -> c.code).l
          codes should contain(Operators.notEquals -> "sizeof(*n) != 4")
          codes should contain(Operators.sizeOf -> "sizeof(*n)")
          codes should contain(Operators.assignment -> "*n = swap32(*n)")
          codes should contain("swap32" -> "swap32(*n)")
          codes should contain(Operators.indirection -> "*n")
          codes should contain(Operators.addressOf -> "&size")
          codes should contain(Operators.conditional -> "size > 1 ? &size : &q->g")
          codes should contain(Operators.cast -> "(s*)q")
          codes should contain(Operators.assignment -> "((s*)q)->f[q->g] = (int)-q->g")
          codes should contain(Operators.postIncrement -> "(*r)++")
          codes should contain(Operators.indirectFieldAccess -> "q->g")
          codes.map(_._2) should contain("*w + 4 - 1 & ~(4 - 1)")
      }

      "cover the whole invocation an expression ends in" in {
          requireEdga()
          val assignment = cpg.method.nameExact("g").call.nameExact(Operators.assignment)
              .filter(_.code.startsWith("size")).l
          assignment.map(_.code) shouldBe List("size = ALIGN(*w, 4)")
      }
  }

  "an expression that ends in a macro invocation" should {
      val cpg = code(
        """#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
        |#define PAD(n) \
        |    ((n) + 7)
        |void h(int *w, int size) {
        |    *w = ALIGN(*w, 2);
        |    size = PAD(
        |        (size + (1)));
        |    size = ALIGN(ALIGN(size, 2),
        |                4);
        |}
        |""".stripMargin
      )

      "keep nested parentheses and several lines" in {
          requireEdga()
          val written = cpg.method.nameExact("h").call.nameExact(Operators.assignment)
              .filter(c => c.lineNumber.exists(_ >= 5)).l
          written.map(_.code) should contain("*w = ALIGN(*w, 2)")
          written.map(_.code) should contain("size = PAD(\n        (size + (1)))")
          written.map(_.code) should contain("size = ALIGN(ALIGN(size, 2),\n                4)")
      }
  }
  "an expression inside a macro argument" should {
      val cpg = code(
        """#define ID(x) (x)
        |#define TWICE(x) ((x) + (x))
        |int use(int, int);
        |int k(int a, int b) {
        |    int r;
        |    r = ID(a + b) * 2;
        |    r = use(ID(a), b);
        |    r = TWICE(a - b) + ID(b);
        |    return ID(a - b);
        |}
        |""".stripMargin
      )

      "keep its own extent rather than the invocation's" in {
          requireEdga()
          val codes = cpg.method.nameExact("k").ast.isCall.code.l
          def balanced(s: String) =
              s.foldLeft(0)((d, c) =>
                  if d < 0 then d else if c == '(' then d + 1 else if c == ')' then d - 1 else d
              ) == 0
          codes.filterNot(balanced) shouldBe empty
          codes should contain("r = ID(a + b) * 2")
          codes should contain("r = use(ID(a), b)")
      }
  }
end MacroExpansionCodeTests
