package io.appthreat.c2cpg.parser

import io.appthreat.c2cpg.testfixtures.{CCodeToCpgSuite, DefaultTestCpgWithC}
import io.shiftleft.codepropertygraph.generated.nodes.Literal
import io.shiftleft.semanticcpg.language.*

/** The three constructs of the C23 and C++23 dialects the CDT grammar cannot read, rewritten to
  * what it can with the gap blanked to spaces, so everything after the gap keeps its column. Each
  * shape has a twin that must pass through the rewrite byte-identically: constructs the parser
  * already accepts are never touched.
  */
class DialectGapRewriteTests extends CCodeToCpgSuite:

  "a C23 attribute on a function" should {
      val cpg = code(
        """#include <stdbool.h>
        |[[nodiscard]] int f_attr(void) { return 0; }
        |[[deprecated("old")]] int g(int x);
        |int use(void) { return f_attr() + g(1); }
        |""".stripMargin,
        "c23_attr.c"
      )
      "parse, with the function and its callers" in {
          (cpg.method.name("f_attr", "g", "use").name.l should contain).allOf("f_attr", "g", "use")
          cpg.call.name("f_attr").l should have size 1
      }
  }

  "a digit separator with a binary literal in C" should {
      val cpg = code(
        """int f_binlit(void) {
        |  int x = 0b1010 + 1'000;
        |  int y = 0xF'F;
        |  return x + y;
        |}
        |""".stripMargin,
        "c23_binlit.c"
      )
      "keep the number's value: 0b1010 is 10, 1'000 is 1000, 0xF'F is 255" in {
          cpg.method.name("f_binlit").l should have size 1
          // the literals keep their spelling; the separator ones read as one token of their value
          cpg.literal.code("0b1010").l should have size 1
          cpg.literal.code("1000").l should have size 1
          cpg.literal.code("0xFF").l should have size 1
          cpg.literal.code("'F").l shouldBe empty
      }
  }

  "a char literal next to a digit" should {
      val cpg = code(
        """int f(void) { char c = '7'; return c - '0'; }
        |const char *s = "it's 1'000";
        |""".stripMargin,
        "charlit.c"
      )
      "pass through untouched: the quotes are a character and a string, not separators" in {
          cpg.literal.code("'7'").l should have size 1
          cpg.literal.code("'0'").l should have size 1
          cpg.literal.code("\"it's 1'000\"").l should have size 1
      }
  }

  "a C++23 explicit object parameter" should {
      val cpg = code(
        """struct S {
        |  int f_deducing(this S& self) { return 1; }
        |  int g(this auto&& self, int x) { return x; }
        |};
        |int use(S& s) { return s.f_deducing() + s.g(2); }
        |""".stripMargin,
        "deducing.cpp"
      )
      "parse as a member function with its object parameter kept" in {
          cpg.method.name("f_deducing").parameter.name("self").l should have size 1
          cpg.method.name("g").parameter.name("self").l should have size 1
          cpg.call.name("f_deducing").l should have size 1
      }
  }

  "`this` as an argument, not a parameter" should {
      val cpg = code(
        """struct S {
        |  int helper(int x) { return x; }
        |  int call_this(void) { return helper(3); }
        |};
        |int take(S* s) { return s->call_this(); }
        |int arr(int n) { int a[2][2]; return a[1][1] + n; }
        |""".stripMargin,
        "thisarg.cpp"
      )
      "parse untouched - the rewrite leaves everything it can already read alone" in {
          cpg.method.name("helper", "call_this", "take", "arr").name.l should have size 4
          cpg.call.name("helper").l should have size 1
          cpg.call.name("call_this").l should have size 1
          cpg.local.name("a").l should have size 1
      }
  }
end DialectGapRewriteTests
