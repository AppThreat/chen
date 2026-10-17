package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** A declaration through `typeof`/`__typeof__` declares the referenced expression's own type, so a
  * buffer declared that way keeps its extent; a pointer, array or function derived from it does not
  * take that type.
  */
class TypeofDeclarationTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
      |void copy(char *d, const char *s);
      |void gnu_spelling(const char *user) {
      |    char a[16];
      |    __typeof__(a) b;
      |    copy(b, user);
      |}
      |""".stripMargin,
    "typeof.c"
  ).moreCode(
    """
      |void keyword_spelling(const char *user) {
      |    char a[16];
      |    typeof(a) b;
      |    copy(b, user);
      |}
      |""".stripMargin,
    "typeof_keyword.c"
  ).moreCode(
    """
      |void cpp_spelling(const char *user) {
      |    char a[16];
      |    typeof(a) b;
      |    copy(b, user);
      |}
      |""".stripMargin,
    "typeof.cpp"
  ).moreCode(
    """
      |void take(void *p, const void *q, const void *r);
      |int round(int v);
      |void derived(const char *user) {
      |    char a[16];
      |    __typeof__(a) *p;
      |    __typeof__(a) arr[4];
      |    __typeof__(a) fn(int);
      |    take(p, arr, user);
      |    fn(round(0));
      |}
      |""".stripMargin,
    "typeof_derived.c"
  )

  private def localType(method: String, local: String): List[String] =
      cpg.method.nameExact(method).local.nameExact(local).typeFullName.l

  "a buffer declared through typeof" should {
      "carry the referenced declaration's type" in {
          localType("gnu_spelling", "b") should contain("char[16]")
          localType("keyword_spelling", "b") should contain("char[16]")
          localType("cpp_spelling", "b") should contain("char[16]")
      }

      "not hand a pointer the referenced array's type" in {
          val tpe = localType("derived", "p")
          tpe should not contain "char[16]"
          tpe.exists(t => t.endsWith("*") || !t.contains("[")) shouldBe true
      }

      "not hand a derived array the referenced array's type" in {
          localType("derived", "arr") should not contain "char[16]"
      }

      "not hand a function declarator the referenced array's type" in {
          localType("derived", "fn") should not contain "char[16]"
      }
  }
end TypeofDeclarationTests
