package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** Regression coverage for constructor calls made through an object declaration
  * (`Point a(1, 2);`). These used to be modelled as a call to the declared *variable* name (`a`),
  * masking the constructor invocation. They are now named after the constructed type, consistent
  * with the explicit constructor-expression form `Point(...)`.
  */
class CppConstructorCallTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  "a constructor call via object declaration" should {
      val cpg = code("""
          |class Point {
          |public:
          |    int x, y;
          |    Point(int a, int b) { x = a; y = b; }
          |    void SetX(int a) { x = a; }
          |};
          |int main() {
          |    Point a(1, 2);
          |    a.SetX(10);
          |    return 0;
          |}
          |""".stripMargin)

      "name the call after the constructed type, not the variable (regression)" in {
          val call = cpg.method.nameExact("main").call.codeExact("a(1, 2)").head
          call.name shouldBe "Point"
          call.methodFullName shouldBe "Point"
          call.typeFullName shouldBe "Point"
      }

      "pass the constructor arguments" in {
          val call = cpg.method.nameExact("main").call.codeExact("a(1, 2)").head
          call.argument.code.l shouldBe List("1", "2")
      }

      "still resolve ordinary member calls" in {
          cpg.method.nameExact("main").call.nameExact("SetX").methodFullName.l shouldBe List(
            "Point.SetX:void(int)"
          )
      }

      "keep the constructor Method node present" in {
          cpg.method.fullNameExact("Point.Point:ANY(int,int)").l should not be empty
      }
  }

  "constructor calls and overloaded operators in one translation unit" should {
      val cpg = code("""
          |class Point {
          |public:
          |    int x, y;
          |    Point(int a, int b) { x = a; y = b; }
          |    Point operator+(const Point& other) const {
          |        return Point(x + other.x, y + other.y);
          |    }
          |};
          |int main() {
          |    Point a(1, 2);
          |    Point b(2, 3);
          |    Point sum = a + b;
          |    return 0;
          |}
          |""".stripMargin)

      "name both declaration constructor calls after the type (regression)" in {
          cpg.method.nameExact("main").call.name("Point").code.toSetMutable should contain allOf (
            "a(1, 2)", "b(2, 3)"
          )
      }

      "keep the constructor and operator+ Method nodes present" in {
          cpg.method.fullNameExact("Point.Point:ANY(int,int)").l should not be empty
          cpg.method.name("operator \\+").fullName.l should contain(
            "Point.operator +:Point(Point &)"
          )
      }

      // The overloaded `a + b` is still modelled with the built-in arithmetic operator rather than
      // being resolved to `Point.operator+`; operator-overload resolution is a separate concern.
      "model a + b with the built-in addition operator" in {
          cpg.method.nameExact("main").call.codeExact("a + b").name.l shouldBe List(
            Operators.addition
          )
      }
  }
end CppConstructorCallTests
