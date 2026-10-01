package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.{ModifierTypes, Operators}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Constructor calls made through an object declaration (`Point a(1, 2);`): named after the
  * constructed type (not the declared variable), and linked to the constructor's METHOD. Overloaded
  * operators call the operator method the class declares.
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
          val call = cpg.method.nameExact("main").call.nameExact("Point").codeExact("a(1, 2)").head
          call.name shouldBe "Point"
          call.methodFullName shouldBe "Point.Point:void(int,int)"
          call.typeFullName shouldBe "Point"
          call.callee(NoResolve).fullName.l shouldBe List("Point.Point:void(int,int)")
      }

      "pass the constructor arguments" in {
          val call = cpg.method.nameExact("main").call.nameExact("Point").codeExact("a(1, 2)").head
          call.argument.code.l shouldBe List("1", "2")
      }

      "assign what the constructor builds to the declared object" in {
          val List(assignment) =
              cpg.method.nameExact("main").call.nameExact(Operators.assignment).l
          assignment.code shouldBe "a(1, 2)"
          assignment.typeFullName shouldBe "Point"
          assignment.argument.map(a => a.argumentIndex -> a.code).l shouldBe List(
            1 -> "a",
            2 -> "a(1, 2)"
          )
          assignment.argument(2).asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
              .name shouldBe "Point"
      }

      "still resolve ordinary member calls" in {
          cpg.method.nameExact("main").call.nameExact("SetX").methodFullName.l shouldBe List(
            "Point.SetX:void(int)"
          )
      }

      "keep the constructor Method node present, marked as a constructor" in {
          val List(ctor) = cpg.method.fullNameExact("Point.Point:void(int,int)").l
          ctor.modifier.modifierType.l should contain(ModifierTypes.CONSTRUCTOR)
          ctor.methodReturn.typeFullName shouldBe "void"
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
          (cpg.method.nameExact("main").call.name("Point").code.toSetMutable should contain).allOf(
            "a(1, 2)",
            "b(2, 3)"
          )
      }

      "keep the constructor and operator+ Method nodes present" in {
          cpg.method.fullNameExact("Point.Point:void(int,int)").l should not be empty
          cpg.method.name("operator \\+").fullName.l should contain(
            "Point.operator +:Point(Point &)"
          )
      }

      "call Point.operator+ for a + b, tagged with the built-in operator" in {
          val List(call) = cpg.method.nameExact("main").call.codeExact("a + b").l
          call.name shouldBe "operator +"
          call.methodFullName shouldBe "Point.operator +:Point(Point &)"
          call.callee(NoResolve).fullName.l shouldBe List("Point.operator +:Point(Point &)")
          call.tag.nameExact(X2CpgDefines.OperatorCallTag).value.l shouldBe List(Operators.addition)
          call.argument.map(a => a.argumentIndex -> a.code).l shouldBe List(0 -> "a", 1 -> "b")
      }

      "call the constructor from the operator's body" in {
          cpg.method.nameExact("operator +").call.nameExact("Point").methodFullName.l shouldBe List(
            "Point.Point:void(int,int)"
          )
      }
  }
end CppConstructorCallTests
