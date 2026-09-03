package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** Evaluates AST/type creation for modern C++ (11/14) constructs drawn from Effective Modern C++:
  * scoped enums with an explicit underlying type, alias declarations, trailing return types,
  * `auto`/`decltype(auto)`, and lambdas with init capture.
  */
class CppModernFeaturesTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  "scoped and unscoped enums" should {
      val cpg = code("""
          |#include <cstdint>
          |enum class Color : std::uint8_t { black, white, red };
          |enum Status { good = 0, failed = 1, bad = 0xFF };
          |Color c = Color::red;
          |""".stripMargin)

      "create TypeDecls for both enums" in {
          (cpg.typeDecl.internal.name.toSetMutable should contain).allOf("Color", "Status")
      }

      "type the scoped enum's members with its explicit underlying type" in {
          cpg.typeDecl.nameExact("Color").member.name.toSetMutable shouldBe Set(
            "black",
            "white",
            "red"
          )
          cpg.typeDecl.nameExact("Color").member.typeFullName.toSetMutable shouldBe Set(
            "std.uint8_t"
          )
      }

      "type a variable of the scoped enum" in {
          cpg.local.nameExact("c").typeFullName.head shouldBe "Color"
      }
  }

  "alias declarations and trailing return types" should {
      val cpg = code("""
          |#include <vector>
          |using IntVec = std::vector<int>;
          |auto add(int a, int b) -> int { return a + b; }
          |auto makeVec() -> IntVec { IntVec v; return v; }
          |""".stripMargin)

      "resolve a primitive trailing return type (regression: was ANY)" in {
          val m = cpg.method.nameExact("add").head
          m.methodReturn.typeFullName shouldBe "int"
          m.signature shouldBe "int (int,int)"
      }

      "resolve an alias-typed trailing return type (regression: was ANY)" in {
          cpg.method.nameExact("makeVec").methodReturn.typeFullName.head shouldBe "IntVec"
      }

      "type the alias-typed local" in {
          cpg.method.nameExact("makeVec").local.nameExact("v").typeFullName.head shouldBe "IntVec"
      }
  }

  "auto and decltype(auto)" should {
      val cpg = code("""
          |class Widget {};
          |Widget w;
          |const Widget& cw = w;
          |int main() {
          |    auto a = cw;
          |    decltype(auto) b = cw;
          |    return 0;
          |}
          |""".stripMargin)

      "deduce the base type for auto and decltype(auto) locals" in {
          val locals = cpg.method.nameExact("main").local.map(l => l.name -> l.typeFullName).toMap
          locals("a") shouldBe "Widget"
          locals("b") shouldBe "Widget"
      }
  }

  "lambdas with init capture" should {
      val cpg = code("""
          |#include <memory>
          |int main() {
          |    auto pw = std::make_unique<int>(5);
          |    auto func = [pw = std::move(pw)]() { return *pw; };
          |    auto x = func();
          |    return 0;
          |}
          |""".stripMargin)

      "create a lambda method and capture the make_unique / lambda-invocation calls" in {
          cpg.method.internal.name(".*lambda.*").l should not be empty
          cpg.method.nameExact("main").call.name.toSetMutable should contain(
            io.shiftleft.codepropertygraph.generated.Operators.assignment
          )
          cpg.method.nameExact("main").call.name(".*make_unique.*").l should not be empty
      }
  }
end CppModernFeaturesTests
