package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.codepropertygraph.generated.nodes.Local
import io.shiftleft.semanticcpg.language.*

/** Evaluates AST creation for class-related and statement-level modern C++ features: virtual /
  * pure-virtual / deleted / defaulted / overriding members with inheritance, structured bindings,
  * and range-based for loops.
  */
class CppClassFeaturesTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  "special member functions and inheritance" should {
      val cpg = code("""
          |class Base {
          |public:
          |    virtual void doWork() = 0;
          |    virtual ~Base() = default;
          |    Base(const Base&) = delete;
          |    constexpr int getId() const noexcept { return 42; }
          |};
          |class Derived : public Base {
          |public:
          |    void doWork() override { return; }
          |};
          |""".stripMargin)

      "create all declared members with correct return types" in {
          cpg.method.nameExact("doWork").methodReturn.typeFullName.toSetMutable shouldBe Set("void")
          cpg.method.nameExact("getId").methodReturn.typeFullName.head shouldBe "int"
          (cpg.typeDecl.nameExact("Base").method.name.toSetMutable should contain).allOf(
            "doWork",
            "getId"
          )
      }

      "record the inheritance relationship" in {
          cpg.typeDecl.nameExact("Derived").inheritsFromTypeFullName.l should contain("Base")
      }

      "create the overriding method in the derived type" in {
          cpg.typeDecl.nameExact("Derived").method.nameExact("doWork").l should not be empty
      }
  }

  "structured bindings" should {
      val cpg = code("""
          |#include <tuple>
          |int main() {
          |    auto [a, b] = std::make_tuple(1, 2);
          |    return a + b;
          |}
          |""".stripMargin)

      "declare a local for each bound name (regression: names were not locals)" in {
          val locals = cpg.method.nameExact("main").ast.isLocal.name.toSetMutable
          (locals should contain).allOf("a", "b")
      }

      "capture the initializer call (regression: initializer was dropped)" in {
          cpg.method.nameExact("main").call.name(".*make_tuple.*").l should not be empty
      }

      "reference the bound names in the return expression" in {
          (cpg.method.nameExact("main").methodReturn.toReturn.ast.isIdentifier.name
              .toSetMutable should contain).allOf(
            "a",
            "b"
          )
      }
  }

  "range-based for with structured binding" should {
      val cpg = code("""
          |void method() {
          |    int foo[2] = {1, 2};
          |    for (const auto& [a, b] : foo) {}
          |}
          |""".stripMargin)

      "create a FOR control structure whose binding declares locals a and b" in {
          val forStmt = cpg.method.nameExact("method").controlStructure.head
          forStmt.controlStructureType shouldBe ControlStructureTypes.FOR
          forStmt.astChildren.order(2).astChildren.collectAll[Local].name.l shouldBe List("a", "b")
      }
  }
end CppClassFeaturesTests
