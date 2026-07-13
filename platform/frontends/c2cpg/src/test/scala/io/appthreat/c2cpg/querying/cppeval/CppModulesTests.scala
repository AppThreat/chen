package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Evaluates AST creation for C++20 module units: module interface / implementation units,
  * module partitions, exported namespaces and declarations, and a module consumer.
  *
  * The underlying Eclipse CDT parser (9.3) has no C++20 module support and represents an exported
  * declaration (`export namespace {...}`, `export void f() {...}`) as a single ProblemDeclaration,
  * which silently drops the whole declaration body. The frontend neutralises the `export` keyword
  * at the preprocessor stage so the underlying declaration parses normally; these tests pin that
  * behaviour and document the remaining known gaps (module `import` statements are not yet modelled
  * as Import nodes; a `module X;` line parses as a stray declaration).
  */
class CppModulesTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private implicit val resolver: NoResolve.type = NoResolve

  "a module interface unit (export module + export namespace)" should {
      val cpg = code("""
          |export module hello;
          |
          |import <string_view>;
          |
          |export namespace hello {
          |    void say_hello(std::string_view name) {
          |        std::cout << "Hello, " << name << '!' << std::endl;
          |    }
          |}
          |""".stripMargin)

      "recover the exported function inside the module namespace" in {
          val m = cpg.method.nameExact("say_hello").head
          m.fullName shouldBe "hello.say_hello:void(ANY)"
          m.parameter.name.l shouldBe List("name")
          m.parameter.nameExact("name").typeFullName.head shouldBe "std.string_view"
      }

      "create the enclosing namespace block" in {
          cpg.namespaceBlock.nameExact("hello").l should not be empty
          cpg.method.nameExact("say_hello").namespace.name.l should contain("hello")
      }

      "recover the body of the exported function (not dropped as a problem decl)" in {
          cpg.method.nameExact("say_hello").call.name(
            io.shiftleft.codepropertygraph.generated.Operators.shiftLeft
          ).l should not be empty
      }
  }

  "a module implementation unit (module + plain namespace)" should {
      val cpg = code("""
          |module hello;
          |
          |import <iostream>;
          |
          |namespace hello {
          |    void say_hello(std::string_view n) {
          |        std::cout << "Hello, " << n << '!' << std::endl;
          |    }
          |}
          |""".stripMargin)

      "parse the function and its body" in {
          cpg.method.nameExact("say_hello").head.parameter.name.l shouldBe List("n")
          cpg.method.nameExact("say_hello").call.name(
            io.shiftleft.codepropertygraph.generated.Operators.shiftLeft
          ).l should not be empty
      }
  }

  "a module partition interface (export module X:part)" should {
      val cpg = code("""
          |export module hello:format;
          |
          |import <string>;
          |import <string_view>;
          |
          |export namespace hello {
          |    std::string format_hello(std::string_view name) {
          |        return "Hello, " + std::string(name) + '!';
          |    }
          |}
          |""".stripMargin)

      "recover the exported partition function" in {
          val m = cpg.method.nameExact("format_hello").head
          // NOTE: the partition selector (`:format`) confuses CDT's name qualification, so the
          // return type comes back unqualified ("string" rather than "std.string"). The important
          // point for this suite is that the declaration body is recovered at all.
          m.methodReturn.typeFullName.endsWith("string") shouldBe true
          m.parameter.nameExact("name").typeFullName.head shouldBe "std.string_view"
          m.ast.isReturn.l should not be empty
      }
  }

  "an exported free function (no namespace)" should {
      val cpg = code("""
          |export module math;
          |export int add(int a, int b) { return a + b; }
          |""".stripMargin)

      "recover the function, parameters and return" in {
          val m = cpg.method.nameExact("add").head
          m.parameter.name.l shouldBe List("a", "b")
          m.methodReturn.typeFullName shouldBe "int"
          m.ast.isReturn.astChildren.isCall.name(
            io.shiftleft.codepropertygraph.generated.Operators.addition
          ).l should not be empty
      }
  }

  "a module consumer (import + qualified call)" should {
      val cpg = code("""
          |import hello;
          |
          |int main() {
          |    hello::say_hello("World");
          |    return 0;
          |}
          |""".stripMargin)

      "parse main and capture the qualified call" in {
          cpg.method.nameExact("main").head.methodReturn.typeFullName shouldBe "int"
          val call = cpg.call.nameExact("say_hello").head
          call.code shouldBe "hello::say_hello(\"World\")"
          call.argument.isLiteral.code.l should contain("\"World\"")
      }
  }
end CppModulesTests
