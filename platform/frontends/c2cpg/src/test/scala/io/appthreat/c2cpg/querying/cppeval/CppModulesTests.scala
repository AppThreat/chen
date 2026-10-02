package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** C++20 module units: interface and implementation units, partitions, exported namespaces,
  * declarations and blocks, and the units that import them. An import of a module the project
  * declares makes the module's exported declarations visible, so calls into it resolve and link
  * across files.
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

      "recover the exported partition function with a fully qualified return type" in {
          val m = cpg.method.nameExact("format_hello").head
          m.methodReturn.typeFullName shouldBe "std.string"
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

  "a project of module units" should {
      val cpg = code(
        """
          |export module hello;
          |export import :format;
          |export namespace hello {
          |  void say_hello(const char *name);
          |}
          |export {
          |  int exported_total(int a, int b);
          |}
          |""".stripMargin,
        "hello.mxx"
      ).moreCode(
        """
          |export module hello:format;
          |export namespace hello {
          |  int format_hello(int n) { return n + 1; }
          |}
          |""".stripMargin,
        "hello-format.mxx"
      ).moreCode(
        """
          |module;
          |#include "log.hpp"
          |module hello;
          |namespace hello {
          |  void say_hello(const char *n) { log_line(n); }
          |}
          |int exported_total(int a, int b) { return a + b; }
          |""".stripMargin,
        "hello.cxx"
      ).moreCode("void log_line(const char *s);", "log.hpp")
          .moreCode(
            """
              |import hello;
              |import "log.hpp";
              |import std;
              |int main() {
              |  hello::say_hello("World");
              |  log_line("done");
              |  return hello::format_hello(1) + exported_total(1, 2);
              |}
              |""".stripMargin,
            "main.cxx"
          )

      "parse module interface units by their extension" in {
          cpg.method.nameExact("format_hello").filename.l shouldBe List("hello-format.mxx")
      }

      "resolve calls into an imported module to its declarations" in {
          val main = cpg.method.nameExact("main").head
          main.call.nameExact("say_hello").methodFullName.l shouldBe List(
            "hello.say_hello:void(char*)"
          )
          main.call.nameExact("format_hello").methodFullName.l shouldBe List(
            "hello.format_hello:int(int)"
          )
          main.call.nameExact("exported_total").methodFullName.l shouldBe List(
            "exported_total:int(int,int)"
          )
      }

      "link those calls to the definitions in the module's units" in {
          // (the interface's declarations have METHODs of their own, as a header's prototypes do)
          val main = cpg.method.nameExact("main").head
          main.call.nameExact("say_hello").callee.filename.l should contain("hello.cxx")
          main.call.nameExact("format_hello").callee.filename.l shouldBe List("hello-format.mxx")
          main.call.nameExact("exported_total").callee.filename.l should contain("hello.cxx")
      }

      "give an implementation unit its interface's declarations" in {
          cpg.method.nameExact("say_hello").filter(_.filename == "hello.cxx").fullName.l shouldBe
              List("hello.say_hello:void(char*)")
      }

      "include an imported header unit" in {
          cpg.method.nameExact("main").call.nameExact("log_line").methodFullName.l shouldBe List(
            "log_line:void(char*)"
          )
      }

      "keep line numbers after rewritten lines" in {
          cpg.method.nameExact("main").call.nameExact("say_hello").lineNumber.l shouldBe List(6)
          cpg.method.nameExact("main").call.nameExact("say_hello").columnNumber.l shouldBe List(3)
      }
  }

  "import outside a module unit" should {
      val cpg = code(
        """
          |typedef int import;
          |import counter;
          |int next() { return ++counter; }
          |""".stripMargin,
        "legacy.cpp"
      )

      "stay a declaration when no module of that name exists" in {
          cpg.method.nameExact("next").ast.isIdentifier.nameExact("counter").l should not be empty
          cpg.call.nameExact("<operator>.preIncrement").argument.code.l shouldBe List("counter")
      }
  }
end CppModulesTests
