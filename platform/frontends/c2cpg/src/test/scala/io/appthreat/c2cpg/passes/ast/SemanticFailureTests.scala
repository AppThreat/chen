package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.Unknown
import io.shiftleft.semanticcpg.language.*

/** Code CDT's semantics fail on, by throwing or by recursing without bound: the construct loses
  * what CDT could not tell, and the rest of the file keeps its AST.
  */
class SemanticFailureTests extends CCodeToCpgSuite(FileDefaults.CPP_EXT):

  "a function whose `auto` return type CDT cannot deduce" should {
      val cpg = code(
        """
          |template <class T> auto make_one() -> decltype(new auto{T{}});
          |int use() { return 1; }
          |""".stripMargin
      )

      "keep its METHOD, with an unknown return type and its parameters" in {
          cpg.method.nameExact("make_one").fullName.l shouldBe List("make_one:ANY()")
          cpg.method.nameExact("use").fullName.l shouldBe List("use:int()")
      }
  }

  "a variable template initialised with itself" should {
      val cpg = code(
        """
          |namespace config {
          |template <class... Ts> bool ready = ready<>;
          |}
          |template <class T> const long width = width<T>;
          |long measured = width<char>;
          |int status() { return 0; }
          |""".stripMargin
      )

      "keep the declarations, and the uses as their code" in {
          cpg.local.nameExact("ready", "width", "measured").name.l.sorted shouldBe
              List("measured", "ready", "width")
          val List(init) = cpg.call.nameExact(Operators.assignment).code("measured = .*").l
          init.argument.l.map(_.code) shouldBe List("measured", "width<char>")
          init.argument(2).isInstanceOf[Unknown] shouldBe true
          cpg.method.nameExact("status").size shouldBe 1
      }

      "leave no name referring to a variable outside the graph" in {
          cpg.identifier.flatMap(_._refOut).filterNot(_._astIn.hasNext).size shouldBe 0
      }
  }

  "nested generic lambdas that fold a pack they capture" should {
      val cpg = code(
        """
          |namespace sums {
          |int sum = [](auto... values) {
          |  return [&](auto scale) {
          |    return [&](auto offset) { return (values , ...); }(1);
          |  }(2);
          |}(3);
          |}
          |int after() { return 2; }
          |""".stripMargin
      )

      "keep the variable, its initialiser as code, and the functions after it" in {
          cpg.local.nameExact("sum").size shouldBe 1
          cpg.call.nameExact(Operators.assignment).code("sum = .*").size shouldBe 1
          cpg.method.nameExact("after").size shouldBe 1
      }
  }

  "a class object called through its conversion to a pointer to function" should {
      val cpg = code(
        """
          |int twice(int v) { return v * 2; }
          |struct Caller {
          |  using Fn = int(int);
          |  operator Fn *() const { return twice; }
          |};
          |int answer = Caller{}(21);
          |""".stripMargin
      )

      "be a call through the pointer" in {
          val List(call) = cpg.call.code("Caller\\{\\}\\(21\\)").l
          call.argument.code.l should contain("21")
      }
  }
end SemanticFailureTests
