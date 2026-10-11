package io.appthreat.jssrc2cpg.dataflow

import io.appthreat.dataflowengineoss.language.*
import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}

/** Rest parameters collect the extra arguments, and a spread argument can supply every parameter
  * from its position on (see ArgumentBinding).
  */
class ArgumentBindingTests extends DataFlowCodeToCpgSuite:

  private given ICallResolver = NoResolve

  "a rest parameter" should {
      val cpg = code("""
          |const cp = require("child_process");
          |function run(first, ...rest) {
          |  cp.exec(rest.join(" "));
          |}
          |function handle(source) {
          |  run("ls", source);
          |  run("ls", "-l", source);
          |}
          |""".stripMargin)

      "be variadic" in {
          cpg.parameter.nameExact("rest").isVariadic.l shouldBe List(true)
      }

      "collect the first and the later extra arguments" in {
          cpg.call.nameExact("run").l.map(
            _.argument.argumentIndexGt(0).l.map(_.parameter.name.l)
          ) shouldBe List(
            List(List("first"), List("rest")),
            List(List("first"), List("rest"), List("rest"))
          )
          def source = cpg.parameter.nameExact("source")
          cpg.call.nameExact("exec").argument(1).reachableByFlows(source).size should be >= 1
      }
  }

  "a spread argument" should {
      val cpg = code("""
          |const cp = require("child_process");
          |function pair(a, b) {
          |  cp.exec(b);
          |}
          |function handle(source) {
          |  const xs = ["ls", source];
          |  pair(...xs);
          |}
          |""".stripMargin)

      "supply the parameters from its position on" in {
          cpg.call.nameExact("pair").argument.argumentIndexGt(0).parameter.name.l shouldBe
              List("a", "b")
          def source = cpg.parameter.nameExact("source")
          cpg.call.nameExact("exec").argument(1).reachableByFlows(source).size should be >= 1
      }
  }
end ArgumentBindingTests
