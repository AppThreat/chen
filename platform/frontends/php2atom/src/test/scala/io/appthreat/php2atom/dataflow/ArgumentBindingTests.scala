package io.appthreat.php2atom.dataflow

import io.appthreat.dataflowengineoss.language.*
import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** PHP 8 named and unpacked arguments: `f(cmd: $x)` binds the parameter `$cmd` wherever it is,
  * `...$args` collects the extra positionals and the names no parameter has, and `f(...$xs)` can
  * supply every parameter from its position on.
  */
class ArgumentBindingTests extends PhpCode2CpgFixture(runOssDataflow = true):

  "named arguments" should {
      val cpg = code("""<?php
          |function run($cmd, $shell = false) {
          |  system($cmd);
          |  echo $shell;
          |}
          |function handle($source) {
          |  run(shell: true, cmd: $source);
          |}
          |""".stripMargin)

      "be named after the parameter they bind, keeping their position" in {
          val args = cpg.call.nameExact("run").argument.l
          args.map(a => (a.argumentIndex, a.argumentName)) shouldBe List(
            (1, Some("shell")),
            (2, Some("cmd"))
          )
          cpg.call.nameExact("run").code.l shouldBe List("run(shell: true,cmd: $source)")
      }

      "bind by name, not by position" in {
          def source = cpg.parameter.nameExact("source")
          cpg.call.nameExact("system").argument(1).reachableByFlows(source).size should be >= 1
          cpg.call.nameExact("echo").argument(1).reachableByFlows(source).size shouldBe 0
          cpg.call.nameExact("run").argument.argumentNameExact("cmd").parameter.name.l shouldBe
              List("cmd")
      }
  }

  "variadic parameters" should {
      val cpg = code("""<?php
          |function log_all($first, ...$rest) {
          |  system($rest);
          |}
          |function handle($source) {
          |  log_all(1, 2, $source);
          |  log_all(1, extra: $source);
          |}
          |""".stripMargin)

      "be written with their ..." in {
          cpg.parameter.nameExact("rest").code.l shouldBe List("...$rest")
          cpg.parameter.nameExact("rest").isVariadic.l shouldBe List(true)
      }

      "collect the extra positionals and the unknown names" in {
          val calls = cpg.call.nameExact("log_all").l
          calls.map(_.argument.l.last.parameter.name.l) shouldBe List(List("rest"), List("rest"))
          def source = cpg.parameter.nameExact("source")
          cpg.call.nameExact("system").argument(1).reachableByFlows(source).size should be >= 1
      }
  }

  "unpacked arguments" should {
      val cpg = code("""<?php
          |function pair($a, $b) {
          |  system($b);
          |}
          |function handle($source) {
          |  $xs = [1, $source];
          |  pair(...$xs);
          |}
          |""".stripMargin)

      "be an <operator>.unpack of the iterable" in {
          val unpack = cpg.call.nameExact("pair").argument.isCall.l
          unpack.name.l shouldBe List("<operator>.unpack")
          unpack.code.l shouldBe List("...$xs")
          cpg.call.nameExact("pair").code.l shouldBe List("pair(...$xs)")
          unpack.parameter.name.l shouldBe List("a", "b")
      }

      "supply the parameters from their position on" in {
          def source = cpg.parameter.nameExact("source")
          cpg.call.nameExact("system").argument(1).reachableByFlows(source).size should be >= 1
      }
  }
end ArgumentBindingTests
