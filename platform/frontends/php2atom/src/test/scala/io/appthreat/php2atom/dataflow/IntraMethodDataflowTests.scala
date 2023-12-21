package io.appthreat.php2atom.dataflow

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language._
import io.appthreat.dataflowengineoss.language._

class IntraMethodDataflowTests extends PhpCode2CpgFixture(runOssDataflow = true) {
  "flows from parameters to corresponding identifiers should be found" in {
    val cpg = code("""<?php
        |function runShell($cmd) {
        |  system($cmd);
        |}
        |""".stripMargin)

    cpg.identifier.name("cmd").reachableBy(cpg.parameter.name("cmd")).size shouldBe 1
  }

  "flows between function calls should be found" in {
    val cpg = code("""<?php
        |function Foo() {
        |  $my_input = input();
        |  sink($my_input);
        |}
        |""".stripMargin)

    val source = cpg.call("input")
    val sink   = cpg.call("sink")
    val flows  = sink.reachableByFlows(source)

    flows.size shouldBe 1
  }
}
