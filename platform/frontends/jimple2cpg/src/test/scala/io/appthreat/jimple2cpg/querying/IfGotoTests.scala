package io.appthreat.jimple2cpg.querying

import io.appthreat.jimple2cpg.testfixtures.JimpleCode2CpgFixture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Unknown}
import io.shiftleft.semanticcpg.language._

class IfGotoTests extends JimpleCode2CpgFixture {

  val cpg: Cpg = code("""
      |class Foo {
      |
      |   void foo(int x, int y) {
      |     for(int i = 0; i < 10; i++) {
      |         if (x > y) {
      |             continue;
      |         }
      |         while (y++ < x) {
      |           System.out.println("foo");
      |         }
      |     }
      |
      |     int i = 0;
      |     do {
      |         i++;
      |     } while(i < 11);
      |   }
      |
      |}
      |""".stripMargin).cpg

  "should identify `goto` blocks" in {
    cpg.all.collect { case x: Unknown => x }.code.toSetMutable shouldBe Set("goto 9", "goto 5")
  }

  "should contain 4 branching nodes at conditional calls" in {
    val branchCodes = cpg.all
      .collect { case x: Call => x }
      .filter { x =>
        x.cfgOut.size > 1
      }
      .code
      .toSetMutable

    branchCodes.size shouldBe 4
    branchCodes.exists(code => code.contains("i") && code.contains("11")) shouldBe true
    branchCodes.exists(code => code.contains("i") && code.contains("10")) shouldBe true
    branchCodes.exists(code => code.contains("x") && code.contains("y")) shouldBe true
    branchCodes.exists(code => code.contains("x") && (code.contains(">=") || code.contains("<="))) shouldBe true
  }

}
