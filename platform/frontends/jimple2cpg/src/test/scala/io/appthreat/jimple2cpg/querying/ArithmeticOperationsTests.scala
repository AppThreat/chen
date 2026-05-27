package io.appthreat.jimple2cpg.querying

import io.appthreat.jimple2cpg.testfixtures.JimpleCode2CpgFixture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.{toNodeTypeStarters, _}

class ArithmeticOperationsTests extends JimpleCode2CpgFixture {

  lazy val cpg: Cpg = code("""
      | class Foo {
      |   static double main(int a, int b) {
      |     double c = a + b;
      |     double d = c - a;
      |     double e = a * b;
      |     double f = b / a;
      |     double g = c + d + e + f;
      |     return g;
      |   }
      | }
      |""".stripMargin).cpg

  private val vars = Set("c", "d", "e", "g")

  "should contain call nodes with <operation>.assignment for all variables" in {
    val assignments = cpg.assignment
      .filterNot(_.target.code.startsWith("$"))
      .filterNot(x => List("a", "b", "this").contains(x.target.code))
      .map(_.target.code)
      .l
    assignments.toSet.intersect(vars) shouldBe vars
  }

  "should contain a call node for the addition operator" in {
    cpg.call.nameExact(Operators.addition).size should be >= 1
  }

  "should contain a call node for the subtraction operator" in {
    cpg.call(Operators.subtraction).size shouldBe 1
  }

  "should contain a call node for the multiplication operator" in {
    cpg.call(Operators.multiplication).size shouldBe 1
  }

  "should contain a call node for the division operator" in {
    cpg.call(Operators.division).size shouldBe 1
  }
}
