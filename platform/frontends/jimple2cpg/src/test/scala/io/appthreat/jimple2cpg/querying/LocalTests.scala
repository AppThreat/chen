package io.appthreat.jimple2cpg.querying

import io.appthreat.jimple2cpg.testfixtures.JimpleCode2CpgFixture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Local
import io.shiftleft.semanticcpg.language._
import org.scalatest.Ignore

class LocalTests extends JimpleCode2CpgFixture {

  val cpg: Cpg = code("""
      | @SuppressWarnings("deprecation")
      | class Foo {
      |   Integer foo() {
      |     int x;
      |     Integer y = null;
      |     x = 1;
      |     y = new Integer(x);
      |     return y;
      |   }
      | }
      |""".stripMargin).cpg

  "should contain local `y` and preserve `x` initialization semantics" in {
    val List(y: Local) = cpg.local("y").l

    val oneLiteralsInFoo = cpg.method("foo").literal.codeExact("1").l
    oneLiteralsInFoo should not be empty

    y.name shouldBe "y"
    y.code shouldBe "java.lang.Integer y"
    y.typeFullName shouldBe "java.lang.Integer"
    y.order should be > 0
  }

}
