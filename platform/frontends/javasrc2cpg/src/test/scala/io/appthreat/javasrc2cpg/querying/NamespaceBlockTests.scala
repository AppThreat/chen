package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.shiftleft.semanticcpg.language._

class NamespaceBlockTests extends JavaSrcCode2CpgFixture {

  val cpg = code("""
      |package foo.bar;
      |class A {
      | void foo() {}
      |}
      |""".stripMargin)

  "should contain two namespace blocks in total (<default>, foo.bar)" in {
    cpg.namespaceBlock.size shouldBe 2
  }

  "should contain correct namespace block for known file" in {
    val List(x) = cpg.namespaceBlock.filename(".*.java").l
    x.name shouldBe "foo.bar"
    x.filename should not be ""
    x.fullName should endWith(":foo.bar")
    x.order shouldBe 1
  }

  "should allow traversing from namespace block to method" in {
    cpg.namespaceBlock.filename(".*java").typeDecl.method.name.toSetMutable shouldBe Set(
      "foo",
      io.appthreat.x2cpg.Defines.ConstructorMethodName
    )
  }

  "should allow traversing from namespace block to type declaration" in {
    cpg.namespaceBlock.filename(".*java").typeDecl.name.l shouldBe List("A")
  }

  "should allow traversing from namespace block to namespace" in {
    cpg.namespaceBlock.filename(".*java").namespace.name.l shouldBe List("foo.bar")
  }

}
