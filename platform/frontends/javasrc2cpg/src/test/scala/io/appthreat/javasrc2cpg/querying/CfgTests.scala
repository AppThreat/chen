package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

class CfgTests extends JavaSrcCode2CpgFixture:

  lazy val cpg = code("""
      |class Foo {
      | int foo(int x, int y) {
      |  if (y < 10)
      |    return -1;
      |  if (x < 10) {
      |   sink(x);
      |  }
      |  System.out.println("foo");
      |  return 0;
      | }
      |}
    """.stripMargin)

  "should find that sink is control dependent on condition" in {
      val controllers = cpg.call("sink").controlledBy.isCall.toSetMutable
      controllers.map(_.code) should contain("y < 10")
      controllers.map(_.code) should contain("x < 10")
  }

  "should find that first if controls `sink`" in {
      cpg.controlStructure.condition.code("y < 10").controls.isCall.name("sink").l.size shouldBe 1
  }

  "should find sink(x) does not dominate anything" in {
      cpg.call("sink").dominates.l.size shouldBe 0
  }

  "should find sink(x) is dominated by `x<10` and `y < 10`" in {
      cpg.call("sink").dominatedBy.isCall.code.toSetMutable shouldBe Set("x < 10", "y < 10")
  }

  "should find that println post dominates correct nodes" in {
      cpg.call("println").postDominates.size shouldBe 10
  }

  "should find that method does not post dominate anything" in {
      cpg.method("foo").postDominates.l.size shouldBe 0
  }

  "catch clauses" should {
      lazy val tryCpg = code("""
          |class Bar {
          | static void a() {}
          | static void b() {}
          | static void c() {}
          | static void d() {}
          | static void bar() {
          |  try {
          |   a();
          |  } catch (IllegalStateException e) {
          |   b();
          |  } catch (RuntimeException e) {
          |   c();
          |  }
          |  d();
          | }
          |}
        """.stripMargin)

      "be alternatives, each entered from the try body and none from another" in {
          def next(name: String) = tryCpg.call.nameExact(name).cfgNext.isCall.name.toSetMutable
          (next("a") should contain).allOf("b", "c")
          next("b") should not contain "c"
          next("c") should contain("d")
          next("b") should contain("d")
      }
  }
end CfgTests
