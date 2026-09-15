package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Pattern-binding LOCAL ownership: a binding's LOCAL must be a direct child of the BLOCK that
  * lexically contains the pattern, however the pattern is nested.
  *
  * Regression guard for the scope-channel design: the channel is a flat buffer drained by body
  * builders, so a lambda built AFTER a pattern binding in the same method used to steal the
  * enclosing method's local (its drain ran first), and constructor/lambda-block bodies never
  * drained at all - their locals leaked to whatever block drained next.
  */
class PatternLocalOwnershipTests extends JavaSrcCode2CpgFixture:

  "pattern binding locals" should {

      "stay owned by the method when a lambda is declared later in the body" in {
          val cpg = code(
            """
            |class Steal {
            |  void m(Object o) {
            |    if (o instanceof String s) {
            |      use(s);
            |    }
            |    Runnable r = () -> use("y");
            |  }
            |
            |  void use(String s) {}
            |}
            |""".stripMargin,
            "Steal.java"
          )

          // Before the per-block drain, the lambda's body builder drained the channel first
          // and stole `s`: m.local was EMPTY and the binding lived under the lambda.
          val m = cpg.method.name("m").head
          m.local.name("s").l should not be empty
          // NB: the lambda method still lists `s` - javasrc2cpg models a lambda as capturing a
          // copy of every in-scope local (a plain `int x` declared before the lambda appears
          // there too). That is the closure model, not the channel; ownership is about `m`.
      }

      "be owned by the constructor block that contains the pattern" in {
          val cpg = code(
            """
            |class Owned {
            |  Owned(Object o) {
            |    if (o instanceof String s) {
            |      use(s);
            |    }
            |  }
            |
            |  void use(String s) {}
            |}
            |""".stripMargin,
            "Owned.java"
          )

          val ctor = cpg.method.name("<init>").head
          ctor.local.name("s").l should not be empty
      }

      "be owned by a lambda's block body, not the enclosing method" in {
          val cpg = code(
            """
            |class Nested {
            |  void m(Object o) {
            |    Runnable r = () -> {
            |      if (o instanceof String t) {
            |        use(t);
            |      }
            |    };
            |  }
            |
            |  void use(String s) {}
            |}
            |""".stripMargin,
            "Nested.java"
          )

          val lambda = cpg.method.name(".*lambda.*").head
          lambda.local.name("t").l should not be empty
          cpg.method.name("m").head.local.name("t").l shouldBe empty
      }
  }
end PatternLocalOwnershipTests
