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

      "not leak into an unrelated method when the pattern is in a FIELD initializer" in {
          val cpg = code(
            """
            |public class P {
            |    Object o = "s";
            |    boolean flag = o instanceof String fs && fs.length() > 0;
            |
            |    void other() { int z = 1; }
            |}
            |""".stripMargin,
            "P.java"
          )

          // A field initializer has no enclosing block; the binding must land on the TYPE_DECL,
          // never on whichever method is lowered next.
          cpg.method.name("other").head.local.name("fs").l shouldBe empty
          cpg.method.name("<init>").head.local.name("fs").l shouldBe empty
          val onTypeDecl = cpg.local.name("fs").l.filter(_.astParent.isTypeDecl)
          onTypeDecl should not be empty
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

      "stay inside a record's compact constructor" in {
          val cpg = code(
            """
            |record R(int x) {
            |  R {
            |    Object o = "v";
            |    if (o instanceof String s) {
            |      use(s);
            |    }
            |  }
            |
            |  static void use(String s) {}
            |}
            |""".stripMargin,
            "R.java"
          )

          // The compact constructor's statements are lowered by astForRecordCanonicalConstructor,
          // which never drained the channel: `s` escaped the record entirely.
          val ctor = cpg.method.fullName(".*R\\.<init>.*").head
          ctor.local.name("s").l should not be empty
      }

      "stay inside an anonymous class whose field initializer binds one" in {
          val cpg = code(
            """
            |class Anon {
            |  Runnable r = new Runnable() {
            |    Object o = "v";
            |    boolean f = o instanceof String s && s.isEmpty();
            |    public void run() {}
            |  };
            |}
            |""".stripMargin,
            "Anon.java"
          )

          // A field-initializer binding belongs to no method, so it attaches to the TYPE_DECL -
          // the anonymous path used to discard it, leaving uses of `s` with no LOCAL at all.
          cpg.local.name("s").l should not be empty
          cpg.local.name("s").astParent.label.l shouldBe List("TYPE_DECL")
      }
  }
end PatternLocalOwnershipTests
