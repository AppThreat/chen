package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

class SelfCallResolutionTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "an instance method calling a sibling via self" should {
    lazy val cpg = code(
      """
        |class Foo:
        |    def run(self):
        |        self.helper()
        |
        |    def helper(self):
        |        pass
        |""".stripMargin,
      "foo.py"
    )

    "type the implicit self parameter with the enclosing class" in {
      val self = cpg.method.name("run").parameter.name("self").head
      self.typeFullName shouldBe "foo.py:<module>.Foo"
    }

    "resolve the self.helper() call's methodFullName to the class method" in {
      val call = cpg.call.name("helper").head
      call.methodFullName shouldBe "foo.py:<module>.Foo.helper"
    }

    "produce a callgraph edge: helper has run as a caller" in {
      cpg.method.name("helper").caller.name.toSet should contain("run")
    }

    "produce a callgraph edge: run's callee includes helper" in {
      cpg.method.name("run").call.callee.fullName.toSet should
          contain("foo.py:<module>.Foo.helper")
    }
  }

  "a static method" should {
    lazy val cpg = code(
      """
        |class Bar:
        |    @staticmethod
        |    def s(x):
        |        return x
        |""".stripMargin,
      "bar.py"
    )

    "not have its first parameter typed as the class (no implicit receiver)" in {
      val x = cpg.method.name("s").parameter.name("x").head
      x.typeFullName should not be "bar.py:<module>.Bar"
    }
  }

  "an explicit self annotation" should {
    lazy val cpg = code(
      """
        |class Baz:
        |    def m(self: "Other"):
        |        pass
        |""".stripMargin,
      "baz.py"
    )

    "not be overwritten by the enclosing class" in {
      val self = cpg.method.name("m").parameter.name("self").head
      self.typeFullName should not be "baz.py:<module>.Baz"
    }
  }
}
