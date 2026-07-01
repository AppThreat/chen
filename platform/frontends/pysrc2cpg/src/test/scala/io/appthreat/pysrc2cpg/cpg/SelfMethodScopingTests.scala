package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** `self.method()` must resolve to the enclosing class's own method even when many sibling classes
  * in the same file define a method of the same name. The base recovery keys `self` on a
  * file-scoped symbol, so it used to collect one candidate per class and the linker — faced with
  * several — left the call `<unknownFullName>`. We scope `self` to the enclosing method's class.
  */
class SelfMethodScopingTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "many sibling classes defining the same method name" should {
    lazy val cpg = code(
      """
        |class A:
        |    def as_sql(self):
        |        pass
        |class B:
        |    def as_sql(self):
        |        pass
        |class C:
        |    def as_sql(self):
        |        pass
        |    def run(self):
        |        self.as_sql()
        |""".stripMargin,
      "t.py"
    )
    "resolve self.as_sql() to the enclosing class only" in {
      cpg.call.name("as_sql").where(_.argument(0).isIdentifier.nameExact("self"))
          .methodFullName.toSet shouldBe Set("t.py:<module>.C.as_sql")
    }
    "link run -> C.as_sql in the callgraph" in {
      cpg.method.fullNameExact("t.py:<module>.C.as_sql").caller.name.toSet should contain("run")
    }
  }

  "inherited method shadowed by same-named siblings" should {
    lazy val cpg = code(
      """
        |class Expression:
        |    def as_sql(self):
        |        pass
        |class Func(Expression):
        |    pass
        |class Other:
        |    def as_sql(self):
        |        pass
        |class Concat(Func):
        |    def run(self):
        |        self.as_sql()
        |""".stripMargin,
      "t.py"
    )
    "resolve self.as_sql() up Concat's own hierarchy, not a sibling's" in {
      cpg.call.name("as_sql").where(_.argument(0).isIdentifier.nameExact("self"))
          .methodFullName.toSet should contain("t.py:<module>.Expression.as_sql")
    }
    "not bind to the unrelated Other.as_sql" in {
      cpg.call.name("as_sql").where(_.argument(0).isIdentifier.nameExact("self"))
          .methodFullName.toSet should not contain "t.py:<module>.Other.as_sql"
    }
  }
}
