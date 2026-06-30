package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

class SuperCallTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "super().method() and super().__init__()" should {
    lazy val cpg = code(
      """
        |class Base:
        |    def __init__(self):
        |        self.x = 1
        |    def ready(self):
        |        pass
        |class Child(Base):
        |    def __init__(self):
        |        super().__init__()
        |    def run(self):
        |        super().ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve super().ready() to the base class" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.Base.ready")
    }
    "resolve super().__init__() to the base class" in {
      cpg.call.name("__init__").methodFullName.toSet should
          contain("t.py:<module>.Base.__init__")
    }
    "link run -> ready in the callgraph" in {
      cpg.method.name("ready").caller.name.toSet should contain("run")
    }
  }

  "super().method() resolving two levels up the MRO" should {
    lazy val cpg = code(
      """
        |class Base:
        |    def ready(self):
        |        pass
        |class Mid(Base):
        |    pass
        |class Child(Mid):
        |    def run(self):
        |        super().ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve super().ready() to the grandparent class via MRO" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.Base.ready")
    }
  }
}
