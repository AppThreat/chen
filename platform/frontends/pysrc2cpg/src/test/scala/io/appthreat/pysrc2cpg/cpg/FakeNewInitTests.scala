package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** The synthetic `<fakeNew>` constructor handler emits `cls.__init__(__newInstance)`. Typing the
  * `cls` parameter with the instance type lets that call resolve to `<class>.__init__`, linking
  * every constructor site to __init__ in the callgraph (instead of leaving an `<unknownFullName>`).
  */
class FakeNewInitTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "a class with an __init__" should {
    lazy val cpg = code(
      """
        |class Greeter:
        |    def __init__(self, name):
        |        self.name = name
        |def make():
        |    return Greeter("x")
        |""".stripMargin,
      "t.py"
    )
    "resolve the synthetic cls.__init__ call to the class __init__" in {
      cpg.call.name("__init__").code("cls.__init__.*").methodFullName.toSet should
          contain("t.py:<module>.Greeter.__init__")
    }
  }

  "a subclass constructed without its own __init__" should {
    lazy val cpg = code(
      """
        |class Base:
        |    def __init__(self):
        |        self.x = 1
        |class Child(Base):
        |    pass
        |def make():
        |    return Child()
        |""".stripMargin,
      "t.py"
    )
    // The inherited __init__ resolution would need MRO on the synthetic call; Child has no
    // __init__ method node of its own, so this remains a documented frontier gap.
    "resolve the inherited __init__ via the base class" ignore {
      cpg.call.name("__init__").code("cls.__init__.*").methodFullName.toSet should
          contain("t.py:<module>.Base.__init__")
    }
  }
}
