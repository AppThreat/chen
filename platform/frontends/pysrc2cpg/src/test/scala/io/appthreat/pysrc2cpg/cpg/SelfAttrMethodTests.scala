package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** `self.attr.method()` where `attr` is typed in `__init__`. The member type is recovered, but the
  * call on `self.attr` (lowered to `tmp = self.attr; tmp.method()`) used to be left unlinked
  * because an unresolvable fallback hint (`tmp.method`) sat alongside the real one. The call linker
  * now prefers candidates that resolve to a defined method.
  */
class SelfAttrMethodTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "self.attr assigned a constructor in __init__" should {
    lazy val cpg = code(
      """
        |class Config:
        |    def ready(self):
        |        pass
        |class Apps:
        |    def __init__(self):
        |        self.config = Config()
        |    def run(self):
        |        self.config.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve self.config.ready()" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.Config.ready")
    }
    "link run -> ready in the callgraph" in {
      cpg.method.name("ready").caller.name.toSet should contain("run")
    }
  }

  "self.attr assigned from a factory in __init__" should {
    lazy val cpg = code(
      """
        |class Config:
        |    @classmethod
        |    def create(cls):
        |        return cls()
        |    def ready(self):
        |        pass
        |class Apps:
        |    def __init__(self):
        |        self.config = Config.create()
        |    def run(self):
        |        self.config.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve self.config.ready() through the factory return type" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.Config.ready")
    }
  }

  "self.attr typed on a base class, used by a subclass" should {
    lazy val cpg = code(
      """
        |class Config:
        |    def ready(self):
        |        pass
        |class Base:
        |    def __init__(self):
        |        self.config = Config()
        |class App(Base):
        |    def run(self):
        |        self.config.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve self.config.ready() via the inherited member type" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.Config.ready")
    }
  }
}
