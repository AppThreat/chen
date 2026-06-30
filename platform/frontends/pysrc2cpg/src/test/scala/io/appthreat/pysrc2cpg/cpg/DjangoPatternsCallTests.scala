package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Broader call-resolution coverage over real-world Django-style patterns. Each
  * `should` block isolates one resolution pattern so failures pinpoint the exact
  * unresolved construct. These are the next robustness targets after self-call
  * resolution.
  */
class DjangoPatternsCallTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "self.attr.method() where attr type is set in __init__" should {
    lazy val cpg = code(
      """
        |class Apps:
        |    def __init__(self):
        |        self.app_configs = {}
        |    def get(self):
        |        return self.app_configs.values()
        |""".stripMargin,
      "registry.py"
    )
    // TODO(task #4): recover the type of self-attributes assigned in __init__
    // (self.app_configs = {} -> dict) so attribute-method calls resolve.
    "resolve app_configs.values() to the builtin dict method" ignore {
      val call = cpg.call.name("values").head
      call.methodFullName shouldBe "__builtin.dict.values"
    }
  }

  "a classmethod calling cls(...)" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    @classmethod
        |    def create(cls, entry):
        |        return cls(entry)
        |""".stripMargin,
      "config.py"
    )
    "type the cls parameter with the enclosing class" in {
      cpg.method.name("create").parameter.name("cls").typeFullName.head shouldBe
          "config.py:<module>.AppConfig"
    }
  }

  "super().__init__() in a subclass" should {
    lazy val cpg = code(
      """
        |class Base:
        |    def __init__(self):
        |        pass
        |class Child(Base):
        |    def __init__(self):
        |        super().__init__()
        |""".stripMargin,
      "models.py"
    )
    // TODO(task #4): resolve super() to the MRO base so super().__init__()
    // binds to Base.__init__ instead of __builtin.super.<returnValue>.__init__.
    "resolve the super().__init__() call to Base.__init__" ignore {
      val call = cpg.call.name("__init__").l
      call.map(_.methodFullName).toSet should contain("models.py:<module>.Base.__init__")
    }
  }

  "an inherited method invoked via self" should {
    lazy val cpg = code(
      """
        |class Base:
        |    def helper(self):
        |        pass
        |class Child(Base):
        |    def run(self):
        |        self.helper()
        |""".stripMargin,
      "models.py"
    )
    "resolve self.helper() to the base class method" in {
      val call = cpg.call.name("helper").head
      call.methodFullName shouldBe "models.py:<module>.Base.helper"
    }
  }

  "a module-level function call within the same module" should {
    lazy val cpg = code(
      """
        |def get_version():
        |    return "1.0"
        |def setup():
        |    get_version()
        |""".stripMargin,
      "version.py"
    )
    "resolve to the module function" in {
      val call = cpg.call.name("get_version").head
      call.methodFullName shouldBe "version.py:<module>.get_version"
    }
  }
}
