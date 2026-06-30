package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Triage of receiver type-recovery for local variables and temporaries — the dominant
  * source of `<unknownFullName>` in the django atom (e.g. `app_config.import_models()`,
  * for-loop temporaries, chained calls). Each block isolates one pattern.
  */
class ReceiverTypeRecoveryTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "a local assigned from a constructor" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def ready(self):
        |        pass
        |def f():
        |    app_config = AppConfig()
        |    app_config.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve app_config.ready() to AppConfig.ready" in {
      cpg.call.name("ready").head.methodFullName shouldBe "t.py:<module>.AppConfig.ready"
    }
  }

  "a local assigned from a classmethod factory returning cls(...)" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    @classmethod
        |    def create(cls, entry):
        |        return cls(entry)
        |    def ready(self):
        |        pass
        |def f(entry):
        |    app_config = AppConfig.create(entry)
        |    app_config.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve app_config.ready() to AppConfig.ready" in {
      cpg.call.name("ready").head.methodFullName shouldBe "t.py:<module>.AppConfig.ready"
    }
  }

  "a string local" should {
    lazy val cpg = code(
      """
        |def f():
        |    s = "hello"
        |    s.upper()
        |""".stripMargin,
      "t.py"
    )
    "resolve s.upper() to the builtin str method" in {
      cpg.call.name("upper").head.methodFullName shouldBe "__builtin.str.upper"
    }
  }

  "a for-loop variable over a typed list" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def ready(self):
        |        pass
        |def f(configs: list[AppConfig]):
        |    for c in configs:
        |        c.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve c.ready() when the element type is known" in {
      cpg.call.name("ready").head.methodFullName shouldBe "t.py:<module>.AppConfig.ready"
    }
  }

  "a for-loop variable over an untyped collection" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def ready(self):
        |        pass
        |def f(configs):
        |    for c in configs:
        |        c.ready()
        |""".stripMargin,
      "t.py"
    )
    // Genuinely unrecoverable: `configs` carries no element type. Documented so the
    // boundary of for-loop element typing stays explicit.
    "leave c.ready() unresolved" ignore {
      cpg.call.name("ready").head.methodFullName shouldBe "t.py:<module>.AppConfig.ready"
    }
  }
}
