package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Regression: the type-hint call linker must not drop user methods whose name merely starts with
  * "import" (e.g. `import_models`, `import_module` — pervasive in Django). Only the synthetic
  * `import(...)` pseudo-call should be excluded.
  */
class ImportPrefixMethodTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "a method named import_models on a constructed instance" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def import_models(self):
        |        pass
        |def f():
        |    cfg = AppConfig()
        |    cfg.import_models()
        |""".stripMargin,
      "t.py"
    )
    "be linked in the callgraph" in {
      cpg.call.name("import_models").methodFullName.toSet should
          contain("t.py:<module>.AppConfig.import_models")
      cpg.method.name("import_models").caller.name.toSet should contain("f")
    }
  }

  "the synthetic import pseudo-call is still excluded" should {
    lazy val cpg = code(
      """
        |import os
        |""".stripMargin,
      "t.py"
    )
    "not be linked to a user method" in {
      cpg.call.name("import").methodFullName.toSet.foreach { mfn =>
        mfn should not startWith "t.py:"
      }
    }
  }
}
