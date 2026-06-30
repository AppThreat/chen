package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** For-loop element typing: `for x in coll` lowers to
  * `tmp = coll.__iter__(); x = tmp.__next__()`, so the loop variable's type must be recovered by
  * unwrapping the iterated collection's generic element type.
  */
class ForLoopElementTypingTests extends PySrc2CpgFixture(withOssDataflow = false) {

  "iterating a builtin-generic list parameter" should {
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
    "resolve c.ready() to the element method" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.AppConfig.ready")
    }
    "link the call into the callgraph" in {
      cpg.method.name("ready").caller.name.toSet should contain("f")
    }
  }

  "iterating a typing.List parameter" should {
    lazy val cpg = code(
      """
        |from typing import List
        |class AppConfig:
        |    def ready(self):
        |        pass
        |def f(configs: List[AppConfig]):
        |    for c in configs:
        |        c.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve c.ready() to the element method" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.AppConfig.ready")
    }
  }

  "iterating a set parameter" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def ready(self):
        |        pass
        |def f(configs: set[AppConfig]):
        |    for c in configs:
        |        c.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve c.ready() to the element method" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.AppConfig.ready")
    }
  }

  "iterating a dict parameter yields keys" should {
    lazy val cpg = code(
      """
        |class AppLabel:
        |    def upper(self):
        |        pass
        |class AppConfig:
        |    pass
        |def f(configs: dict[AppLabel, AppConfig]):
        |    for label in configs:
        |        label.upper()
        |""".stripMargin,
      "t.py"
    )
    "resolve the loop var to the key type" in {
      cpg.call.name("upper").methodFullName.toSet should
          contain("t.py:<module>.AppLabel.upper")
    }
  }

  "iterating a tuple parameter" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def ready(self):
        |        pass
        |def f(configs: tuple[AppConfig, AppConfig]):
        |    for c in configs:
        |        c.ready()
        |""".stripMargin,
      "t.py"
    )
    "resolve c.ready() to the element method" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("t.py:<module>.AppConfig.ready")
    }
  }
}
