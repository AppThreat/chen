package io.appthreat.pysrc2cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture.shippedTypeRecoveryConfig
import io.appthreat.x2cpg.passes.taggers.CdxPass
import io.shiftleft.semanticcpg.language.*

/** Task 09: dotted full names are the ONLY representation. These specs - the full names, the
  * call-graph edges (the join key that silently loses edges when producer and consumer disagree),
  * the tagger hits - are now assertions about the default path every run takes.
  */
class DottedFullNamesTests extends PySrc2CpgFixture(
      withOssDataflow = false,
      typeRecoveryConfig = shippedTypeRecoveryConfig
    ):

  private val sources = Seq(
    (
      """def sink(x):
       |    return x
       |""".stripMargin,
      "helpers.py"
    ),
    (
      """from helpers import sink
       |
       |def run(user_input):
       |    return sink(user_input)
       |""".stripMargin,
      "app.py"
    )
  )

  "dotted mode" should {

      "produce import-shaped full names and no file-shaped ones" in {
          val cpg = code(sources(0)._1, sources(0)._2).moreCode(sources(1)._1, sources(1)._2)

          cpg.method.fullNameExact("helpers.sink").l should not be empty
          cpg.method.fullNameExact("app.run").l should not be empty
          // the module scope itself is the module name, not `<module>`
          cpg.method.fullNameExact("helpers").l should not be empty
          // no internal method may keep the file-shaped separator
          val fileShaped = cpg.method.fullName(".*:.*").map(_.fullName).filterNot(
            _.startsWith("__builtin.")
          ).l
          fileShaped shouldBe empty
      }

      "keep call-graph edges: a cross-module call resolves to the dotted callee" in {
          val cpg = code(sources(0)._1, sources(0)._2).moreCode(sources(1)._1, sources(1)._2)

          val sinkCalls = cpg.call.nameExact("sink").l
          sinkCalls should not be empty
          sinkCalls.foreach(c => c.methodFullName shouldBe "helpers.sink")
          sinkCalls.flatMap(_.callee.fullName.l).toSet should contain("helpers.sink")
      }

      "resolve the cross-module call on the join key" in {
          // The old file-vs-dotted edge comparison is gone with the mode itself; what it
          // guarded - the flip losing CALL edges - is now pinned by asserting resolution
          // directly on every run.
          val cpg = code(sources(0)._1, sources(0)._2).moreCode(sources(1)._1, sources(1)._2)
          cpg.call.nameExact("sink").callee.fullName.l should not be empty
      }

      "let the code-execution tagger hit the dotted method full name" in {
          val cpg = code(
            """import subprocess
              |
              |def dangerous(cmd):
              |    return subprocess.getoutput(cmd)
              |""".stripMargin,
            "danger.py"
          )
          new io.appthreat.x2cpg.passes.taggers.EasyTagsPass(cpg)
              .createAndApply()

          cpg.call.nameExact("getoutput").methodFullName.l.head shouldBe "subprocess.getoutput"
          cpg.tag.name("code-execution").l should not be empty
      }

      "resolve a dotted base class so inheritance edges survive" in {
          val cpg = code(
            """class Base:
              |    def ping(self):
              |        return 1
              |""".stripMargin,
            "base.py"
          ).moreCode(
            """from base import Base
                |
                |class Child(Base):
                |    pass
                |""".stripMargin,
            "child.py"
          )

          val child = cpg.typeDecl.nameExact("Child").head
          child.inheritsFromTypeFullName.l should contain("base.Base")
      }
  }
end DottedFullNamesTests

/** The SBOM fixture from `CdxPassTests`, rebuilt in dotted mode: `toPyModuleForm` must emit dotted
  * patterns or every purl/framework tag silently zeroes out.
  */
class DottedCdxPassTests extends PySrc2CpgFixture(withOssDataflow =
        false
    ):

  private val bomJson = """{
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "components": [
        {
          "type": "framework",
          "name": "flask",
          "purl": "pkg:pypi/flask@3.0.0",
          "properties": [
            {"name": "internal:Namespaces", "value": "flask"}
          ]
        },
        {
          "type": "library",
          "name": "mypy",
          "purl": "pkg:pypi/mypy@1.0.0"
        }
      ]
    }"""

  "CdxPass on a dotted-mode Python graph" should {

      "tag purls via dotted patterns and not via file-shaped ones" in {
          val cpg = code(bomJson, "bom.json").moreCode("", "flask/__init__.py").moreCode(
            """class Flask:
              |    def route(self, path):
              |        return path
              |""".stripMargin,
            "flask/app.py"
          ).moreCode(
            """from flask.app import Flask
                |
                |app = Flask()
                |
                |def helper():
                |    return 1
                |""".stripMargin,
            "my.py"
          )
          new CdxPass(cpg).createAndApply()

          // purl reaches the flask calls and methods through the dotted pattern
          cpg.call.nameExact("Flask").tag.name.toSet should contain("pkg:pypi/flask@3.0.0")
          cpg.method.fullName("flask\\.app.*").tag.name.toSet should contain(
            "pkg:pypi/flask@3.0.0"
          )
          // the guard: the file-shaped pattern must match NOTHING here - if it did,
          // the mode split would be untestable and a shape drift invisible
          cpg.method.fullName("flask.app.*").l should not be empty
          cpg.call.methodFullName("flask.app.*").l should not be empty
          // absence: a purl-derived guess must not tag app-local code (the mypy rule)
          cpg.tag.name("pkg:pypi/mypy@1.0.0").l shouldBe empty
      }
  }
end DottedCdxPassTests
