package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.CdxPass
import io.shiftleft.semanticcpg.language.*

/** Builds a small Python project *with a `bom.json` in it*, runs `CdxPass` over the real frontend
  * output, and asserts the three things an SBOM must deliver for `atom reachables`: purls on
  * dependency nodes, the `framework` tag on framework-typed component nodes, and namespace patterns
  * that match the `methodFullName` shapes the frontend actually produces.
  *
  * The second half is what makes Task 6 (full-name normalization) safe to attempt:
  * `CdxPass.toPyModuleForm` encodes the current full-name shape (`<module>.<callee>`), and every
  * shape assertion below fails with a message naming the actual full names if that shape changes
  * without the pass changing with it.
  */
class CdxPassTests extends PySrc2CpgFixture(withOssDataflow = false):

  private val bomJson = """{
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "components": [
        {
          "type": "library",
          "name": "PyYAML",
          "purl": "pkg:pypi/pyyaml@6.0.1",
          "properties": [
            {"name": "internal:Namespaces", "value": "yaml\npyyaml"}
          ]
        },
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

  lazy val cpg = code(bomJson, "bom.json")
      .moreCode(
        """def helper(x):
        |    return x
        |""".stripMargin,
        "my.py"
      )
      .moreCode(
        """import my
        |import yaml
        |from flask import Flask
        |
        |app = Flask(__name__)
        |
        |def load_config(path):
        |    return yaml.safe_load(my.helper(path))
        |
        |def run(server: Flask) -> None:
        |    return None
        |""".stripMargin,
        "app.py"
      )
  lazy val taggedCpg =
    val c = cpg
    new CdxPass(c).createAndApply()
    c

  "CdxPass on a Python project with an SBOM" should {

      "match a purl where the frontend's method full names have the shape toPyModuleForm expects" in {
          val fullNames = taggedCpg.call.name("safe_load").methodFullName.l
          withClue(
            s"toPyModuleForm patterns no longer match the frontend's full names; " +
                s"actual safe_load methodFullNames: [${fullNames.mkString(", ")}]; " +
                s"expected the shape <module>.<callee>, e.g. yaml.safe_load"
          ) {
              fullNames should not be empty
              fullNames.foreach(_ should startWith("yaml"))
          }
      }

      "put the purl tag on the dependency's calls" in {
          taggedCpg.call.name("safe_load").tag.name.toSet should contain("pkg:pypi/pyyaml@6.0.1")
      }

      "put the framework tag on nodes of a framework-typed component" in {
          val fullNames = taggedCpg.call.name("Flask").methodFullName.l
          withClue(
            s"frontend full-name shape changed; actual Flask methodFullNames: " +
                s"[${fullNames.mkString(", ")}]; expected the shape <module>.<callee>, " +
                s"e.g. flask.Flask.__init__"
          ) {
              fullNames should not be empty
              fullNames.foreach(_ should startWith("flask"))
          }
          taggedCpg.call.name("Flask").tag.name.toSet should contain("pkg:pypi/flask@3.0.0")
          // the compType tagging reaches parameters typed as the framework type - the
          // surface `atom reachables` uses as framework source evidence
          val paramTypes = taggedCpg.parameter.name("server").typeFullName.l
          withClue(
            s"frontend type shape changed; actual server parameter typeFullNames: " +
                s"[${paramTypes.mkString(", ")}]; expected the shape <module>.<Type>, " +
                s"e.g. flask.Flask"
          ) {
              paramTypes should not be empty
              paramTypes.foreach(_ should startWith("flask"))
          }
          taggedCpg.parameter.name("server").tag.name.toSet should contain("framework")
      }

      "put the purl on every traversal a component implies, not only its calls" in {
          // Regression guard for a dedup design that split each component's tagging into a
          // "purl half" and a "generic half" and let the pypi path claim the pattern first:
          // `framework` landed, but the purl was then suppressed on parameters, types and
          // method full names - three traversals the pypi path never visits itself. Both
          // paths must apply the whole tag set for the pattern they claim.
          val serverTags = taggedCpg.parameter.name("server").tag.name.toSet
          withClue(s"tags on the flask-typed parameter: [${serverTags.mkString(", ")}]") {
              serverTags should contain("pkg:pypi/flask@3.0.0")
          }
          taggedCpg.method.fullName("flask.*").tag.name.toSet should contain(
            "pkg:pypi/flask@3.0.0"
          )
      }

      "not tag a local module whose name a purl-derived pattern could collide with" in {
          // the old name-guessing arm turned mypy into `my`, tagging app-local code
          // with pkg:pypi/mypy@1.0.0; the fallback must not do that
          taggedCpg.call.methodFullName("my.*").tag shouldBe empty
          taggedCpg.tag.name("pkg:pypi/mypy@1.0.0").l shouldBe empty
      }
  }
end CdxPassTests

/** `donePkgs` makes the first component to claim a namespace pattern the only one that tags it. The
  * rest of this file asserts that purls *land*; nothing asserted that they land *once*, so a
  * one-level dedent of `tagByLanguage` out of the `donePkgs` guard - easy to make and easy to miss
  * in Scala's significant indentation - passed the whole suite while letting every later component
  * re-tag a pattern an earlier one had already claimed.
  */
class CdxPassDedupTests extends PySrc2CpgFixture(withOssDataflow = false):

  // Two components whose namespaces both resolve to the same pattern for `yaml`.
  private val bomJson = """{
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "components": [
        {
          "type": "library",
          "name": "PyYAML",
          "purl": "pkg:pypi/pyyaml@6.0.1",
          "properties": [
            {"name": "internal:Namespaces", "value": "yaml"}
          ]
        },
        {
          "type": "framework",
          "name": "ruamel-yaml",
          "purl": "pkg:pypi/ruamel-yaml@0.18.6",
          "properties": [
            {"name": "internal:Namespaces", "value": "yaml"}
          ]
        }
      ]
    }"""

  lazy val cpg = code(bomJson, "bom.json")
      .moreCode(
        """import yaml
          |
          |def load_config(path):
          |    return yaml.safe_load(path)
          |""".stripMargin,
        "app.py"
      )

  lazy val taggedCpg =
    val c = cpg
    new CdxPass(c).createAndApply()
    c

  // The assertions target `method.fullName`, which is where `tagByLanguage` puts the
  // component's tags. The call's own `methodFullName` is tagged by the pypi path, which
  // stayed inside the guard, so asserting there would miss the regression entirely.
  private def yamlMethodTags = taggedCpg.method.fullName("yaml.*").tag.name.toSet

  "two components claiming one namespace" should {

      "let only the first component tag it" in {
          withClue(s"tags on the shared-namespace method: [${yamlMethodTags.mkString(", ")}]") {
              yamlMethodTags should contain("pkg:pypi/pyyaml@6.0.1")
              yamlMethodTags should not contain "pkg:pypi/ruamel-yaml@0.18.6"
          }
      }

      "not apply the second component's type tag either" in {
          // `tagByLanguage` also carries the component type, so the same dedent leaks
          // `framework` from the second component onto nodes the first claimed as a library.
          withClue(s"tags on the shared-namespace method: [${yamlMethodTags.mkString(", ")}]") {
              yamlMethodTags should not contain "framework"
          }
      }
  }
end CdxPassDedupTests
