package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Languages}
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewConfigFile, NewIdentifier}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class CdxPassTests extends AnyWordSpec with Matchers:

  import CdxPassTests.Fixture

  private def componentJson(name: String, purl: String, extra: String = ""): String =
      s"""{"type": "library", "name": "$name", "purl": "$purl"$extra}"""

  "CdxPass" should {

      "tag calls by method full name from a new-format internal:Namespaces property" in
          Fixture(components =
              Seq(componentJson(
                name = "PyYAML",
                purl = "pkg:pypi/pyyaml@6.0.1",
                extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "yaml\npyyaml"}
            ]"""
              ))
          ) { cpg =>
            cpg.call.name("safe_load").tag.name.toSet should contain("pkg:pypi/pyyaml@6.0.1")
            // both namespaces the distribution provides become patterns
            cpg.call.name("pyyaml_load").tag.name.toSet should contain("pkg:pypi/pyyaml@6.0.1")
          }

      "tag identically from an old-format bare Namespaces property (prefix-insensitive)" in
          Fixture(components =
              Seq(componentJson(
                name = "PyYAML",
                purl = "pkg:pypi/pyyaml@6.0.1",
                extra = """,
            "properties": [
              {"name": "Namespaces", "value": "yaml"}
            ]"""
              ))
          ) { cpg =>
              cpg.call.name("safe_load").tag.name.toSet should contain("pkg:pypi/pyyaml@6.0.1")
          }

      "prefer internal:ImportedModules over Namespaces for the pypi pass" in
          Fixture(components =
              Seq(componentJson(
                name = "PyYAML",
                purl = "pkg:pypi/pyyaml@6.0.1",
                extra = """,
            "properties": [
              {"name": "internal:ImportedModules", "value": "yaml.safe_load,yaml.dump"},
              {"name": "internal:Namespaces", "value": "pyyaml"}
            ]"""
              ))
          ) { cpg =>
            // the imported module drives the pypi tagging pass
            cpg.call.name("safe_load").tag.name.toSet should contain("pkg:pypi/pyyaml@6.0.1")
            // the Namespaces entry is not lost: the property pass still applies it
            cpg.identifier.name("pyyamlObj").tag.name.toSet should contain("pkg:pypi/pyyaml@6.0.1")
          }

      "fall back to the purl name when no namespace property exists" in
          Fixture(components =
              Seq(componentJson(name = "yaml", purl = "pkg:pypi/yaml@1.0"))
          ) { cpg =>
              cpg.call.name("safe_load").tag.name.toSet should contain("pkg:pypi/yaml@1.0")
          }

      "not mangle module names the way the deleted .replace(\"py\", \"\") arm did" in
          Fixture(
            components = Seq(
              componentJson(name = "numpy", purl = "pkg:pypi/numpy@1.25.0"),
              componentJson(name = "scipy", purl = "pkg:pypi/scipy@1.0"),
              componentJson(name = "mypy", purl = "pkg:pypi/mypy@1.0.0"),
              componentJson(name = "cryptography", purl = "pkg:pypi/cryptography@39.0.1")
            ),
            calls = Seq("num.py:<module>.x", "sci.py:<module>.y", "my.py:<module>.z")
          ) { cpg =>
            // the old arm derived `num` from numpy, `sci` from scipy and `my` from mypy
            cpg.call.methodFullName("num.py:<module>.*").tag shouldBe empty
            cpg.call.methodFullName("sci.py:<module>.*").tag shouldBe empty
            cpg.call.methodFullName("my.py:<module>.*").tag shouldBe empty
          }

      "filter internal:SrcFile instead of treating it as a namespace, and still apply the component type" in
          Fixture(components =
              Seq(componentJson(
                name = "Django",
                purl = "pkg:pypi/django@4.2",
                extra = """,
            "type": "framework",
            "properties": [
              {"name": "internal:SrcFile", "value": "django"},
              {"name": "internal:Namespaces", "value": "django"}
            ]"""
              ))
          ) { cpg =>
            // the pypi pass claims the pattern from Namespaces and applies the purl;
            // the property pass must still apply the generic half (compType = framework)
            cpg.call.name("routing").tag.name.toSet should contain("pkg:pypi/django@4.2")
            cpg.call.name("routing").tag.name.toSet should contain("framework")
            // the manifest path must not become a namespace pattern
            cpg.tag.name.l.filter(_.contains("requirements")) shouldBe empty
          }

      "not tag anything from properties that are not namespace lists" in
          Fixture(components =
              Seq(componentJson(
                name = "requests",
                purl = "pkg:pypi/requests@2.28.2",
                extra = """,
            "properties": [
              {"name": "internal:SrcFile", "value": "requirements.txt"},
              {"name": "cdx:pypi:classifiers", "value": "Topic :: Internet :: WWW/HTTP"},
              {"name": "internal:ResolvedUrl", "value": "https://pypi.org/simple/"},
              {"name": "cdx:pypi:artifactDigestSha256", "value": "abc123"}
            ]"""
              ))
          ) { cpg =>
              cpg.tag.name.l shouldBe empty
          }

      "derive the same description fallback tags as cdxgen's extractTags" in
          Fixture(components =
              Seq(
                componentJson(
                  name = "PyYAML",
                  purl = "pkg:pypi/pyyaml@6.0.1",
                  extra = """,
              "description": "The Werkzeug WSGI HTTP Utility Library for Python",
              "properties": [
                {"name": "internal:Namespaces", "value": "yaml\npyyaml"}
              ]"""
                ),
                componentJson(
                  name = "authlib",
                  purl = "pkg:pypi/authlib@1.2.0",
                  extra = """,
              "description": "A robust authentication and authorization library",
              "properties": [
                {"name": "internal:Namespaces", "value": "authlib"}
              ]"""
                )
              )
          ) { cpg =>
            // no `tags` array: CdxPass re-derives from the description with the
            // vendored vocabulary, and must produce cdxgen's sorted output
            cpg.identifier.name("pyyamlObj").tag.name.toSet should contain("http")
            cpg.identifier.name("pyyamlObj").tag.name.toSet should contain("wsgi")
            // leading-boundary near-miss: chen's old rule produced `auth` for any
            // description containing " authentication"; the vendored rule must not
            cpg.tag.name("auth").l shouldBe empty
          }
  }
end CdxPassTests

object CdxPassTests:

  private object Fixture:
    def apply[T](
      components: Seq[String],
      calls: Seq[String] = Seq.empty
    )(fun: Cpg => T): T =
      val bom =
          s"""{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [${components.mkString(",")}]
          }"""
      val cpg = MockCpg().withMetaData(Languages.PYTHONSRC, Nil).withCustom { (graph, _) =>
        graph.addNode(NewConfigFile().name("bom.json").content(bom))
        // a call shape that toPyModuleForm patterns match: <module>.py:<module>.<name>
        calls.foreach { mfn =>
            graph.addNode(
              NewCall().name(mfn.split("\\.").last).methodFullName(mfn).code(mfn.split("\\.").last)
            )
        }
        // a fixed dependency call and identifier, present in every test
        graph.addNode(
          NewCall().name("safe_load").methodFullName("yaml.py:<module>.safe_load").code("safe_load")
        )
        graph.addNode(
          NewCall().name("pyyaml_load").methodFullName("pyyaml.py:<module>.load").code(
            "pyyaml_load"
          )
        )
        graph.addNode(
          NewCall().name("routing")
              .methodFullName("django.py:<module>.urls")
              .typeFullName("django.py:<module>")
              .code("routing")
        )
        graph.addNode(
          NewIdentifier().name("pyyamlObj").typeFullName("pyyaml.py:<module>").code("pyyamlObj")
        )
        graph.addNode(
          NewIdentifier().name("djangoConf").typeFullName("django.py:<module>").code("djangoConf")
        )
      }.cpg
      new CdxPass(cpg).createAndApply()
      fun(cpg)
    end apply
  end Fixture
end CdxPassTests
