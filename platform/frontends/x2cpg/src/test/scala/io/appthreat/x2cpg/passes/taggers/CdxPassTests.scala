package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Languages}
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewConfigFile, NewIdentifier}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class CdxPassTests extends AnyWordSpec with Matchers:

  import CdxPassTests.{Fixture, JvmFixture, RubyFixture}

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
            // namespaced, so it cannot collide with the `framework` source tag the
            // reachables queries match
            cpg.call.name("routing").tag.name.toSet should contain("comp-type:framework")
            cpg.tag.name("framework").l shouldBe empty
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
            // vendored vocabulary, and must produce cdxgen's sorted output -
            // namespaced with comp-desc:, since `http` and `wsgi` are sink/source
            // tag names the reachables queries match
            cpg.identifier.name("pyyamlObj").tag.name.toSet should contain("comp-desc:http")
            cpg.identifier.name("pyyamlObj").tag.name.toSet should contain("comp-desc:wsgi")
            cpg.tag.name("http").l shouldBe empty
            // leading-boundary near-miss: chen's old rule produced `auth` for any
            // description containing " authentication"; the vendored rule must not
            cpg.tag.name("auth").l shouldBe empty
          }

      "tag every version of a package that claims a namespace, whichever comes first" in
          Fixture(components =
              Seq(
                componentJson(
                  name = "django",
                  purl = "pkg:pypi/django@5.2.17",
                  extra = """,
            "type": "library" """
                ),
                componentJson(
                  name = "django",
                  purl = "pkg:pypi/django@6.1.2",
                  extra = """,
            "type": "framework",
            "tags": ["django", "framework", "http"],
            "properties": [
              {"name": "internal:Namespaces", "value": "django"}
            ]"""
                )
              )
          ) { cpg =>
            // both versions' exact purls land, so cdxgen can attach evidence to
            // each component; the enriched second version's type and description
            // tags stay namespaced
            val routingTags = cpg.call.name("routing").tag.name.toSet
            routingTags should contain("pkg:pypi/django@5.2.17")
            routingTags should contain("pkg:pypi/django@6.1.2")
            routingTags should contain("comp-type:framework")
            routingTags should contain("comp-desc:django")
            cpg.tag.name("framework").l shouldBe empty
            cpg.tag.name("http").l shouldBe empty
          }

      "let the component order decide neither purls nor tags" in
          Fixture(components =
              Seq(
                componentJson(
                  name = "django",
                  purl = "pkg:pypi/django@6.1.2",
                  extra = """,
            "type": "framework",
            "tags": ["django", "framework", "http"],
            "properties": [
              {"name": "internal:Namespaces", "value": "django"}
            ]"""
                ),
                componentJson(
                  name = "django",
                  purl = "pkg:pypi/django@5.2.17",
                  extra = """,
            "type": "library" """
                )
              )
          ) { cpg =>
            val routingTags = cpg.call.name("routing").tag.name.toSet
            routingTags should contain("pkg:pypi/django@5.2.17")
            routingTags should contain("pkg:pypi/django@6.1.2")
            routingTags should contain("comp-type:framework")
          }
      "tag a JVM component from its purl when the SBOM declares no namespaces" in
          JvmFixture(components =
              Seq(componentJson(
                name = "h2",
                purl = "pkg:maven/com.h2database/h2@2.2.224"
              ))
          ) { cpg =>
              cpg.call.name("connect").tag.name.toSet should contain(
                "pkg:maven/com.h2database/h2@2.2.224"
              )
          }

      "prefer the declared namespaces over the purl when both are available" in
          JvmFixture(components =
              Seq(componentJson(
                name = "h2",
                purl = "pkg:maven/com.h2database/h2@2.2.224",
                extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "org.h2.jdbc"}
            ]"""
              ))
          ) { cpg =>
            // The namespace the component declares is tagged...
            cpg.call.name("execute").tag.name.toSet should contain(
              "pkg:maven/com.h2database/h2@2.2.224"
            )
            // ...and the group id is not also claimed on its behalf.
            cpg.call.name("connect").tag.name.toSet shouldBe empty
          }

      "not attribute a group id that several components share" in
          JvmFixture(components =
              Seq(
                componentJson(
                  name = "spring-web",
                  purl = "pkg:maven/org.springframework/spring-web@6.1.0"
                ),
                componentJson(
                  name = "spring-beans",
                  purl = "pkg:maven/org.springframework/spring-beans@6.1.0"
                )
              )
          ) { cpg =>
              cpg.call.name("getBean").tag.name.toSet shouldBe empty
          }

      "not let a same-named component of another group into a claimed namespace" in
          JvmFixture(
            components =
                Seq(
                  componentJson(
                    name = "utils",
                    purl = "pkg:maven/org.a/utils@1.0.0",
                    extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "org.shared"}
            ]"""
                  ),
                  componentJson(
                    name = "utils",
                    purl = "pkg:maven/org.b/utils@2.0.0",
                    extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "org.shared"}
            ]"""
                  )
                ),
            calls = Seq(("load", "org.shared.Callee", "load"))
          ) { cpg =>
            // both purls end in `utils`; the bare-name comparison read them as one
            // package and let the second group tag the namespace the first claimed
            val tags = cpg.call.name("load").tag.name.toSet
            tags should contain("pkg:maven/org.a/utils@1.0.0")
            tags should not.contain("pkg:maven/org.b/utils@2.0.0")
          }

      "claim a namespace for every version and qualifier of one package" in
          JvmFixture(
            components =
                Seq(
                  componentJson(
                    name = "utils",
                    purl = "pkg:maven/org.a/utils@1.0.0?type=jar",
                    extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "org.a"}
            ]"""
                  ),
                  componentJson(
                    name = "utils",
                    purl = "pkg:maven/org.a/utils@2.0.0?type=aar",
                    extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "org.a"}
            ]"""
                  )
                ),
            calls = Seq(("load", "org.a.Callee", "load"))
          ) { cpg =>
            val tags = cpg.call.name("load").tag.name.toSet
            tags should contain("pkg:maven/org.a/utils@1.0.0?type=jar")
            tags should contain("pkg:maven/org.a/utils@2.0.0?type=aar")
          }

      "claim a namespace for a versionless purl that carries qualifiers" in
          JvmFixture(
            components =
                Seq(
                  componentJson(
                    name = "utils",
                    purl = "pkg:maven/org.a/utils?type=jar",
                    extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "org.a"}
            ]"""
                  ),
                  componentJson(
                    name = "utils",
                    purl = "pkg:maven/org.a/utils@2.0.0",
                    extra = """,
            "properties": [
              {"name": "internal:Namespaces", "value": "org.a"}
            ]"""
                  )
                ),
            calls = Seq(("load", "org.a.Callee", "load"))
          ) { cpg =>
            val tags = cpg.call.name("load").tag.name.toSet
            tags should contain("pkg:maven/org.a/utils?type=jar")
            tags should contain("pkg:maven/org.a/utils@2.0.0")
          }

      "tag a Ruby component from its gem purl when the SBOM declares no namespaces" in
          RubyFixture(components =
              Seq(
                componentJson(name = "bcrypt", purl = "pkg:gem/bcrypt@3.1.22"),
                componentJson(name = "json", purl = "pkg:gem/json@2.18.0"),
                componentJson(name = "parser", purl = "pkg:gem/parser@1.8.1")
              )
          )(
            Seq(
              "BCrypt::Password.create(secret)" -> "secret",
              "JSON.parse(text)"                -> "text",
              "format.json { render body }"     -> "body",
              "SearchParser.new.parse(params)"  -> "params"
            )
          ) { cpg =>
            cpg.identifier.name("secret").tag.name.toSet should contain(
              "pkg:gem/bcrypt@3.1.22"
            )
            // only the constant's first letter is case-sensitive, which is what
            // keeps the BCrypt and JSON gems matchable
            cpg.identifier.name("text").tag.name.toSet should contain(
              "pkg:gem/json@2.18.0"
            )
            // Rails' responder label is not the json gem: a Ruby constant must
            // start uppercase
            cpg.identifier.name("body").tag.name.toSet shouldBe empty
            // a constant the gem name is merely embedded in is not the gem
            cpg.identifier.name("params").tag.name.toSet shouldBe empty
            cpg.tag.name("pkg:gem/parser@1.8.1").l shouldBe empty
          }

      "reject the lobsters false families the case rule removed" in
          RubyFixture(components =
              Seq(
                componentJson(name = "mail", purl = "pkg:gem/mail@2.8.1"),
                componentJson(name = "oauth", purl = "pkg:gem/oauth@1.1.1")
              )
          )(
            Seq(
              "logger.debug(\"mod mail delivered\")" -> "notice",
              "session[\"/oauth/token\"]"            -> "token"
            )
          ) { cpg =>
            // a `mod mail` string literal is not the mail gem, a `/oauth/token`
            // URL is not the oauth gem: a Ruby constant must start uppercase
            cpg.identifier.name("notice").tag.name.toSet shouldBe empty
            cpg.identifier.name("token").tag.name.toSet shouldBe empty
          }

      "nest a hyphenated gem's name into a constant path" in
          RubyFixture(components =
              Seq(
                componentJson(name = "rack-attack", purl = "pkg:gem/rack-attack@6.7.0"),
                componentJson(name = "pdf-reader", purl = "pkg:gem/pdf-reader@2.5.0")
              )
          )(
            Seq(
              "Rack::Attack.throttle(req)"        -> "req",
              "Rack::Utils.escape(html)"          -> "html",
              "PDF::Reader.new(pdf_stream).pages" -> "pages"
            )
          ) { cpg =>
            // `rack-attack` nests as `Rack::Attack`: the gem name's `-` segments
            // are the `::` chain of the constant
            cpg.identifier.name("req").tag.name.toSet should contain(
              "pkg:gem/rack-attack@6.7.0"
            )
            // Rack::Utils is rack's own namespace, not rack-attack's
            cpg.identifier.name("html").tag.name.toSet shouldBe empty
            cpg.identifier.name("pages").tag.name.toSet should contain(
              "pkg:gem/pdf-reader@2.5.0"
            )
          }

      "camelize underscore words within one constant segment" in
          RubyFixture(components =
              Seq(
                componentJson(
                  name = "unicode-display_width",
                  purl = "pkg:gem/unicode-display_width@1.2.0"
                ),
                componentJson(
                  name = "active_support",
                  purl = "pkg:gem/active_support@8.0.0"
                )
              )
          )(
            Seq(
              "Unicode::DisplayWidth.of(str)"                 -> "str",
              "ActiveSupport::Notifications.subscribe(event)" -> "payload"
            )
          ) { cpg =>
            // `_` joins the words of one segment; only `-` nests
            cpg.identifier.name("str").tag.name.toSet should contain(
              "pkg:gem/unicode-display_width@1.2.0"
            )
            cpg.identifier.name("payload").tag.name.toSet should contain(
              "pkg:gem/active_support@8.0.0"
            )
          }

      "give a parent gem only the calls its child gems do not claim" in
          RubyFixture(components =
              Seq(
                componentJson(name = "rack", purl = "pkg:gem/rack@3.2.7"),
                componentJson(name = "rack-attack", purl = "pkg:gem/rack-attack@6.7.0")
              )
          )(
            Seq(
              "Rack::Attack.throttle(req)" -> "req",
              "Rack::Utils.escape(html)"   -> "html"
            )
          ) { cpg =>
            // the child's constant path shadows the parent's `::.*` suffix:
            // Rack::Attack.throttle belongs to rack-attack alone
            cpg.identifier.name("req").tag.name.toSet should contain(
              "pkg:gem/rack-attack@6.7.0"
            )
            cpg.identifier.name("req").tag.name.toSet should not.contain(
              "pkg:gem/rack@3.2.7"
            )
            // calls the child does not match stay with the parent
            cpg.identifier.name("html").tag.name.toSet should contain(
              "pkg:gem/rack@3.2.7"
            )
          }

      "leave a parent gem the calls of a child that is not in the SBOM" in
          RubyFixture(components =
              Seq(componentJson(name = "rack", purl = "pkg:gem/rack@3.2.7"))
          )(
            Seq(
              "Rack::Attack.throttle(req)" -> "req",
              "Rack::Utils.escape(html)"   -> "html"
            )
          ) { cpg =>
            // without rack-attack in the BOM nothing shadows the parent
            cpg.identifier.name("req").tag.name.toSet should contain(
              "pkg:gem/rack@3.2.7"
            )
            cpg.identifier.name("html").tag.name.toSet should contain(
              "pkg:gem/rack@3.2.7"
            )
          }

      "drop a trailing -ruby segment the code does not reference" in
          RubyFixture(components =
              Seq(
                componentJson(name = "sentry-ruby", purl = "pkg:gem/sentry-ruby@5.28.0"),
                componentJson(name = "concurrent-ruby", purl = "pkg:gem/concurrent-ruby@1.3.8")
              )
          )(
            Seq(
              "Sentry.capture_message(msg)"       -> "msg",
              "Concurrent::Promise.execute(task)" -> "task"
            )
          ) { cpg =>
            // sentry-ruby defines Sentry, concurrent-ruby defines Concurrent:
            // a trailing -ruby names no constant the code writes
            cpg.identifier.name("msg").tag.name.toSet should contain(
              "pkg:gem/sentry-ruby@5.28.0"
            )
            cpg.identifier.name("task").tag.name.toSet should contain(
              "pkg:gem/concurrent-ruby@1.3.8"
            )
          }

      "give Ruby the component type under its namespaced tag only" in
          RubyFixture(components =
              Seq(componentJson(
                name = "rails",
                purl = "pkg:gem/rails@8.1.3.1",
                extra = """,
            "type": "framework",
            "tags": ["framework"]"""
              ))
          )(
            Seq("Rails.application.name" -> "name")
          ) { cpg =>
            cpg.identifier.name("name").tag.name.toSet should contain(
              "pkg:gem/rails@8.1.3.1"
            )
            // framework-as-source: the component type and its description words
            // must not become source tags, on Ruby just as on the generic path
            cpg.tag.name("framework-input").l shouldBe empty
            cpg.tag.name("framework").l shouldBe empty
          }
  }
end CdxPassTests

object CdxPassTests:

  /** A Ruby graph whose calls carry the code snippets the gem patterns key off, each with one
    * identifier argument the purl tags land on.
    */
  private object RubyFixture:
    def apply[T](components: Seq[String])(calls: Seq[(String, String)])(fun: Cpg => T): T =
      val bom =
          s"""{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [${components.mkString(",")}]
          }"""
      val cpg = MockCpg().withMetaData(Languages.RUBYSRC, Nil).withCustom { (graph, _) =>
        graph.addNode(NewConfigFile().name("bom.json").content(bom))
        calls.foreach { case (code, argument) =>
            val call = NewCall().name("invoke").methodFullName("app.rb:<module>.invoke").code(code)
            val argumentNode = NewIdentifier().name(argument).code(argument)
                .typeFullName("ANY").argumentIndex(1).order(1)
            graph.addNode(call)
            graph.addNode(argumentNode)
            graph.addEdge(call, argumentNode, EdgeTypes.ARGUMENT)
        }
      }.cpg
      new CdxPass(cpg).createAndApply()
      fun(cpg)
    end apply
  end RubyFixture

  /** A JVM graph whose calls sit under the package roots the JVM tests key off. */
  private object JvmFixture:
    def apply[T](components: Seq[String])(fun: Cpg => T): T =
        apply(components, Seq.empty)(fun)
    def apply[T](
      components: Seq[String],
      calls: Seq[(String, String, String)]
    )(
      fun: Cpg => T
    ): T =
      val bom =
          s"""{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [${components.mkString(",")}]
          }"""
      val cpg = MockCpg().withMetaData(Languages.JAVASRC, Nil).withCustom { (graph, _) =>
        graph.addNode(NewConfigFile().name("bom.json").content(bom))
        // The JVM path keys off the type a call is made on, so each call carries its owning type.
        graph.addNode(
          NewCall().name("connect")
              .methodFullName("com.h2database.Driver.connect:void()")
              .typeFullName("com.h2database.Driver")
              .code("connect")
        )
        graph.addNode(
          NewCall().name("execute")
              .methodFullName("org.h2.jdbc.JdbcStatement.execute:void()")
              .typeFullName("org.h2.jdbc.JdbcStatement")
              .code("execute")
        )
        graph.addNode(
          NewCall().name("getBean")
              .methodFullName("org.springframework.beans.Factory.getBean:void()")
              .typeFullName("org.springframework.beans.Factory")
              .code("getBean")
        )
        calls.foreach { case (name, typeFullName, code) =>
            graph.addNode(
              NewCall().name(name).methodFullName(s"$typeFullName.$name:void()").typeFullName(
                typeFullName
              ).code(code)
            )
        }
      }.cpg
      new CdxPass(cpg).createAndApply()
      fun(cpg)
    end apply
  end JvmFixture

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
