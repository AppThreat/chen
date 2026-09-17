package io.appthreat.dataflowengineoss

import io.appthreat.dataflowengineoss.semantics.{JavaFrameworkSemantics, PhpFrameworkSemantics}
import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.generated.Languages
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The PHP framework sanitizer summaries are keyed on bare names (`e`, `esc_html`,
  * `htmlspecialchars`). `FlowSemantic` matching is by exact `methodFullName` with no language
  * scoping, so having them in the global default list silently cleared taint for any same-named
  * function in a C/Java/JS graph. They must therefore only reach a PHP graph.
  */
class LanguageScopedSemanticsTests extends AnyWordSpec with Matchers:

  private val phpSanitizerNames = PhpFrameworkSemantics.allSanitizerNames

  "the language-neutral default semantics" should {

      "not declare any PHP sanitizer" in {
          val semantics = DefaultSemantics()
          phpSanitizerNames.foreach { name =>
              withClue(s"$name must not be in the language-neutral defaults: ") {
                  semantics.forMethod(name) shouldBe None
              }
          }
      }

      "still declare the operator and C/Java summaries" in {
          val semantics = DefaultSemantics()
          semantics.forMethod("<operator>.assignment") should not be None
          semantics.forMethod("strlen") should not be None
      }

      "declare the Java framework sanitizers (fully qualified, so language-safe)" in {
          val semantics = DefaultSemantics()
          JavaFrameworkSemantics.allSanitizerFullNames.foreach { name =>
              withClue(s"$name: ") {
                  val semantic = semantics.forMethod(name)
                  semantic should not be None
                  // A sanitizer declares no mapping at all: taint does not reach the return.
                  semantic.get.mappings shouldBe List.empty
              }
          }
      }

      "declare the Java framework carriers (taint passes to the returned object)" in {
          val semantics = DefaultSemantics()
          JavaFrameworkSemantics.allCarrierFullNames.foreach { name =>
              withClue(s"$name: ") {
                  semantics.forMethod(name) should not be None
              }
          }
      }
  }

  "flowsForLanguage" should {

      "return the PHP sanitizer flows for a PHP graph" in {
          val flows = DefaultSemantics.flowsForLanguage(Languages.PHP)
          flows.map(_.methodFullName).toSet shouldBe phpSanitizerNames
          // A sanitizer must declare no mapping at all, otherwise taint would flow to the return value.
          flows.foreach(_.mappings shouldBe List.empty)
      }

      "return the Java request-reader flows for JVM-language graphs" in {
          val readers  = JavaFrameworkSemantics.RequestReaders
          val expected = readers.callNames
          Seq(Languages.JAVA, Languages.JAVASRC, "JAR", "JIMPLE").foreach { language =>
              withClue(s"$language must receive the Java request readers: ") {
                  val flows = DefaultSemantics.flowsForLanguage(language)
                  // Bare names (unresolved calls) exactly, plus receiver-qualified REGEX
                  // entries (resolved calls, whose fullName carries a `:signature`).
                  flows.map(_.methodFullName).toSet should contain allElementsOf expected
                  flows.filterNot(f => expected.contains(f.methodFullName)).foreach { f =>
                    f.regex shouldBe true
                    f.methodFullName should endWith(":.*")
                  }
                  flows.map(_.methodFullName).count(!expected.contains(_)) shouldBe
                      readers.fullNames.size
                  // Every reader's declared semantic maps receiver (0) to return (-1): the
                  // returned value is request data. Checked through the composed semantics,
                  // because FlowPath is opaque.
                  val semantics = Semantics.fromList(flows)
                  expected.foreach { name =>
                      withClue(s"$name: ") {
                          semantics.forMethod(name) should not be None
                      }
                  }
              }
          }
      }

      "return nothing for graphs of other languages" in {
          Seq(
            Languages.NEWC,
            Languages.C,
            Languages.JSSRC,
            Languages.JAVASCRIPT,
            Languages.PYTHONSRC,
            Languages.RUBYSRC
          ).foreach { language =>
              withClue(s"$language must not receive PHP or Java flows: ") {
                  DefaultSemantics.flowsForLanguage(language) shouldBe List.empty
              }
          }
      }
  }

  "phpSemantics" should {

      "declare every PHP sanitizer as taint clearing" in {
          val semantics = DefaultSemantics.phpSemantics()
          phpSanitizerNames.foreach { name =>
              withClue(s"$name must be declared for PHP: ") {
                  semantics.forMethod(name).map(_.mappings) shouldBe Some(List.empty)
              }
          }
      }

      "keep the language-neutral summaries too" in {
          DefaultSemantics.phpSemantics().forMethod("<operator>.assignment") should not be None
      }
  }

  "the PHP sanitizer vocabulary" should {

      "cover the framework escapers documented in the design" in {
          (phpSanitizerNames should contain).allOf(
            "e",
            "esc_html",
            "sanitize_text_field",
            "htmlspecialchars"
          )
      }
  }
end LanguageScopedSemanticsTests
