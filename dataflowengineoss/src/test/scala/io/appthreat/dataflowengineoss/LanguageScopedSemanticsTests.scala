package io.appthreat.dataflowengineoss

import io.appthreat.dataflowengineoss.semantics.PhpFrameworkSemantics
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
  }

  "flowsForLanguage" should {

      "return the PHP sanitizer flows for a PHP graph" in {
          val flows = DefaultSemantics.flowsForLanguage(Languages.PHP)
          flows.map(_.methodFullName).toSet shouldBe phpSanitizerNames
          // A sanitizer must declare no mapping at all, otherwise taint would flow to the return value.
          flows.foreach(_.mappings shouldBe List.empty)
      }

      "return nothing for non-PHP graphs" in {
          Seq(
            Languages.NEWC,
            Languages.C,
            Languages.JAVA,
            Languages.JAVASRC,
            Languages.JSSRC,
            Languages.JAVASCRIPT,
            Languages.PYTHONSRC,
            Languages.RUBYSRC
          ).foreach { language =>
              withClue(s"$language must not receive PHP flows: ") {
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
