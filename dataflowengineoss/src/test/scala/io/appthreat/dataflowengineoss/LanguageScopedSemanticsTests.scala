package io.appthreat.dataflowengineoss

import io.appthreat.dataflowengineoss.semantics.{JavaFrameworkSemantics, PhpFrameworkSemantics}
import io.appthreat.dataflowengineoss.semanticsloader.{FlowMapping, ParameterNode, Semantics}
import io.shiftleft.codepropertygraph.generated.Languages
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The language-specific summaries are keyed on bare names (`e`, `esc_html` for PHP; `free`,
  * `read`, `strncpy` for C). `FlowSemantic` matching is by exact `methodFullName` with no language
  * scoping, so having them in the global default list silently cleared taint for any same-named
  * function in a graph of another language. They must therefore only reach graphs of their own
  * language.
  */
class LanguageScopedSemanticsTests extends AnyWordSpec with Matchers:

  private val phpSanitizerNames = PhpFrameworkSemantics.allSanitizerNames

  /** C summaries whose bare names are the most likely to collide with a user function of the same
    * name in a non-C graph.
    */
  private val bareCNames =
      Seq("free", "read", "getc", "exit", "strlen", "strncpy", "strcpy", "sprintf", "scanf", "malloc")

  "the language-neutral default semantics" should {

      "not declare any PHP sanitizer" in {
          val semantics = DefaultSemantics()
          phpSanitizerNames.foreach { name =>
              withClue(s"$name must not be in the language-neutral defaults: ") {
                  semantics.forMethod(name) shouldBe None
              }
          }
      }

      "not declare any bare C library name" in {
          val semantics = DefaultSemantics()
          bareCNames.foreach { name =>
              withClue(s"$name must not be in the language-neutral defaults: ") {
                  semantics.forMethod(name) shouldBe None
              }
          }
      }

      "still declare the operator and Java summaries" in {
          val semantics = DefaultSemantics()
          semantics.forMethod("<operator>.assignment") should not be None
          semantics.forMethod(
            "java.lang.String.format:java.lang.String(java.lang.String,java.lang.Object[])"
          ) should not be None
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

      "return the C library flows for C/C++ graphs" in {
          Seq(Languages.C, Languages.NEWC).foreach { language =>
              withClue(s"$language must receive the C summaries: ") {
                  val flows = DefaultSemantics.flowsForLanguage(language)
                  flows.map(_.methodFullName) should contain allElementsOf bareCNames
                  val semantics = Semantics.fromList(flows)
                  semantics.forMethod("strncpy") should not be None
                  // ... including the (2, 1) source-to-destination mapping, whose absence is why
                  // `strncpy(dst, tainted, n)` used to leave `dst` clean.
                  val strncpy = semantics.forMethod("strncpy").get
                  strncpy.mappings.count {
                      case FlowMapping(ParameterNode(src, _), ParameterNode(dst, _)) =>
                          src == 2 && dst == 1
                      case _ => false
                  } shouldBe 1
              }
          }
      }

      "not give a JVM graph C's bare free" in {
          // A Java graph is analysed with the neutral defaults plus the JVM request readers -
          // neither carries a bare `free`, so a user-defined Java/JS `free` keeps the permissive
          // default instead of libc `free`'s summary.
          Seq(Languages.JAVA, Languages.JAVASRC).foreach { language =>
              withClue(s"$language must not receive C's bare names: ") {
                  val flows = DefaultSemantics.flowsForLanguage(language)
                  flows.map(_.methodFullName) should not contain "free"
                  flows.map(_.methodFullName) should not contain "read"
              }
          }
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
            Languages.JSSRC,
            Languages.JAVASCRIPT,
            Languages.PYTHONSRC,
            Languages.RUBYSRC
          ).foreach { language =>
              withClue(s"$language must not receive PHP, Java or C flows: ") {
                  DefaultSemantics.flowsForLanguage(language) shouldBe List.empty
              }
          }
      }
  }

  "cSemantics" should {

      "declare every C library summary" in {
          val semantics = DefaultSemantics.cSemantics()
          bareCNames.foreach { name =>
              withClue(s"$name must be declared for C: ") {
                  semantics.forMethod(name) should not be None
              }
          }
      }

      "keep the language-neutral summaries too" in {
          DefaultSemantics.cSemantics().forMethod("<operator>.assignment") should not be None
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
