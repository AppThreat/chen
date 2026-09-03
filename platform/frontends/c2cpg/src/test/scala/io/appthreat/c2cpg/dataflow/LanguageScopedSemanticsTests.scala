package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.dataflowengineoss.language.*
import _root_.io.shiftleft.semanticcpg.language.*

/** Guards against PHP framework sanitizer semantics leaking into non-PHP graphs.
  *
  * `FlowSemantic` matching is by exact `methodFullName` with no language scoping, and the PHP
  * sanitizers are bare names (`e`, `esc_html`, `htmlspecialchars`). While they were part of the
  * global `DefaultSemantics()`, an unrelated C function of the same name had its taint silently
  * cleared - a cross-language false negative with no diagnostic. The PHP flows are now added per
  * graph by `DefaultSemantics.flowsForLanguage`, which `OssDataFlow` applies using the CPG's own
  * language, so taint must still flow through these calls in a C graph.
  */
class LanguageScopedSemanticsTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |char* e(char* x);
      |char* esc_html(char* x);
      |char* htmlspecialchars(char* x);
      |void sink(char* s);
      |
      |void viaE(char* tainted) {
      |  char* y = e(tainted);
      |  sink(y);
      |}
      |
      |void viaEscHtml(char* tainted) {
      |  char* y = esc_html(tainted);
      |  sink(y);
      |}
      |
      |void viaHtmlSpecialChars(char* tainted) {
      |  char* y = htmlspecialchars(tainted);
      |  sink(y);
      |}
      |""".stripMargin)

  "a C graph" should:

    "keep taint flowing through a function named e()" in:
      val source = cpg.method.name("viaE").parameter.name("tainted")
      val sink   = cpg.method.name("viaE").call.name("sink").argument
      sink.reachableByFlows(source).size should be >= 1

    "keep taint flowing through a function named esc_html()" in:
      val source = cpg.method.name("viaEscHtml").parameter.name("tainted")
      val sink   = cpg.method.name("viaEscHtml").call.name("sink").argument
      sink.reachableByFlows(source).size should be >= 1

    "keep taint flowing through a function named htmlspecialchars()" in:
      val source = cpg.method.name("viaHtmlSpecialChars").parameter.name("tainted")
      val sink   = cpg.method.name("viaHtmlSpecialChars").call.name("sink").argument
      sink.reachableByFlows(source).size should be >= 1
end LanguageScopedSemanticsTests
