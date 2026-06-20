package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import _root_.io.appthreat.x2cpg.passes.taggers.ChennaiTagsPass
import _root_.io.shiftleft.semanticcpg.language.*

/** Validates that ChennaiTagsPass tags calls to declared sanitisers/validators from an external
  * config (the chennai.json schema passed in directly rather than embedded in the graph).
  */
class SanitizerTaggingTests extends DataFlowCodeToCpgSuite:

  private val cpg = code("""
      |char* escapeHtml(char* s);
      |int validate(int x);
      |
      |void handler(char* input, int n) {
      |  char* safe = escapeHtml(input);
      |  int ok = validate(n);
      |}
      |""".stripMargin)

  private val config =
      """{
        |  "sanitizers": [
        |    { "name": "html", "methods": [".*escapeHtml.*"], "categories": ["http"] }
        |  ],
        |  "validators": [
        |    { "name": "any-validator", "methods": [".*validate.*"] }
        |  ]
        |}""".stripMargin

  new ChennaiTagsPass(cpg, Some(config)).createAndApply()

  "ChennaiTagsPass sanitiser tagging" should:
    "tag a categorised sanitiser call with the sanitizer and category tags" in:
      val tags = cpg.call.name("escapeHtml").tag.name.toSet
      tags should contain("sanitizer")
      tags should contain("sanitizer-http")

    "tag an uncategorised validator call with just the sanitizer tag" in:
      val tags = cpg.call.name("validate").tag.name.toSet
      tags should contain("sanitizer")
      tags.exists(_.startsWith("sanitizer-")) shouldBe false

    "leave unrelated calls untagged" in:
      cpg.call.name("escapeHtml").tag.name.toSet should not contain "framework-input"
end SanitizerTaggingTests
