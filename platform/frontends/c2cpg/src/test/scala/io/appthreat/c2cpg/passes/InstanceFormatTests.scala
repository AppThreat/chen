package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    MemorySemanticsPass,
    ValueOriginPass
}
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** The format rule's forwarder exemption is actual variadicity - a `va_list` parameter or a
  * signature that still carries the ellipsis. An instantiated template's pack parameter keeps its
  * written `Args... args` spelling while the instance's signature holds the expanded types, and
  * that instance's printf is a call with concrete arguments.
  */
class InstanceFormatTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <cstdio>
      |#include <cstdarg>
      |
      |template <typename... Args>
      |static int log_line(const char *fmt, Args... args) {
      |    return printf(fmt, args...);
      |}
      |void bad_forwarded_format(const char *user) {
      |    log_line(user, 1, 2);
      |}
      |void good_forwarded_literal(void) {
      |    log_line("count %d %d", 1, 2);
      |}
      |
      |static void va_forward(const char *fmt, ...) {
      |    va_list ap;
      |    va_start(ap, fmt);
      |    vprintf(fmt, ap);
      |    va_end(ap);
      |}
      |void bad_va_forward(const char *user) {
      |    va_forward(user, 1);
      |}
      |""".stripMargin,
    "formats.cpp"
  )

  private lazy val cpg =
    val graph = sourceCpg
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    new GuardPass(graph).createAndApply()
    new ValueOriginPass(graph).createAndApply()
    new IntegerWidthPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    new MemorySafetyFindingPass(graph).createAndApply()
    graph

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "an instantiated template's forwarded format" should {
      "report the non-literal format inside the instance" in {
          findingsIn("log_line") should contain("MS-FMT-001")
      }
  }

  "an instance every caller gives a literal" should {
      "stay silent" in {
          // the instance for ("count %d %d", 1, 2) has its own body; its format is a literal
          findingsIn("good_forwarded_literal") shouldBe Set.empty
      }
  }

  "a true va_list forwarder" should {
      "keep its exemption" in {
          findingsIn("va_forward") should not contain "MS-FMT-001"
      }
  }
end InstanceFormatTests
