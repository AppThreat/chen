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

/** A call the graph resolves to a method is judged by THAT method's own body: an overload the front
  * end selected, or a lambda's instance, keeps its own copy summary at the call, instead of
  * borrowing whatever same-named methods agreed on.
  */
class ResolvedCalleeSummaryTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <cstring>
      |
      |static void copy_into(char *dst, const char *src) {
      |    strcpy(dst, src);
      |}
      |static void copy_into(class std::string &dst, const char *src) {
      |    dst = src;
      |}
      |void bad_overload_copy(const char *user) {
      |    char buf[16];
      |    copy_into(buf, user);
      |}
      |void good_overload_copy(const char *user) {
      |    static const char *sink;
      |    (void)sink;
      |    char local[4] = "ab";
      |    copy_into(local, "cd");
      |}
      |
      |static void copy_n(char *dst, const char *src, unsigned long n) {
      |    memcpy(dst, src, n);
      |}
      |void bad_literal_length(const char *user) {
      |    char buf[16];
      |    copy_n(buf, user, 64);
      |}
      |void good_clamped_length(const char *user) {
      |    char buf[16];
      |    copy_n(buf, user, 8);
      |}
      |static void copy_clamped(char *dst, const char *src, size_t n) {
      |    if (n > 16) n = 16;
      |    memcpy(dst, src, n);
      |}
      |void good_callee_clamped_length(const char *user) {
      |    char buf[16];
      |    copy_clamped(buf, user, 64);
      |}
      |void note_large(void);
      |static void copy_reset_on_error(char *dst, const char *src, size_t n, int err) {
      |    if (n > 1024) note_large();
      |    if (err) n = 0;
      |    memcpy(dst, src, n);
      |}
      |void bad_unclamped_length(const char *user, int err) {
      |    char buf[16];
      |    copy_reset_on_error(buf, user, 64, err);
      |}
      |""".stripMargin,
    "overloads.cpp"
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

  "a call resolved to the copying overload" should {
      "overrun the caller's fixed buffer at the call" in {
          findingsIn("bad_overload_copy") should contain("MS-BOUND-006")
      }
  }

  "a call resolved to the overload that does not copy" should {
      "say nothing" in {
          // the string overload concludes nothing from its body, and a call into it borrows no
          // copy summary from its name-sharer
          findingsIn("good_overload_copy") shouldBe Set.empty
      }
  }

  "a wrapper call with a literal length past the buffer" should {
      "overrun it at the call" in {
          findingsIn("bad_literal_length") should contain("MS-BOUND-006")
      }
      "honour a length inside the buffer" in {
          findingsIn("good_clamped_length") should not contain "MS-BOUND-006"
      }
      "honour a length the CALLEE clamps inside the buffer" in {
          findingsIn("good_callee_clamped_length") should not contain "MS-BOUND-006"
      }
      "not take a store to the length elsewhere in the callee for a clamp" in {
          findingsIn("bad_unclamped_length") should contain("MS-BOUND-006")
      }
  }
end ResolvedCalleeSummaryTests
