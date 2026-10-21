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
import io.shiftleft.codepropertygraph.generated.nodes.{Method, MethodRef, StoredNode}
import io.shiftleft.semanticcpg.language.*

/** A lambda's captures, from CDT's capture list: a closure holding a local by reference must not
  * outlive the local's frame, and the lambda's body reads the captured values from the enclosing
  * function.
  */
class ClosureCaptureTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |struct fn {
      |  template <class F> fn(F f);
      |  const char *operator()() const;
      |};
      |static fn dangling = fn([]() -> const char * { return 0; });
      |int atoi(const char *);
      |int printf(const char *, ...);
      |void bad_lambda_string_escape(void) {
      |    char buf[16] = "hi";
      |    auto g = [&buf]() -> const char * { return buf; };
      |    dangling = g;
      |}
      |void good_lambda_called_in_frame(void) {
      |    int local = 42;
      |    auto f = [&local]() -> int { return local; };
      |    printf("%d\n", f());
      |}
      |static fn kept_ok = fn([]() -> const char * { return 0; });
      |void good_lambda_copy_escape(void) {
      |    char text = 'x';
      |    kept_ok = [text]() -> const char * { return 0; };
      |}
      |void *memcpy(void *, const void *, unsigned long);
      |void bad_init_capture_length(const char *user) {
      |    char buf[8] = {0};
      |    auto f = [len = 16]() -> int { return len; };
      |    memcpy(buf, user, f());
      |}
      |void good_init_capture_length(const char *user) {
      |    char buf[8] = {0};
      |    auto f = [len = 8]() -> int { return len; };
      |    memcpy(buf, user, f());
      |}
      |void bad_lambda_capture_index(const char *user) {
      |    char buf[8] = {0};
      |    int idx = atoi(user);
      |    auto f = [&buf, idx]() -> char { return buf[idx]; };
      |    printf("%c\n", f());
      |}
      |static void fill_through_closure(char *dst, unsigned long n) {
      |    auto put = [&]() { memcpy(dst, "abcdefgh", n); };
      |    put();
      |}
      |void good_closure_parameter_bounded_by_callers(void) {
      |    char small[16];
      |    fill_through_closure(small, 8);
      |}
      |""".stripMargin,
    "closures.cpp"
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

  private def lambdaFindingsWithin(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[MethodRef].flatMap(_._refOut.collectAll[Method])
          .ast.collectAll[StoredNode].flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "a lambda's capture list" should {
      "tag what it captures" in {
          (cpg.method.nameExact("bad_lambda_capture_index").ast.collectAll[MethodRef].tag
              .nameExact("capture").value.l should contain).allOf("ref:buf", "copy:idx")
      }
  }

  "a closure holding a local by reference" should {
      "report it stored where it outlives the frame" in {
          findingsIn("bad_lambda_string_escape") should contain("MS-ESC-001")
      }
      "stay silent called inside the frame, and for a copy capture" in {
          findingsIn("good_lambda_called_in_frame") should not contain "MS-ESC-001"
          findingsIn("good_lambda_copy_escape") should not contain "MS-ESC-001"
      }
  }

  "an init-capture" should {
      "carry its constant into what the lambda returns" in {
          findingsIn("bad_init_capture_length") should contain("MS-BOUND-006")
          findingsIn("good_init_capture_length") should not contain "MS-BOUND-006"
      }
  }

  "a lambda's body" should {
      "read a captured array's extent and a captured index's origin" in {
          lambdaFindingsWithin("bad_lambda_capture_index") should contain("MS-BOUND-003")
      }
      "ask the enclosing function's callers about a parameter it captured" in {
          lambdaFindingsWithin("fill_through_closure").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }
end ClosureCaptureTests
