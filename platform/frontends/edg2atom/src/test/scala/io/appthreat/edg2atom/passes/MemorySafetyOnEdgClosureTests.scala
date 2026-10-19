package io.appthreat.edg2atom.passes

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

/** What a lambda captures, from the front end's capture list: a closure holding a local by
  * reference must not outlive the local's frame, and the lambda's body reads the captured values -
  * their extents and their origins - from the enclosing function.
  */
class MemorySafetyOnEdgClosureTests extends Code2CpgFixture(() => new DefaultTestCpgWithEdg(".cpp")):

  private val edgaAvailable       = EdgaRunner.locate().isDefined
  private def requireEdga(): Unit = assume(edgaAvailable, "edga is not installed")

  private lazy val cpg =
    val graph = code(
      """
      |#include <cstdio>
      |#include <cstdlib>
      |#include <cstring>
      |#include <functional>
      |static int (*late_call)(void);
      |void bad_lambda_ref_escape(void)
      |{
      |    int local = 42;
      |    auto f = [&local]() -> int { return local; };
      |    late_call = []() -> int { return 0; };
      |    printf("%d\n", f()); 
      |}
      |int bad_lambda_after_frame(void)
      |{
      |    int local = 7;
      |    auto f = [&local]() -> int { return local; };
      |    struct holder { int (*fn)(); } h = { nullptr };
      |    (void)h;
      |    return f() + local; 
      |}
      |static std::function<const char *()> dangling;
      |void bad_lambda_string_escape(void)
      |{
      |    char buf[16] = "hi";
      |    auto g = [&buf]() -> const char * { return buf; };
      |    dangling = g; 
      |}
      |void bad_lambda_capture_index(const char *user)
      |{
      |    char buf[8] = {0};
      |    int idx = atoi(user);
      |    auto f = [&buf, idx]() -> char { return buf[idx]; };
      |    printf("%c\n", f()); 
      |}
      |void bad_init_capture_length(const char *user)
{
    char buf[8] = {0};
    auto f = [len = 16]() -> int { return len; };
    memcpy(buf, user, f());
}
void good_init_capture_length(const char *user)
{
    char buf[8] = {0};
    auto f = [len = 8]() -> int { return len; };
    memcpy(buf, user, f());
}
static std::function<int()> kept_ok;
      |void good_lambda_copy_escape(void)
      |{
      |    int local = 3;
      |    kept_ok = [local]() -> int { return local; };
      |}
      |std::function<int()> bad_lambda_returned(void)
      |{
      |    int local = 9;
      |    return [&local]() -> int { return local; };
      |}
      |""".stripMargin,
      "closures.cpp"
    )
    X2Cpg.applyDefaultOverlays(graph)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(graph))
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    new GuardPass(graph).createAndApply()
    new ValueOriginPass(graph).createAndApply()
    new IntegerWidthPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    new MemorySafetyFindingPass(graph).createAndApply()
    graph
  end cpg

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  private def lambdaFindingsWithin(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[io.shiftleft.codepropertygraph.generated.nodes.MethodRef]
          .flatMap(_._refOut.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Method])
          .ast.collectAll[StoredNode].flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "a lambda's capture list" should {
      "tag what it captures by reference, by copy and by init-capture" in {
          requireEdga()
          cpg.method.nameExact("bad_lambda_capture_index").ast.collectAll[io.shiftleft.codepropertygraph.generated.nodes.MethodRef]
              .tag.nameExact("capture").value.l should contain allOf ("ref:buf", "copy:idx")
      }
  }

  "a closure holding a local by reference" should {
      "report it stored where it outlives the frame, or returned" in {
          requireEdga()
          findingsIn("bad_lambda_string_escape") should contain("MS-ESC-001")
          findingsIn("bad_lambda_returned") should contain("MS-ESC-001")
      }
      "stay silent while it is called inside the frame, and for a copy capture" in {
          requireEdga()
          findingsIn("bad_lambda_ref_escape") should not contain "MS-ESC-001"
          findingsIn("bad_lambda_after_frame") should not contain "MS-ESC-001"
          findingsIn("good_lambda_copy_escape") should not contain "MS-ESC-001"
      }
  }

  "an init-capture" should {
      "carry its constant into what the lambda returns" in {
          requireEdga()
          findingsIn("bad_init_capture_length") should contain("MS-BOUND-006")
          findingsIn("good_init_capture_length") should not contain "MS-BOUND-006"
      }
  }

  "a lambda's body" should {
      "read a captured array's extent and a captured index's origin" in {
          requireEdga()
          lambdaFindingsWithin("bad_lambda_capture_index") should contain("MS-BOUND-003")
      }
  }
end MemorySafetyOnEdgClosureTests
