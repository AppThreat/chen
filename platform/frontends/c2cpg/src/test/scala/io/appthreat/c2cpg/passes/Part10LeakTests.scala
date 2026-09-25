package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 10, tasks 1 and 2: the leak rule reports at `medium`, the overwrite arm keeps its
  * pointer-arithmetic and fresh-allocation conditions, the loop-carried leak renders once, and a
  * call into a method that may throw is an exit the frame's allocations do not survive.
  */
class Part10LeakTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |
    |void bad_early_return(int n)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    if (n < 0)
    |    {
    |        return;
    |    }
    |    free(p);
    |}
    |
    |void bad_overwrite(void)
    |{
    |    char *p = (char *)malloc(64);
    |    p = (char *)malloc(128);
    |    free(p);
    |}
    |
    |void bad_overwrite_uncast(void)
    |{
    |    char *p = (char *)malloc(64);
    |    p = malloc(128);
    |    free(p);
    |}
    |
    |void bad_loop_alloc(int n)
    |{
    |    int i;
    |    for (i = 0; i < n; i++)
    |    {
    |        char *p = (char *)malloc(16);
    |        if (p == NULL) return;
    |        p[0] = 'a';
    |    }
    |}
    |
    |void bad_arith_rebind(void)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    p = p + 4;
    |    free(p);
    |}
    |
    |void good_freed(int n)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    if (n < 0)
    |    {
    |        free(p);
    |        return;
    |    }
    |    free(p);
    |}
    |
    |void good_unbraced_free(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p;
    |    if (n == 0 || n > 4096) return;
    |    p = (char *)malloc(n);
    |    if (p) free(p);
    |}
    |""".stripMargin,
    "part10leak.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def leakNodesIn(method: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-ALLOC-003")).l

  private def confidenceOf(node: StoredNode, rule: String): String =
      MemorySafetyFindingPass.confidenceOf(
        node,
        MemorySafetyFindingPass.rules(rule)
      )

  "the must-leak rule" should:
    "report the early-return leak at medium" in {
        val nodes = leakNodesIn("bad_early_return")
        nodes should not be empty
        nodes.map(confidenceOf(_, "MS-ALLOC-003")) should contain("medium")
    }

    "report the overwrite of a live handle, cast or not" in {
        leakNodesIn("bad_overwrite") should not be empty
        leakNodesIn("bad_overwrite_uncast") should not be empty
    }

    "render the loop-carried leak once" in {
        leakNodesIn("bad_loop_alloc").size shouldBe 1
    }

    "not read `p = p + 4` as an overwrite that loses the block" in {
        leakNodesIn("bad_arith_rebind") shouldBe empty
    }

    "stay silent when every path frees" in {
        leakNodesIn("good_freed") shouldBe empty
    }

    "stay silent behind an unbraced conditional free" in {
        leakNodesIn("good_unbraced_free") shouldBe empty
    }
end Part10LeakTests

class Part10LeakCppTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <string>
    |#include <vector>
    |
    |void mayThrow(int n)
    |{
    |    if (n < 0) throw std::runtime_error("bad");
    |}
    |
    |void bad_leak_on_throw(int n)
    |{
    |    int *p = new int[64];
    |    mayThrow(n);
    |    delete[] p;
    |}
    |
    |void bad_early_return(int n)
    |{
    |    char *buf = new char[n];
    |    if (n < 10) return;
    |    delete[] buf;
    |}
    |
    |void no_throw_call(int n)
    |{
    |    int *p = new int[64];
    |    use(p, n);
    |    delete[] p;
    |}
    |
    |void caught_here(int n)
    |{
    |    int *p = new int[64];
    |    try { mayThrow(n); } catch (...) {}
    |    delete[] p;
    |}
    |
    |void use(int *p, int n) { (void)p; (void)n; }
    |
    |void good_raii(int n)
    |{
    |    std::vector<int> v(64);
    |    mayThrow(n);
    |}
    |""".stripMargin,
    "part10leak.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def leakNodesIn(method: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-ALLOC-003")).l

  "the exception-path leak" should:
    "report an allocation live across a call that may throw" in {
        leakNodesIn("bad_leak_on_throw") should not be empty
    }

    "still report the plain early-return leak after new" in {
        leakNodesIn("bad_early_return") should not be empty
    }

    "not fire on a call whose callee cannot throw" in {
        leakNodesIn("no_throw_call") shouldBe empty
    }

    "not fire when the call is caught inside the frame" in {
        leakNodesIn("caught_here") shouldBe empty
    }

    "not fire on RAII storage" in {
        leakNodesIn("good_raii") shouldBe empty
    }
end Part10LeakCppTests
