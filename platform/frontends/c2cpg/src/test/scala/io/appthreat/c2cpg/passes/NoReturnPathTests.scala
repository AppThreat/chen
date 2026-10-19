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
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, StoredNode}
import io.shiftleft.semanticcpg.language.*

/** A call that does not return ends its path, as `return` does: the statements after it in its
  * branch run on no path, so an assignment there defines nothing a later read can see, and a guard
  * whose branch ends in the call bounds what follows the branch.
  */
class NoReturnPathTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <stdio.h>
      |#include <stdlib.h>
      |_Noreturn static void bail(const char *why) {
      |    fprintf(stderr, "%s\n", why);
      |    abort();
      |}
      |__attribute__((noreturn)) void die(int code);
      |static void warn(const char *why) {
      |    fprintf(stderr, "%s\n", why);
      |}
      |void bad_dead_reset(int n, const char *user) {
      |    char buf[8];
      |    if (n < 0) {
      |        bail(user);
      |        n = 0;
      |    }
      |    buf[n] = 'x';
      |}
      |void good_exit_guard(int n, const char *user) {
      |    char buf[8];
      |    if (n < 0 || n >= 8) {
      |        bail(user);
      |    }
      |    buf[n] = 'x';
      |}
      |void good_attribute_guard(int n) {
      |    char buf[8];
      |    if (n < 0 || n >= 8) die(1);
      |    buf[n] = 'x';
      |}
      |void bad_returning_helper(int n, const char *user) {
      |    char buf[8];
      |    if (n < 0 || n >= 8) {
      |        warn(user);
      |    }
      |    buf[n] = 'x';
      |}
      |int after_exit(int x) {
      |    exit(x);
      |    return x + 1;
      |}
      |int nondet_int(void);
      |void good_pinned_by_assumption(void) {
      |    int cells[10];
      |    int x = nondet_int();
      |    if (!(x == 3)) abort();
      |    cells[x] = 1;
      |}
      |void bad_unpinned_input(void) {
      |    int cells[10];
      |    int x = nondet_int();
      |    if (!(x != 3)) abort();
      |    cells[x] = 1;
      |}
      |""".stripMargin,
    "noreturn.c"
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

  "a call to a function that does not return" should {
      "end its path: the statement after it has no predecessor" in {
          val exit = cpg.method.nameExact("after_exit").call.nameExact("exit").head
          exit._cfgOut.l.map(_.label) shouldBe List("METHOD_RETURN")
          val after = cpg.method.nameExact("after_exit").call.nameExact("<operator>.addition")
              .argument(1).collectAll[CfgNode].head
          after.cfgPrev.l shouldBe empty
      }
      "be tagged on the call when the callee is declared _Noreturn" in {
          cpg.call.nameExact("bail").tag.nameExact("fn-attr").value.l should contain("noreturn")
      }
      "leave the parameter the only definition past a dead reset (C11 _Noreturn)" in {
          findingsIn("bad_dead_reset") should contain("MS-BOUND-004")
      }
      "make the guard whose branch ends in it bound what follows" in {
          findingsIn("good_exit_guard") shouldBe Set.empty
      }
      "read the attribute of a function only declared" in {
          findingsIn("good_attribute_guard") shouldBe Set.empty
      }
  }

  "an equality the path requires" should {
      "pin the value it compares with a constant" in {
          findingsIn("good_pinned_by_assumption") shouldBe Set.empty
      }
      "say nothing when the path only excludes the constant" in {
          findingsIn("bad_unpinned_input") should contain("MS-BOUND-004")
      }
  }

  "a call to a function that returns" should {
      "keep the guard's branch falling through to the access" in {
          findingsIn("bad_returning_helper") should contain("MS-BOUND-004")
      }
  }
end NoReturnPathTests
