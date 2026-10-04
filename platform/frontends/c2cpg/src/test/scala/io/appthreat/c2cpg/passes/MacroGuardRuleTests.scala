package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A guard written as a macro guards, and a read inside a macro's expansion is a read. */
class MacroGuardRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#define CHECK_INDEX(i, n) if ((i) < 0 || (i) >= (n)) return
    |#define TWICE(v) ((v) + (v))
    |void note(void);
    |
    |void good_macro_guard(int idx)
    |{
    |    char buf[16];
    |    CHECK_INDEX(idx, 16);
    |    buf[idx] = 0;
    |    note();
    |}
    |
    |void bad_no_guard(int idx)
    |{
    |    char buf[16];
    |    buf[idx] = 0;
    |    note();
    |}
    |
    |int bad_uninitialised_in_macro(void)
    |{
    |    int count;
    |    return TWICE(count);
    |}
    |
    |int bad_uninitialised_plain(void)
    |{
    |    int count;
    |    return count + count;
    |}
    |
    |int good_initialised_in_macro(void)
    |{
    |    int count = 2;
    |    return TWICE(count);
    |}
    |""".stripMargin,
    "macroguard.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findings(method: String): List[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l).l

  "a guard written as a macro" should {
      "bound the index it checks" in {
          findings("good_macro_guard").filter(_.startsWith("MS-BOUND")) shouldBe empty
          findings("bad_no_guard").filter(_.startsWith("MS-BOUND")) should not be empty
      }
  }

  "a read inside a macro's expansion" should {
      "be a read of an uninitialised variable, as it is outside a macro" in {
          // each read of the expansion, as `count + count` reports both; the argument copy is none
          findings("bad_uninitialised_in_macro").count(_ == "MS-INIT-001") shouldBe
              findings("bad_uninitialised_plain").count(_ == "MS-INIT-001")
          findings("good_initialised_in_macro").filter(_ == "MS-INIT-001") shouldBe empty
      }
  }
end MacroGuardRuleTests
