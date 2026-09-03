package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** Confidence coverage for control-flow (CFG) and dominator/post-dominator edges on a branching
  * function - the `dominatedBy`/`dominates`/`postDominates` relationships an analysis relies on.
  */
class CppCfgDominatorTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private val cpg = code("""
      |int f(int x) {
      |    int y = x + 1;
      |    if (y > 10) {
      |        y = y - 5;
      |    } else {
      |        y = y + 5;
      |    }
      |    return y;
      |}
      |""".stripMargin)

  "the CFG" should {
      "start at the first evaluated expression of the body" in {
          cpg.method.nameExact("f").cfgFirst.code.l should not be empty
      }
      "record the branch condition on the if control structure" in {
          cpg.method.nameExact("f").controlStructure.condition.code.l shouldBe List("y > 10")
      }
  }

  "the dominator tree" should {
      "have the return dominated by the branch condition and the pre-branch assignment" in {
          val doms = cpg.method.nameExact("f").methodReturn.dominatedBy.isCall.code.toSetMutable
          (doms should contain).allOf("y = x + 1", "y > 10")
      }

      "have the branch condition dominate both branch bodies and the return" in {
          val dominated =
              cpg.method.nameExact("f").controlStructure.condition.dominates.code.toSetMutable
          (dominated should contain).allOf("y = y - 5", "y = y + 5", "return y;")
      }

      "not have either branch body dominate the other (they are mutually exclusive)" in {
          cpg.call.codeExact("y = y - 5").dominates.code.l should not contain "y = y + 5"
          cpg.call.codeExact("y = y + 5").dominates.code.l should not contain "y = y - 5"
      }
  }

  "the post-dominator tree" should {
      "have the return post-dominate the branch condition" in {
          cpg.method
              .nameExact("f")
              .controlStructure
              .condition
              .postDominatedBy
              .isReturn
              .code
              .l should contain("return y;")
      }
  }
end CppCfgDominatorTests
