package io.appthreat.edg2atom.astcreation

import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

class EdgDataFlowTestCpg extends DefaultTestCpgWithEdg(".c"):
  override protected def applyPasses(): Unit =
    X2Cpg.applyDefaultOverlays(this)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(this))

/** Inline assembly: an asm statement is a call of `asm` on its operands, so data flows through it,
  * and an asm label names the symbol a function links to.
  */
class AsmTests extends Code2CpgFixture(() => new EdgDataFlowTestCpg()):

  private implicit val context: EngineContext = EngineContext()

  private val cpg = code(
    """int add(int a, int b) {
      |  int out;
      |  __asm__ volatile("add %0, %1, %2" : "=r"(out) : "r"(a), "r"(b) : "memory");
      |  return out;
      |}
      |
      |void barrier(void) { __asm__ __volatile__("" ::: "memory"); }
      |
      |extern int renamed(int) __asm__("real_symbol");
      |int call_renamed(void) { return renamed(1); }
      |""".stripMargin
  )

  /** Cancels the test where edga is missing, or too old to write an asm statement's operands. */
  private def requireAsmOperands(): Unit =
    assume(EdgaRunner.locate().isDefined, "edga is not installed")
    assume(
      cpg.call.nameExact(X2CpgDefines.AsmCallName).nonEmpty,
      "edga does not export asm operands"
    )

  "an asm statement" should {
      "be a call of asm on its operands, outputs first" in {
          requireAsmOperands()
          val asm = cpg.method.nameExact("add").call.nameExact(X2CpgDefines.AsmCallName).head
          asm.argument.code.l shouldBe List("out", "a", "b")
          asm.argument.flatMap(_.tag.nameExact(X2CpgDefines.AsmOperandTag).value).l shouldBe List(
            "out:=r",
            "in:r",
            "in:r"
          )
          asm.code should startWith("__asm__ volatile(\"add")
      }

      "carry what it reads to what it writes" in {
          requireAsmOperands()
          val source = cpg.method.nameExact("add").parameter.nameExact("a")
          val sink   = cpg.method.nameExact("add").ast.isReturn.ast.isIdentifier.nameExact("out")
          sink.reachableBy(source).l should not be empty
      }

      "be a call without arguments when it has no operands" in {
          requireAsmOperands()
          cpg.method.nameExact("barrier").call.nameExact(X2CpgDefines.AsmCallName).argument.l shouldBe empty
      }
  }

  "an asm label" should {
      "name the symbol on the calls of the function" in {
          requireAsmOperands()
          cpg.call.nameExact("renamed").tag.nameExact(X2CpgDefines.AsmNameTag).value.l shouldBe List(
            "real_symbol"
          )
      }
  }
end AsmTests
