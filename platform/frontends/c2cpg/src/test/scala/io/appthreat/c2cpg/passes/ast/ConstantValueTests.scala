package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.generated.nodes.Expression
import io.shiftleft.semanticcpg.language.*

/** Every integer constant expression the source writes as more than a literal carries its value. */
class ConstantValueTests extends CCodeToCpgSuite:

  private def valueOf(e: Expression): Option[String] =
      e.tag.nameExact(Defines.ConstValueTag).value.headOption

  private def valuesByCode(cpg: io.shiftleft.codepropertygraph.Cpg): Map[String, String] =
      cpg.all.collectAll[Expression]
          .flatMap(e => valueOf(e).map(e.code -> _))
          .l
          .toMap

  "constant expressions in a body" should {
      val cpg = code(
        """
          |struct packet { char name[16]; int len; };
          |enum level { LOW = 2, HIGH = LOW * 4 };
          |static const int SLOTS = 3;
          |static const volatile int REG = 7;
          |#define N (4 * 8)
          |void use(long);
          |int run(int a, struct packet *p) {
          |  use(sizeof(struct packet));
          |  use(sizeof(*p));
          |  use(sizeof(char *));
          |  use(sizeof(char));
          |  use(HIGH + 1);
          |  use(SLOTS * 2);
          |  use(REG + 1);
          |  use(N);
          |  use((unsigned int)-1);
          |  use(a + 1);
          |  use(a ? 1 : 2);
          |  return sizeof(p->name) > 8 ? 1 : 0;
          |}
          |""".stripMargin,
        "constants.c"
      )
      val values = valuesByCode(cpg)

      "measure types and objects for the target" in {
          values("sizeof(struct packet)") shouldBe "20"
          values("sizeof(*p)") shouldBe "20"
          values("sizeof(char *)") shouldBe "8"
          values("sizeof(char)") shouldBe "1"
          values("sizeof(p->name)") shouldBe "16"
      }

      "fold enumerators, const integers and the arithmetic over them" in {
          values("HIGH") shouldBe "8"
          values("HIGH + 1") shouldBe "9"
          values("SLOTS") shouldBe "3"
          values("SLOTS * 2") shouldBe "6"
          values("sizeof(p->name) > 8") shouldBe "1"
      }

      "give a macro constant its value" in {
          // the INLINED call that stands for the expansion, and the expansion inside it
          val macroCall = cpg.call.nameExact("N").l
          macroCall.map(valueOf) shouldBe List(Some("32"))
          macroCall.ast.isCall.nameExact("<operator>.multiplication").map(valueOf).l shouldBe
              List(Some("32"))
      }

      "wrap an unsigned value at its width" in {
          values("(unsigned int)-1") shouldBe "4294967295"
      }

      "leave literals and non-constant expressions alone" in {
          values.contains("a + 1") shouldBe false
          // a const volatile object can change under the program
          values.contains("REG + 1") shouldBe false
          values.contains("a ? 1 : 2") shouldBe false
          cpg.literal.filter(l => valueOf(l).isDefined).size shouldBe 0
      }
  }

  "a constant read inside a macro argument" should {
      val cpg = code(
        """
          |#define TWICE(x) ((x) * 2)
          |void use(unsigned long);
          |void run(void) { use(TWICE(sizeof(int))); }
          |""".stripMargin,
        "macro_arg.c"
      )

      "keep its value on every copy the graph holds" in {
          val sizes = cpg.call.nameExact("<operator>.sizeOf").l
          sizes should not be empty
          sizes.map(valueOf).distinct shouldBe List(Some("4"))
          sizes.foreach(_._astIn.hasNext shouldBe true)
          cpg.call.nameExact("TWICE").map(valueOf).l shouldBe List(Some("8"))
      }
  }

  "sizes for an LLP64 target" should {
      val cpg = code(
        "void use(int);\nvoid run(void) { use(sizeof(long)); use(sizeof(void *)); }",
        "win.c"
      )
          .moreCode(
            """[{"directory": ".", "file": "win.c", "arguments": ["cl.exe", "/c", "win.c"]}]""",
            "compile_commands.json"
          ).withConfig(Config().withCompileCommands("compile_commands.json"))

      "come from the target's compiler, not the host" in {
          val values = valuesByCode(cpg)
          values("sizeof(long)") shouldBe "4"
          values("sizeof(void *)") shouldBe "8"
      }
  }
end ConstantValueTests
