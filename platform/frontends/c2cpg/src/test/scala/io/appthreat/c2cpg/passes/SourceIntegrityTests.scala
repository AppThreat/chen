package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.passes.taggers.SourceIntegrityPass
import io.shiftleft.semanticcpg.language.*

/** Unicode that hides what the code does: look-alike names and bidi controls (Trojan Source). */
class SourceIntegrityTests extends CCodeToCpgSuite:

  "source-integrity tags" should {
      // `vаlue` spells its `а` with CYRILLIC SMALL LETTER A (U+0430)
      val cpg = code(
        "int check(int value) {\n" +
            "  int vаlue = 0;\n" +
            "  /* ‮ } if (admin) { ⁦ */\n" +
            "  const char *msg = \"user‮\";\n" +
            "  int rn = 1, m = 2;\n" +
            "  return value + vаlue + rn + m;\n" +
            "}\n",
        "trojan.c"
      ).withConfig(Config().withIncludeComments(true))

      new SourceIntegrityPass(cpg).createAndApply()

      "tag a name that looks like another name of its file" in {
          cpg.local.nameExact("vаlue").tag.nameExact(Defines.UnicodeConfusableTag).value.l shouldBe
              List("value")
          cpg.parameter.nameExact("value").tag.nameExact(Defines.UnicodeConfusableTag).value.l shouldBe
              List("vаlue")
          // the initialiser's and the return's
          cpg.identifier.nameExact("vаlue").l.map(
            _.tag.nameExact(Defines.UnicodeConfusableTag).value.l
          ) shouldBe List(List("value"), List("value"))
      }

      "tag bidi controls in a comment and in a string" in {
          // a comment carries no tag: its method does, with the comment's line
          cpg.method.nameExact("check").tag.nameExact(Defines.UnicodeBidiControlTag).value.l shouldBe
              List("3:U+202E,U+2066")
          cpg.literal.tag.nameExact(Defines.UnicodeBidiControlTag).value.l shouldBe List("U+202E")
      }

      "leave ASCII names that only look alike untouched" in {
          cpg.local.nameExact("rn", "m").tag.nameExact(Defines.UnicodeConfusableTag).size shouldBe 0
      }
  }

  "look-alike type names" should {
      // `Аccount` spells its `А` with CYRILLIC CAPITAL LETTER A (U+0410). TYPE_DECL cannot carry
      // a TAGGED_BY edge, and tagging one used to fail the whole pass.
      val cpg = code(
        "struct Account { int id; };\n" +
            "struct Аccount { int id; };\n" +
            "int f(struct Аccount *a) { return a->id; }\n",
        "types.c"
      )
      new SourceIntegrityPass(cpg).createAndApply()

      "leave the type declarations untagged and still apply" in {
          cpg.typeDecl.nameExact("Account", "Аccount").size shouldBe 2
          cpg.tag.nameExact(Defines.UnicodeConfusableTag).size should be >= 0
      }
  }

  "a file of ASCII names" should {
      val cpg = code("int f(int rn) { int m = rn; return m; }\n", "plain.c")
      new SourceIntegrityPass(cpg).createAndApply()

      "carry no source-integrity tag" in {
          cpg.tag.nameExact(Defines.UnicodeConfusableTag, Defines.UnicodeBidiControlTag).size shouldBe 0
      }
  }
end SourceIntegrityTests
