package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcTestCpg
import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.passes.taggers.SourceIntegrityPass
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** Java translates Unicode escapes before it lexes (JLS 3.3): the CPG holds the code javac
  * compiles, and SourceIntegrityPass tags what the escapes hide. The pass reads the file, so it
  * runs while the test sources are still on disk.
  */
class UnicodeEscapeTests
    extends Code2CpgFixture(() =>
        new JavaSrcTestCpg():
          override def applyPasses(): Unit =
            super.applyPasses()
            new SourceIntegrityPass(this).createAndApply()
    ):

  private val bs = "\\"

  private val cpg = code(s"""
      |class Conf {
      |  int check(int value) {
      |    // ${bs}u000a value = 42;
      |    int ${bs}u0061b = 1;
      |    /* ${bs}u002a/ value = 7; /* */
      |    String s = "a${bs}u0041";
      |    return value + ab;
      |  }
      |}
      |""".stripMargin)

  "Unicode escapes" should {
      "be translated before the code is lexed" in {
          (cpg.call.nameExact(Operators.assignment).code.l should contain).allOf(
            "value = 42",
            "value = 7",
            "int ab = 1"
          )
          cpg.local.name.l should contain("ab")
          cpg.identifier.nameExact("ab").lineNumber.l shouldBe List(5, 8)
          cpg.literal.code.l should contain("\"aA\"")
      }

      "tag the method where they end a comment" in {
          cpg.method.nameExact("check").tag.nameExact(Defines.UnicodeHiddenCodeTag).value.l shouldBe
              List(s"4:${bs}u000a", s"6:${bs}u002a")
      }

      "tag a name with the spelling they give it" in {
          cpg.local.nameExact("ab").tag.nameExact(Defines.UnicodeConfusableTag).value.l shouldBe
              List(s"${bs}u0061b")
          cpg.identifier.nameExact("ab").lineNumber(5).tag.nameExact(Defines.UnicodeConfusableTag)
              .value.l shouldBe List(s"${bs}u0061b")
          cpg.identifier.nameExact("ab").lineNumber(8).tag.size shouldBe 0
      }
  }
end UnicodeEscapeTests
