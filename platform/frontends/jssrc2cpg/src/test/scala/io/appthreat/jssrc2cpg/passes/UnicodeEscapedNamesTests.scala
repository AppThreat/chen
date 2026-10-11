package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.testfixtures.JsSrc2CpgSuite
import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.passes.taggers.SourceIntegrityPass
import io.shiftleft.semanticcpg.language.*

/** A JavaScript identifier may spell its characters with Unicode escapes: `eval(x)` calls `eval`.
  * The CPG names it as the program means it and keeps the spelling in its code, which
  * SourceIntegrityPass tags `unicode-confusable`.
  */
class UnicodeEscapedNamesTests extends JsSrc2CpgSuite:

  private val bs = "\\"

  "names spelled with Unicode escapes" should {
      val cpg = code(
        s"""var r = ${bs}u0065val("1+1");
           |var ${bs}u{61}b = 2;
           |var o = { run: function (x) { return x; } };
           |o.${bs}u0072un(ab);
           |""".stripMargin
      )
      new SourceIntegrityPass(cpg).createAndApply()

      "be named as the program means them" in {
          cpg.call.nameExact("eval").code.l shouldBe List(s"${bs}u0065val(\"1+1\")")
          cpg.call.nameExact("run").code.l shouldBe List(s"o.${bs}u0072un(ab)")
          cpg.identifier.nameExact("ab").size shouldBe 2
          cpg.fieldAccess.fieldIdentifier.canonicalName.l should contain("run")
      }

      "be tagged with their spelling" in {
          def spellings(
            nodes: Iterator[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          ) =
              nodes.flatMap(_.tag.nameExact(Defines.UnicodeConfusableTag).value).toSet
          spellings(cpg.call.nameExact("eval")) shouldBe Set(s"${bs}u0065val")
          spellings(cpg.call.nameExact("run")) shouldBe Set(s"${bs}u0072un")
          spellings(cpg.identifier.nameExact("ab")) shouldBe Set(s"${bs}u{61}b")
          spellings(cpg.call.nameExact("<operator>.assignment")) shouldBe Set()
      }
  }
end UnicodeEscapedNamesTests
