package io.appthreat.edg2atom.passes

import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.semanticcpg.language.*

class EdgCTestCpg extends DefaultTestCpgWithEdg(".c"):
  override protected def applyPasses(): Unit = X2Cpg.applyDefaultOverlays(this)

/** A member of a record that only a typedef names resolves through the record, so the extent rules
  * find the member's declared size where they found no members of the shared `<unnamed>` record.
  */
class MemorySafetyOnEdgTypedefRecordTests extends Code2CpgFixture(() => new EdgCTestCpg()):

  private lazy val cpg =
    val graph = code(
      """#include <string.h>
      |typedef struct { float lo, hi; } range;
      |typedef struct { int nHsync; range hsync[8]; char name[4]; } MonRec, *MonPtr;
      |typedef struct { char other[64]; } Other;
      |Other unused_other;
      |void f(MonPtr m, const char *user) { strcpy(m->name, user); }
      |""".stripMargin,
      "mon.c"
    )
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    graph

  "the extent of a member through a typedef'd anonymous record" should {
      "resolve through the record the typedef names" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          cpg.typeDecl.nameExact("MonRec").member.name.l should contain("hsync")
          cpg.typeDecl.nameExact("MonRec").member.nameExact("name").typeFullName.l shouldBe
              List("char[4]")
          cpg.typeDecl.nameExact("Other").member.name.l shouldBe List("other")
          cpg.typeDecl.nameExact("MonRec").member.nameExact("other").l shouldBe empty
      }
  }
end MemorySafetyOnEdgTypedefRecordTests
