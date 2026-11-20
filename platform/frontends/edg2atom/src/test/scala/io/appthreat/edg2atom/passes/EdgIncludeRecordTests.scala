package io.appthreat.edg2atom.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.Defines
import io.appthreat.edg2atom.Edg2Atom
import io.appthreat.edg2atom.parser.EdgaRunner
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The include record this frontend writes: the FILE node of each translation unit's primary source
  * file carries one `includes` tag per header the unit itself includes, and a header's own FILE
  * node carries none of the unit's. The names come from the include directives edga reports for the
  * primary file, which is where the IMPORT nodes the record is built from come from too.
  */
class EdgIncludeRecordTests extends AnyWordSpec with Matchers:

  private val libHeader  = "int lib_func(int x);\n"
  private val projHeader = "int proj_helper(int x);\n"
  private val mainC =
      """#include <stdio.h>
        |#include "libdir/lib.h"
        |#include "proj.h"
        |
        |int main(void) { return lib_func(proj_helper(1)); }
        |""".stripMargin

  private var atomFile: File = File("")

  private def graph(check: Cpg => Unit): Unit =
      File.usingTemporaryDirectory("edgincl") { root =>
        (root / "externlib" / "libdir").createDirectories()
        (root / "proj").createDirectories()
        (root / "externlib" / "libdir" / "lib.h").write(libHeader)
        (root / "proj" / "proj.h").write(projHeader)
        (root / "proj" / "main.c").write(mainC)
        atomFile = File.newTemporaryFile("edgincl", ".atom")
        atomFile.deleteOnExit()
        val cpg = new Edg2Atom().createCpg(
          Config()
              .withInputPath((root / "proj").pathAsString)
              .withOutputPath(atomFile.pathAsString)
              .withIncludePaths(Set((root / "externlib").pathAsString))
              .withAstCache(false)
              .withFunctionBodies(true)
        ).get
        try check(cpg)
        finally cpg.close()
      }

  "the include record" should {

      "tag the unit's FILE node with the basename of each header it includes" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          graph { cpg =>
              cpg.file.name("main.c").tag.nameExact(Defines.IncludesTag).value.l.sorted shouldBe
                  List("lib.h", "proj.h", "stdio.h")
          }
      }

      "write the includes on the FILE node that carries the frontend tag" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          graph { cpg =>
            val main = cpg.file.name("main.c").l
            main should have size 1
            main.head.tag.nameExact(FrontendTagPass.Tag).value.l shouldBe List("edg")
            main.head.tag.nameExact(Defines.IncludesTag).value.l should not be empty
          }
      }

      "leave a project header's FILE node without the unit's includes" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          graph { cpg =>
              cpg.file.name("proj.h").tag.nameExact(Defines.IncludesTag).value.l shouldBe empty
          }
      }
  }
end EdgIncludeRecordTests
