package io.appthreat.edg2atom.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.edg2atom.Edg2Atom
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** A project header is attributed to the project over real paths, not by the spelling each side of
  * the comparison carries (atom#390). edga's `inRoot` flag compares the header's path with the
  * project root byte by byte, so it comes out false when one side spells the directory differently
  * from the other: the 8.3 short name a temporary directory carries on Windows (`RUNNER~1`) against
  * its long one, or the same file named through a redundant segment. The exporter's flag then hides
  * a header the project owns.
  *
  * The stub answers `--edga-version` and exports one canned unit whose header entry names an
  * existing file through a redundant segment and carries `inRoot: false`, as edga reports a header
  * of a directory spelled two ways. Everything else in the pipeline real-paths its paths already
  * (the header's owner, the unit that writes it), so the flag is the only gate the test turns: the
  * header is dropped while attribution trusts the spelling, and written once it is decided over
  * real paths. The redundant segment stands in for the short name, which only a Windows runner can
  * spell; both call for the same reconciliation, and neither needs symlinks or privileges.
  */
class EdgShortNameAttributionTests extends AnyWordSpec with Matchers:

  private val main   = "main.c"     -> "#include \"proj_hdr.h\"\nint main(void) { return 0; }\n"
  private val header = "proj_hdr.h" -> "int h(void);\nint h(void) { return 42; }\n"

  private def project(files: (String, String)*)(test: File => Unit): Unit =
      File.usingTemporaryDirectory("edg2atom") { dir =>
        files.foreach { (name, text) =>
            (dir / name).createIfNotExists(createParents = true).writeText(text)
        }
        test(dir)
      }

  private def graph(dir: File)(check: Cpg => Unit): Unit =
    val out = File.newTemporaryFile("edg2atom", ".atom")
    val config = Config().withInputPath(dir.pathAsString).withOutputPath(out.pathAsString)
        .withFunctionBodies(true)
    val cpg = new Edg2Atom().createCpg(config).get
    try check(cpg)
    finally
      cpg.close()
      out.delete(swallowIOExceptions = true)

  /** The unit the stub exports: `h` is defined in the header, whose entry names the real file
    * through a redundant segment and carries the false `inRoot` a byte-by-byte comparison leaves
    * when the two sides spell the directory differently.
    */
  private def cannedUnit(dir: File): String =
    // the project root, spelled as the runner gives it and with the separators JSON needs
    val dirPath = dir.pathAsString.replace("\\", "\\\\")
    s"""{
        |  "schema": "edga/1",
        |  "tu": { "path": "$dirPath/main.c", "language": "c", "status": "ok" },
        |  "files": [
        |    { "id": 0, "path": "$dirPath/main.c", "written": "main.c", "system": false, "inRoot": true },
        |    { "id": 1, "path": "$dirPath/./proj_hdr.h", "written": "proj_hdr.h", "system": false,
        |      "inRoot": false, "includedFrom": [0, 1], "systemInclude": false }
        |  ],
        |  "types": [
        |    { "id": 0, "kind": "routine", "name": "int (void)", "returns": 1, "params": [] },
        |    { "id": 1, "kind": "integer", "name": "int", "size": 4, "signed": true },
        |    { "id": 2, "kind": "routine", "name": "int (void)", "returns": 1, "params": [] }
        |  ],
        |  "routines": [
        |    {
        |      "id": 1, "name": "h", "qualifiedName": "h", "type": 0, "returnType": 1,
        |      "prototyped": true, "linkage": "external", "storage": "unspecified",
        |      "p": [1, 2, 5], "start": [1, 2, 1], "defined": true, "params": [],
        |      "body": {
        |        "k": "block", "p": [1, 2, 13], "end": [1, 2, 26],
        |        "stmts": [
        |          { "k": "return", "p": [1, 2, 15], "end": [1, 2, 24],
        |            "expr": { "k": "constant", "t": 1, "p": [1, 2, 22], "ck": "integer", "value": "42" } }
        |        ]
        |      }
        |    },
        |    {
        |      "id": 2, "name": "main", "qualifiedName": "main", "type": 2, "returnType": 1,
        |      "prototyped": true, "linkage": "external", "storage": "unspecified",
        |      "p": [0, 2, 5], "start": [0, 2, 1], "defined": true, "params": [],
        |      "body": {
        |        "k": "block", "p": [0, 2, 16], "end": [0, 2, 28],
        |        "stmts": [
        |          { "k": "return", "p": [0, 2, 18], "end": [0, 2, 26],
        |            "expr": { "k": "constant", "t": 1, "p": [0, 2, 25], "ck": "integer", "value": "0" } }
        |        ]
        |      }
        |    }
        |  ],
        |  "diagnostics": []
        |}""".stripMargin
  end cannedUnit

  /** Runs `test` with edga replaced by a program that exports the canned unit. The twin of the
    * failing stub the AST cache tests use, in its shell and `.bat` forms.
    */
  private def withStubEdga(dir: File)(test: => Unit): Unit =
    val doc = dir / "edga-stub-unit.json"
    doc.writeText(cannedUnit(dir))
    val fake = dir / (if scala.util.Properties.isWin then "fake-edga.bat" else "fake-edga")
    if scala.util.Properties.isWin then
      fake.writeText(
        s"""@echo off
            |if "%~1"=="--edga-version" (
            |  echo edga-stub
            |  exit /b 0
            |)
            |set NEXTOUT=
            |set OUT=
            |for %%a in (%*) do (
            |  if defined NEXTOUT (
            |    set "OUT=%%~a"
            |    set NEXTOUT=
            |  ) else if "%%~a"=="--edga-out" set NEXTOUT=1
            |)
            |if not defined OUT exit /b 4
            |copy /y "${doc.pathAsString}" "%OUT%" >nul
            |exit /b 0
            |""".stripMargin.replace("\n", "\r\n")
      )
    else
      fake.writeText(
        s"""#!/bin/sh
            |if [ "$$1" = "--edga-version" ]; then
            |  echo edga-stub
            |  exit 0
            |fi
            |out=
            |prev=
            |for a in "$$@"; do
            |  if [ "$$prev" = "--edga-out" ]; then out=$$a; fi
            |  prev=$$a
            |done
            |if [ -z "$$out" ]; then
            |  exit 4
            |fi
            |cp "${doc.pathAsString}" "$$out"
            |""".stripMargin
      )
      fake.toJava.setExecutable(true)
    end if
    val saved = sys.props.get("edga.path")
    sys.props("edga.path") = fake.pathAsString
    try test
    finally saved match
          case Some(p) => sys.props("edga.path") = p
          case None    => sys.props.remove("edga.path")
  end withStubEdga

  "a project header the exporter's root check misses" should {
      "still be written, named by its real path in the project" in {
          project(main, header) { dir =>
              withStubEdga(dir) {
                  graph(dir) { cpg =>
                    val h = cpg.method.nameExact("h").filter(_.block.astChildren.nonEmpty).l
                    h.size shouldBe 1
                    h.head.filename shouldBe "proj_hdr.h"
                    // the unit itself is unaffected
                    cpg.method.nameExact("main").filter(_.block.astChildren.nonEmpty).size shouldBe 1
                  }
              }
          }
      }
  }
end EdgShortNameAttributionTests
