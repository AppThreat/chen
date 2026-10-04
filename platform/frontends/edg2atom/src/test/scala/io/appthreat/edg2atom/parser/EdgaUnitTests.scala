package io.appthreat.edg2atom.parser

import io.appthreat.edg2atom.parser.EdgaUnit.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class EdgaUnitTests extends AnyWordSpec with Matchers:

  private val document = EdgaUnit.parse(
    """{
      |  "schema": "edga/1",
      |  "tu": { "path": "/src/main.cpp", "status": "ok", "language": "c++" },
      |  "files": [
      |    { "id": 0, "path": "/src/main.cpp", "inRoot": true },
      |    { "id": 1, "path": "/usr/include/stdio.h", "system": true, "includedFrom": [0, 2] }
      |  ],
      |  "types": [ { "id": 0, "kind": "integer", "name": "int", "signed": true } ],
      |  "macros": [ { "id": 3, "name": "MIN", "text": "#define MIN(a, b) ((a) < (b) ? (a) : (b))" } ],
      |  "macroInvocations": [
      |    { "id": 1, "name": "MIN", "macro": 3, "parent": 0 },
      |    { "id": 2, "name": "INNER", "parent": 1 },
      |    { "id": 3, "name": "INNERMOST", "parent": 2 }
      |  ],
      |  "routines": [ { "id": 7, "name": "main", "p": [0, 4, 5], "k": "x", "zero": null } ],
      |  "globals": [],
      |  "diagnostics": []
      |}""".stripMargin
  )

  "a document" should {
      "describe its translation unit" in {
          document.path shouldBe "/src/main.cpp"
          document.status shouldBe "ok"
          document.isCpp shouldBe true
          document.primaryFile.map(_.path) shouldBe Some("/src/main.cpp")
      }

      "index its tables by id" in {
          document.files(1L) shouldBe FileEntry(
            1L,
            "/usr/include/stdio.h",
            true,
            false,
            Some((0L, 2))
          )
          document.types(0L).string("name") shouldBe Some("int")
          document.routinesById(7L).string("name") shouldBe Some("main")
      }

      "find the top-level invocation a nested one was expanded in" in {
          document.topLevelInvocation(3L) shouldBe 1L
          document.topLevelInvocation(1L) shouldBe 1L
      }
  }

  "the field helpers" should {
      val routine = document.routinesById(7L)

      "read positions and kinds" in {
          routine.position shouldBe Some(Pos(0L, 4, 5))
          routine.kind shouldBe "x"
      }

      "treat a null field as absent" in {
          routine.field("zero") shouldBe None
          routine.flag("missing") shouldBe false
          routine.list("missing") shouldBe Seq.empty
      }
  }

  "a failed or partial document" should {
      "default what it does not say" in {
          val bare = EdgaUnit.parse("""{ "tu": {} }""")
          bare.status shouldBe "failed"
          bare.language shouldBe "c"
          bare.routines shouldBe Seq.empty
          bare.primaryFile shouldBe None
      }
  }
end EdgaUnitTests
