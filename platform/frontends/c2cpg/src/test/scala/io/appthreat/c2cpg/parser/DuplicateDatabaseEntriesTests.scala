package io.appthreat.c2cpg.parser

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The commands a compilation database carries for a file it names more than once: the first one is
  * the command the file has always been parsed with, and every entry is one build context of the
  * file.
  */
class DuplicateDatabaseEntriesTests extends AnyWordSpec with Matchers:

  private val database =
      """[
        |  {"directory": ".", "file": "selected-body.c", "command": "cc -DFAST_PATH -c selected-body.c"},
        |  {"directory": ".", "file": "helper.c", "command": "cc -c helper.c"},
        |  {"directory": ".", "file": "selected-body.c", "command": "cc -c selected-body.c"}
        |]""".stripMargin

  private def loaded(root: File): CompileDatabase =
    (root / CompileDatabase.FileName).write(database)
    CompileDatabase.load((root / CompileDatabase.FileName).path)

  private def fileIn(root: File, name: String): java.nio.file.Path =
      (root / name).path.normalize

  "a compilation database that names a file twice" should {

      "keep the first entry as the file's command, and its units free of duplicates" in {
          File.usingTemporaryDirectory("dupdb") { root =>
            val db     = loaded(root)
            val file   = fileIn(root, "selected-body.c")
            val helper = fileIn(root, "helper.c")
            (db.files should contain).theSameElementsInOrderAs(Seq(file, helper))
            db.commandFor(file).get.arguments shouldBe
                Seq("cc", "-DFAST_PATH", "-c", "selected-body.c")
          }
      }

      "list every entry's command for the file, in database order" in {
          File.usingTemporaryDirectory("dupdb") { root =>
            val db     = loaded(root)
            val file   = fileIn(root, "selected-body.c")
            val helper = fileIn(root, "helper.c")
            db.commandsFor(file).map(_.arguments) shouldBe Seq(
              Seq("cc", "-DFAST_PATH", "-c", "selected-body.c"),
              Seq("cc", "-c", "selected-body.c")
            )
            db.commandsFor(helper).map(_.arguments) shouldBe Seq(Seq("cc", "-c", "helper.c"))
            db.commandsFor(fileIn(root, "other.c")) shouldBe Nil
          }
      }
  }
end DuplicateDatabaseEntriesTests
