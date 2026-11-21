package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{CompileCommand, FileDefaults, SourceLanguage}
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.testfixtures.DefaultTestCpg
import io.shiftleft.semanticcpg.language.*

import java.nio.file.Paths
import scala.jdk.CollectionConverters.*

/** The build-context record: the FILE node of every file a C front end parsed carries one
  * `build-context` tag. A translation unit's tag is the fingerprint of the compile command the
  * graph was built from, so of the two database entries that compile one file with different
  * definitions it names the one whose code is in the graph. A header's tag names the unit whose
  * parse it was read with, then that unit's fingerprint.
  */
class BuildContextTests extends CCodeToCpgSuite(FileDefaults.C_EXT):

  private val fixtureDir = File(
    Paths.get(getClass.getClassLoader.getResource("contexts/two-includers/window.c").toURI)
  ).parent

  private def sourceOf(name: String): String = (fixtureDir / name).contentAsString

  private def database(entries: String*): String = entries.mkString("[", ",", "]")

  private def entry(file: String, command: String): String =
      s"""{"directory": ".", "file": "$file", "command": "$command"}"""

  /** The fixture's compilation database, which compiles `window.c` twice with different
    * definitions: the first entry selects the wide window, the second the narrow one.
    */
  private val duplicate = code(
    sourceOf("window.c"),
    "window.c"
  ).moreCode(sourceOf("window.h"), "window.h")
      .moreCode(
        database(
          entry("window.c", "cc -DWINDOW_WIDE -c window.c"),
          entry("window.c", "cc -DWINDOW_TALL -c window.c")
        ),
        "compile_commands.json"
      )
      .withConfig(Config().withCompileCommands("compile_commands.json"))

  /** The look-alike: the same project, a database with no duplicates. */
  private val lookalike = code(
    sourceOf("window.c"),
    "window.c"
  ).moreCode(sourceOf("window.h"), "window.h")
      .moreCode(
        database(entry("window.c", "cc -DWINDOW_WIDE -c window.c")),
        "compile_commands.json"
      )
      .withConfig(Config().withCompileCommands("compile_commands.json"))

  private def tagsOf(cpg: DefaultTestCpg, file: String): List[String] =
      cpg.file.name(file).tag.nameExact(X2CpgDefines.BuildContextTag).value.l

  /** The graph's nodes by label and edges by type, without the tags this record adds: two graphs
    * are the same graph when this is equal.
    */
  private def shapeOf(cpg: DefaultTestCpg): (Map[String, Int], Map[String, Int]) =
    val nodes  = cpg.graph.nodes().asScala.toSeq
    val out    = nodes.flatMap(n => n.outE().asScala.toSeq)
    val labels = nodes.groupBy(_.label()).view.mapValues(_.size).toMap - "TAG"
    val edges  = out.groupBy(_.label()).view.mapValues(_.size).toMap - "TAGGED_BY"
    (labels, edges)

  "the build context of a unit compiled twice" should {

      "carry the fingerprint of the entry the graph was built from on the unit's FILE node" in {
          duplicate.file.name("window.c").l should have size 1
          // the two entries fingerprint differently, and the graph names the first one's
          val wide = fingerprintOf("cc -DWINDOW_WIDE -c window.c")
          val tall = fingerprintOf("cc -DWINDOW_TALL -c window.c")
          wide should not be tall
          tagsOf(duplicate, "window.c") shouldBe List(wide)
      }

      "name the context whose code is in the graph: the wide window, not the narrow one" in {
          // first entry wins: WINDOW_WIDE is in the graph, WINDOW_TALL is not, and the tag
          // is the fingerprint of the entry that put it there
          duplicate.literal.code.l should contain("4096")
          duplicate.literal.code.l should not contain "64"
          tagsOf(duplicate, "window.c") should not be empty
      }

      "value a header's tag with its owner unit and the owner's fingerprint" in {
          duplicate.file.name("window.h").l should have size 1
          val headerTags = tagsOf(duplicate, "window.h")
          headerTags shouldBe s"window.c:${tagsOf(duplicate, "window.c").head}" :: Nil
      }

      "give every file of the look-alike project its tag, on no other FILE node" in {
          tagsOf(lookalike, "window.c") should have size 1
          tagsOf(lookalike, "window.h") shouldBe
              s"window.c:${tagsOf(lookalike, "window.c").head}" :: Nil
          // two tags for the two parsed files; the synthetic FILE nodes of the graph
          // (`<includes>`, `<unknown>`) name no file and carry none
          lookalike.tag.nameExact(X2CpgDefines.BuildContextTag).l should have size 2
      }
  }

  "a database with no duplicates" should {
      "build the same graph as the duplicate database, apart from the build-context tags" in {
          shapeOf(lookalike) shouldBe shapeOf(duplicate)
      }

      "keep every node and edge the project had, and add only the FILE tags" in {
          val (labels, edges) = shapeOf(lookalike)
          labels shouldBe Map(
            "NAMESPACE_BLOCK"      -> 4,
            "IMPORT"               -> 1,
            "TYPE_DECL"            -> 5,
            "METHOD_PARAMETER_OUT" -> 1,
            "NAMESPACE"            -> 1,
            "BINDING"              -> 1,
            "LITERAL"              -> 1,
            "METHOD_RETURN"        -> 5,
            "BLOCK"                -> 6,
            "METHOD_PARAMETER_IN"  -> 1,
            "META_DATA"            -> 1,
            "CALL"                 -> 1,
            "METHOD"               -> 5,
            "RETURN"               -> 1,
            "FILE"                 -> 4,
            "DEPENDENCY"           -> 1,
            "TYPE"                 -> 3
          )
          edges shouldBe Map(
            "IMPORTS"        -> 1,
            "REF"            -> 8,
            "CONTAINS"       -> 16,
            "CALL"           -> 1,
            "POST_DOMINATE"  -> 8,
            "AST"            -> 28,
            "DOMINATE"       -> 8,
            "SOURCE_FILE"    -> 13,
            "ARGUMENT"       -> 1,
            "CFG"            -> 8,
            "BINDS"          -> 1,
            "PARAMETER_LINK" -> 1,
            "EVAL_TYPE"      -> 13
          )
      }
  }

  /** The fingerprint a command line gives, read the way a database entry's command is read. */
  private def fingerprintOf(command: String): String =
      BuildContextPass.fingerprintOf(
        CompileCommand.parseArguments(CompileCommand.tokenize(command), Paths.get(".")),
        Paths.get(".").toAbsolutePath.normalize
      )

  "a header two units include" should {

      /** Two units include the one header, each compiled with its own definition. */
      val both = code(sourceOf("window.c"), "window.c")
          .moreCode(sourceOf("frame.c"), "frame.c")
          .moreCode(sourceOf("window.h"), "window.h")
          .moreCode(
            database(
              entry("frame.c", "cc -DWINDOW_WIDE -c frame.c"),
              entry("window.c", "cc -DWINDOW_TALL -c window.c")
            ),
            "compile_commands.json"
          )
          .withConfig(Config().withCompileCommands("compile_commands.json"))

      "name the first includer in path order, not the last" in {
          val frame  = fingerprintOf("cc -DWINDOW_WIDE -c frame.c")
          val window = fingerprintOf("cc -DWINDOW_TALL -c window.c")
          frame should not be window
          // frame.c sorts before window.c: the header names the first unit of its language
          // that includes it, and each unit names its own command's fingerprint
          tagsOf(both, "window.h") shouldBe List(s"frame.c:$frame")
          tagsOf(both, "window.h") should not be List(s"window.c:$window")
          tagsOf(both, "frame.c") shouldBe List(frame)
          tagsOf(both, "window.c") shouldBe List(window)
      }
  }

  "a header no unit includes" should {

      "carry its own settings fingerprint, with no owner named" in {
          val own = code(sourceOf("window.c"), "window.c").moreCode(
            sourceOf("window.h"),
            "window.h"
          ).moreCode(sourceOf("orphan.h"), "orphan.h")
          val configured = BuildContextPass.fingerprintOf(Config(), SourceLanguage.C)
          // nothing claims the orphan header: no owner to name, its own settings stand in
          tagsOf(own, "orphan.h") shouldBe List(configured)
          tagsOf(own, "orphan.h") should not be List(s"window.c:$configured")
      }
  }

  "a project no compilation database compiles" should {

      "tag each file with the fingerprint of its configured settings" in {
          val plain =
              code(sourceOf("window.c"), "window.c").moreCode(sourceOf("window.h"), "window.h")
          val configured = BuildContextPass.fingerprintOf(Config(), SourceLanguage.C)
          tagsOf(plain, "window.c") shouldBe List(configured)
          // the header names the unit that includes it and that unit's fingerprint
          tagsOf(plain, "window.h") shouldBe List(s"window.c:$configured")
      }
  }

  "the context fingerprint" should {

      "distinguish the two definitions the fixture's duplicate entry spells" in {
          fingerprintOf("cc -DWINDOW_WIDE -c window.c") should not be
              fingerprintOf("cc -DWINDOW_TALL -c window.c")
      }

      "read one context from commands that differ in what no part of the program reads" in {
          fingerprintOf("cc -c window.c") shouldBe
              fingerprintOf("cc -o out/window.o -g -Wall -Werror -MMD -c window.c")
      }

      "distinguish a different definition removal, language, standard and include path" in {
          fingerprintOf("cc -DWINDOW_WIDE -c window.c") should not be
              fingerprintOf("cc -DWINDOW_WIDE -UWINDOW_WIDE -c window.c")
          fingerprintOf("cc -c window.c") should not be fingerprintOf("cc -x c++ -c window.c")
          fingerprintOf("cc -c window.c") should not be fingerprintOf("cc -std=c11 -c window.c")
          fingerprintOf("cc -Iinclude -c window.c") should not be
              fingerprintOf("cc -Iother -c window.c")
      }

      "read one context from the joined and separated spellings of one option's value" in {
          fingerprintOf("cc -Iinclude -c window.c") shouldBe
              fingerprintOf("cc -I include -c window.c")
          fingerprintOf("cc -DWINDOW_WIDE -c window.c") shouldBe
              fingerprintOf("cc -D WINDOW_WIDE -c window.c")
      }

      "read definitions of distinct macros in any order as one context, and keep order otherwise" in {
          fingerprintOf("cc -DA -DB=2 -c window.c") shouldBe fingerprintOf(
            "cc -DB=2 -DA -c window.c"
          )
          fingerprintOf("cc -DA -UA -c window.c") should not be
              fingerprintOf("cc -UA -DA -c window.c")
      }

      "distinguish the configured settings of a unit no database compiles" in {
          val plain = BuildContextPass.fingerprintOf(Config(), SourceLanguage.C)
          plain shouldBe BuildContextPass.fingerprintOf(Config(), SourceLanguage.C)
          plain should not be BuildContextPass.fingerprintOf(
            Config().withDefines(Set("WINDOW_WIDE")),
            SourceLanguage.C
          )
          plain should not be BuildContextPass.fingerprintOf(
            Config().withIncludePaths(Set("extra")),
            SourceLanguage.C
          )
          plain should not be BuildContextPass.fingerprintOf(Config(), SourceLanguage.Cpp)
      }
  }
end BuildContextTests
