package io.appthreat.edg2atom.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{CompileCommand, CompileDatabase}
import io.appthreat.c2cpg.passes.BuildContextPass
import io.appthreat.edg2atom.Edg2Atom
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Paths
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** The build-context record this frontend writes: the FILE node of each translation unit carries
  * the fingerprint of the compile command the graph was built from, and the FILE node of each
  * header names the unit whose parse it was written with and that unit's fingerprint. Of the
  * database entries that compile one file with different definitions, the tag names the one whose
  * code the graph holds.
  */
class EdgBuildContextTests extends AnyWordSpec with Matchers:

  private val fixtureDir = File(
    Paths.get(getClass.getClassLoader.getResource("contexts/two-includers/window.c").toURI)
  ).parent

  private val duplicateDatabase =
      """[
        |  {"directory": ".", "file": "window.c", "command": "cc -DWINDOW_WIDE -c window.c"},
        |  {"directory": ".", "file": "window.c", "command": "cc -DWINDOW_TALL -c window.c"}
        |]""".stripMargin

  /** The look-alike: the same project, a database with no duplicates. */
  private val singleEntryDatabase =
      """[
        |  {"directory": ".", "file": "window.c", "command": "cc -DWINDOW_WIDE -c window.c"}
        |]""".stripMargin

  /** Two units include the one header, each compiled with its own definition. */
  private val twoIncluderDatabase =
      """[
        |  {"directory": ".", "file": "frame.c", "command": "cc -DWINDOW_WIDE -c frame.c"},
        |  {"directory": ".", "file": "window.c", "command": "cc -DWINDOW_TALL -c window.c"}
        |]""".stripMargin

  private def graph(root: File, database: String)(check: Cpg => Unit): Unit =
    fixtureDir.children
        .filter(f => f.extension.exists(Seq(".c", ".h").contains))
        .foreach(file => (root / file.name).write(file.contentAsString))
    (root / CompileDatabase.FileName).write(database)
    val out = File.newTemporaryFile("edgbctx", ".bin")
    out.deleteOnExit()
    val cpg = new Edg2Atom().createCpg(
      Config()
          .withInputPath(root.pathAsString)
          .withOutputPath(out.pathAsString)
          .withCompileCommands(root.pathAsString)
          .withFunctionBodies(true)
    ).get
    try check(cpg)
    finally cpg.close()

  private def tagsOf(cpg: Cpg, file: String): List[String] =
      cpg.file.name(file).tag.nameExact(X2CpgDefines.BuildContextTag).value.l

  private def allTagsOf(cpg: Cpg): Map[String, List[String]] =
      cpg.file.l
          .map(f => f.name -> f.tag.nameExact(X2CpgDefines.BuildContextTag).value.l)
          .toMap

  /** The graph's nodes by label and edges by type, without the tags this record adds: two graphs
    * are the same graph when this is equal.
    */
  private def shapeOf(cpg: Cpg): (Map[String, Int], Map[String, Int]) =
    val nodes  = cpg.graph.nodes().asScala.toSeq
    val out    = nodes.flatMap(n => Try(n.outE().asScala.toSeq).getOrElse(Nil))
    val labels = nodes.groupBy(_.label()).view.mapValues(_.size).toMap - "TAG"
    val edges  = out.groupBy(_.label()).view.mapValues(_.size).toMap - "TAGGED_BY"
    (labels, edges)

  private def shapeOf(root: File, database: String): (Map[String, Int], Map[String, Int]) =
    var shape: (Map[String, Int], Map[String, Int]) = (Map.empty, Map.empty)
    graph(root, database)(cpg => shape = shapeOf(cpg))
    shape

  private def fingerprintOf(command: String): String =
      BuildContextPass.fingerprintOf(
        CompileCommand.parseArguments(CompileCommand.tokenize(command), Paths.get(".")),
        Paths.get(".").toAbsolutePath.normalize
      )

  "the build context of the unit edga exports" should {

      "carry the fingerprint of the entry the graph was built from on the unit's FILE node" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edgbctx") { root =>
              graph(root, duplicateDatabase) { cpg =>
                // first entry wins: the wide window's edge is in the graph, the narrow one is not
                cpg.literal.code.l should contain("4096")
                cpg.literal.code.l should not contain "64"
                tagsOf(cpg, "window.c") shouldBe List(
                  fingerprintOf("cc -DWINDOW_WIDE -c window.c")
                )
              }
          }
      }

      "value a header's tag with its owner unit and the owner's fingerprint" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edgbctx") { root =>
              graph(root, duplicateDatabase) { cpg =>
                  tagsOf(cpg, "window.h") shouldBe
                      s"window.c:${fingerprintOf("cc -DWINDOW_WIDE -c window.c")}" :: Nil
              }
          }
      }

      "give a run over the cached project the tags the fresh parse gave" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edgbctxwarm") { root =>
            (root / "window.c").write((fixtureDir / "window.c").contentAsString)
            (root / "window.h").write((fixtureDir / "window.h").contentAsString)
            (root / CompileDatabase.FileName).write(duplicateDatabase)

            def build(): Cpg =
              val out = File.newTemporaryFile("edgbctxwarm", ".bin")
              out.deleteOnExit()
              new Edg2Atom().createCpg(
                Config()
                    .withInputPath(root.pathAsString)
                    .withOutputPath(out.pathAsString)
                    .withCompileCommands(root.pathAsString)
                    .withFunctionBodies(true)
              ).get

            val cold     = build()
            val coldTags = allTagsOf(cold)
            cold.close()
            (root / ".chen").glob("*.ast").toList should not be empty
            val warm     = build()
            val warmTags = allTagsOf(warm)
            warm.close()
            warmTags shouldBe coldTags
            warmTags("window.c") should have size 1
            warmTags("window.h") shouldBe s"window.c:${warmTags("window.c").head}" :: Nil
          }
      }
  }

  "a database with no duplicates" should {

      "build the same graph as the duplicate database, apart from the build-context tags" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edgbctxone") { one =>
              File.usingTemporaryDirectory("edgbctxdup") { dup =>
                  shapeOf(one, singleEntryDatabase) shouldBe
                      shapeOf(dup, duplicateDatabase)
              }
          }
      }
  }

  "a header two units include" should {

      "name the first includer in path order, the unit whose parse wrote it" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edgbincl") { root =>
              graph(root, twoIncluderDatabase) { cpg =>
                val frame  = fingerprintOf("cc -DWINDOW_WIDE -c frame.c")
                val window = fingerprintOf("cc -DWINDOW_TALL -c window.c")
                frame should not be window
                // frame.c sorts before window.c: the header names the first unit of its
                // language that includes it, and each unit names its own command
                tagsOf(cpg, "window.h") shouldBe List(s"frame.c:$frame")
                tagsOf(cpg, "window.h") should not be List(s"window.c:$window")
                tagsOf(cpg, "frame.c") shouldBe List(frame)
                tagsOf(cpg, "window.c") shouldBe List(window)
              }
          }
      }
  }
end EdgBuildContextTests
