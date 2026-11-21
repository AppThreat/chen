package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.c2cpg.parser.CompileDatabase
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.passes.frontend.CacheControl
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The build-context tags over the AST cache: the tag is rebuilt on every run from the compilation
  * database and the header owners, which no cache carries, so a run over a project the cache covers
  * gives the tags the fresh parse gave. Both cache codecs are tried, the per-file bitcode and the
  * fragment.
  */
class BuildContextWarmCacheTests extends AnyWordSpec with Matchers:

  private val fixtureDir = File(
    java.nio.file.Paths.get(
      getClass.getClassLoader.getResource("contexts/two-includers/window.c").toURI
    )
  ).parent

  private def writeProject(root: File): Unit =
    (root / "window.c").write((fixtureDir / "window.c").contentAsString)
    (root / "window.h").write((fixtureDir / "window.h").contentAsString)
    (root / CompileDatabase.FileName).write(
      """[
        |  {"directory": ".", "file": "window.c", "command": "cc -DWINDOW_WIDE -c window.c"},
        |  {"directory": ".", "file": "window.c", "command": "cc -DWINDOW_TALL -c window.c"}
        |]""".stripMargin
    )

  private def build(root: File): Cpg =
    val out = File.newTemporaryFile("c2bcache", ".bin")
    out.deleteOnExit()
    new C2Cpg().createCpg(
      Config()
          .withInputPath(root.pathAsString)
          .withOutputPath(out.pathAsString)
          .withCompileCommands(root.pathAsString)
          .withFunctionBodies(true)
          .withIncludeComments(true)
    ).get

  private def tagsOf(cpg: Cpg): Map[String, List[String]] =
      cpg.file.l
          .map(f => f.name -> f.tag.nameExact(X2CpgDefines.BuildContextTag).value.l)
          .toMap

  "the build-context tags over the AST cache" should:

    "be the same on the run over the cached project as on the fresh parse, bitcode cache" in:
      File.usingTemporaryDirectory("c2bcache") { root =>
        writeProject(root)
        val cold     = build(root)
        val coldTags = tagsOf(cold)
        cold.close()
        (root / ".chen").glob("*.ast").toList should not be empty
        val warm     = build(root)
        val warmTags = tagsOf(warm)
        warm.close()
        warmTags shouldBe coldTags
        warmTags("window.c") should have size 1
        warmTags("window.h") shouldBe s"window.c:${warmTags("window.c").head}" :: Nil
      }

    "be the same on the run over the cached project as on the fresh parse, fragments" in:
      CacheControl.enableFragments()
      try
          File.usingTemporaryDirectory("c2bcachefrag") { root =>
            writeProject(root)
            val cold     = build(root)
            val coldTags = tagsOf(cold)
            cold.close()
            (root / ".chen").glob("*.frag").toList should not be empty
            val warm     = build(root)
            val warmTags = tagsOf(warm)
            warm.close()
            warmTags shouldBe coldTags
            warmTags("window.h") shouldBe s"window.c:${warmTags("window.c").head}" :: Nil
          }
      finally CacheControl.disableFragments()
end BuildContextWarmCacheTests
