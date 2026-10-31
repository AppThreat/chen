package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.js.{
    JsFrameworkRecognizersPass,
    JsIndexes,
    JsPathAliases,
    JsStats
}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** The parsed path-alias configs are shared per graph: K config files are parsed exactly once for
  * the graph, however many passes hold a `JsPathAliases` and however many specifiers resolve
  * (chen#258). The resolutions themselves are pinned by the tagger snapshot suite.
  */
class JsPathAliasesTest extends DataFlowCodeToCpgSuite:

  /** A project of K packages, each with a tsconfig (one `paths` entry), a lib module and `files`
    * modules resolving the alias, `calls` aliasing call sites per module.
    */
  private def counted(k: Int, files: Int, calls: Int): (Int, Long, Long, Long, Int) =
    val all = (0 until k).flatMap { i =>
      val tsconfig =
          s"""{
               |  "compilerOptions": {
               |    "baseUrl": ".",
               |    "paths": { "@lib/*": ["./src/lib/*"] }
               |  }
               |}""".stripMargin -> s"pkg$i/tsconfig.json"
      val lib = s"export const v = () => $i;" -> s"pkg$i/src/lib/mod.js"
      val importers = (0 until files).map { f =>
        val specifiers = "import { v } from '@lib/mod';"
        val callsites  = (0 until calls).map(_ => "v();").mkString("\n")
        s"$specifiers\n$callsites" -> s"pkg$i/src/use$f.js"
      }
      tsconfig +: lib +: importers
    }
    val cpg = all.tail.foldLeft(code(all.head._1, all.head._2))((c, f) => c.moreCode(f._1, f._2))
    val configCount = cpg.configFile.size
    configCount should be >= k // the tsconfigs are among the config files of the graph

    def resolvedBy(holder: JsPathAliases): Int =
        (for
          i   <- 0 until k
          f   <- 0 until files
          hit <- holder.resolve(s"pkg$i/src/use$f.js", "@lib/mod")
        yield hit).size

    // the frontend's own import resolution parsed them already: forget the graph's cache and
    // count a run of the holder over the cleared graph
    JsIndexes.clear(cpg.graph)
    JsStats.reset()
    val first      = new JsPathAliases(cpg)
    val resolved   = resolvedBy(first)
    val parsedOnce = JsStats.get("compute.pathAliasConfig")

    // a second holder, the way a second pass builds its own, parses nothing
    JsStats.reset()
    resolvedBy(new JsPathAliases(cpg))
    val parsedBySecondHolder = JsStats.get("compute.pathAliasConfig")

    // a tagging run clears the per-graph indexes and parses the configs once for the whole pass
    JsStats.reset()
    new JsFrameworkRecognizersPass(cpg).createAndApply()
    val parsedByTaggingRun = JsStats.get("compute.pathAliasConfig")

    (configCount, parsedOnce, parsedBySecondHolder, parsedByTaggingRun, resolved)
  end counted

  "the path-alias configs" should {

      "parse exactly once per graph, however many specifiers resolve" in {
          val (configCount, parsedOnce, parsedBySecondHolder, parsedByTaggingRun, resolved) =
              counted(k = 4, files = 3, calls = 20)
          // one parse per config file, however many specifiers resolved
          parsedOnce shouldBe configCount
          // a second holder parses nothing: the parse is the graph's, not the holder's
          parsedBySecondHolder shouldBe 0L
          // a tagging run, which clears the per-graph indexes, parses them once for the run
          parsedByTaggingRun shouldBe configCount
          resolved shouldBe 4 * 3
      }
  }
end JsPathAliasesTest
