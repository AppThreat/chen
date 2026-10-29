package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.appthreat.x2cpg.passes.taggers.js.JsStats
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

import java.nio.file.{Files, Path, Paths}
import scala.jdk.CollectionConverters.*

/** The tags the JS taggers put on real framework sources, byte for byte: the indexes and memos of
  * the taggers must change how fast they run, never what they find. Each fixture directory has a
  * golden file written by the tagger as it was before them. `UPDATE_GOLDEN=<dir>` writes fresh
  * goldens into `<dir>` (point it at this suite's `src/test/resources/js-tagger-snapshots`).
  *
  * Angular is a subset of the OWASP Juice Shop frontend; the React, Vue and DOM fixtures are small
  * apps that exercise the same bridges.
  */
class JsTaggerSnapshotTest extends DataFlowCodeToCpgSuite:

  private val root = Paths.get(getClass.getResource("/js-tagger-snapshots").toURI)

  private def sources(dir: String): List[(String, String)] =
    val base = root.resolve(dir)
    Files.walk(base).iterator().asScala.filter(Files.isRegularFile(_)).toList.sorted.map(p =>
        base.relativize(p).toString -> Files.readString(p)
    )

  /** Every tag the pipeline put on a node, with where the node is. */
  private def snapshot(dir: String): String =
    val files = sources(dir)
    val cpg: Cpg = files.tail.foldLeft(code(files.head._2, files.head._1))((c, f) =>
        c.moreCode(f._2, f._1)
    )
    JsStats.reset()
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg.tag.l.flatMap { t =>
        t._taggedByIn.map { n =>
          val file = scala.util.Try(
            n.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.CfgNode].method.filename
          ).getOrElse("?")
          val line = n.propertiesMap.getOrDefault("LINE_NUMBER", "?")
          val code = n.propertiesMap.getOrDefault("CODE", n.label).toString.replace('\n', ' ')
          s"${t.name}=${t.value}\t$file:$line\t${n.label}\t$code"
        }
    }.sorted.mkString("\n") + "\n"

  Seq("angular", "react", "vue", "dom").foreach { dir =>
      s"The $dir fixture" should {
          "carry exactly the tags the golden file records" in {
              val actual = snapshot(dir)
              sys.env.get("UPDATE_GOLDEN").foreach(out =>
                  Files.writeString(Paths.get(out).resolve(s"$dir.golden"), actual)
              )
              val golden = root.resolve(s"$dir.golden")
              withClue(s"$golden exists: ") { Files.exists(golden) shouldBe true }
              withClue(s"$dir has tags at all: ") { actual.linesIterator.size should be > 3 }
              // the lookups the fixture's framework makes go through the indexes
              if dir == "angular" then
                Seq("lookup.calls", "lookup.annotations", "lookup.methodsByFile").foreach(k =>
                    withClue(s"$k: ") { JsStats.get(k) should be > 0L }
                )
              actual shouldBe Files.readString(golden)
              // and two runs agree
              snapshot(dir) shouldBe actual
          }
      }
  }
end JsTaggerSnapshotTest
