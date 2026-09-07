package io.appthreat.pysrc2cpg

import io.appthreat.pythonparser.PyParser
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

import java.io.File
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.Using

/** In-process counterpart of the `~/sandbox/py-corpus` harness (P0.3): runs the grammar-corpus
  * assertions from the corpus files' `# CHEN-EXPECT:` headers, so CI catches parser regressions
  * without the built atom binary.
  *
  * The corpus lives in `src/test/resources/corpus/grammar` and mirrors
  * `~/sandbox/py-corpus/grammar`. Structural assertions (parse errors, node absence, control
  * structures) are evaluated here; the heavier framework/flow suite stays in the external harness.
  * An `# CHEN-EXPECT-XFAIL:` header marks a known-red assertion; when it starts passing the test
  * fails with a request to remove the -XFAIL.
  */
class PyCorpusRegressionTests extends AnyFreeSpec with Matchers:

  private val corpusDir = new File("src/test/resources/corpus/grammar")

  private case class Expectation(line: Int, xfail: Boolean, text: String)

  private val Header =
      """^#\s*CHEN-EXPECT(?<xfail>-XFAIL)?\s*:\s*(?<body>[^#]*?)\s*(?:#.*)?$""".r
  private val ControlStructure = """control-structure (\w+) count=(\d+)""".r
  private val NodeAbsent       = """node-absent (\w+).*""".r
  private val ParseErrorsCount = """parse-errors count=(\d+)""".r

  private def expectations(code: String): Seq[Expectation] =
      code.linesIterator.zipWithIndex.collect {
          case (l, i) if l.trim.startsWith("# CHEN-EXPECT") =>
              val m = Header
                  .findFirstMatchIn(l.trim)
                  .getOrElse(fail(s"Malformed CHEN-EXPECT header: $l"))
              Expectation(i + 1, m.group("xfail") != null, m.group("body"))
      }.toSeq

  private def corpusFiles: Seq[File] =
      Option(corpusDir.listFiles(_.getName.endsWith(".py")))
          .map(_.toSeq.sortBy(_.getName))
          .getOrElse(fail(s"corpus dir not found: ${corpusDir.getPath}"))

  // One CPG per corpus file, built lazily and only when a file carries a
  // graph-level assertion.
  private val cpgCache = mutable.Map.empty[File, Cpg]

  private def cpgFor(file: File, code: String): Cpg =
      cpgCache.getOrElseUpdate(file, Py2CpgTestContext.buildCpg(code, file.getName))

  private def evaluate(exp: Expectation, file: File, code: String): Boolean =
      exp.text match
        case "no-parse-errors" =>
            val parser = new PyParser()
            parser.parse(code)
            parser.errors.isEmpty
        case ParseErrorsCount(n) =>
            val parser = new PyParser()
            parser.parse(code)
            parser.errors.size == n.toInt
        case NodeAbsent("UNKNOWN") =>
            unknownNodeCount(cpgFor(file, code)) == 0
        case ControlStructure(csType, n) =>
            cpgFor(file, code).controlStructure.controlStructureType.l
                .count(_.toString == csType) == n.toInt
        case other =>
            fail(s"Assertion kind not supported by the in-repo harness: $other")

  private def unknownNodeCount(cpg: Cpg): Int =
      cpg.graph.nodes("UNKNOWN").asScala.size

  corpusFiles.foreach { file =>
    val code = Using.resource(scala.io.Source.fromFile(file))(_.mkString)
    val exps = expectations(code)
    s"${file.getName}" - {
        if exps.isEmpty then
          "carries at least one CHEN-EXPECT header" in { fail("no CHEN-EXPECT header") }
        exps.foreach { exp =>
            s"[L${exp.line}${if exp.xfail then " xfail" else ""}] ${exp.text}" in {
                val ok = evaluate(exp, file, code)
                if exp.xfail then
                  if ok then
                    fail(
                      s"${file.getName}:${exp.line} now passes - remove the -XFAIL marker"
                    )
                else ok shouldBe true
            }
        }
    }
  }
end PyCorpusRegressionTests
