package io.appthreat.pysrc2cpg

import io.appthreat.pythonparser.ast
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** chen#255: a file whose statements fail to parse stays in the graph with ErrorStatement nodes, a
  * file the parser cannot recover from is dropped, and a file the conversion throws on is dropped
  * later. All three must be recorded, each at its own stage.
  */
class ParseFailureReportingTests extends AnyWordSpec with Matchers:

  private def withReporterEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      ParseReporter.reset()

  private def buildCpg(pairs: (String, String)*): Cpg =
    val context = Py2CpgTestContext()
    pairs.foreach((code, name) => context.addSource(code, name))
    context.buildCpg

  "pysrc2cpg parse failure reporting" should {

      "record a recovered file as partial and an unrecoverable one as unparsed" in
          withReporterEnabled {
              val cpg = buildCpg(
                ("def add(a, b):\n    return a + b\n", "good.py"),
                // the parser recovers this and records an ErrorStatement
                ("def broken(:\n    pass\n", "broken_stmt.py"),
                // a lexical error the recovery cannot swallow: the whole file is lost
                ("name = f'{x'\n", "broken_fstring.py")
              )
              try
                val partial = ParseReporter.records.filter(_.file == "broken_stmt.py")
                partial should have size 1
                partial.head.frontend shouldBe "python"
                partial.head.outcome shouldBe "partial"
                partial.head.stage shouldBe "parse"
                partial.head.message should startWith("1 statements failed to parse:")

                val unparsed = ParseReporter.records.filter(_.file == "broken_fstring.py")
                unparsed should have size 1
                unparsed.head.frontend shouldBe "python"
                unparsed.head.outcome shouldBe "unparsed"
                unparsed.head.stage shouldBe "parse"
                unparsed.head.message should startWith("TokenMgrError:")

                ParseReporter.records.exists(_.file == "good.py") shouldBe false
                // the good twin is in the graph, the unrecoverable file is not
                cpg.method.name("add").l should have size 1
                cpg.method.name.l.map(_.length).sum should be > 0
              finally cpg.close()
              end try
          }

      "record a conversion failure as dropped at the ast stage" in withReporterEnabled {
          // No known Python source makes the JVM-side conversion throw today, so the failure is
          // injected through the AST transform hook dependency ingestion uses.
          val cpg = new Cpg()
          val codeToCpg = new CodeToCpg(
            cpg,
            List[Py2Cpg.InputProvider](() =>
                Py2Cpg.InputPair("x = 1\n", "injected.py")
            ),
            ValidationMode.Disabled,
            "/pysrc-parse-report/project",
            enableAstCache = false,
            transformAst = (m: ast.Module) =>
                throw new IllegalStateException("injected conversion failure")
          )
          codeToCpg.createAndApply()
          cpg.close()
          ParseReporter.records shouldBe List(
            io.appthreat.x2cpg.parse.ParseFailureRecord(
              "python",
              "injected.py",
              "dropped",
              "ast",
              "IllegalStateException: injected conversion failure"
            )
          )
      }

      "record nothing when the reporter is disabled" in {
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          val cpg = buildCpg(("def broken(:\n    pass\n", "broken_stmt.py"))
          try ParseReporter.records shouldBe empty
          finally cpg.close()
      }
  }
end ParseFailureReportingTests
