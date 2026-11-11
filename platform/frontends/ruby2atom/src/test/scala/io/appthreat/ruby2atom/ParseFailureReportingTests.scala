package io.appthreat.ruby2atom

import better.files.File
import io.appthreat.ruby2atom.astcreation.AstCreator
import io.appthreat.ruby2atom.datastructures.RubyProgramSummary
import io.appthreat.ruby2atom.passes.AstCreationPass
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.appthreat.x2cpg.parse.ParseReporter
import io.appthreat.x2cpg.testfixtures.LogCapture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import ch.qos.logback.classic.Level
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import overflowdb.BatchedUpdate.DiffGraphBuilder

/** chen#255: a file the Ruby generator cannot parse produces no JSON at all, a file whose JSON
  * cannot be lowered is dropped before AST creation, and a file whose AST creation throws is
  * dropped inside the pass. All three must be recorded, the first with the generator's own message.
  */
class ParseFailureReportingTests extends AnyWordSpec with Matchers:

  /** True when rbastgen really parses: it answers `--version` even without the Ruby 3.4+ it runs
    * on, and then exits 0 having written nothing, so the check parses a one-line file.
    */
  private val rbastgenAvailable: Boolean =
    val probe = File.newTemporaryDirectory("ruby-parse-report-probe")
    try
      ((probe / "src").createDirectoryIfNotExists() / "a.rb").writeText("x = 1\n")
      val out = probe / "out"
      io.appthreat.x2cpg.utils.ExternalCommand
          .run(s"rbastgen -i ${probe / "src"} -o $out", probe.toString, true)
          .isSuccess && out.exists && out.list.exists(_.name.endsWith(".json"))
    finally probe.delete(swallowIOExceptions = true)

  // the object's logger: LoggerFactory.getLogger(getClass) inside `object Ruby2Atom`
  private val FrontendLoggerName = "io.appthreat.ruby2atom.Ruby2Atom$"

  private def withReporterEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      ParseReporter.reset()

  private def buildProject(): File =
    val dir = File.newTemporaryDirectory("ruby-parse-report")
    (dir / "good.rb").writeText("def add(a, b)\n  a + b\nend\n")
    // the construct rbastgen 2.x itself reports a parse error for, with this message
    (dir / "broken.rb").writeText("def broken(:\n")
    dir

  private def buildCpg(input: File): Cpg =
    val config = Config().withInputPath(input.toString).withOutputPath(
      File.newTemporaryDirectory("ruby-parse-report-out").toString
    )
    new Ruby2Atom().createCpg(config).get

  "ruby2atom parse failure reporting" should {

      "record the file the generator failed, with the generator's own message" in {
          if !rbastgenAvailable then
            cancel("rbastgen 2.x is not on PATH or cannot run (it needs Ruby 3.4+)")
          withReporterEnabled {
              val project = buildProject()
              val cpg     = buildCpg(project)
              try
                val broken = ParseReporter.records.filter(_.file == "broken.rb")
                broken should have size 1
                broken.head.frontend shouldBe "ruby"
                broken.head.outcome shouldBe "unparsed"
                broken.head.stage shouldBe "parse"
                broken.head.message shouldBe "unexpected ':'; expected a `)` to close the parameters"
                ParseReporter.records.exists(_.file == "good.rb") shouldBe false
                // the good twin is in the graph, unchanged, and the broken one is not
                cpg.method.name("add").l should have size 1
                cpg.method.name("broken").l shouldBe empty
              finally cpg.close()
          }
      }

      "record a file whose astgen JSON cannot be lowered, and name it at debug" in
          withReporterEnabled {
              val out = File.newTemporaryDirectory("ruby-parse-report-json")
              (out / "corrupt.rb.json").writeText("""{"not": "an astgen file"}""")
              val debugLines = LogCapture.withCapture(FrontendLoggerName, Level.DEBUG) { appender =>
                scala.util.Try(
                  Ruby2Atom
                      .parseAstGenResults(
                        List((out / "corrupt.rb.json").toString),
                        outDir = Some(out)
                      )
                      .foreach(_())
                )
                LogCapture.messagesAt(appender, Level.DEBUG)
              }
              debugLines.exists(message =>
                  message.contains("Failed to parse AST file") && message.contains("corrupt.rb")
              ) shouldBe true
              val record = ParseReporter.records.filter(_.file == "corrupt.rb")
              record should have size 1
              record.head.frontend shouldBe "ruby"
              record.head.outcome shouldBe "unparsed"
              record.head.stage shouldBe "parse"
              ParseReporter.records.filterNot(_.file == "corrupt.rb") shouldBe empty
          }

      "record a file whose AST creation throws, at the ast stage" in withReporterEnabled {
          // No known Ruby source makes the JVM-side AST creation throw today, so the failure is
          // injected by an AstCreator that throws, run through the real pass. The root node is
          // never touched, so null stands in for it.
          val cpg = newEmptyCpg()
          val creator = new AstCreator(
            "/ruby-parse-report/app/models/user.rb",
            None,
            RubyProgramSummary(),
            false,
            null
          )(using ValidationMode.Disabled):
            override def createAst(): DiffGraphBuilder =
                throw new IllegalStateException("injected AST failure")
          new AstCreationPass(cpg, List(creator), "/ruby-parse-report").createAndApply()
          cpg.close()
          ParseReporter.records shouldBe List(
            io.appthreat.x2cpg.parse.ParseFailureRecord(
              "ruby",
              "app/models/user.rb",
              "dropped",
              "ast",
              "IllegalStateException: injected AST failure"
            )
          )
      }

      "log nothing for the lost files at the default level" in {
          if !rbastgenAvailable then
            cancel("rbastgen 2.x is not on PATH or cannot run (it needs Ruby 3.4+)")
          withReporterEnabled {
              val warnLines = LogCapture.withCapture(FrontendLoggerName, Level.WARN) { appender =>
                val cpg = buildCpg(buildProject())
                cpg.close()
                LogCapture.messagesAtOrAbove(appender, Level.WARN)
              }
              warnLines.exists(message => message.contains("broken.rb")) shouldBe false
          }
      }

      "record nothing when the reporter is disabled" in {
          if !rbastgenAvailable then
            cancel("rbastgen 2.x is not on PATH or cannot run (it needs Ruby 3.4+)")
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          val cpg = buildCpg(buildProject())
          try ParseReporter.records shouldBe empty
          finally cpg.close()
      }
  }
end ParseFailureReportingTests
