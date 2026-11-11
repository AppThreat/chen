package io.appthreat.c2cpg.passes

import better.files.File
import ch.qos.logback.classic.Level
import io.appthreat.c2cpg.Config
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.appthreat.x2cpg.parse.ParseReporter
import io.appthreat.x2cpg.testfixtures.LogCapture
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Paths
import scala.concurrent.duration.*

/** chen#255: a file whose translation unit carries CDT problem nodes is in the graph but partly
  * read, a file the parser returned nothing for is lost silently, and a file that exceeds the parse
  * or AST timeout is dropped through the catch that used to println. All three must be recorded.
  */
class ParseFailureReportingTests extends AnyWordSpec with Matchers:

  private def withReporterEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      ParseReporter.reset()

  private def buildProject(): File =
    val dir = File.newTemporaryDirectory("c2cpg-parse-report")
    (dir / "good.c").writeText("int add(int a, int b) {\n  return a + b;\n}\n")
    // parses into a translation unit with a problem node where CDT gave up
    (dir / "problem.c").writeText("int main() {\n  int x = ;\n  return x;\n}\n")
    dir

  private def runPass(
    dir: File,
    timeout: FiniteDuration = 2.minutes
  ): io.shiftleft.codepropertygraph.Cpg =
    val cpg = newEmptyCpg()
    val config = Config().withInputPath(dir.toString).withOutputPath(dir.toString)
        .withFunctionBodies(true)
    new AstCreationPass(cpg, config, timeoutDuration = timeout, parseTimeoutDuration = timeout)
        .createAndApply()
    cpg

  "c2cpg parse failure reporting" should {

      "record the file whose unit carries problem nodes as partial, and not its good twin" in
          withReporterEnabled {
              val dir = buildProject()
              val cpg = runPass(dir)
              try
                val partial = ParseReporter.records.filter(_.file == "problem.c")
                partial should have size 1
                partial.head.frontend shouldBe "c"
                partial.head.outcome shouldBe "partial"
                partial.head.stage shouldBe "parse"
                partial.head.message should startWith("1 problem nodes, ")
                ParseReporter.records.exists(_.file == "good.c") shouldBe false
                // the good twin is in the graph, unchanged
                cpg.method.name("add").l should have size 1
              finally cpg.close()
          }

      "record a file the parser returned nothing for, as unparsed" in withReporterEnabled {
          val dir    = buildProject()
          val config = Config().withInputPath(dir.toString).withOutputPath(dir.toString)
          val parser = new io.appthreat.c2cpg.parser.CdtParser(config, null)
          // the broken-symlink branch of CdtParser.parseInternal: a real path the parser
          // rejects with a failure rather than a problem-bearing AST
          parser.parse(Paths.get(dir.toString, "missing.c"))
          val record = ParseReporter.records.filter(_.file == "missing.c")
          record should have size 1
          record.head.frontend shouldBe "c"
          record.head.outcome shouldBe "unparsed"
          record.head.stage shouldBe "parse"
          record.head.message should include("does not exist")
      }

      "record a file that exceeds the timeout as dropped at the ast stage" in withReporterEnabled {
          val dir = buildProject()
          // a timeout so small the parse cannot finish: the rethrown TimeoutException lands in
          // the catch that used to println, the real path a wedged parse takes
          val warnLines = LogCapture.withCapture(
            classOf[AstCreationPass].getName,
            Level.WARN
          ) { appender =>
            val cpg = runPass(dir, timeout = 0.nanoseconds)
            cpg.close()
            LogCapture.messagesAtOrAbove(appender, Level.WARN)
          }
          // the message the catch used to println to stdout is not even a warning now
          warnLines.exists(message => message.contains("Exception processing file")) shouldBe false

          val debugLines = LogCapture.withCapture(
            classOf[AstCreationPass].getName,
            Level.DEBUG
          ) { appender =>
            val cpg = runPass(dir, timeout = 0.nanoseconds)
            cpg.close()
            LogCapture.messagesAt(appender, Level.DEBUG)
          }
          debugLines.exists(message =>
              message.contains("Exception processing file") && message.contains("good.c")
          ) shouldBe true
          // A 0ns deadline lands wherever the race puts it: past the parse (dropped at the ast
          // stage) or inside it (unparsed at the parse stage). Either way the file is recorded
          // once per run, by the c frontend, with the timeout's own text.
          val dropped = ParseReporter.records.filter(_.file == "good.c")
          dropped should not be empty
          dropped.foreach { record =>
            record.frontend shouldBe "c"
            (record.outcome, record.stage) should (
              equal(("dropped", "ast")).or(equal(("unparsed", "parse")))
            )
            record.message should (startWith("TimeoutException").or(startWith("ParseError")))
          }
      }

      "record nothing when the reporter is disabled" in {
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          val dir = buildProject()
          val cpg = runPass(dir)
          try ParseReporter.records shouldBe empty
          finally cpg.close()
      }
  }
end ParseFailureReportingTests
