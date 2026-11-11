package io.appthreat.jssrc2cpg.io

import better.files.File
import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.passes.AstCreationPass
import io.appthreat.jssrc2cpg.testfixtures.JsSrc2CpgSuite
import io.appthreat.jssrc2cpg.utils.AstGenRunner
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.BeforeAndAfterAll

/** chen#255: a file astgen cannot parse never reaches the AST pass at all, and a file whose astgen
  * JSON cannot be turned into the graph is dropped in AstCreationPass. Both must be recorded.
  *
  * The collector is global to the JVM and other suites of this project run alongside, so the
  * fixture names carry a prefix no other suite uses and the assertions look only at those.
  */
class ParseFailureReportingTests extends JsSrc2CpgSuite with BeforeAndAfterAll:

  private implicit val schemaValidationMode: ValidationMode = ValidationMode.Enabled

  /** True when the astgen binary this suite drives is runnable. */
  private val astgenAvailable: Boolean =
      io.appthreat.x2cpg.utils.ExternalCommand.run("astgen --version", ".", true).isSuccess

  private def cancelUnlessAstgen(): Unit =
      if !astgenAvailable then cancel("astgen is not on PATH")

  private val projectWithBrokenFile: File =
    val dir      = File.newTemporaryDirectory("jssrcParseReport")
    val goodFile = dir / "pr255-good.js"
    goodFile.createIfNotExists(createParents = true)
    goodFile.write(s"""console.log("good");""")
    val brokenFile = dir / "pr255-broken.js"
    brokenFile.createIfNotExists(createParents = true)
    brokenFile.write(s"""console.log("broken""")
    // a page with no Alpine directives or Angular bindings: astgen writes its JSON with a null AST
    (dir / "pr255-page.html").write("<div></div>\n")
    dir

  override def afterAll(): Unit =
      projectWithBrokenFile.delete(swallowIOExceptions = true)

  private def withReporterEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      ParseReporter.reset()

  /** Runs astgen and the AST pass the way ProjectParseTest does, so the generator's real output
    * decides what the records say.
    */
  private def runAstGeneration(tsTypes: Boolean)(corruptJsonOf: File => Unit = _ => {})(
    f: Cpg => Unit
  ): Unit =
      File.usingTemporaryDirectory("jssrcParseReportOut") { tmpDir =>
        val cpg = newEmptyCpg()
        val config = Config(tsTypes = tsTypes)
            .withInputPath(projectWithBrokenFile.toString)
            .withOutputPath(tmpDir.toString)
        val astGenResult = new AstGenRunner(config).execute(tmpDir)
        corruptJsonOf(tmpDir)
        new AstCreationPass(cpg, astGenResult, config).createAndApply()
        f(cpg)
      }

  "jssrc2cpg parse failure reporting" should {

      "record the file astgen could not parse, with astgen's own reason" in withReporterEnabled {
          cancelUnlessAstgen()
          runAstGeneration(tsTypes = false)() { cpg =>
            val broken = ParseReporter.records.filter(_.file.endsWith("pr255-broken.js"))
            broken should have size 1
            broken.head.frontend shouldBe "jssrc"
            broken.head.outcome shouldBe "unparsed"
            broken.head.stage shouldBe "parse"
            broken.head.file shouldBe "pr255-broken.js"
            ParseReporter.records.exists(_.file.endsWith("pr255-good.js")) shouldBe false
            cpg.file.name.l should (contain("pr255-good.js").and(not) contain "pr255-broken.js")
          }
      }

      "record the same file from the manifest's file_error records when types are on" in
          withReporterEnabled {
              cancelUnlessAstgen()
              runAstGeneration(tsTypes = true)() { cpg =>
                val broken = ParseReporter.records.filter(_.file.endsWith("pr255-broken.js"))
                broken should have size 1
                broken.head.outcome shouldBe "unparsed"
                broken.head.stage shouldBe "parse"
                broken.head.file shouldBe "pr255-broken.js"
                ParseReporter.records.exists(_.file.endsWith("pr255-good.js")) shouldBe false
              }
          }

      "record a file whose astgen JSON cannot be read, at the ast stage" in withReporterEnabled {
          cancelUnlessAstgen()
          // astgen parses pr255-broken.js? No: the file that reaches the pass is pr255-good.js, and its JSON
          // is corrupted here so the failure happens where the pass drops a file.
          val corruptor = (out: File) =>
              out.listRecursively.filter(f => f.name == "pr255-good.js.json").foreach(f =>
                  f.write("""{"not": "an astgen file"}""")
              )
          runAstGeneration(tsTypes = false)(corruptor) { cpg =>
            val good = ParseReporter.records.filter(_.file.endsWith("pr255-good.js"))
            good should have size 1
            good.head.frontend shouldBe "jssrc"
            good.head.outcome shouldBe "dropped"
            good.head.stage shouldBe "ast"
            good.head.file shouldBe "pr255-good.js"
          }
      }

      "not record a page astgen found no code in" in withReporterEnabled {
          cancelUnlessAstgen()
          val nullAst = (out: File) =>
            out.listRecursively.find(_.name == "pr255-page.html.json") match
              case Some(json) => ujson.read(json.contentAsString)("ast").isNull shouldBe true
              case None       => fail("astgen wrote no JSON for pr255-page.html")
            ()
          runAstGeneration(tsTypes = false)(nullAst) { cpg =>
              // other suites in this JVM may record their own files meanwhile
              ParseReporter.records.map(_.file).filter(_.startsWith("pr255-")) shouldBe
                  List("pr255-broken.js")
          }
      }

      "record nothing when the reporter is disabled" in {
          cancelUnlessAstgen()
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          runAstGeneration(tsTypes = false)() { cpg =>
              ParseReporter.records shouldBe empty
          }
      }
  }
end ParseFailureReportingTests
