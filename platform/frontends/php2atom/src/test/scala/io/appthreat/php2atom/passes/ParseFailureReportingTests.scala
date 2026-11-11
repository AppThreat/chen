package io.appthreat.php2atom.passes

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.parser.PhpParser
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.appthreat.x2cpg.parse.ParseReporter
import io.appthreat.x2cpg.utils.ExternalCommand
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.compiletime.uninitialized
import scala.util.{Success, Try}

/** chen#255: a file the PHP generator cannot parse is left out with only a debug line. The failures
  * are forced with a stub generator, because the real phpastgen recovers even a file of garbage
  * bytes into an AST and so loses nothing; the real-generator test below pins that no false record
  * appears for exactly that reason.
  */
class ParseFailureReportingTests extends AnyWordSpec with Matchers with BeforeAndAfterAll:

  private val phpAvailable: Boolean =
      Try(ExternalCommand.run("php --version", ".", true)) match
        case Success(Success(_)) => true
        case _                   => false

  private var iniPath: String = uninitialized
  private var workRoot: File  = uninitialized

  override def beforeAll(): Unit =
      if phpAvailable then
        workRoot = File.newTemporaryDirectory("php-parse-report-")
        val ini = workRoot / "php.ini"
        ini.writeText("memory_limit = -1")
        iniPath = ini.canonicalPath

  override def afterAll(): Unit =
      if workRoot != null then Try(workRoot.delete(swallowIOExceptions = true))

  private def withReporterEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      ParseReporter.reset()

  private def runPass(inputDir: File, parser: PhpParser): Cpg =
    val config = Config().withInputPath(inputDir.toString)
    val cpg    = newEmptyCpg()
    new AstCreationPass(config, cpg, parser)(using ValidationMode.Disabled).createAndApply()
    cpg

  private val phpArgHelpers =
      """function hasArg($needle) { global $argv; return in_array($needle, $argv, true); }
        |function argAfter($flag) {
        |  global $argv;
        |  foreach ($argv as $i => $a) { if ($a === $flag && isset($argv[$i + 1])) return $argv[$i + 1]; }
        |  return null;
        |}
        |""".stripMargin

  private val goodWrapper =
      """{
        |  "ast": [ { "nodeType": "Stmt_Nop", "attributes": { "startLine": 1, "startFilePos": 0, "kind": 1 } } ],
        |  "parser_backend": "nikic/php-parser@5.8.0",
        |  "generator_version": "2.0.0",
        |  "rel_file_path": "good.php"
        |}""".stripMargin

  "php2atom parse failure reporting" should {

      "record a file the generator cannot parse, with the generator's stderr as the reason" in {
          if !phpAvailable then cancel("No PHP runtime available on this platform")
          withReporterEnabled {
              val inputDir = (workRoot / "stubbed").createDirectoryIfNotExists()
              (inputDir / "good.php").writeText("<?php ;")
              (inputDir / "broken.php").writeText("<?php ;")

              // The stub: a batch-capable generator that covers only good.php, and whose
              // per-file invocation fails for anything else, printing a reason to stderr.
              val gen = (workRoot / "gen").createDirectoryIfNotExists() / "stubgen.php"
              gen.writeText(
                s"""<?php
                  |${phpArgHelpers}
                  |if (hasArg("--parser-info")) {
                  |    echo "Generator version: 2.0.0\\n";
                  |    exit(0);
                  |}
                  |if (hasArg("-i")) {
                  |    $$out = argAfter("-o");
                  |    @mkdir($$out, 0777, true);
                  |    file_put_contents($$out . "/good.json", <<<'JSON'
                  |$goodWrapper
                  |JSON);
                  |    exit(0);
                  |}
                |if (hasArg("--json-dump")) {
                |    global $$argv;
                |    if (end($$argv) && strpos(end($$argv), "broken.php") !== false) {
                |        fwrite(STDERR, "syntax error, unexpected end of file\\n");
                |        exit(1);
                |    }
                |    echo '[{"nodeType":"Stmt_Nop","attributes":{"startLine":1,"startFilePos":0,"kind":1}}]';
                |    exit(0);
                |}
                  |exit(1);
                  |""".stripMargin
              )
              val parser = PhpParser.fromPaths(gen.canonicalPath, iniPath)

              val cpg = runPass(inputDir, parser)
              try
                val broken = ParseReporter.records.filter(_.file.endsWith("broken.php"))
                broken should have size 1
                broken.head.frontend shouldBe "php"
                broken.head.outcome shouldBe "unparsed"
                broken.head.stage shouldBe "parse"
                broken.head.message shouldBe "generator run failed: syntax error, unexpected end of file"
                ParseReporter.records.exists(_.file.endsWith("good.php")) shouldBe false
              finally cpg.close()
          }
      }

      "record nothing for a project the real generator recovers completely" in {
          if !phpAvailable then cancel("No PHP runtime available on this platform")
          withReporterEnabled {
              val inputDir = (workRoot / "real").createDirectoryIfNotExists()
              (inputDir / "good.php")
                  .writeText("<?php\nfunction add($a, $b) { return $a + $b; }\n")
              // garbage bytes: the real generator's recovery turns them into an AST, so the
              // file is not lost and must not be recorded
              (inputDir / "garbage.php")
                  .outputStream.foreach(out =>
                      out.write(Array(0x00.toByte, 0x01.toByte, 0xff.toByte, 0xfe.toByte))
                  )
              val parser = PhpParser.getParser(Config().withInputPath(inputDir.toString)).get
              val cpg    = runPass(inputDir, parser)
              try
                ParseReporter.records shouldBe empty
                cpg.method.name("add").l should have size 1
              finally cpg.close()
          }
      }

      "record nothing when the reporter is disabled" in {
          if !phpAvailable then cancel("No PHP runtime available on this platform")
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          val inputDir = (workRoot / "disabled").createDirectoryIfNotExists()
          (inputDir / "good.php").writeText("<?php ;")
          (inputDir / "broken.php").writeText("<?php ;")
          val gen = (workRoot / "gen2").createDirectoryIfNotExists() / "stubgen.php"
          gen.writeText(
            s"""<?php
              |${phpArgHelpers}
              |if (hasArg("--parser-info")) {
              |    echo "Generator version: 2.0.0\\n";
              |    exit(0);
              |}
              |if (hasArg("-i")) { exit(0); }
              |if (hasArg("--json-dump")) {
              |    fwrite(STDERR, "syntax error, unexpected end of file\\n");
              |    exit(1);
              |}
              |exit(1);
              |""".stripMargin
          )
          val parser = PhpParser.fromPaths(gen.canonicalPath, iniPath)
          val cpg    = runPass(inputDir, parser)
          try ParseReporter.records shouldBe empty
          finally cpg.close()
      }
  }
end ParseFailureReportingTests
