package io.appthreat.php2atom.passes

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.parser.PhpParser
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.utils.ExternalCommand
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.compiletime.uninitialized
import scala.util.{Success, Try}

/** End-to-end proof that batch ingestion is actually WIRED INTO [[AstCreationPass]], not merely
  * available on [[PhpParser]].
  *
  * The batch and per-file paths of a stub generator are made to emit DIFFERENT function names
  * (`batchOnlyFunc` vs `perFileFunc`), so the resulting CPG identifies which path produced it:
  *   - a method named `batchOnlyFunc` can ONLY come from the batch (`-i <in> -o <out>`) output,
  *   - a method named `perFileFunc` can ONLY come from the legacy per-file `--json-dump` stdout.
  *
  * The pass is driven directly (`createAndApply()`) against a real empty CPG, i.e. exactly the way
  * `Php2Atom.createCpg` drives it.
  *
  * A non-`phpastgen` bin path makes [[PhpParser]] take its `php --php-ini <ini> <bin> ...` wrapper
  * branch, so the stub is a PHP script run by the real `php` interpreter. The suite cancels (rather
  * than fails) when no `php` is available.
  */
class BatchIngestionWiringTests extends AnyWordSpec with Matchers with BeforeAndAfterAll:

  private val phpAvailable: Boolean =
      Try(ExternalCommand.run("php --version", ".", true)) match
        case Success(Success(_)) => true
        case _                   => false

  private var workRoot: File  = uninitialized
  private var iniPath: String = uninitialized

  override def beforeAll(): Unit =
      if phpAvailable then
        workRoot = File.newTemporaryDirectory("batch-wiring-")
        val ini = workRoot / "php.ini"
        ini.writeText("memory_limit = -1")
        iniPath = ini.canonicalPath

  override def afterAll(): Unit =
      if workRoot != null then Try(workRoot.delete(swallowIOExceptions = true))

  private def cancelUnlessRunnable(): Unit =
      if !phpAvailable then cancel("No PHP runtime available on this platform")

  /** A well-formed AST wrapper object declaring a single function called `funcName`. */
  private def functionWrapperJson(funcName: String, relFilePath: String): String =
      s"""{
       |  "ast": [ ${functionNodeJson(funcName)} ],
       |  "parser_backend": "nikic/php-parser@5.8.0",
       |  "generator_version": "2.0.0",
       |  "php_version": "8.4.1",
       |  "target_version": "8.4",
       |  "rel_file_path": "$relFilePath"
       |}""".stripMargin

  private def functionNodeJson(funcName: String): String =
      s"""{
       |    "nodeType": "Stmt_Function",
       |    "attributes": { "startLine": 1, "endLine": 1, "startFilePos": 0, "kind": 1 },
       |    "byRef": false,
       |    "name": { "nodeType": "Identifier", "name": "$funcName", "attributes": { "startLine": 1 } },
       |    "params": [],
       |    "returnType": null,
       |    "stmts": [],
       |    "namespacedName": null,
       |    "attrGroups": []
       |  }""".stripMargin

  private def phpArgHelpers: String =
      """function hasArg($needle) { global $argv; return in_array($needle, $argv, true); }
      |function argAfter($flag) {
      |  global $argv;
      |  foreach ($argv as $i => $a) { if ($a === $flag && isset($argv[$i + 1])) return $argv[$i + 1]; }
      |  return null;
      |}
      |""".stripMargin

  private def writeStub(dir: File, body: String): String =
    dir.createDirectoryIfNotExists(createParents = true)
    val bin = dir / "stubgen.php"
    bin.writeText("<?php\n" + body)
    bin.canonicalPath

  /** Stub generator whose batch output declares `batchOnlyFunc` for each `batchFiles` entry, and
    * whose per-file output declares `perFileFunc`.
    *
    * @param advertiseBatch
    *   when false, `--parser-info` prints no version line so the capability probe fails.
    */
  private def stubBody(advertiseBatch: Boolean, batchFiles: Seq[String]): String =
    val writes = batchFiles.map { rel =>
      val jsonName = rel.replace('/', '_').stripSuffix(".php") + ".json"
      s"""    file_put_contents($$out . "/$jsonName", <<<'JSON'
         |${functionWrapperJson("batchOnlyFunc", rel)}
         |JSON);""".stripMargin
    }.mkString("\n")

    val probeOutput =
        if advertiseBatch then """    echo "Generator version: 2.0.0\n";"""
        else """    echo "old passthrough generator\n";"""

    s"""${phpArgHelpers}
       |if (hasArg("--parser-info")) {
       |$probeOutput
       |    exit(0);
       |}
       |if (hasArg("-i")) {
       |    $$out = argAfter("-o");
       |    @mkdir($$out, 0777, true);
       |$writes
       |    exit(0);
       |}
       |if (hasArg("--json-dump")) {
       |    echo <<<'JSON'
       |[ ${functionNodeJson("perFileFunc")} ]
       |JSON;
       |    echo "\\n";
       |    exit(0);
       |}
       |exit(1);
       |""".stripMargin
  end stubBody

  /** Run [[AstCreationPass]] over `inputDir` with the given stub and return the method names. */
  private def methodNamesFor(inputDir: File, stubBin: String): List[String] =
    val config   = Config(enableAstCache = false).withInputPath(inputDir.canonicalPath)
    val parser   = PhpParser.fromPaths(stubBin, iniPath)
    val cpg: Cpg = X2Cpg.newEmptyCpg()
    try
      new AstCreationPass(config, cpg, parser)(using config.schemaValidation).createAndApply()
      cpg.method.name.l
    finally cpg.close()

  "AstCreationPass with a batch-capable generator" should {

      "build the CPG from the batch output rather than per-file parsing" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "wired").createDirectoryIfNotExists()
          val inputDir = (scenario / "in").createDirectoryIfNotExists()
          (inputDir / "only.php").writeText("<?php ;")

          val bin = writeStub(scenario / "gen", stubBody(advertiseBatch = true, Seq("only.php")))
          val methods = methodNamesFor(inputDir, bin)

          // Only the batch output could have produced this method.
          methods should contain("batchOnlyFunc")
          // Proof the per-file path was NOT used for this file.
          methods should not contain "perFileFunc"
      }

      "fall back to per-file parsing for files the batch did not cover" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "partial").createDirectoryIfNotExists()
          val inputDir = (scenario / "in").createDirectoryIfNotExists()
          (inputDir / "covered.php").writeText("<?php ;")
          (inputDir / "missing.php").writeText("<?php ;")

          // Batch emits an AST for `covered.php` only; `missing.php` must still be parsed individually.
          val bin = writeStub(scenario / "gen", stubBody(advertiseBatch = true, Seq("covered.php")))
          val methods = methodNamesFor(inputDir, bin)

          methods should contain("batchOnlyFunc")
          methods should contain("perFileFunc")
      }

      "pass an input directory containing spaces through to the generator unmangled" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "quoting").createDirectoryIfNotExists()
          // A shell-interpolated command would word-split this path; the argument-vector invocation
          // used for the probe and the batch run cannot.
          val inputDir = (scenario / "in dir with space").createDirectoryIfNotExists()
          (inputDir / "only.php").writeText("<?php ;")

          val bin = writeStub(scenario / "gen", stubBody(advertiseBatch = true, Seq("only.php")))
          val methods = methodNamesFor(inputDir, bin)

          methods should contain("batchOnlyFunc")
          methods should not contain "perFileFunc"
      }
  }

  "AstCreationPass with a generator without batch support" should {

      "keep using the legacy per-file path" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "legacy").createDirectoryIfNotExists()
          val inputDir = (scenario / "in").createDirectoryIfNotExists()
          (inputDir / "only.php").writeText("<?php ;")

          val bin = writeStub(scenario / "gen", stubBody(advertiseBatch = false, Seq("only.php")))
          val methods = methodNamesFor(inputDir, bin)

          methods should contain("perFileFunc")
          methods should not contain "batchOnlyFunc"
      }
  }
end BatchIngestionWiringTests
