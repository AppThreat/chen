package io.appthreat.php2atom.parser

import better.files.File
import io.appthreat.php2atom.parser.Domain.*
import io.appthreat.x2cpg.utils.ExternalCommand
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.compiletime.uninitialized
import scala.util.{Success, Try}

/** Integration tests for the probe-gated ingestion (capability probe, directory-batch ingestion
  * with per-file isolation, and the per-file fallback).
  *
  * Unlike the hermetic domain-decode tests, these exercise the real shell-out surface of
  * [[PhpParser]] by pointing it — via the [[PhpParser.fromPaths]] testing seam — at a small PHP
  * stub "generator" that mimics the three invocation shapes the parser drives:
  *   - `<bin> --parser-info` (capability probe, [[PhpParser.supportsBatch]])
  *   - `<bin> -i <in> -o <out>` (batch generation, [[PhpParser.parseDirectory]])
  *   - `<bin> --with-recovery --resolve-names -P --json-dump <file>` (per-file fallback)
  *
  * A non-`phpastgen` bin path makes [[PhpParser]] take its `php --php-ini <ini> <bin> <args>`
  * wrapper branch (exactly the shape used in production for a configured generator binary), so the
  * stub is a PHP script executed by the real `php` interpreter. The suite cancels (rather than
  * hard-fails) when no `php` is on `PATH`, keeping CI green on hosts without a PHP runtime.
  */
class ProbeGatedIngestionTests extends AnyWordSpec with Matchers with BeforeAndAfterAll:

  /** True only when a real `php` interpreter is available to run the stub scripts. */
  private val phpAvailable: Boolean =
      Try(ExternalCommand.run("php --version", ".", true)) match
        case Success(Success(_)) => true
        case _                   => false

  private var workRoot: File  = uninitialized
  private var iniPath: String = uninitialized

  override def beforeAll(): Unit =
      if phpAvailable then
        workRoot = File.newTemporaryDirectory("probe-gated-ingestion-")
        val ini = workRoot / "php.ini"
        ini.writeText("memory_limit = -1")
        iniPath = ini.canonicalPath

  override def afterAll(): Unit =
      if workRoot != null then Try(workRoot.delete(swallowIOExceptions = true))

  // --- helpers ---------------------------------------------------------------

  private def cancelUnlessRunnable(): Unit =
      if !phpAvailable then cancel("No PHP runtime available on this platform")

  /** Write `body` as a PHP stub generator under `dir` and return its absolute path. The parser is
    * then constructed via [[PhpParser.fromPaths]] with this path, which — being anything other than
    * the literal `phpastgen` — routes through the `php --php-ini <ini> <bin> ...` wrapper branch.
    */
  private def writeStub(dir: File, body: String): String =
    dir.createDirectoryIfNotExists(createParents = true)
    val bin = dir / "stubgen.php"
    bin.writeText("<?php\n" + body)
    bin.canonicalPath

  /** A minimal, well-formed AST wrapper object with a single `Stmt_Nop`, as a PHP heredoc-safe
    * literal (no interpolation).
    */
  private def wrapperJson(relFilePath: String): String =
      s"""{
       |  "ast": [ { "nodeType": "Stmt_Nop", "attributes": { "startLine": 1, "startFilePos": 0, "kind": 1 } } ],
       |  "parser_backend": "nikic/php-parser@5.8.0",
       |  "generator_version": "2.0.0",
       |  "php_version": "8.4.1",
       |  "target_version": "8.4",
       |  "rel_file_path": "$relFilePath"
       |}""".stripMargin

  /** PHP snippet: scan `$argv` for the flag at the given position/value semantics. */
  private def phpArgHelpers: String =
      """function hasArg($needle) { global $argv; return in_array($needle, $argv, true); }
      |function argAfter($flag) {
      |  global $argv;
      |  foreach ($argv as $i => $a) { if ($a === $flag && isset($argv[$i + 1])) return $argv[$i + 1]; }
      |  return null;
      |}
      |""".stripMargin

  // --- scenarios -------------------------------------------------------------

  "Probe-gated ingestion with a modern batch generator" should {

      "detect batch support and decode every AST wrapper, ignoring the .jsonl manifest" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "modern").createDirectoryIfNotExists()
          val inputDir = (scenario / "in").createDirectoryIfNotExists()
          (inputDir / "a.php").writeText("<?php ;")
          (inputDir / "b.php").writeText("<?php ;")

          // Stub: `--parser-info` advertises a version line; `-i <in> -o <out>` writes two AST wrappers
          // plus a manifest .jsonl (which must NOT be decoded as an AST).
          val stubBody =
              s"""${phpArgHelpers}
           |if (hasArg("--parser-info")) {
           |    echo "Backend: nikic/php-parser@5.8.0\\n";
           |    echo "Generator version: 2.0.0\\n";
           |    exit(0);
           |}
           |if (hasArg("-i")) {
           |    $$out = argAfter("-o");
           |    @mkdir($$out, 0777, true);
           |    file_put_contents($$out . "/a.json", <<<'JSON'
           |${wrapperJson("a.php")}
           |JSON);
           |    file_put_contents($$out . "/b.json", <<<'JSON'
           |${wrapperJson("b.php")}
           |JSON);
           |    file_put_contents($$out . "/phpastgen_manifest.jsonl", "{\\"rel_file_path\\":\\"a.php\\"}\\n{\\"rel_file_path\\":\\"b.php\\"}\\n");
           |    exit(0);
           |}
           |exit(1);
           |""".stripMargin

          val bin    = writeStub(scenario / "gen", stubBody)
          val parser = PhpParser.fromPaths(bin, iniPath)

          parser.supportsBatch shouldBe true

          val outputDir = (scenario / "out").canonicalPath
          val direct    = parser.parseDirectory(inputDir.canonicalPath, outputDir)

          (direct should have).length(2)
          // The manifest .jsonl was not decoded (only the two .json wrappers produced results).
          (direct.flatMap(_.phpFile.children) should have).length(2)
          all(direct.flatMap(_.phpFile.children)) shouldBe a[NopStmt]
          // Provenance carried through from the wrapper.
          direct.map(_.phpFile.provenance.generatorVersion).toSet shouldBe Set(Some("2.0.0"))
          // sourcePath resolved from rel_file_path against the input directory.
          direct.map(_.sourcePath).exists(_.endsWith("a.php")) shouldBe true
          direct.map(_.sourcePath).exists(_.endsWith("b.php")) shouldBe true

          // parseInput chooses the batch path since supportsBatch is true.
          val viaInput = parser.parseInput(
            inputDir.canonicalPath,
            (scenario / "out2").canonicalPath,
            Seq((inputDir / "a.php").canonicalPath, (inputDir / "b.php").canonicalPath),
            None
          )
          (viaInput should have).length(2)
          all(viaInput.flatMap(_.phpFile.children)) shouldBe a[NopStmt]
      }
  }

  "Probe-gated ingestion with an old/failing probe" should {

      "report no batch support and fall back to per-file parsing" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "legacy").createDirectoryIfNotExists()
          val inputDir = (scenario / "in").createDirectoryIfNotExists()
          (inputDir / "x.php").writeText("<?php ;")
          (inputDir / "y.php").writeText("<?php ;")

          // Stub: `--parser-info` prints nothing useful (no "Generator version:" line) so the probe
          // fails; the per-file `--json-dump <file>` invocation returns a bare AST array on stdout.
          val stubBody =
              s"""${phpArgHelpers}
           |if (hasArg("--parser-info")) {
           |    echo "old passthrough generator\\n";
           |    exit(0);
           |}
           |if (hasArg("--json-dump")) {
           |    echo '[{"nodeType":"Stmt_Nop","attributes":{"startLine":1,"startFilePos":0,"kind":1}}]';
           |    echo "\\n";
           |    exit(0);
           |}
           |exit(1);
           |""".stripMargin

          val bin    = writeStub(scenario / "gen", stubBody)
          val parser = PhpParser.fromPaths(bin, iniPath)

          parser.supportsBatch shouldBe false

          val files = Seq((inputDir / "x.php").canonicalPath, (inputDir / "y.php").canonicalPath)
          val results = parser.parseInput(
            inputDir.canonicalPath,
            (scenario / "out").canonicalPath,
            files,
            None
          )

          // One PhpFile returned per input file via the per-file fallback path.
          (results should have).length(2)
          all(results.flatMap(_.phpFile.children)) shouldBe a[NopStmt]
          results.map(_.sourcePath).exists(_.endsWith("x.php")) shouldBe true
          results.map(_.sourcePath).exists(_.endsWith("y.php")) shouldBe true
      }
  }

  "Batch ingestion with a single undecodable AST file" should {

      "isolate the failure and return only the valid file" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "isolation").createDirectoryIfNotExists()
          val inputDir = (scenario / "in").createDirectoryIfNotExists()
          (inputDir / "good.php").writeText("<?php ;")
          (inputDir / "bad.php").writeText("<?php ;")

          // Stub writes one valid wrapper and one malformed json; batch must skip only the bad one.
          val stubBody =
              s"""${phpArgHelpers}
           |if (hasArg("--parser-info")) {
           |    echo "Generator version: 2.0.0\\n";
           |    exit(0);
           |}
           |if (hasArg("-i")) {
           |    $$out = argAfter("-o");
           |    @mkdir($$out, 0777, true);
           |    file_put_contents($$out . "/good.json", <<<'JSON'
           |${wrapperJson("good.php")}
           |JSON);
           |    file_put_contents($$out . "/bad.json", '{ "ast": this-is-not-valid-json ] [');
           |    exit(0);
           |}
           |exit(1);
           |""".stripMargin

          val bin    = writeStub(scenario / "gen", stubBody)
          val parser = PhpParser.fromPaths(bin, iniPath)

          parser.supportsBatch shouldBe true

          val results = parser.parseDirectory(
            inputDir.canonicalPath,
            (scenario / "out").canonicalPath
          )

          // Only the valid file survives; the run was not aborted by the malformed sibling.
          (results should have).length(1)
          results.head.sourcePath should endWith("good.php")
          results.head.phpFile.children.head shouldBe a[NopStmt]
      }
  }

  "Batch ingestion through a Node generator named by PHP_ASTGEN_BIN" should {

      "probe and batch through node even when the per-file parser is a php script" in {
          cancelUnlessRunnable()

          val scenario = (workRoot / "nodegen").createDirectoryIfNotExists()
          val inputDir = (scenario / "in").createDirectoryIfNotExists()
          (inputDir / "a.php").writeText("<?php ;")

          // The per-file stub mimics the vendored php-parse: it knows neither
          // --parser-info nor -i/-o, so probing it (the historic behaviour)
          // cannot yield batch support.
          val perFileStub = writeStub(
            scenario / "gen",
            s"""${phpArgHelpers}
          |exit(1);
          |""".stripMargin
          )

          // The Node stub mimics phpastgen.js: answers --parser-info and batches -i/-o.
          val argsFile = scenario / "batch-args.json"
          val nodeGen  = scenario / "gen" / "phpastgen.js"
          nodeGen.writeText(
            s"""const args = process.argv.slice(2);
             |if (args.includes("--parser-info")) {
             |  console.log("Parser backend: nikic/php-parser@5.8.0");
             |  console.log("Generator version: 2.0.0");
             |  process.exit(0);
             |}
             |const outIdx = args.indexOf("-o");
             |if (args.includes("-i") && outIdx !== -1) {
             |  const fs = require("fs");
             |  const path = require("path");
             |  fs.writeFileSync(${ujson.write(
                ujson.Str(argsFile.canonicalPath)
              )}, JSON.stringify(args));
             |  const out = args[outIdx + 1];
             |  fs.mkdirSync(out, { recursive: true });
             |  fs.writeFileSync(path.join(out, "a.json"), JSON.stringify(${wrapperJsonJs(
                "a.php"
              )}));
             |  process.exit(0);
             |}
             |process.exit(1);
             |""".stripMargin
          )

          val parser =
              PhpParser.fromPaths(perFileStub, iniPath, Some(nodeGen.canonicalPath))

          // The probe runs the Node generator, not the per-file php stub.
          parser.supportsBatch shouldBe true

          val results = parser.parseDirectory(
            inputDir.canonicalPath,
            (scenario / "out").canonicalPath
          )
          (results should have).length(1)
          results.head.sourcePath should endWith("a.php")
          results.head.phpFile.children.head shouldBe a[NopStmt]
          results.head.phpFile.provenance.generatorVersion shouldBe Some("2.0.0")

          // The batch asks for the whole tree: dependency code included, no default exclusions.
          val batchArgs = ujson.read(argsFile.contentAsString).arr.map(_.str)
          batchArgs.containsSlice(PhpParser.CompleteTreeArgs) shouldBe true
      }
  }

  /** The wrapper object as a JavaScript object literal, for the Node stub generator. */
  private def wrapperJsonJs(relFilePath: String): String =
      s"""{ ast: [ { nodeType: "Stmt_Nop", attributes: { startLine: 1, startFilePos: 0, kind: 1 } } ],
       |  parser_backend: "nikic/php-parser@5.8.0", generator_version: "2.0.0",
       |  php_version: "8.4.1", target_version: "8.4", rel_file_path: "$relFilePath" }"""
          .stripMargin
end ProbeGatedIngestionTests
