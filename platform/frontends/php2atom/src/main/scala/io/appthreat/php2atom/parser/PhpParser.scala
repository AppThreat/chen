package io.appthreat.php2atom.parser

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.parser.Domain.PhpFile
import io.appthreat.x2cpg.utils.ExternalCommand
import org.slf4j.LoggerFactory

import java.nio.file.Paths
import scala.util.{Failure, Success, Try}

/** Result of decoding a single AST document produced by the batch generator.
  *
  * @param sourcePath
  *   the source `.php` file this AST corresponds to. When the wrapper carries a `rel_file_path`
  *   provenance key it is resolved against the batch input directory; otherwise the AST json path
  *   is used as a best-effort fallback.
  * @param phpFile
  *   the successfully decoded [[Domain.PhpFile]].
  */
case class BatchParsedFile(sourcePath: String, phpFile: PhpFile)

class PhpParser private (
  phpParserPath: String,
  phpIniPath: String,
  batchGeneratorOverride: Option[String] = None
):

  private val logger = LoggerFactory.getLogger(this.getClass)

  private def phpParseCommand(filename: String): String =
    val phpParserCommands = "--with-recovery --resolve-names -P --json-dump"
    phpParserPath match
      case path if path.endsWith(".js") =>
          // A Node script (phpastgen.js) cannot run under the php interpreter.
          s"node $path $phpParserCommands $filename"
      case "phpastgen" =>
          s"$phpParserPath $phpParserCommands $filename"
      case _ =>
          s"php --php-ini $phpIniPath $phpParserPath $phpParserCommands $filename"

  /** Milliseconds a capability probe may run before it is killed.
    *
    * The probe is one `node` cold start, but it races the first wave of AST
    * cache misses (thousands of file reads and hashes) on worker threads that
    * start as soon as the pass does; five seconds was regularly lost to that
    * contention on loaded runners, silently demoting whole-directory batch
    * ingestion to the per-file fallback. Thirty seconds still bounds a wedged
    * generator while leaving room for a busy machine.
    */
  private val ProbeTimeoutMs = 30000L

  /** Argument-vector head that launches the batch-capable generator, or `None` when only the
    * per-file parser is available.
    *
    * The batch generator is `phpastgen` — the Node CLI shipped by @appthreat/atom-parsetools —
    * which is a different program from the per-file `php-parse` the parser path may name: a
    * configured php-parse is the LEGACY per-file parser and knows neither `--parser-info` nor
    * `-i/-o`, so probing it can only fail and, worse, leaves the frontend grinding through one
    * interpreter spawn per file (hours for a vendored PHP project on Windows). Resolution order:
    *
    *   1. the `PHP_ASTGEN_BIN` environment variable — an absolute path to `phpastgen.js`
    *      (forwarded by cdxgen, which knows the install location) — run as `node <path>`;
    *   2. a phpParserPath that already names phpastgen (a `.js` path, or the bare name);
    *   3. otherwise no batch: the configured per-file parser cannot batch, and the caller
    *      falls back to per-file parsing without wasting a probe.
    *
    * The result is an ARGUMENT VECTOR rather than a shell string: the probe and the batch
    * invocation are executed through [[ExternalCommand.runWithResult]] (a `ProcessBuilder`), so
    * no shell ever parses these paths. A project directory containing spaces, quotes, backticks
    * or `$(...)` is therefore passed through verbatim and cannot be word-split or injected.
    *
    * Windows note: `ProcessBuilder` cannot launch the bare name `phpastgen` (`CreateProcess`
    * appends `.exe` only, while the bin shims are `.cmd`), so the bare name is resolved once
    * through `where phpastgen` — preferring the package's `phpastgen.js` under `node`, which
    * keeps the batch invocation shell-free — and, failing that, run through `cmd /c`, which
    * resolves the shim. POSIX executes the bare name directly.
    */
  private lazy val batchCommandPrefix: Option[Seq[String]] =
    def jsInvocation(path: String): Option[Seq[String]] =
        Option.when(File(path).exists())(Seq("node", path))

    batchGeneratorOverride
        .orElse(Option(System.getenv(PhpParser.BatchGeneratorEnvVar)))
        .flatMap(jsInvocation)
        .orElse(phpParserPath match
          case path if path.endsWith(".js") => jsInvocation(path)
          case "phpastgen"                  => Some(resolveBarePhpastgen())
          // A configured php script (the vendored php-parse) is still probed via
          // the php wrapper: it cannot batch today, but the probe is one cheap
          // spawn and a future/custom generator keeping the php shape stays
          // supported.
          case path => Some(Seq("php", "--php-ini", phpIniPath, path))
        )

  /** Derive the `phpastgen.js` script path next to a bin shim.
    *
    * A project shim `<node_modules>/.bin/phpastgen.cmd` puts the package at
    * `<node_modules>/@appthreat/atom-parsetools/phpastgen.js`; a global-prefix shim
    * `<prefix>/phpastgen.cmd` puts it at `<prefix>/node_modules/@appthreat/atom-parsetools/phpastgen.js`.
    */
  private def phpastgenJsNear(shimPath: String): Option[String] =
    val shim       = File(shimPath)
    val shimDir    = shim.parent
    val candidates = Seq(
      shimDir.parent / "@appthreat" / "atom-parsetools" / "phpastgen.js",
      shimDir / "node_modules" / "@appthreat" / "atom-parsetools" / "phpastgen.js"
    )
    candidates.find(_.exists()).map(_.canonicalPath)

  /** Argument-vector head for the bare `phpastgen` name (see [[batchCommandPrefix]]). */
  private def resolveBarePhpastgen(): Seq[String] =
    if !scala.util.Properties.isWin then Seq("phpastgen")
    else
      val resolved  = ExternalCommand.runWithResult(
        Seq("where", "phpastgen"),
        ".",
        timeoutMillis = ProbeTimeoutMs
      )
      val shimPath  = resolved.stdOut
          .map(_.trim)
          .filter(p => p.toLowerCase.endsWith(".cmd") || p.toLowerCase.endsWith(".bat"))
          .headOption
      shimPath match
        case Some(shim) =>
            phpastgenJsNear(shim) match
              case Some(script) => Seq("node", script)
              case None         => Seq("cmd", "/c", File(shim).canonicalPath)
        case None =>
            // Last resort: let the shell resolve the name from PATH.
            Seq("cmd", "/c", "phpastgen")

  /** Argument vector for the capability probe, when a batch generator is available. */
  private def parserInfoCommand: Option[Seq[String]] =
    batchCommandPrefix.map(_ :+ "--parser-info")

  /** Argument vector for batch mode: `<bin> -i <inputDir> -o <outputDir>`. */
  private def batchCommand(inputDir: String, outputDir: String): Option[Seq[String]] =
    batchCommandPrefix.map(prefix => prefix ++ Seq("-i", inputDir, "-o", outputDir))

  /** Capability probe.
    *
    * Invokes the generator's `--parser-info` and returns `true` ONLY when the output contains a
    * `Generator version:` line. The probe is treated as FAILED (returns `false`) on any of:
    *   - no batch generator being resolvable at all,
    *   - a non-zero exit / exception from the underlying command,
    *   - no `Generator version:` line in the output,
    *   - the probe not returning within [[ProbeTimeoutMs]] (the process is destroyed).
    */
  def supportsBatch: Boolean =
    parserInfoCommand match
      case Some(command) =>
          val result = ExternalCommand.runWithResult(command, ".", timeoutMillis = ProbeTimeoutMs)
          if result.timedOut then
              logger.debug(
                s"Capability probe timed out after ${ProbeTimeoutMs}ms: ${command.mkString(" ")}"
              )
              false
          else
              result.exitCode == 0 && result.stdOut.exists(_.contains("Generator version:"))
      case None =>
          false

  /** Directory-batch ingestion with per-file isolation.
    *
    * Runs the generator once in batch mode (`<bin> -i <inputDir> -o <outputDir>`), then reads every
    * `*.json` document under `outputDir`. `*.jsonl` files (side-records such as
    * `phpastgen_manifest.jsonl`) are SKIPPED — they are not AST documents.
    *
    * Each AST json is decoded independently via [[Domain.fromJson]]. On an INDIVIDUAL decode
    * failure the offending file is excluded from the result and a diagnostic naming the file and
    * the reason is logged, but the directory as a whole is never aborted.
    *
    * @return
    *   the successfully decoded files paired with their resolved source paths. When the batch
    *   command itself fails to run, an empty sequence is returned (callers can then fall back to
    *   the per-file path — see [[parseInput]]).
    */
  def parseDirectory(inputDir: String, outputDir: String): Seq[BatchParsedFile] =
    val inDir  = File(inputDir).canonicalPath
    val outDir = File(outputDir)
    outDir.createDirectoryIfNotExists(createParents = true)
    val outDirPath = outDir.canonicalPath

    batchCommand(inDir, outDirPath) match
      case Some(command) =>
          ExternalCommand.runWithResult(command, inDir).toTry match
            case Success(_) =>
                collectBatchAsts(inDir, outDir)
            case Failure(exception) =>
                logger.debug(
                  s"Batch generation failed for input '$inDir' -> '$outDirPath': ${exception.getMessage}"
                )
                Seq.empty
      case None =>
          Seq.empty

  /** Read and decode every AST `*.json` under `outputDir`, isolating per-file decode failures. */
  private def collectBatchAsts(inputDir: String, outputDir: File): Seq[BatchParsedFile] =
      if !outputDir.exists then
        logger.debug(s"Batch output directory does not exist: ${outputDir.canonicalPath}")
        Seq.empty
      else
        val jsonFiles = outputDir.listRecursively
            .filter(_.isRegularFile)
            .filter(f => f.extension.contains(".json")) // `.json` only; `.jsonl` is excluded here
            .toList

        jsonFiles.flatMap { astFile =>
            decodeAstFile(astFile, inputDir) match
              case Right(parsed) =>
                  Some(parsed)
              case Left(reason) =>
                  // Per-file isolation: skip only this file's contribution and keep going.
                  logger.warn(s"Skipping AST file '${astFile.canonicalPath}': $reason")
                  None
        }
  end collectBatchAsts

  /** Decode a single AST json document, resolving its source path from the wrapper's
    * `rel_file_path` provenance (falling back to the AST file path). Returns `Left(reason)` on any
    * read/parse/decode failure so the caller can isolate it.
    */
  private def decodeAstFile(astFile: File, inputDir: String): Either[String, BatchParsedFile] =
      for
        rawJson <- Try(astFile.contentAsString).toEither.left.map(e =>
            s"could not read file: ${e.getMessage}"
        )
        jsonValue <- Try(ujson.read(rawJson)).toEither.left.map(e =>
            s"invalid JSON: ${e.getMessage}"
        )
        phpFile <- Try(Domain.fromJson(jsonValue)).toEither.left.map(e =>
            s"AST decode failed: ${e.getMessage}"
        )
      yield
        val sourcePath = phpFile.provenance.relFilePath match
          case Some(rel) if rel.nonEmpty =>
              File(inputDir, rel).pathAsString
          case _ =>
              astFile.pathAsString
        BatchParsedFile(sourcePath, phpFile)

  def parseFile(inputPath: String, phpIniOverride: Option[String]): Option[PhpFile] =
    val inputFile      = File(inputPath)
    val inputFilePath  = inputFile.canonicalPath
    val inputDirectory = inputFile.parent.canonicalPath

    val command = phpParseCommand(inputFilePath)

    ExternalCommand.run(command, inputDirectory, true) match
      case Success(output) =>
          processParserOutput(output, inputFilePath)

      case Failure(exception) =>
          None

  private def processParserOutput(output: Seq[String], filename: String): Option[PhpFile] =
    val maybeJson =
        linesToJsonValue(output, filename)
    maybeJson.flatMap(jsonValueToPhpFile(_, filename))

  private def linesToJsonValue(lines: Seq[String], filename: String): Option[ujson.Value] =
    // The generator emits either a bare JSON array (older passthrough) or the new wrapper object
    // `{ "ast": [...], ...provenance }`. Skip any leading non-JSON banner lines and start at the
    // first line that opens either shape, so chen stays compatible with both generators
    // (backward + forward compatible). `Domain.fromJson` then unwraps `ast`.
    val jsonLines = lines.dropWhile(line => !line.startsWith("[") && !line.startsWith("{"))

    if jsonLines.isEmpty then
      None
    else
      val jsonString = jsonLines.mkString("\n")
      Try(ujson.read(jsonString)) match
        case Success(value) => Some(value)
        case Failure(e) =>
            None

  private def jsonValueToPhpFile(json: ujson.Value, filename: String): Option[PhpFile] =
      Try(Domain.fromJson(json)) match
        case Success(phpFile) => Some(phpFile)

        case Failure(e) =>
            None

  /** Top-level ingestion entry that chooses batch vs. legacy per-file based on the capability
    * probe.
    *
    * When [[supportsBatch]] returns `true` the whole input directory is parsed in one batch pass
    * via [[parseDirectory]]. Otherwise — probe failure/timeout, or a batch that produced no
    * decodable output — ingestion falls back to the legacy per-file `--json-dump` stdout path,
    * invoking [[parseFile]] for each supplied file. The legacy passthrough therefore keeps working
    * unchanged.
    *
    * @param inputDir
    *   the batch input directory (used only for the batch path).
    * @param outputDir
    *   the directory batch AST documents are written to (used only for the batch path).
    * @param files
    *   the individual `.php` files to parse; used to drive the per-file fallback and to key results
    *   when batch output does not carry a resolvable source path.
    * @param phpIniOverride
    *   optional php.ini override forwarded to the per-file path.
    * @return
    *   decoded files paired with their source paths. Batch and fallback produce the same shape so
    *   callers are agnostic to which path ran.
    *
    * Note: `io.appthreat.php2atom.passes.AstCreationPass` drives [[supportsBatch]] and
    * [[parseDirectory]] directly rather than calling this method, because it must keep its per-file
    * AST caching (and per-file fallback) inside `runOnPart`. This entry point remains the
    * one-call-does-everything variant for callers that want the whole input decoded eagerly.
    */
  def parseInput(
    inputDir: String,
    outputDir: String,
    files: Seq[String],
    phpIniOverride: Option[String]
  ): Seq[BatchParsedFile] =
      if supportsBatch then
        val batchResults = parseDirectory(inputDir, outputDir)
        if batchResults.nonEmpty then
          batchResults
        else
          // Distinct from the "old generator, no batch support" case below: the generator DID
          // advertise batch support, so producing nothing means the batch run itself is broken
          // (crash, unwritable output dir, undecodable documents). Warn so it is not mistaken for
          // an expected legacy fallback.
          logger.warn(
            s"Batch mode is supported by the generator but produced no decodable AST documents " +
                s"for input '$inputDir' (output '$outputDir'); falling back to per-file parsing."
          )
          parseFilesIndividually(files, phpIniOverride)
      else
        logger.debug("Batch mode unsupported by generator; using per-file parsing.")
        parseFilesIndividually(files, phpIniOverride)
  end parseInput

  /** Legacy per-file fallback: parse each file via [[parseFile]], isolating per-file failures. */
  private def parseFilesIndividually(
    files: Seq[String],
    phpIniOverride: Option[String]
  ): Seq[BatchParsedFile] =
      files.flatMap { file =>
          parseFile(file, phpIniOverride) match
            case Some(phpFile) =>
                Some(BatchParsedFile(File(file).canonicalPath, phpFile))
            case None =>
                logger.debug(s"Could not parse file $file. Results will be missing!")
                None
      }
end PhpParser

object PhpParser:

  val PhpParserBinEnvVar = "PHP_PARSER_BIN"

  /** Environment variable carrying the absolute path of the batch-capable `phpastgen.js`
    * (a Node CLI), forwarded by callers such as cdxgen that know where it is installed. Unlike
    * [[PhpParserBinEnvVar]] — which names the LEGACY per-file `php-parse` — this one selects the
    * generator used for batch ingestion. Unset means "resolve phpastgen from PATH/the default".
    */
  val BatchGeneratorEnvVar = "PHP_ASTGEN_BIN"

  private lazy val defaultPhpIni: String =
    val tmpIni = File.newTemporaryFile(suffix = "-php.ini").deleteOnExit()
    tmpIni.writeText("memory_limit = -1")
    tmpIni.canonicalPath

  private def isPhpAstgenSupported: Boolean =
    val result = ExternalCommand.run("phpastgen --help", ".")
    result match
      case Success(listString) =>
          true
      case Failure(exception) =>
          false

  private def defaultPhpParserBin: String =
    // In a GraalVM native image getCodeSource.getLocation is null, and a classpath layout
    // without a php2atom segment makes indexOf return -1 (substring would throw); either
    // would kill getParser where a plain "phpastgen" default keeps the frontend alive.
    val builtInGen = Try {
        val dir = Paths
            .get(this.getClass.getProtectionDomain.getCodeSource.getLocation.toURI)
            .toAbsolutePath.toString
        val fixedDir = new java.io.File(dir.substring(0, dir.indexOf("php2atom"))).toString
        Paths.get(fixedDir, "php2atom", "vendor", "bin", "php-parse").toAbsolutePath.toString
    }.toOption
    builtInGen.filter(p => File(p).exists()).getOrElse("phpastgen")

  private def configOverrideOrDefaultPath(
    identifier: String,
    maybeOverride: Option[String],
    defaultValue: => String
  ): Option[String] =
    val pathString = maybeOverride match
      case Some(overridePath) if overridePath.nonEmpty =>
          overridePath
      case _ =>
          defaultValue

    File(pathString) match
      case file if file.exists() && file.isRegularFile(using File.LinkOptions.follow) =>
          Some(file.canonicalPath)
      case _ => Some(defaultValue)

  private def maybePhpParserPath(config: Config): Option[String] =
    val phpParserPathOverride =
        config.phpParserBin
            .orElse(Option(System.getenv(PhpParserBinEnvVar)))

    configOverrideOrDefaultPath("PhpParserBin", phpParserPathOverride, defaultPhpParserBin)

  private def maybePhpIniPath(config: Config): Option[String] =
      configOverrideOrDefaultPath("PhpIni", config.phpIni, defaultPhpIni)

  def getParser(config: Config): Option[PhpParser] =
      for (
        phpParserPath <- maybePhpParserPath(config);
        phpIniPath    <- maybePhpIniPath(config)
      )
          yield new PhpParser(phpParserPath, phpIniPath)

  /** Construct a parser directly from an explicit binary + ini pair.
    *
    * Primarily a testing seam for the batch/probe/fallback paths: it lets tests point the parser at
    * a stub generator without going through [[Config]] resolution. The public behaviour of
    * [[getParser]] is unchanged. `batchGeneratorOverride` stands in for the
    * [[BatchGeneratorEnvVar]] environment variable (which cannot be mutated in-JVM for tests).
    */
  def fromPaths(
    phpParserPath: String,
    phpIniPath: String,
    batchGeneratorOverride: Option[String] = None
  ): PhpParser =
    new PhpParser(phpParserPath, phpIniPath, batchGeneratorOverride)
end PhpParser
