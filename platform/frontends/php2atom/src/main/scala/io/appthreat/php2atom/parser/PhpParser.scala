package io.appthreat.php2atom.parser

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.parser.Domain.PhpFile
import io.appthreat.x2cpg.utils.ExternalCommand
import org.slf4j.LoggerFactory

import java.nio.file.Paths
import scala.concurrent.duration.*
import scala.concurrent.{Await, Future, TimeoutException}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

/** Result of decoding a single AST document produced by the batch generator.
  *
  * @param sourcePath
  *   the source `.php` file this AST corresponds to. When the wrapper carries a `rel_file_path`
  *   provenance key it is resolved against the batch input directory; otherwise the AST json path
  *   is used as a best-effort fallback.
  * @param phpFile
  *   the successfully decoded [[PhpFile]].
  */
case class BatchParsedFile(sourcePath: String, phpFile: PhpFile)

class PhpParser private (phpParserPath: String, phpIniPath: String):

  private val logger = LoggerFactory.getLogger(this.getClass)

  private def phpParseCommand(filename: String): String =
    val phpParserCommands = "--with-recovery --resolve-names -P --json-dump"
    phpParserPath match
      case "phpastgen" =>
          s"$phpParserPath $phpParserCommands $filename"
      case _ =>
          s"php --php-ini $phpIniPath $phpParserPath $phpParserCommands $filename"

  /** Prefix the generator arguments with the right invocation shape, mirroring
    * [[phpParseCommand]]'s two forms (vendored/`phpastgen` binary vs the `php --php-ini <ini>
    * <bin>` wrapper).
    *
    * Returns an ARGUMENT VECTOR rather than a shell string: both the probe and the batch invocation
    * are executed through [[ExternalCommand.runWithResult]] (a `ProcessBuilder`), so no shell ever
    * parses these paths. A project directory containing spaces, quotes, backticks or `$(...)` is
    * therefore passed through verbatim and cannot be word-split or injected.
    */
  private def generatorCommand(args: Seq[String]): Seq[String] =
      phpParserPath match
        case "phpastgen" =>
            phpParserPath +: args
        case _ =>
            Seq("php", "--php-ini", phpIniPath, phpParserPath) ++ args

  /** Argument vector for the capability probe. */
  private def parserInfoCommand: Seq[String] =
      generatorCommand(Seq("--parser-info"))

  /** Argument vector for batch mode: `<bin> -i <inputDir> -o <outputDir>`. */
  private def batchCommand(inputDir: String, outputDir: String): Seq[String] =
      generatorCommand(Seq("-i", inputDir, "-o", outputDir))

  /** Capability probe (Task 14.1 / Requirement 3.6).
    *
    * Invokes the generator's `--parser-info` and returns `true` ONLY when the output contains a
    * `Generator version:` line. The probe is treated as FAILED (returns `false`) on any of:
    *   - a non-zero exit / exception from the underlying command,
    *   - no `Generator version:` line in the output,
    *   - the probe not returning within 5 seconds (timeout).
    *
    * The timeout is enforced by running the (blocking) command on a `Future` and `Await`-ing it for
    * at most 5 seconds; a [[TimeoutException]] (or any other throwable) is caught and mapped to
    * `false` so a hung generator can never wedge ingestion.
    */
  def supportsBatch: Boolean =
    val command = parserInfoCommand
    val probe: Future[Boolean] = Future {
        ExternalCommand.runWithResult(command, ".").toTry match
          case Success(output) =>
              output.exists(_.contains("Generator version:"))
          case Failure(_) =>
              false
    }
    Try(Await.result(probe, 5.seconds)) match
      case Success(result) =>
          result
      case Failure(_: TimeoutException) =>
          logger.debug(s"Capability probe timed out after 5s: ${command.mkString(" ")}")
          false
      case Failure(exception) =>
          logger.debug(s"Capability probe failed: ${exception.getMessage}")
          false

  /** Directory-batch ingestion with per-file isolation (Task 14.2 / Requirements 3.7, 3.9).
    *
    * Runs the generator once in batch mode (`<bin> -i <inputDir> -o <outputDir>`), then reads every
    * `*.json` document under `outputDir`. `*.jsonl` files (side-records such as
    * `phpastgen_manifest.jsonl`) are SKIPPED — they are not AST documents (invariant 2).
    *
    * Each AST json is decoded independently via [[Domain.fromJson]]. On an INDIVIDUAL decode
    * failure the offending file is excluded from the result and a diagnostic naming the file and
    * the reason is logged, but the directory as a whole is never aborted (Requirement 3.9).
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

    val command = batchCommand(inDir, outDirPath)
    ExternalCommand.runWithResult(command, inDir).toTry match
      case Success(_) =>
          collectBatchAsts(inDir, outDir)
      case Failure(exception) =>
          logger.debug(
            s"Batch generation failed for input '$inDir' -> '$outDirPath': ${exception.getMessage}"
          )
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
    // (backward + forward compatible, Requirement 4.1/4.2). `Domain.fromJson` then unwraps `ast`.
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

  /** Top-level ingestion entry that chooses batch vs. legacy per-file based on the capability probe
    * (Task 14.3 / Requirement 3.8, invariant 4).
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
    val dir =
        Paths.get(
          this.getClass.getProtectionDomain.getCodeSource.getLocation.toURI
        ).toAbsolutePath.toString

    val fixedDir = new java.io.File(dir.substring(0, dir.indexOf("php2atom"))).toString

    val builtInGen = Paths.get(
      fixedDir,
      "php2atom",
      "vendor",
      "bin",
      "php-parse"
    ).toAbsolutePath.toString
    if File(builtInGen).exists() then builtInGen
    else "phpastgen"

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
    * Primarily a testing seam for the batch/probe/fallback paths (Tasks 14.1-14.3): it lets tests
    * point the parser at a stub generator without going through [[Config]] resolution. The public
    * behaviour of [[getParser]] is unchanged.
    */
  def fromPaths(phpParserPath: String, phpIniPath: String): PhpParser =
      new PhpParser(phpParserPath, phpIniPath)
end PhpParser
