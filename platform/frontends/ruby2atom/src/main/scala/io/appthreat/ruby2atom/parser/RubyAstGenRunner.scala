package io.appthreat.ruby2atom.parser

import better.files.File
import io.appthreat.ruby2atom.Config
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.astgen.AstGenRunner.{
    AstGenProgramMetaData,
    AstGenRunnerResult,
    DefaultAstGenRunnerResult
}
import io.appthreat.x2cpg.astgen.AstGenRunnerBase
import io.appthreat.x2cpg.passes.frontend.{CacheControl, CpgCacheStore, ExternalParseCache}
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.resolveCacheDir
import io.appthreat.x2cpg.utils.{Environment, ExternalCommand}
import org.slf4j.LoggerFactory

import java.io.File.separator
import java.io.{ByteArrayOutputStream, InputStream, PrintStream}
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.util
import java.util.jar.JarFile
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try, Using}

object RubyAstGenRunner:

  /** Default generator binary, resolved through `PATH`. */
  val DefaultProgram: String = "rbastgen"

  /** System property and environment variable that override the generator binary. */
  val ProgramProperty: String = "rbastgen.path"
  val ProgramEnvVar: String   = "RBASTGEN_PATH"

  /** Side-record names the generator (ruby_ast_gen 2.x) writes inside the output directory. Both
    * are `.jsonl` on purpose: `collectResult` feeds every `*.json` file to the AST reader, so a
    * side-record must never carry that suffix.
    */
  val ManifestFilename: String    = "ruby_ast_gen_manifest.jsonl"
  val DiagnosticsFilename: String = "ruby_ast_gen_diagnostics.jsonl"

  /** The generator's own accounting, read from its manifest side-record. */
  final case class RunManifestCounts(filesParsed: Int, filesFailed: Int, input: String)

  /** Reads the run manifest the 2.x generator leaves in the output directory. A 1.x generator
    * writes none, and a malformed record must not fail a finished run, so any reading problem
    * degrades to `None`.
    */
  def readRunManifest(out: File): Option[RunManifestCounts] =
      Try {
          val manifestPath = out.path.resolve(ManifestFilename)
          if !Files.exists(manifestPath) then None
          else
            val json = ujson.read(Files.readString(manifestPath))
            Some(
              RunManifestCounts(
                filesParsed = json("files_parsed").num.toInt,
                filesFailed = json("files_failed").num.toInt,
                input = json("input").str
              )
            )
      }.toOption.flatten

  /** Number of parse-error records in the diagnostics side-record, when the generator wrote one.
    */
  def diagnosticsRecordCount(out: File): Option[Int] =
      Try {
          val diagnosticsPath = out.path.resolve(DiagnosticsFilename)
          if Files.exists(diagnosticsPath) then
            Some(Files.readAllLines(diagnosticsPath).asScala.size)
          else None
      }.toOption.flatten

  /** The output files that count as AST JSONs. Deliberately `.json` only: the generator
    * (ruby_ast_gen 2.x) also writes `.jsonl` side-records into this directory, and feeding those to
    * the AST reader (which requires a top-level `file_path` and re-reads the source) would throw,
    * get swallowed downstream, and silently miscount the run.
    */
  def astFilesIn(out: File, config: Config): List[String] =
      SourceFiles.determine(
        out.pathAsString,
        Set(".json"),
        ignoredDefaultRegex = Option(config.defaultIgnoredFilesRegex),
        ignoredFilesRegex = Option(config.ignoredFilesRegex),
        ignoredFilesPath = Option(config.ignoredFiles)
      )

  /** Chooses the generator binary. A custom build is selected without touching `PATH`, which is
    * what makes it usable when ruby2atom runs inside another process (e.g. atom): the property can
    * be set with `-Drbastgen.path=...` or `System.setProperty`, the environment variable by the
    * caller's shell. Blank values are ignored so that `RBASTGEN_PATH=` behaves like unset.
    */
  def resolveProgram(
    property: Option[String] = Option(System.getProperty(ProgramProperty)),
    environment: Option[String] = sys.env.get(ProgramEnvVar)
  ): String =
      property.orElse(environment).map(_.trim).filter(_.nonEmpty).getOrElse(DefaultProgram)
end RubyAstGenRunner

class RubyAstGenRunner(config: Config) extends AstGenRunnerBase(config):

  private val logger = LoggerFactory.getLogger(getClass)

  /** Quoted for the shell `ExternalCommand` runs the generator through; a bare program name still
    * resolves through `PATH` when quoted.
    */
  private def rbastgen: String = s"\"${RubyAstGenRunner.resolveProgram()}\""

  override def fileFilter(file: String, out: File): Boolean =
      file.stripSuffix(".json").replace(out.pathAsString, config.inputPath) match
        case filePath if isIgnoredByUserConfig(filePath)   => false
        case filePath if isIgnoredByDefaultRegex(filePath) => false
        case _                                             => true

  private def isIgnoredByDefaultRegex(filePath: String): Boolean =
      config.defaultIgnoredFilesRegex.exists(_.matches(filePath))

  override def runAstGenNative(in: String, out: File, exclude: String, include: String)(implicit
    metaData: AstGenProgramMetaData
  ): AstGenRunnerResult =
    val command     = s"$rbastgen -i $in -o ${out.pathAsString}"
    val excludeArgs = if exclude.isEmpty then "" else s" -e '$exclude'"
    ExternalCommand.run(s"$command$excludeArgs", in, true) match
      case Success(result) =>
          val collected = collectResult(out)
          logRunSummary(out)
          collected
      case Failure(f) =>
          DefaultAstGenRunnerResult()

  /** Surfaces the generator's own accounting once per run, from the manifest it writes
    * (ruby_ast_gen 2.x). A generator that parses nothing still exits 0, so "0 parsed" is the only
    * symptom of a silently empty atom - hence the warn with the input path. Parse errors from the
    * diagnostics side-record are surfaced at debug level; neither record is fatal and a missing one
    * (older generator, or a malformed write) is tolerated silently.
    */
  private def logRunSummary(out: File): Unit =
      RubyAstGenRunner.readRunManifest(out) match
        case Some(counts) =>
            logger.info(
              s"rbastgen parsed ${counts.filesParsed} file(s), ${counts.filesFailed} failed to parse"
            )
            if counts.filesParsed == 0 then
              logger.warn(
                s"rbastgen parsed no Ruby files for input '${counts.input}'; the CPG will be empty"
              )
            RubyAstGenRunner.diagnosticsRecordCount(out).foreach { records =>
                logger.debug(
                  s"rbastgen reported $records parse error(s) in " +
                      out.path.resolve(RubyAstGenRunner.DiagnosticsFilename)
                )
            }
        case None => // a 1.x generator (no manifest), or a record that did not parse
  end logRunSummary

  /** Collect the parsed JSON files produced (or restored from cache) under `out`. */
  private def collectResult(out: File): AstGenRunnerResult =
      DefaultAstGenRunnerResult(
        filterFiles(RubyAstGenRunner.astFilesIn(out, config), out),
        List.empty
      )

  /** Best-effort rbastgen version, folded into the cache fingerprint so a parser upgrade
    * invalidates cached output. Falls back to "unknown" if the version cannot be determined.
    */
  private lazy val astGenVersion: String =
      ExternalCommand
          .run(s"$rbastgen --version", config.inputPath)
          .toOption
          .flatMap(_.headOption)
          .map(_.trim)
          .getOrElse("unknown")

  /** Identity of everything (besides the sources) that affects rbastgen's output. */
  private def astGenFingerprint(excludeRegex: String): String =
      CpgCacheStore.projectFingerprint(
        config.inputPath,
        Seq(s"rbastgen-version=$astGenVersion", s"exclude=$excludeRegex")
      )

  override def execute(out: File): AstGenRunnerResult =
    implicit val metaData: AstGenProgramMetaData = config.astGenMetaData
    val combineIgnoreRegex =
        if config.ignoredFilesRegex.toString().isEmpty && config.defaultIgnoredFilesRegex.toString.nonEmpty
        then
          config.defaultIgnoredFilesRegex.mkString("|")
        else if config.ignoredFilesRegex.toString().nonEmpty && config.defaultIgnoredFilesRegex
              .toString.isEmpty
        then
          config.ignoredFilesRegex.toString()
        else if config.ignoredFilesRegex.toString().nonEmpty && config.defaultIgnoredFilesRegex
              .toString().nonEmpty
        then
          s"((${config.ignoredFilesRegex.toString()})|(${config.defaultIgnoredFilesRegex.mkString("|")}))"
        else
          ""

    // Cache the (expensive) rbastgen output keyed by a cheap project fingerprint.
    val cache =
        new ExternalParseCache(resolveCacheDir(config.inputPath, ""), CacheControl.Astgen)
    val fp = astGenFingerprint(combineIgnoreRegex)
    if cache.restore(fp, out.path) then
      collectResult(out)
    else
      val res = runAstGenNative(config.inputPath, out, combineIgnoreRegex, "")
      if res.parsedFiles.nonEmpty then cache.store(fp, out.path)
      res
  end execute

  private sealed trait ExecutionEnvironment extends AutoCloseable:
    def path: Path

    def close(): Unit = {}

  private case class TempDir(path: Path) extends ExecutionEnvironment:

    override def close(): Unit =
      def cleanUpDir(f: Path): Unit =
        if Files.isDirectory(f) then
          Files.list(f).iterator.asScala.foreach(cleanUpDir)
        Files.deleteIfExists(f)

      cleanUpDir(path)

  private case class LocalDir(path: Path) extends ExecutionEnvironment
end RubyAstGenRunner
