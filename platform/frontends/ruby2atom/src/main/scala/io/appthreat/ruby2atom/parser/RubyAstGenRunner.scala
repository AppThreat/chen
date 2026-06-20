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

import java.io.File.separator
import java.io.{ByteArrayOutputStream, InputStream, PrintStream}
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.util
import java.util.jar.JarFile
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try, Using}

class RubyAstGenRunner(config: Config) extends AstGenRunnerBase(config):

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
    val command     = s"rbastgen -i $in -o ${out.pathAsString}"
    val excludeArgs = if exclude.isEmpty then "" else s" -e '$exclude'"
    ExternalCommand.run(s"$command$excludeArgs", in, true) match
      case Success(result) =>
          collectResult(out)
      case Failure(f) =>
          DefaultAstGenRunnerResult()

  /** Collect the parsed JSON files produced (or restored from cache) under `out`. */
  private def collectResult(out: File): AstGenRunnerResult =
    val srcFiles = SourceFiles.determine(
      out.pathAsString,
      Set(".json"),
      ignoredDefaultRegex = Option(config.defaultIgnoredFilesRegex),
      ignoredFilesRegex = Option(config.ignoredFilesRegex),
      ignoredFilesPath = Option(config.ignoredFiles)
    )
    val parsed = filterFiles(srcFiles, out)
    DefaultAstGenRunnerResult(parsed, List.empty)

  /** Best-effort rbastgen version, folded into the cache fingerprint so a parser upgrade
    * invalidates cached output. Falls back to "unknown" if the version cannot be determined.
    */
  private lazy val astGenVersion: String =
      ExternalCommand
          .run("rbastgen --version", config.inputPath)
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
