package io.appthreat.jssrc2cpg.utils

import better.files.File
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.passes.frontend.{CacheControl, CpgCacheStore, ExternalParseCache}
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.resolveCacheDir
import io.appthreat.x2cpg.utils.{Environment, ExternalCommand}
import io.shiftleft.utils.IOUtils
import com.typesafe.config.ConfigFactory
import io.appthreat.jssrc2cpg.Config
import org.slf4j.LoggerFactory
import versionsort.VersionHelper

import java.nio.file.Paths
import scala.util.Failure
import scala.util.Success
import scala.util.matching.Regex
import scala.util.Try

object AstGenRunner:

  private val TypeDefinitionFileExtensions = List(".t.ts", ".d.ts")

  private val IgnoredTestsRegex: Seq[Regex] =
      List(
        ".*cypress\\.json".r,
        ".*test.*\\.json".r
      )

  private val IgnoredFilesRegex: Seq[Regex] = List(
    ".*\\.types\\.js".r,
    ".*\\.devcontainer\\.json".r,
    ".*i18n.*\\.json".r
  )

  case class AstGenRunnerResult(
    parsedFiles: List[(String, String)] = List.empty,
    /** Which engine wrote the type maps, from the types record of astgen_manifest.jsonl in the
      * astgen output; None when astgen wrote no record (atom-parsetools 1.x, or a user-supplied
      * output directory without one).
      */
    typeMapEngine: Option[String] = None
  )

  /** The manifest astgen appends its types record to. The name ends in .jsonl because every *.json
    * under the astgen output is read as an AST.
    */
  private val ManifestName = "astgen_manifest.jsonl"

  private val KnownEngines = Set("native", "ts6")

  /** The engine of the last types record in the manifest, or None. The file is one JSON object per
    * line; lines that do not parse are skipped, and a record without a known engine is not ours.
    */
  private[jssrc2cpg] def typeMapEngineOf(manifest: File): Option[String] =
      if manifest.isRegularFile then
        manifest.contentAsString.linesIterator
            .map(_.trim)
            .filter(_.nonEmpty)
            .flatMap(line =>
                Try(ujson.read(line).obj)
                    .toOption
                    .flatMap(obj =>
                        for
                          kind   <- obj.get("kind") if kind.str == "types"
                          engine <- obj.get("engine") if KnownEngines.contains(engine.str)
                        yield engine.str
                    )
            )
            .toVector
            .lastOption
      else None

  /** The astgen command to run. "astgen" unless a test setting names another one, which is how the
    * suite runs against a chosen astgen (the 1.x release from npm, or a worktree build) instead of
    * whatever is on PATH.
    */
  private[utils] def astGenCommand: String =
      // a blank setting counts as unset, so a blank property does not hide the environment variable
      sys.props
          .get("jssrc2cpg.test.astgenCmd")
          .map(_.trim)
          .filter(_.nonEmpty)
          .orElse(sys.env.get("JSSRC2CPG_TEST_ASTGEN_CMD").map(_.trim).filter(_.nonEmpty))
          .getOrElse("astgen")
end AstGenRunner

class AstGenRunner(config: Config):

  import AstGenRunner.*

  private val executableArgs = if !config.tsTypes then " --no-tsTypes" else ""
  private val typeArgs       = if config.flow then "flow" else "ts"

  /** The environment astgen is started with, beyond the JVM's own: ASTGEN_TYPES when the
    * configuration names a type map engine. Without it astgen keeps whatever the environment says,
    * so a default run is unchanged.
    */
  private[utils] def astGenEnv: Map[String, String] =
      config.astGenTypes.map(t => Map("ASTGEN_TYPES" -> t)).getOrElse(Map.empty)
  private def isIgnoredByUserConfig(filePath: String): Boolean =
    lazy val isInIgnoredFiles = config.ignoredFiles.exists {
        case ignorePath if File(ignorePath).isDirectory => filePath.startsWith(ignorePath)
        case ignorePath                                 => filePath == ignorePath
    }
    lazy val isInIgnoredFileRegex = config.ignoredFilesRegex.matches(filePath)
    if isInIgnoredFiles || isInIgnoredFileRegex then
      true
    else
      false

  private def isIgnoredByDefault(filePath: String): Boolean =
    lazy val isIgnored     = IgnoredFilesRegex.exists(_.matches(filePath))
    lazy val isIgnoredTest = IgnoredTestsRegex.exists(_.matches(filePath))
    if isIgnored || isIgnoredTest then
      true
    else
      false

  private def filterFiles(files: List[String], out: File): List[String] =
      files.filter { file =>
          file.stripSuffix(".json").replace(out.pathAsString, config.inputPath) match
            case filePath if TypeDefinitionFileExtensions.exists(filePath.endsWith) => false
            case filePath if isIgnoredByUserConfig(filePath)                        => false
            case filePath if isTranspiledCopy(filePath)                             => false
            case _                                                                  => true
      }

  /** A `dist/` directory next to a `src/` sibling is the transpiled copy of that source: it
    * declares every class a second time, which makes a recovered `Type:method` callee name match
    * both the copy and the original, and no unique method can be picked. The copy is dropped here,
    * where the files are chosen - flows are not deduplicated after the fact. A `dist/` without a
    * `src/` sibling stays: it can be the only code a package ships.
    */
  private def isTranspiledCopy(filePath: String): Boolean =
    // Only directories inside the project count: a project checked out under some `dist/` stays
    val root     = Paths.get(config.inputPath).toAbsolutePath.normalize
    val relative = root.relativize(Paths.get(filePath).toAbsolutePath.normalize)
    val dirs     = (0 until relative.getNameCount - 1).map(relative.getName(_).toString)
    dirs.indices.exists(i =>
        dirs(i) == "dist" && dirs.take(i).foldLeft(root)(_.resolve(_)).resolve("src").toFile.isDirectory
    )

  /** Changes the file-extension by renaming this file; if file does not have an extension, it adds
    * the extension. If file does not exist (or is a directory) no change is done and the current
    * file is returned.
    */
  private def changeExtensionTo(file: File, extension: String): File =
    val newName =
        s"${file.nameWithoutExtension(includeAll = false)}.${extension.stripPrefix(".")}"
    if file.isRegularFile then file.renameTo(newName)
    else if file.notExists then File(newName)
    else file

  private def vueFiles(in: File, out: File): Try[Seq[String]] =
    val files = SourceFiles.determine(in.pathAsString, Set(".vue"))
    if files.nonEmpty then
      ExternalCommand.run(s"$astGenCommand$executableArgs -t vue -o $out", in.toString(), astGenEnv)
    else Success(Seq.empty)

  private def jsFiles(in: File, out: File): Try[Seq[String]] =
      ExternalCommand.run(
        s"$astGenCommand$executableArgs -t $typeArgs -o $out",
        in.toString(),
        astGenEnv
      )

  private def runAstGenNative(in: File, out: File): Try[Seq[String]] =
      for
        jsResult  <- jsFiles(in, out)
        vueResult <- vueFiles(in, out)
      yield jsResult ++ vueResult

  /** Best-effort astgen version, folded into the cache fingerprint so an astgen upgrade invalidates
    * cached output. Falls back to "unknown" if the version cannot be determined.
    */
  private lazy val astGenVersion: String =
      ExternalCommand
          .run(s"$astGenCommand --version", config.inputPath)
          .toOption
          .flatMap(_.headOption)
          .map(_.trim)
          .getOrElse("unknown")

  /** What, besides the sources, decides astgen's output: a change in any of these must not restore
    * a cached parse. A type map written by the native binary differs from one written by TypeScript
    * 6.
    */
  private[utils] def astGenFingerprintInputs: Seq[String] =
      Seq(
        s"astgen-version=$astGenVersion",
        s"tsTypes=${config.tsTypes}",
        s"flow=${config.flow}",
        s"astgen-types=${config.effectiveAstGenTypes()}"
      )

  /** Identity of everything (besides the sources) that affects astgen's output. */
  private def astGenFingerprint: String =
      CpgCacheStore.projectFingerprint(config.inputPath, astGenFingerprintInputs)

  def execute(out: File): AstGenRunnerResult =
    val in = File(config.inputPath)
    val runResult =
        if config.astGenOutDir.nonEmpty then
          // A user-provided astgen output directory (e.g. CHEN_ASTGEN_OUT) is authoritative: reuse
          // its contents ONLY when it actually contains astgen `.json` output, otherwise run astgen
          // into it (populating it for next time). The shared ExternalParseCache is deliberately
          // bypassed here so that pointing at an empty directory always triggers a real astgen run
          // rather than silently restoring a previously cached parse.
          if out.exists && SourceFiles.determine(out.toString(), Set(".json")).nonEmpty then
            Success(Seq.empty)
          else
            runAstGenNative(in, out)
        else
          val cache =
              new ExternalParseCache(resolveCacheDir(config.inputPath, ""), CacheControl.Astgen)
          val fp = astGenFingerprint
          if cache.restore(fp, out.path) then Success(Seq.empty)
          else
            runAstGenNative(in, out).map { res =>
              cache.store(fp, out.path); res
            }
    def written =
        filterFiles(SourceFiles.determine(out.toString(), Set(".json")), out).map((
          in.toString(),
          _
        ))
    // Which engine really ran, read once per astgen run from the manifest astgen wrote (also when
    // the output was restored from the parse cache or reused from a user directory): the
    // configuration only says what was asked for, and astgen may have fallen back.
    val engine = typeMapEngineOf(out / ManifestName)
    runResult match
      case Success(_)   => AstGenRunnerResult(written, engine)
      case Failure(err) =>
          // astgen writes each file's AST as it finishes it, so when it dies part way (out of
          // memory, a crash) the files before are sound. The run is reported, never passed off as
          // a project without sources; on stderr, since atom does not print chen's log.
          val reason = Option(err.getMessage).toSeq.flatMap(_.linesIterator)
              .filterNot(l => l.isBlank || l.trim.matches("\\d+: 0x.*"))
              .takeRight(3)
          val parsed = written
          System.err.println(
            s"astgen failed on $in, so the atom holds only the ${parsed.size} files it finished: ${reason.mkString(" | ")}"
          )
          AstGenRunnerResult(parsed, engine)
  end execute
end AstGenRunner
