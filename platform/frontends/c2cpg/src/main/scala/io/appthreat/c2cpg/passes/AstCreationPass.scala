package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{CdtParser, FileDefaults, HeaderFileFinder}
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.StreamingCpgPass
import org.eclipse.cdt.core.dom.ast.IASTTranslationUnit

import java.nio.file.{Files, Paths}
import java.util.concurrent.*
import java.util.regex.Pattern
import scala.concurrent.duration.*
import scala.util.Try
import scala.util.matching.Regex

object AstCreationPass:
  // The parse pool exists only to give each parse a cancellable thread for the timeout below.
  // Concurrency (and therefore peak memory) is already bounded upstream by StreamingCpgPass's
  // producer semaphore (~0.7 * cores). Sizing this pool ABOVE that bound is essential: if it is
  // smaller, admitted files queue here while their `future.get(timeout)` clock is already running,
  // so a fast file can "time out" purely from waiting behind a couple of slow headers. Sizing to
  // the full core count guarantees a submitted parse starts immediately, so the timeout measures
  // real parse time rather than queue wait.
  private val maxConcurrentParsers = Math.max(4, Runtime.getRuntime.availableProcessors())

  /** Per-file parse/AST timeout. Defaults to 2 minutes; override via `CHEN_CDT_TIMEOUT` (seconds)
    * for projects with pathologically heavy translation units (e.g. template-heavy SDK headers).
    */
  private[passes] val parseTimeout: FiniteDuration =
      sys.env.get("CHEN_CDT_TIMEOUT").flatMap(s => Try(s.trim.toInt).toOption).filter(_ > 0) match
        case Some(seconds) => seconds.seconds
        case None          => 2.minutes

  /** When `CHEN_CDT_DEBUG` is set, log the parse duration of any file that takes over a second.
    * Useful for pinpointing pathological headers / include-resolution blow-ups.
    */
  private[passes] val debugTiming: Boolean =
      sys.env.get("CHEN_CDT_DEBUG").exists(v => v == "1" || v.equalsIgnoreCase("true"))

  private val EscapedFileSeparator = Pattern.quote(java.io.File.separator)
  private val DefaultIgnoredFolders: List[Regex] = List(
    "\\..*".r,
    s"(.*[$EscapedFileSeparator])?tests?[$EscapedFileSeparator].*".r,
    s"(.*[$EscapedFileSeparator])?CMakeFiles[$EscapedFileSeparator].*".r
  )

  /** The set of source/header files the AST pass would process, in the same order. Shared with the
    * warm-restore path so it keys exactly the same parts.
    */
  def sourceFiles(config: Config): Array[String] =
      SourceFiles
          .determine(
            config.inputPath,
            FileDefaults.SOURCE_FILE_EXTENSIONS ++ FileDefaults.HEADER_FILE_EXTENSIONS,
            ignoredDefaultRegex = Option(DefaultIgnoredFolders),
            ignoredFilesRegex = Option(config.ignoredFilesRegex),
            ignoredFilesPath = Option(config.ignoredFiles)
          )
          .sortWith(_.compareToIgnoreCase(_) > 0)
          .toArray

  /** The AST cache key for a file: absolute path identity + file content (matches what the AST pass
    * uses, so warm-restore finds the same `.frag`).
    */
  def fileCacheKey(filename: String): Option[CacheKey] =
      Try {
          val path = Paths.get(filename).toAbsolutePath
          CacheKey(path.toString, Files.readAllBytes(path))
      }.toOption
end AstCreationPass

class AstCreationPass(
  cpg: Cpg,
  config: Config,
  timeoutDuration: FiniteDuration = AstCreationPass.parseTimeout,
  parseTimeoutDuration: FiniteDuration = AstCreationPass.parseTimeout
) extends StreamingCpgPass[String](cpg):

  import AstCreationPass.*

  private val cacheStore = new AstCacheStore(
    config.enableAstCache,
    resolveCacheDir(config.inputPath, config.cacheDir),
    config.onlyAstCache
  )

  private val parseExecutor = Executors.newFixedThreadPool(maxConcurrentParsers)

  private val sharedHeaderFileFinder = new HeaderFileFinder(config.inputPath)

  override def finish(): Unit =
      try
        parseExecutor.shutdownNow()
      catch
        case e: Exception => println(s"Error shutting down parse executor: ${e.getMessage}")
      finally
        super.finish()

  override def generateParts(): Array[String] = AstCreationPass.sourceFiles(config)

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
      cacheStore.process(
        diffGraph,
        filename,
        cacheKey = AstCreationPass.fileCacheKey(filename),
        fingerprint = "",
        registerUsedTypes = registerUsedTypes,
        createAst = createAst(filename)
      )

  private def createAst(filename: String): Option[ParsedUnit] =
    val path             = Paths.get(filename).toAbsolutePath
    val relPath          = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val file2OffsetTable = new ConcurrentHashMap[String, Array[Int]]()
    val parser           = new CdtParser(config, sharedHeaderFileFinder)
    val parseStart       = if AstCreationPass.debugTiming then System.nanoTime() else 0L
    try
      val parsed =
          try runWithTimeout(() => parser.parse(path), parseTimeoutDuration)
          catch
            case e: TimeoutException =>
                // Cooperatively stop the CDT scanner/parser so the cancelled parse does not keep
                // a thread spinning in the background after future.cancel(true).
                parser.cancel()
                throw e
      if AstCreationPass.debugTiming then
        val ms = (System.nanoTime() - parseStart) / 1000000L
        if ms > 1000L then println(s"[c2cpg] parsed $relPath in ${ms}ms")
      parsed match
        case Some(translationUnit: IASTTranslationUnit) =>
            val astCreator =
                new AstCreator(relPath, config, translationUnit, file2OffsetTable)(using
                  config.schemaValidation
                )
            val localDiff = runWithTimeout(() => astCreator.createAst(), timeoutDuration)
            Some(ParsedUnit(localDiff, astCreator.usedTypes))
        case _ => None
    catch
      case e: Throwable =>
          println(s"Exception processing file $path: ${e.getClass.getSimpleName} - ${e.getMessage}")
          None
    end try
  end createAst

  private def registerUsedTypes(usedTypes: Seq[String]): Unit =
      usedTypes.foreach(CGlobal.usedTypes.putIfAbsent(_, true))

  private def runWithTimeout[T](block: () => T, timeout: FiniteDuration): T =
    val future = parseExecutor.submit(new Callable[T]:
      override def call(): T = block()
    )
    try
      future.get(timeout.toMillis, TimeUnit.MILLISECONDS)
    catch
      case _: TimeoutException =>
          future.cancel(true)
          throw new TimeoutException(s"Operation timed out after $timeout")
      case e: InterruptedException =>
          future.cancel(true)
          val cause = e.getCause
          throw new InterruptedException(s"Operation interrupted - ${cause.getMessage}")
      case e =>
          future.cancel(true)
          throw e
end AstCreationPass
