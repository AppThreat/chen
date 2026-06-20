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
  private val theoriticalMaxProcs  = Math.max(1, Runtime.getRuntime.availableProcessors() / 3)
  private val maxConcurrentParsers = Math.min(4, theoriticalMaxProcs)

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
  timeoutDuration: FiniteDuration = 2.minutes,
  parseTimeoutDuration: FiniteDuration = 2.minutes
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
    try
      runWithTimeout(() => parser.parse(path), parseTimeoutDuration) match
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

  private def registerUsedTypes(usedTypes: Seq[String]): Unit =
      usedTypes.foreach(CGlobal.usedTypes.putIfAbsent(_, true))

  private def runWithTimeout[T](block: () => T, timeout: FiniteDuration): T =
    val future = parseExecutor.submit(new Callable[T]:
      override def call(): T = block()
    )
    try
      future.get(timeout.toMinutes, TimeUnit.MINUTES)
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
