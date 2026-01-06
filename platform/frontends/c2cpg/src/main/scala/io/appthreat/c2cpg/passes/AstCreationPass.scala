package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{CdtParser, FileDefaults, HeaderFileFinder}
import io.appthreat.x2cpg.{Ast, AstCache, SourceFiles, ValidationMode}
import io.appthreat.x2cpg.AstCache.AstBitcode
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.StreamingCpgPass
import upickle.default.*

import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import java.util.concurrent.*
import java.util.regex.Pattern
import scala.concurrent.duration.*
import scala.util.{Failure, Success, Try}
import scala.util.matching.Regex

object AstCreationPass:
  private val theoriticalMaxProcs  = Math.max(1, Runtime.getRuntime.availableProcessors() / 3)
  private val maxConcurrentParsers = Math.min(4, theoriticalMaxProcs)

class AstCreationPass(
  cpg: Cpg,
  config: Config,
  timeoutDuration: FiniteDuration = 2.minutes,
  parseTimeoutDuration: FiniteDuration = 2.minutes
) extends StreamingCpgPass[String](cpg):

  import AstCreationPass.*

  private val parseExecutor = Executors.newFixedThreadPool(maxConcurrentParsers)

  private val sharedHeaderFileFinder = new HeaderFileFinder(config.inputPath)
  private val EscapedFileSeparator   = Pattern.quote(java.io.File.separator)
  private val DefaultIgnoredFolders: List[Regex] = List(
    "\\..*".r,
    s"(.*[$EscapedFileSeparator])?tests?[$EscapedFileSeparator].*".r,
    s"(.*[$EscapedFileSeparator])?CMakeFiles[$EscapedFileSeparator].*".r
  )

  if config.enableAstCache then
    Try(Files.createDirectories(Paths.get(config.cacheDir))) match
      case Failure(e) =>
          println(s"Warning: Failed to create cache directory ${config.cacheDir}: ${e.getMessage}")
      case Success(_) =>

  override def finish(): Unit =
      try
        parseExecutor.shutdownNow()
      catch
        case e: Exception => println(s"Error shutting down parse executor: ${e.getMessage}")
      finally
        super.finish()

  override def generateParts(): Array[String] =
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

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
    val path             = Paths.get(filename).toAbsolutePath
    val relPath          = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val file2OffsetTable = new ConcurrentHashMap[String, Array[Int]]()
    val fileHash         = if config.enableAstCache then Option(computeEntryHash(path)) else None

    try
      val cachedAst: Option[Ast] = fileHash.flatMap(h => checkAndLoadCache(h, config.cacheDir))
      cachedAst match
        case Some(ast) =>
            if !config.onlyAstCache then Ast.storeInDiffGraph(ast, diffGraph)
        case None =>
            val parser: CdtParser = new CdtParser(config, sharedHeaderFileFinder)
            val parseResult       = runWithTimeout(() => parser.parse(path), parseTimeoutDuration)
            parseResult match
              case Some(translationUnit: org.eclipse.cdt.core.dom.ast.IASTTranslationUnit) =>
                  val localDiff = runWithTimeout(
                    () =>
                        new AstCreator(
                          relPath,
                          config,
                          translationUnit,
                          file2OffsetTable,
                          fileHash
                        )(using config.schemaValidation).createAst(),
                    timeoutDuration
                  )
                  if !config.onlyAstCache then diffGraph.absorb(localDiff)
              case None =>
      end match
    catch
      case e: TimeoutException =>
          println(s"Timeout occurred during processing for file: $path: ${e.getMessage}")
      case e: ExecutionException =>
          val cause = e.getCause
          println(
            s"Exception processing file $path: ${cause.getClass.getSimpleName} - ${cause.getMessage}"
          )
      case e: Throwable =>
          println(s"Exception processing file $path: ${e.getClass.getSimpleName} - ${e.getMessage}")
    end try
  end runOnPart

  private def computeEntryHash(path: Path): String =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(path.toAbsolutePath.toString.getBytes("UTF-8"))
    digest.update(Files.readAllBytes(path))
    digest.digest().map("%02x".format(_)).mkString

  private def checkAndLoadCache(hash: String, cacheDir: String): Option[Ast] =
    val cacheFile = Paths.get(cacheDir, s"$hash.ast")
    if !Files.exists(cacheFile) then return None

    try
      val bytes                            = Files.readAllBytes(cacheFile)
      val bitcode                          = readBinary[AstBitcode](bytes)
      implicit val valMode: ValidationMode = config.schemaValidation
      Some(AstCache.fromBitcode(bitcode))
    catch
      case e: Exception =>
          println(s"Failed to load cache for $hash: ${e.getClass.getSimpleName} - ${e.getMessage}")
          Try(Files.deleteIfExists(cacheFile))
          None

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
