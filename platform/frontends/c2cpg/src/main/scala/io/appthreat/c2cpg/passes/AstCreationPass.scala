package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{CdtParser, FileDefaults, HeaderFileFinder}
import io.appthreat.x2cpg.SourceFiles
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass

import java.nio.file.Paths
import java.util.concurrent.*
import java.util.regex.Pattern
import scala.concurrent.duration.*
import scala.jdk.DurationConverters.*
import scala.util.matching.Regex

class AstCreationPass(
  cpg: Cpg,
  config: Config,
  timeoutDuration: FiniteDuration = 2.minutes,
  parseTimeoutDuration: FiniteDuration = 2.minutes
) extends ConcurrentWriterCpgPass[String](cpg):

  private val file2OffsetTable: ConcurrentHashMap[String, Array[Int]] = new ConcurrentHashMap()
  private val sharedHeaderFileFinder = new HeaderFileFinder(config.inputPath)
  private val EscapedFileSeparator   = Pattern.quote(java.io.File.separator)
  private val DefaultIgnoredFolders: List[Regex] = List(
    "\\..*".r,
    s"(.*[$EscapedFileSeparator])?tests?[$EscapedFileSeparator].*".r,
    s"(.*[$EscapedFileSeparator])?CMakeFiles[$EscapedFileSeparator].*".r
  )

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
    val path                = Paths.get(filename).toAbsolutePath
    val relPath             = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val computationExecutor = Executors.newVirtualThreadPerTaskExecutor()
    try
      val parser: CdtParser = new CdtParser(config, sharedHeaderFileFinder)
      val parseFuture       = computationExecutor.submit(() => parser.parse(path))
      val parseResult       = runWithTimeout(parseFuture, parseTimeoutDuration, computationExecutor)
      parseResult match
        case Some(translationUnit: org.eclipse.cdt.core.dom.ast.IASTTranslationUnit) =>
            val astFuture = computationExecutor.submit(() =>
                new AstCreator(relPath, config, translationUnit, file2OffsetTable)(
                  using config.schemaValidation
                ).createAst()
            )

            val localDiff = runWithTimeout(astFuture, timeoutDuration, computationExecutor)
            diffGraph.absorb(localDiff)
        case None =>
    catch
      case e: TimeoutException =>
          println(s"Timeout occurred during processing for file: $filename: ${e.getMessage}")
      case e: Throwable =>
          println(
            s"""Exception occurred during processing for file: $filename: ${e
                    .getMessage} - ${e
                    .getStackTrace.take(40)
                    .mkString("\n")}"""
          )
          throw e
    finally
      computationExecutor.shutdown()
      try
        if !computationExecutor.awaitTermination(10, TimeUnit.SECONDS) then
          computationExecutor.shutdownNow()
      catch
        case _: InterruptedException =>
            computationExecutor.shutdownNow()
            Thread.currentThread().interrupt()
    end try
  end runOnPart

  private def runWithTimeout[T](
    future: Future[T],
    timeout: FiniteDuration,
    executor: ExecutorService
  ): T =
      try
        future.get(timeout.toMinutes, TimeUnit.MINUTES)
      catch
        case _: TimeoutException =>
            future.cancel(true)
            throw new TimeoutException(s"Operation timed out after ${timeout}")

  override def finish(): Unit =
      try
          sharedHeaderFileFinder.clear()
      finally
          super.finish()
end AstCreationPass
