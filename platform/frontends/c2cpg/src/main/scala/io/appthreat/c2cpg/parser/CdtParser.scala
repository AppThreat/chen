package io.appthreat.c2cpg.parser

import better.files.File
import io.appthreat.c2cpg.Config
import io.shiftleft.utils.IOUtils
import org.eclipse.cdt.core.CCorePlugin
import org.eclipse.cdt.core.dom.ast.gnu.c.GCCLanguage
import org.eclipse.cdt.core.dom.ast.gnu.cpp.GPPLanguage
import org.eclipse.cdt.core.dom.ast.{IASTPreprocessorStatement, IASTTranslationUnit}
import org.eclipse.cdt.core.index.IIndex
import org.eclipse.cdt.core.model.{CoreModel, ICProject, ILanguage}
import org.eclipse.cdt.core.parser.{DefaultLogService, ExtendedScannerInfo, FileContent}
import org.eclipse.cdt.internal.core.dom.parser.cpp.semantics.CPPVisitor
import org.eclipse.cdt.internal.core.index.EmptyCIndex
import org.eclipse.cdt.internal.core.util.{ICancelable, ICanceler}
import org.slf4j.LoggerFactory

import java.nio.file.{NoSuchFileException, Path}
import java.util.HashMap
import scala.jdk.CollectionConverters.*

object CdtParser:

  private val logger = LoggerFactory.getLogger(classOf[CdtParser])

  private case class ParseResult(
    translationUnit: Option[IASTTranslationUnit],
    preprocessorErrorCount: Int = 0,
    problems: Int = 0,
    failure: Option[Throwable] = None
  )

  /** Reads and UTF-8-decodes a file into an immutable `char[]` of source. Kept separate so the
    * shared header content cache in [[CustomFileContentProvider]] can memoise the decoded array.
    */
  def readFileChars(path: Path): Array[Char] =
      IOUtils.readLinesInFile(path).mkString("\n").toArray

  /** A parser log service that also exposes CDT's cooperative cancellation hook.
    *
    * `AbstractCLikeLanguage.getASTTranslationUnit` registers an `ICancelable` on the log service
    * when it implements `ICanceler` (CDT bug 226682). Calling `setCanceled` from another thread
    * therefore propagates to `scanner.cancel()` / `parser.cancel()`, which makes the parse abort at
    * the next cancellation check instead of running to completion. Without this, a timed-out parse
    * keeps a CPU-bound thread alive in the background since CDT does not poll `Thread.interrupt()`.
    */
  final class CancelableLogService extends DefaultLogService with ICanceler:
    @volatile private var cancelable: ICancelable = null
    @volatile private var canceled: Boolean       = false

    override def setCancelable(c: ICancelable): Unit = synchronized:
      cancelable = c
      if canceled && (c ne null) then c.cancel()

    override def setCanceled(value: Boolean): Unit = synchronized:
      canceled = value
      if value && (cancelable ne null) then cancelable.cancel()

    override def isCanceled: Boolean = canceled
end CdtParser

class CdtParser(
  config: Config,
  headerFileFinder: HeaderFileFinder,
  projectSources: ProjectSources = null
) extends ParseProblemsLogger
    with PreprocessorStatementsLogger:

  import CdtParser.*

  private val sources = Option(projectSources).getOrElse(new ProjectSources(config))
  private val log     = new CancelableLogService

  /** Cooperatively cancels an in-flight parse on this parser (see `CancelableLogService`). Safe to
    * call from another thread, e.g. a timeout watchdog.
    */
  def cancel(): Unit = log.setCanceled(true)

  private def scannerInfo(settings: UnitSettings): ExtendedScannerInfo =
      new ExtendedScannerInfo(
        settings.definedSymbols.asJava,
        settings.includePaths.map(_.toString).toArray,
        settings.macroFiles.map(_.toString).toArray,
        settings.includeFiles.map(_.toString).toArray
      )

  // Setup indexing
  var index: Option[IIndex] = Option(EmptyCIndex.INSTANCE)
  if config.useProjectIndex then
    try
      val allProjects: Array[ICProject] = CoreModel.getDefault.getCModel.getCProjects
      index = Option(CCorePlugin.getIndexManager.getIndex(allProjects))
    catch
      case e: Throwable => logger.warn("Failed to initialize Eclipse CDT Project Index", e)

  // enables parsing of code behind disabled preprocessor defines:
  private var opts: Int = 0
  if config.parseInactiveCode then opts |= ILanguage.OPTION_PARSE_INACTIVE_CODE
  // instructs the parser to skip function and method bodies
  if !config.includeFunctionBodies then opts |= ILanguage.OPTION_SKIP_FUNCTION_BODIES
  // performance optimization, allows the parser not to create image-locations
  if !config.includeImageLocations then opts |= ILanguage.OPTION_NO_IMAGE_LOCATIONS
  if !config.includeTrivialExpressions then
    opts |= ILanguage.OPTION_SKIP_TRIVIAL_EXPRESSIONS_IN_AGGREGATE_INITIALIZERS

  private def parseLanguage(settings: UnitSettings): ILanguage = settings.language match
    case SourceLanguage.Cpp => GPPLanguage.getDefault
    case SourceLanguage.C   => GCCLanguage.getDefault

  private def parseInternal(file: Path): ParseResult =
    val realPath = File(file)
    if realPath.isRegularFile then // handling potentially broken symlinks
      val settings = sources.settingsFor(realPath.path)
      // a header included into a C++ unit reads as C++, module syntax included
      val transform: (Path, Array[Char]) => Array[Char] =
          if settings.language == SourceLanguage.Cpp then sources.modules.rewrite else (_, c) => c
      val fileContentProvider =
          new CustomFileContentProvider(headerFileFinder, realPath.path, transform)
      try
        val fileContent = FileContent.create(
          realPath.path.toString,
          true,
          sources.textOf(realPath.path, settings.language)
        )
        val lang = parseLanguage(settings)
        index match
          case Some(x) => if x.isFullyInitialized then x.acquireReadLock()
          case _       =>
        val translationUnit =
            lang.getASTTranslationUnit(
              fileContent,
              scannerInfo(settings),
              fileContentProvider,
              index.get,
              opts,
              log
            )
        val problems = CPPVisitor.getProblems(translationUnit)
        if config.logProblems then logProblems(problems.toList)
        if config.logPreprocessor then logPreprocessorStatements(translationUnit)
        ParseResult(
          Option(translationUnit),
          preprocessorErrorCount = translationUnit.getPreprocessorProblemsCount,
          problems = problems.length
        )
      catch
        case u: UnsupportedClassVersionError =>
            logger.debug(
              "c2cpg requires at least JRE-21 to run. Please check your Java Runtime Environment!",
              u
            )
            System.exit(1)
            ParseResult(
              None,
              failure = Option(u)
            ) // return value to make the compiler happy
        case e: Throwable =>
            ParseResult(None, failure = Option(e))
      finally
        index match
          case Some(x) => x.releaseReadLock()
          case _       =>
      end try
    else
      ParseResult(
        None,
        failure = Option(new NoSuchFileException(
          s"File '$realPath' does not exist. Check for broken symlinks!"
        ))
      )
    end if
  end parseInternal

  def preprocessorStatements(file: Path): Iterable[IASTPreprocessorStatement] =
      parse(file).map(t => preprocessorStatements(t)).getOrElse(Iterable.empty)

  def parse(file: Path): Option[IASTTranslationUnit] =
    val parseResult = parseInternal(file)
    parseResult match
      case ParseResult(Some(t), c, p, _) =>
          Option(t)
      case ParseResult(_, _, _, maybeThrowable) =>
          logger.warn(
            s"Failed to parse '$file': ${maybeThrowable.map(extractParseException).getOrElse("Unknown parse error!")}"
          )
          None
end CdtParser
