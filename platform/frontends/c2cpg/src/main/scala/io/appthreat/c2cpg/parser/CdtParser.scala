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

  def readFileAsFileContent(path: Path): FileContent =
    val lines = IOUtils.readLinesInFile(path).mkString("\n").toArray
    FileContent.create(path.toString, true, lines)

class CdtParser(config: Config) extends ParseProblemsLogger with PreprocessorStatementsLogger:

  import CdtParser.*

  private val headerFileFinder    = new HeaderFileFinder(config.inputPath)
  private val fileContentProvider = new CustomFileContentProvider(headerFileFinder)
  private val parserConfig        = ParserConfig.fromConfig(config)
  private val definedSymbols      = parserConfig.definedSymbols.asJava
  private val includePaths        = parserConfig.userIncludePaths
  private val log                 = new DefaultLogService

  private var stayCpp: Boolean = false

  private val cScannerInfo: ExtendedScannerInfo = new ExtendedScannerInfo(
    definedSymbols,
    (includePaths ++ parserConfig.systemIncludePathsC).map(_.toString).toArray,
    parserConfig.macroFiles.map(_.toString).toArray,
    parserConfig.includeFiles.map(_.toString).toArray
  )

  private val cppScannerInfo: ExtendedScannerInfo =
    val symbolMap = new HashMap[String, String](definedSymbols)

    val stdVal = config.cppStandard.toLowerCase match
      case ""                => ""
      case "c++98" | "c++03" => "199711L"
      case "c++11"           => "201103L"
      case "c++14"           => "201402L"
      case "c++17"           => "201703L"
      case "c++20"           => "202002L"
      case "c++23"           => "202302L"
      case other             => other

    if stdVal.nonEmpty then
      symbolMap.put("__cplusplus", stdVal)
    else if !symbolMap.containsKey("__cplusplus") then
      symbolMap.put("__cplusplus", "201703L")

    new ExtendedScannerInfo(
      symbolMap,
      (includePaths ++ parserConfig.systemIncludePathsCPP).map(_.toString).toArray,
      parserConfig.macroFiles.map(_.toString).toArray,
      parserConfig.includeFiles.map(_.toString).toArray
    )
  end cppScannerInfo

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
  opts |= ILanguage.OPTION_SKIP_TRIVIAL_EXPRESSIONS_IN_AGGREGATE_INITIALIZERS

  private def createParseLanguage(file: Path): ILanguage =
      if FileDefaults.isCPPFile(file.toString) then
        GPPLanguage.getDefault
      else
        GCCLanguage.getDefault

  private def createScannerInfo(file: Path): ExtendedScannerInfo =
      if stayCpp || FileDefaults.isCPPFile(file.toString) then
        stayCpp = true
        cppScannerInfo
      else cScannerInfo

  private def parseInternal(file: Path): ParseResult =
    val realPath = File(file)
    if realPath.isRegularFile then // handling potentially broken symlinks
      fileContentProvider.setContext(realPath.path)
      try
        val fileContent = readFileAsFileContent(realPath.path)
        val lang        = createParseLanguage(realPath.path)
        val scannerInfo = createScannerInfo(realPath.path)
        index match
          case Some(x) => if x.isFullyInitialized then x.acquireReadLock()
          case _       =>
        val translationUnit =
            lang.getASTTranslationUnit(
              fileContent,
              scannerInfo,
              fileContentProvider,
              index.get,
              opts,
              log
            )
        val problems = CPPVisitor.getProblems(translationUnit)
        if parserConfig.logProblems then logProblems(problems.toList)
        if parserConfig.logPreprocessor then logPreprocessorStatements(translationUnit)
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
        fileContentProvider.clearContext()
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
