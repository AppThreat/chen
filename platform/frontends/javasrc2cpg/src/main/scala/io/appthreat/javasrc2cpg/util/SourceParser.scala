package io.appthreat.javasrc2cpg.util

import better.files.File
import Delombok.DelombokMode
import Delombok.DelombokMode.*
import io.appthreat.x2cpg.SourceFiles
import com.github.javaparser.{JavaParser, ParserConfiguration}
import com.github.javaparser.ParserConfiguration.LanguageLevel
import com.github.javaparser.ast.CompilationUnit
import com.github.javaparser.ast.Node.Parsedness
import io.appthreat.javasrc2cpg.{Config, JavaSrc2Cpg}

import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.jdk.OptionConverters.RichOptional
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap
import java.nio.charset.MalformedInputException
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import scala.util.Try
import scala.util.Success

class SourceParser private (originalInputPath: Path, analysisRoot: Path, typesRoot: Path):

  /** Parse the given file into a JavaParser CompliationUnit that will be used for creating the CPG
    * AST.
    *
    * @param relativeFilename
    *   path to the input file relative to the project root.
    */
  def parseAnalysisFile(relativeFilename: String): Option[CompilationUnit] =
    val analysisFilename = analysisRoot.resolve(relativeFilename).toString
    // Need to store tokens for position information.
    fileIfExists(analysisFilename).flatMap(parse(_, storeTokens = true))

  /** Parse the given file into a JavaParser CompliationUnit that will be used for reading type
    * information. These should not be used for determining the structure of the AST.
    *
    * @param relativeFilename
    *   path to the input file relative to the project root.
    */
  def parseTypesFile(relativeFilename: String): Option[CompilationUnit] =
    val typesFilename = typesRoot.resolve(relativeFilename).toString
    fileIfExists(typesFilename).flatMap(parse(_, storeTokens = false))

  def fileIfExists(filename: String): Option[File] =
    val file = File(filename)

    Option.when(file.exists)(file)

  def getTypesFileLines(relativeFilename: String): Try[Iterable[String]] =
    val typesFilename = typesRoot.resolve(relativeFilename).toString
    Try(File(typesFilename).lines(Charset.defaultCharset()))
        .orElse(Try(File(typesFilename).lines(StandardCharsets.ISO_8859_1)))

  def doesTypesFileExist(relativeFilename: String): Boolean =
      File(typesRoot.resolve(relativeFilename)).isRegularFile

  private def parse(file: File, storeTokens: Boolean): Option[CompilationUnit] =
    val javaParserConfig =
        new ParserConfiguration()
            .setLanguageLevel(LanguageLevel.BLEEDING_EDGE)
            .setAttributeComments(false)
            .setLexicalPreservationEnabled(true)
            .setStoreTokens(storeTokens)
    val parseResult = new JavaParser(javaParserConfig).parse(file.toJava)

    parseResult.getResult.toScala match
      case Some(result) if result.getParsed == Parsedness.PARSED => Some(result)
      case _ =>
          None
end SourceParser

object SourceParser:

  def apply(config: Config, hasLombokDependency: Boolean): SourceParser =
    val canonicalInputPath = File(config.inputPath).canonicalPath
    val (analysisDir, typesDir) =
        getAnalysisAndTypesDirs(
          canonicalInputPath,
          config.delombokJavaHome,
          config.delombokMode,
          hasLombokDependency
        )
    new SourceParser(Path.of(canonicalInputPath), Path.of(analysisDir), Path.of(typesDir))

  def getSourceFilenames(
    config: Config,
    sourcesOverride: Option[List[String]] = None
  ): Array[String] =
      SourceFiles.determine(
        config.inputPath,
        JavaSrc2Cpg.sourceFileExtensions,
        ignoredDefaultRegex = Option(JavaSrc2Cpg.DefaultIgnoredFilesRegex),
        ignoredFilesRegex = Option(config.ignoredFilesRegex),
        ignoredFilesPath = Option(config.ignoredFiles)
      ).toArray

  /** Implements the logic described in the option description for the "delombok-mode" option:
    *   - no-delombok: do not run delombok.
    *   - default: run delombok if a lombok dependency is found and analyse delomboked code.
    *   - types-only: run delombok, but use it for type information only
    *   - run-delombok: run delombok and analyse delomboked code
    *
    * @return
    *   the tuple (analysisRoot, typesRoot) where analysisRoot is used to locate source files for
    *   creating the AST and typesRoot is used for locating source files from which to extract type
    *   information.
    */
  private def getAnalysisAndTypesDirs(
    originalDir: String,
    delombokJavaHome: Option[String],
    delombokMode: Option[String],
    hasLombokDependency: Boolean
  ): (String, String) =
    lazy val delombokDir = Delombok.run(originalDir, delombokJavaHome)
    if delombokDir.nonEmpty then
      Delombok.parseDelombokModeOption(delombokMode) match
        case Default if hasLombokDependency =>
            (delombokDir, delombokDir)

        case Default => (originalDir, originalDir)

        case NoDelombok => (originalDir, originalDir)

        case TypesOnly => (originalDir, delombokDir)

        case RunDelombok => (delombokDir, delombokDir)
    else (delombokDir, delombokDir)
  end getAnalysisAndTypesDirs
end SourceParser
