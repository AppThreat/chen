package io.appthreat.pysrc2cpg

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import Py2Cpg.InputProvider
import io.appthreat.pythonparser.PyParser
import io.appthreat.pythonparser.ast
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import org.slf4j.LoggerFactory

import scala.jdk.CollectionConverters.*
import scala.util.Try

class CodeToCpg(
  cpg: Cpg,
  inputProvider: Iterable[InputProvider],
  schemaValidationMode: ValidationMode,
  inputPath: String,
  enableAstCache: Boolean = true,
  cacheDir: String = "",
  strictParse: Boolean = false,
  moduleNames: Map[String, String] = Map.empty,
  transformAst: PythonDependencyStubs.Transform = identity,
  extraCacheFingerprint: String = ""
) extends ConcurrentWriterCpgPass[InputProvider](cpg):
  import CodeToCpg.logger

  private val cacheStore =
      new AstCacheStore(
        enableAstCache && !strictParse,
        resolveCacheDir(inputPath, cacheDir),
        onlyAstCache = false
      )

  // The cached fragment carries the full-name shape it was built with; without this,
  // switching modes on a warm cache would serve fragments in the other shape. The extra
  // fingerprint distinguishes AST-transformed builds (dependency signatures) from plain ones.
  private val cacheFingerprint =
      Seq(
        if moduleNames.isEmpty then "" else "dotted-full-names",
        extraCacheFingerprint
      ).filter(_.nonEmpty).mkString("+")

  // Written concurrently by runOnPart, read once after createAndApply() completes.
  private val parseErrors = java.util.Collections
      .synchronizedList(new java.util.ArrayList[CodeToCpg.ParseError]())

  override def generateParts(): Array[InputProvider] = inputProvider.toArray

  override def runOnPart(diffGraph: DiffGraphBuilder, provider: InputProvider): Unit =
      cacheStore.process(
        diffGraph,
        provider,
        cacheKey = cacheKey(provider),
        fingerprint = cacheFingerprint,
        registerUsedTypes = _ => (),
        createAst = createAst(provider)
      )

  /** The parse errors recorded while this pass instance ran, ordered by file and line. */
  def getParseErrors: List[CodeToCpg.ParseError] =
      parseErrors.asScala.toList.sortBy(e => (e.relFileName, e.line))

  private def cacheKey(provider: InputProvider): Option[CacheKey] =
      Try {
          val pair = provider()
          CacheKey(pair.relFileName, pair.content.getBytes("UTF-8"))
      }.toOption

  private def createAst(provider: InputProvider): Option[ParsedUnit] =
    val inputPair = provider()
    try
      val parser                 = new PyParser()
      val lineBreakCorrectedCode = inputPair.content.replace("\r\n", "\n").replace("\r", "\n")
      val parsedRoot             = parser.parse(lineBreakCorrectedCode)
      // Optional AST-level transform (dependency signature ingestion truncates function
      // bodies here, so bodies never reach the visitor). Identity for every plain build.
      val astRoot = parsedRoot match
        case m: ast.Module => transformAst(m)
        case other         => other
      // Parse errors surface as inline ErrorStatement/UNKNOWN nodes; record them here
      // so the run summary (and strict-parse mode) can report them loudly.
      parser.errors.foreach { err =>
          parseErrors.add(
            CodeToCpg.ParseError(
              inputPair.relFileName,
              err.attributeProvider.lineno,
              Option(err.exception.getMessage).getOrElse(err.exception.getClass.getName)
            )
          )
      }
      val nodeToCode = new NodeToCode(lineBreakCorrectedCode)
      val astVisitor = new PythonAstVisitor(
        inputPair.relFileName,
        nodeToCode,
        PythonV2AndV3,
        moduleNames.get(inputPair.relFileName)
      )(
        using schemaValidationMode
      )
      astVisitor.convert(astRoot)
      Some(ParsedUnit(astVisitor.getDiffGraph))
    catch
      case exception: Throwable =>
          logger.debug(s"Failed to convert file ${inputPair.relFileName}", exception)
          parseErrors.add(
            CodeToCpg.ParseError(
              inputPair.relFileName,
              0,
              Option(exception.getMessage).getOrElse(
                exception.getClass.getName
              )
            )
          )
          None
    end try
  end createAst
end CodeToCpg

object CodeToCpg:
  private val logger = LoggerFactory.getLogger(getClass)

  /** One failed statement: the file, the line it starts at (0 when the whole file failed), and the
    * parser message.
    */
  final case class ParseError(relFileName: String, line: Int, message: String)

  /** Renders the summary line the frontend prints after a run with parse failures. */
  def summarize(errors: List[ParseError]): String =
    val files = errors.map(_.relFileName).toSet
    val body  = errors.take(20).map(e => s"  ${e.relFileName}:${e.line}: ${e.message}")
    val tail  = if errors.size > 20 then List(s"  ... and ${errors.size - 20} more") else Nil
    (s"${errors.size} statements failed to parse across ${files.size} files:" :: body ::: tail)
        .mkString(System.lineSeparator)
