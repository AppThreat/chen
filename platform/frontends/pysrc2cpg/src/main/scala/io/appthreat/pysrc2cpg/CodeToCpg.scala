package io.appthreat.pysrc2cpg

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import Py2Cpg.InputProvider
import io.appthreat.pythonparser.PyParser
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import org.slf4j.LoggerFactory

import scala.util.Try

class CodeToCpg(
  cpg: Cpg,
  inputProvider: Iterable[InputProvider],
  schemaValidationMode: ValidationMode,
  inputPath: String,
  enableAstCache: Boolean = true,
  cacheDir: String = ""
) extends ConcurrentWriterCpgPass[InputProvider](cpg):
  import CodeToCpg.logger

  private val cacheStore =
      new AstCacheStore(enableAstCache, resolveCacheDir(inputPath, cacheDir), onlyAstCache = false)

  override def generateParts(): Array[InputProvider] = inputProvider.toArray

  override def runOnPart(diffGraph: DiffGraphBuilder, provider: InputProvider): Unit =
      cacheStore.process(
        diffGraph,
        provider,
        cacheKey = cacheKey(provider),
        fingerprint = "",
        registerUsedTypes = _ => (),
        createAst = createAst(provider)
      )

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
      val astRoot                = parser.parse(lineBreakCorrectedCode)
      val nodeToCode             = new NodeToCode(lineBreakCorrectedCode)
      val astVisitor = new PythonAstVisitor(inputPair.relFileName, nodeToCode, PythonV2AndV3)(
        using schemaValidationMode
      )
      astVisitor.convert(astRoot)
      Some(ParsedUnit(astVisitor.getDiffGraph))
    catch
      case exception: Throwable =>
          logger.debug(s"Failed to convert file ${inputPair.relFileName}", exception)
          None
end CodeToCpg

object CodeToCpg:
  private val logger = LoggerFactory.getLogger(getClass)
