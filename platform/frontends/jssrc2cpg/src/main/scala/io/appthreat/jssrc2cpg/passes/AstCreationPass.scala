package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.astcreation.AstCreator
import io.appthreat.jssrc2cpg.parser.BabelJsonParser
import io.appthreat.jssrc2cpg.utils.AstGenRunner.AstGenRunnerResult
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.passes.frontend.{AstCacheStore, CacheControl}
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import io.appthreat.x2cpg.utils.{Report, TimeUtils}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import io.shiftleft.utils.IOUtils

import java.nio.file.{Files, Paths}
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.EnumerationHasAsScala
import scala.util.{Failure, Success, Try}

object AstCreationPass:
  // Folded into the AST cache key so an astcreator change invalidates cached JS mini-graphs.
  private val Fingerprint = "jssrc-ast-v2"
  // Separator for the (typeName, typeFullName) usedTypes pairs in the cache sidecar.
  private val TypeSep = '\u0000'

class AstCreationPass(
  cpg: Cpg,
  astGenRunnerResult: AstGenRunnerResult,
  config: Config,
  report: Report = new Report()
)(
  implicit withSchemaValidation: ValidationMode
) extends ConcurrentWriterCpgPass[(String, String)](cpg):

  import AstCreationPass.*

  private val usedTypes: ConcurrentHashMap[(String, String), Boolean] = new ConcurrentHashMap()

  /** Per-file JS AST caching is opt-in via the Flux fragment cache (atom `--flux` /
    * `-Dchen.cache.fragments=true`). AST creation for a single file is pure (cross-file resolution
    * and type recovery happen in later passes), so a content-addressed per-file cache is sound; it
    * is keyed on the astgen JSON path + content, which is stable across runs when a fixed
    * `CHEN_ASTGEN_OUT` directory is used.
    */
  private val cacheStore =
      new AstCacheStore(
        CacheControl.useFragments,
        resolveCacheDir(config.inputPath, ""),
        onlyAstCache = false
      )

  override def generateParts(): Array[(String, String)] = astGenRunnerResult.parsedFiles.toArray

  def allUsedTypes(): List[(String, String)] =
      usedTypes.keys().asScala.filterNot { case (typeName, _) => typeName == Defines.Any }.toList

  override def finish(): Unit = super.finish()

  override def runOnPart(diffGraph: DiffGraphBuilder, input: (String, String)): Unit =
    val (rootPath, jsonFilename) = input
    cacheStore.process(
      diffGraph,
      input,
      cacheKey = jsonCacheKey(jsonFilename),
      fingerprint = Fingerprint,
      registerUsedTypes = registerUsedTypes,
      createAst = createAst(rootPath, jsonFilename)
    )

  /** Key on the astgen JSON (the deterministic parse input): identity = its path, content = its
    * bytes. Stable across runs with a fixed astgen output directory.
    */
  private def jsonCacheKey(jsonFilename: String): Option[CacheKey] =
      Try(CacheKey(jsonFilename, Files.readAllBytes(Paths.get(jsonFilename)))).toOption

  /** Re-register a cache hit's `usedTypes` (encoded `name\u0000fullName` pairs) into the shared
    * table, so a cached run produces the same TYPE nodes as a fresh parse.
    */
  private def registerUsedTypes(types: Seq[String]): Unit =
      types.foreach { encoded =>
        val sep = encoded.indexOf(TypeSep.toInt)
        if sep >= 0 then
          usedTypes.putIfAbsent((encoded.substring(0, sep), encoded.substring(sep + 1)), true)
      }

  private def createAst(rootPath: String, jsonFilename: String): Option[ParsedUnit] =
    val ((result, filename), duration) = TimeUtils.time {
        Try {
            val parseResult =
                BabelJsonParser.readFile(Paths.get(rootPath), Paths.get(jsonFilename))
            val fileLOC = IOUtils.readLinesInFile(Paths.get(parseResult.fullPath)).size
            report.addReportInfo(parseResult.filename, fileLOC, parsed = true)
            // Collect this file's types in a private map so they can be cached and replayed.
            val perFileTypes = new ConcurrentHashMap[(String, String), Boolean]()
            val localDiff =
                new AstCreator(config, parseResult, perFileTypes, astGenRunnerResult.typeMapEngine)
                    .createAst()
            perFileTypes.keys().asScala.foreach(k => usedTypes.put(k, true))
            val encoded =
                perFileTypes.keys().asScala.map { case (a, b) => s"$a$TypeSep$b" }.toSeq
            (Some(ParsedUnit(localDiff, encoded)), parseResult.filename)
        } match
          case Failure(_)     => (None, jsonFilename)
          case Success(value) => value
    }
    report.updateReport(filename, cpg = result.isDefined, duration)
    result
  end createAst
end AstCreationPass
