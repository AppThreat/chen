package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.astcreation.AstCreator
import io.appthreat.jssrc2cpg.parser.BabelJsonParser
import io.appthreat.jssrc2cpg.utils.AstGenRunner.AstGenRunnerResult
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.parse.ParseReporter
import io.appthreat.x2cpg.passes.frontend.{AstCacheStore, CacheControl}
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import io.shiftleft.utils.IOUtils
import org.slf4j.LoggerFactory

import java.nio.file.{Files, Paths}
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.EnumerationHasAsScala
import scala.util.{Failure, Success, Try}

object AstCreationPass:
  // Folded into the AST cache key so an astcreator change invalidates cached JS mini-graphs.
  private val Fingerprint = "jssrc-ast-v2"
  // Separator for the (typeName, typeFullName) usedTypes pairs in the cache sidecar.
  private val TypeSep = '\u0000'

class AstCreationPass(cpg: Cpg, astGenRunnerResult: AstGenRunnerResult, config: Config)(
  implicit withSchemaValidation: ValidationMode
) extends ConcurrentWriterCpgPass[(String, String)](cpg):

  import AstCreationPass.*

  private val logger = LoggerFactory.getLogger(getClass)

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
    // The name the graph would know the file by, kept for the failure record: without it the
    // record could only name the astgen JSON, which says nothing to a reader of the report.
    var relativeName: Option[String] = None
    Try {
        val parseResult =
            BabelJsonParser.readFile(Paths.get(rootPath), Paths.get(jsonFilename))
        relativeName = Some(parseResult.filename)
        // Read the source even though only its line count used to be consumed: a vanished source
        // file must keep failing here, where the file is dropped and reported, exactly as before.
        IOUtils.readLinesInFile(Paths.get(parseResult.fullPath)).size
        if parseResult.json.obj.get("ast").forall(_.isNull) then
          // astgen found nothing to parse: an HTML page with no Alpine directives or Angular
          // bindings. Nothing of the file is lost, so this is not a failure to report.
          logger.debug(s"astgen wrote no AST for '${parseResult.filename}', so it has no code")
          None
        else
          // Collect this file's types in a private map so they can be cached and replayed.
          val perFileTypes = new ConcurrentHashMap[(String, String), Boolean]()
          val localDiff =
              new AstCreator(config, parseResult, perFileTypes, astGenRunnerResult.typeMapEngine)
                  .createAst()
          perFileTypes.keys().asScala.foreach(k => usedTypes.put(k, true))
          val encoded =
              perFileTypes.keys().asScala.map { case (a, b) => s"$a$TypeSep$b" }.toSeq
          Some(ParsedUnit(localDiff, encoded))
    } match
      case Failure(t) =>
          // The whole file is left out of the graph: say which one and why
          logger.debug(s"Unable to create the AST for '$jsonFilename', so it is left out", t)
          // A failure before the JSON is read knows no relative name; the JSON path under the
          // astgen output mirrors the source tree, so strip the output directory and the suffix.
          val fallbackName =
              if astGenRunnerResult.astGenOutDir.nonEmpty then
                jsonFilename.stripSuffix(".json").replace(astGenRunnerResult.astGenOutDir, "")
                    .dropWhile(ch => ch == '/' || ch == '\\')
              else jsonFilename
          ParseReporter.record(
            ParseReporter.Frontend.JsSrc,
            relativeName.getOrElse(fallbackName),
            ParseReporter.Outcome.Dropped,
            ParseReporter.Stage.Ast,
            ParseReporter.describe(t)
          )
          None
      case Success(value) => value
    end match
  end createAst
end AstCreationPass
