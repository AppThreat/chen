package io.appthreat.php2atom.passes

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.astcreation.AstCreator
import io.appthreat.php2atom.parser.Domain.PhpFile
import io.appthreat.php2atom.parser.PhpParser
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import org.slf4j.LoggerFactory

import java.nio.file.{Files, Paths}
import scala.util.{Failure, Success, Try}

class AstCreationPass(config: Config, cpg: Cpg, parser: PhpParser)(implicit
  withSchemaValidation: ValidationMode
) extends ConcurrentWriterCpgPass[String](cpg):

  private val logger = LoggerFactory.getLogger(this.getClass)

  private val cacheStore = new AstCacheStore(
    config.enableAstCache,
    resolveCacheDir(config.inputPath, config.cacheDir),
    onlyAstCache = false
  )

  private val PhpSourceFileExtensions: Set[String] = Set(".php")

  /** Temporary directory holding the batch generator's AST documents, when a batch run happened.
    *
    * Deliberately OUTSIDE the scanned input tree so batch output can never pollute the project or
    * be picked up by a later scan. Written once during [[batchAsts]] initialization and read by
    * [[finish]] on a different thread, hence `@volatile`.
    */
  @volatile private var batchOutputDir: Option[File] = None

  /** Canonical source path -> [[PhpFile]] produced by a SINGLE batch generator run.
    *
    * Empty when batch ingestion is not applicable (generator without `--parser-info`/batch support,
    * a single-file input path, or a batch run that produced nothing) — in which case every file
    * takes the unchanged legacy per-file path.
    *
    * Thread-safety: `lazy val` initialization is atomic and once-only in Scala, so the generator is
    * invoked exactly once per pass even though [[runOnPart]] runs concurrently; workers that arrive
    * while the batch is running block until the map is published.
    *
    * Deliberately NOT forced eagerly from [[generateParts]]: [[AstCacheStore.process]] takes
    * `createAst` by name and evaluates it only on a cache MISS, so a fully warm AST cache must keep
    * spawning no generator at all. Forcing this map up front would re-parse the whole project on
    * every warm run and defeat the cache. The first cache miss forces it instead.
    */
  private lazy val batchAsts: Map[String, PhpFile] = computeBatchAsts()

  private def computeBatchAsts(): Map[String, PhpFile] =
    val inputFile = File(config.inputPath)
    // Batch mode ingests a directory; a single-file input keeps the per-file path.
    if !inputFile.isDirectory then Map.empty
    else if !parser.supportsBatch then
      logger.debug("Generator does not support batch ingestion; using per-file parsing.")
      Map.empty
    else
      Try {
          val outDir = File.newTemporaryDirectory("php2atom-batch-")
          batchOutputDir = Some(outDir)
          val results = parser.parseDirectory(inputFile.canonicalPath, outDir.canonicalPath)
          results.flatMap { parsed =>
              // Canonicalize so keys match the lookup key derived from `generateParts()` paths.
              Try(File(parsed.sourcePath).canonicalPath).toOption.map(_ -> parsed.phpFile)
          }.toMap
      } match
        case Success(asts) if asts.nonEmpty =>
            logger.debug(
              s"Batch ingestion decoded ${asts.size} AST document(s) in one generator run."
            )
            asts
        case Success(_) =>
            logger.warn(
              "Batch ingestion is supported by the generator but produced no decodable AST " +
                  s"documents for '${config.inputPath}'; falling back to per-file parsing."
            )
            Map.empty
        case Failure(exception) =>
            logger.warn(
              s"Batch ingestion failed for '${config.inputPath}': ${exception.getMessage}; " +
                  "falling back to per-file parsing."
            )
            Map.empty
    end if
  end computeBatchAsts

  /** Delete the batch scratch directory once every part has been processed. */
  override def finish(): Unit =
      try
        batchOutputDir.foreach(dir => Try(dir.delete(swallowIOExceptions = true)))
        batchOutputDir = None
      finally
        super.finish()

  private def relativeFilename(filename: String): String =
      if filename == config.inputPath then File(filename).name
      else File(config.inputPath).relativize(File(filename)).toString

  private def isIgnored(filename: String): Boolean =
    val rel = relativeFilename(filename)
    config.ignoredFilesRegex.matches(rel) ||
    config.defaultIgnoredFilesRegex.exists(_.matches(rel))

  override def generateParts(): Array[String] = SourceFiles
      .determine(config.inputPath, PhpSourceFileExtensions)
      .filterNot(isIgnored)
      .toArray

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
      cacheStore.process(
        diffGraph,
        filename,
        cacheKey = fileCacheKey(filename),
        fingerprint = "",
        registerUsedTypes = _ => (),
        createAst = createAst(filename)
      )

  private def fileCacheKey(filename: String): Option[CacheKey] =
      Try {
          val path = Paths.get(filename).toAbsolutePath
          CacheKey(path.toString, Files.readAllBytes(path))
      }.toOption

  /** The batch-produced AST for `filename`, or `None` when there is no batch result to use.
    *
    * When no batch run happened at all the map is empty and this is a no-op, keeping the legacy
    * per-file path unchanged. When a batch DID run but did not cover this file, the miss is logged
    * so a partially-complete batch is diagnosable.
    */
  private def batchAstFor(filename: String): Option[PhpFile] =
      if batchAsts.isEmpty then None
      else
        val key = Try(File(filename).canonicalPath).getOrElse(filename)
        batchAsts.get(key) match
          case hit @ Some(_) => hit
          case None =>
              logger.debug(
                s"Batch output did not include $filename; parsing it individually."
              )
              None

  private def createAst(filename: String): Option[ParsedUnit] =
      batchAstFor(filename).orElse(parser.parseFile(filename, config.phpIni)) match
        case Some(parseResult) =>
            val diff = new AstCreator(relativeFilename(filename), parseResult)(
              using config.schemaValidation
            ).createAst()
            Some(ParsedUnit(diff))
        case None =>
            logger.debug(s"Could not parse file $filename. Results will be missing!")
            None
end AstCreationPass
