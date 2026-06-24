package io.appthreat.php2atom.passes

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.astcreation.AstCreator
import io.appthreat.php2atom.parser.PhpParser
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import org.slf4j.LoggerFactory

import java.nio.file.{Files, Paths}
import scala.util.Try

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

  private def createAst(filename: String): Option[ParsedUnit] =
      parser.parseFile(filename, config.phpIni) match
        case Some(parseResult) =>
            val diff = new AstCreator(relativeFilename(filename), parseResult)(
              using config.schemaValidation
            ).createAst()
            Some(ParsedUnit(diff))
        case None =>
            logger.debug(s"Could not parse file $filename. Results will be missing!")
            None
end AstCreationPass
