package io.appthreat.edg2atom.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.parser.{FileDefaults, ProjectSources}
import io.appthreat.c2cpg.passes.AstCreationPass
import io.appthreat.edg2atom.astcreation.AstCreator
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.ParsedUnit
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ForkJoinParallelCpgPass
import org.slf4j.LoggerFactory

import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.ConcurrentHashMap
import scala.util.Try

/** One AST per translation unit, from what edga exports for it. Headers are not parsed on their
  * own: a project header's functions, types and variables are written with the unit it belongs to
  * (the first one, in path order, that includes it), so every run writes it from the same unit.
  *
  * A unit's AST is cached like the CDT frontend's, keyed also on the project headers it includes
  * and on the edga build that exported it.
  */
class EdgAstCreationPass(cpg: Cpg, config: Config, sources: ProjectSources, runner: EdgaRunner)
    extends ForkJoinParallelCpgPass[String](cpg):

  private val logger = LoggerFactory.getLogger(getClass)

  /** Header -> the unit it belongs to, by real path: edga reports files by their real paths
    * (`/private/var/...` for `/var/...` on macOS).
    */
  private val owners: Map[Path, Path] =
      sources.headerOwners.map((header, unit) => EdgAstCreationPass.real(header) -> unit)

  private val cacheStore = new AstCacheStore(
    config.enableAstCache,
    AstCacheStore.resolveCacheDir(config.inputPath, config.cacheDir),
    config.onlyAstCache
  )

  /** Translation units edga could not export, for a caller that parses them another way. */
  val failed: java.util.Set[String] = ConcurrentHashMap.newKeySet[String]()

  /** Why each failed unit failed: the front end's first error, if it reported one. */
  val failures = new ConcurrentHashMap[String, String]()

  /** Translation units whose AST was written, exported or from the cache. */
  val written: java.util.Set[String] = ConcurrentHashMap.newKeySet[String]()

  override def generateParts(): Array[String] =
      sources.files.filterNot(FileDefaults.isHeaderFile).sorted

  /** Whether `unit` writes the project file `path`: its own file, or a header it owns. */
  private def writes(unit: Path)(path: String): Boolean =
    val p = EdgAstCreationPass.real(Paths.get(path))
    p == EdgAstCreationPass.real(unit) || owners.get(p).contains(unit)

  override def runOnPart(diffGraph: DiffGraphBuilder, file: String): Unit =
    val path = Paths.get(file).toAbsolutePath.normalize
    // the AST is built only when the cache has none
    var attempted = false
    var exported  = false
    cacheStore.process(
      diffGraph,
      file,
      cacheKey = AstCreationPass.fileCacheKey(file),
      fingerprint = fingerprint(path, file),
      registerUsedTypes = types => types.foreach(CGlobal.usedTypes.putIfAbsent(_, true)),
      createAst =
        attempted = true
        runner.exportUnit(path, EdgAstCreationPass.TimeoutSeconds) match
          case Some(unit) if unit.status == "failed" =>
              unit.diagnostics.find(_.obj.get("level").exists(_.str == "error"))
                  .flatMap(_.obj.get("message")).foreach(m => failures.put(file, m.str))
              None
          case Some(unit) =>
              exported = true
              val relative = SourceFiles.toRelativePath(path.toString, config.inputPath)
              val creator =
                  new AstCreator(relative, unit, config, writes(path))(using
                    config.schemaValidation
                  )
              val diff = creator.createAst()
              Some(ParsedUnit(diff, creator.usedTypeNames))
          case _ => None
    )
    if !attempted || exported then written.add(file)
    else
      failed.add(file)
      logger.warn(s"edga could not export $file")
  end runOnPart

  /** What else a unit's AST depends on: how the CDT frontend would parse it, the edga build, and
    * the content of the project headers it includes.
    */
  private def fingerprint(path: Path, file: String): String =
    def contentOf(p: Path): String =
      val crc = new java.util.zip.CRC32()
      Try(Files.readAllBytes(p)).foreach(b => crc.update(b))
      s"$p:${crc.getValue}"
    (Seq(
      AstCreationPass.fileFingerprint(config, sources, file),
      EdgAstCreationPass.AstFormatVersion,
      runner.identity
    ) ++ sources.projectIncludes(path).map(contentOf)).mkString("\u0000")

  /** The project headers no unit wrote: those whose unit edga could not export. */
  def unwrittenHeaders: Seq[String] =
      owners.collect {
          case (header, unit) if failed.contains(unit.toString) => header.toString
      }.toSeq.sorted
end EdgAstCreationPass

object EdgAstCreationPass:
  def real(path: Path): Path = AstCreator.realPath(path)

  /** How long the front end may take on one translation unit. */
  val TimeoutSeconds: Long = 600

  /** Changes when the ASTs this frontend builds change, so cached ones are rebuilt. */
  val AstFormatVersion = "edg2atom-ast-1"
