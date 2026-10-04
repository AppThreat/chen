package io.appthreat.edg2atom.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{FileDefaults, ProjectSources}
import io.appthreat.edg2atom.astcreation.AstCreator
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.x2cpg.SourceFiles
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ForkJoinParallelCpgPass
import org.slf4j.LoggerFactory

import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap

/** One AST per translation unit, from what edga exports for it. Headers are not parsed on their
  * own: a project header's functions, types and variables are written by the first unit that
  * includes it.
  */
class EdgAstCreationPass(cpg: Cpg, config: Config, sources: ProjectSources, runner: EdgaRunner)
    extends ForkJoinParallelCpgPass[String](cpg):

  private val logger = LoggerFactory.getLogger(getClass)

  private val claimed = ConcurrentHashMap.newKeySet[String]()

  /** Translation units edga could not export, for a caller that parses them another way. */
  val failed: java.util.Set[String] = ConcurrentHashMap.newKeySet[String]()

  override def generateParts(): Array[String] =
      sources.files.filterNot(FileDefaults.isHeaderFile).sorted

  override def runOnPart(diffGraph: DiffGraphBuilder, file: String): Unit =
    val path = Paths.get(file).toAbsolutePath
    runner.exportUnit(path, EdgAstCreationPass.TimeoutSeconds) match
      case Some(unit) if unit.status != "failed" =>
          val relative = SourceFiles.toRelativePath(path.toString, config.inputPath)
          claimed.add(path.normalize.toString)
          val creator =
              new AstCreator(relative, unit, config, p => claimed.add(p))(using
                config.schemaValidation
              )
          diffGraph.absorb(creator.createAst())
      case _ =>
          failed.add(file)
          logger.warn(s"edga could not export $file")
end EdgAstCreationPass

object EdgAstCreationPass:
  /** How long the front end may take on one translation unit. */
  val TimeoutSeconds: Long = 600
