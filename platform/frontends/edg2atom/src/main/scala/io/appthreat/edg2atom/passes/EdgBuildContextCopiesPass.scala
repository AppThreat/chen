package io.appthreat.edg2atom.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{CompileCommand, FileDefaults, ProjectSources}
import io.appthreat.c2cpg.passes.{BuildContextCopies, BuildContextPass}
import io.appthreat.edg2atom.astcreation.AstCreator
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import java.nio.file.{Path, Paths}
import scala.collection.mutable

/** The analyses of a file's extra build contexts: with `--c-build-contexts all`, a file the
  * compilation database compiles with more than one distinct context is exported once per context,
  * the way the first context's export builds it, and the copies the extra contexts build are named
  * and tagged by [[BuildContextCopies]] before they are written.
  *
  * A function whose body is the same in every context is kept once, the copy the first context
  * wrote, by [[io.appthreat.c2cpg.passes.BuildContextDuplicatesPass]]; a function whose body
  * differs keeps one copy per context. The extra exports run fresh on every run, on this pass's
  * thread, one file at a time; the AST cache holds the first context's fragments, keyed as it
  * always was. A context whose export fails contributes nothing, and the parse report carries the
  * failure with the context it belongs to.
  */
class EdgBuildContextCopiesPass(
  cpg: Cpg,
  config: Config,
  sources: ProjectSources,
  runner: EdgaRunner
) extends CpgPass(cpg):

  import BuildContextCopies.ContextAnalysis

  /** Header -> the unit it belongs to, by real path: edga reports files by their real paths. */
  private val owners: Map[Path, Path] =
      sources.headerOwners.map((header, unit) => AstCreator.realPath(header) -> unit)

  /** Whether `unit` writes the project file `path`: its own file, or a header it owns. */
  private def writes(unit: Path)(path: String): Boolean =
    val p = AstCreator.realPath(Paths.get(path))
    p == AstCreator.realPath(unit) || owners.get(p).contains(unit)

  override def run(diffGraph: DiffGraphBuilder): Unit =
      if !config.buildContextsAll || runner.executable.isEmpty then ()
      else
        val analyses = extraContextAnalyses()
        if analyses.nonEmpty then writeCopies(analyses, diffGraph)
  end run

  /** The ASTs of the extra contexts, built fresh, one file's contexts after another's. */
  private def extraContextAnalyses(): Seq[ContextAnalysis] =
    val analyses = mutable.ArrayBuffer.empty[ContextAnalysis]
    sources.files.filterNot(FileDefaults.isHeaderFile).foreach { file =>
      val contexts = sources.contextsOf(Paths.get(file).toAbsolutePath)
      if contexts.size > 1 then
        contexts.drop(1).foreach { command =>
            analyse(Paths.get(file).toAbsolutePath, command).foreach(analyses += _)
        }
    }
    analyses.toSeq

  /** The AST one extra context builds for the file, on this thread, in the context's settings: what
    * the front end exports for the command the context compiles the file with.
    */
  private def analyse(path: Path, command: CompileCommand): Option[ContextAnalysis] =
    val relative = SourceFiles.toRelativePath(path.toString, config.inputPath)
    sources.withContextCommand(command) {
        val fingerprint = BuildContextPass.fingerprintOf(command.flags, root)
        runner.exportUnit(path, EdgAstCreationPass.TimeoutSeconds) match
          case Some(unit) if unit.status == "failed" =>
              val diagnostic = unit.diagnostics
                  .find(_.obj.get("level").exists(_.str == "error"))
                  .flatMap(_.obj.get("message"))
                  .map(_.str)
                  .getOrElse("edga exported no unit and reported no diagnostic")
              ParseReporter.record(
                ParseReporter.Frontend.Edg,
                relative,
                ParseReporter.Outcome.Unparsed,
                ParseReporter.Stage.Parse,
                s"build context ${fingerprint.take(8)}: $diagnostic"
              )
              None
          case Some(unit) =>
              val creator = new AstCreator(
                relative,
                unit,
                config,
                writes(path),
                runner.macroFilePaths
              )(using config.schemaValidation)
              val diff = creator.createAst()
              Some(ContextAnalysis(
                path,
                fingerprint,
                diff,
                BuildContextCopies.methodEntriesOf(diff),
                creator.usedTypeNames
              ))
          case None =>
              ParseReporter.record(
                ParseReporter.Frontend.Edg,
                relative,
                ParseReporter.Outcome.Unparsed,
                ParseReporter.Stage.Parse,
                s"build context ${fingerprint.take(8)}: edga could not be run or wrote nothing"
              )
              None
        end match
    }
  end analyse

  private val root = Paths.get(config.inputPath).toAbsolutePath.normalize

  /** Writes the copies, compared against the methods the first context's export wrote: the unit's
    * own and those of the headers the unit owns, which the export writes as part of it.
    */
  private def writeCopies(analyses: Seq[ContextAnalysis], diffGraph: DiffGraphBuilder): Unit =
      BuildContextCopies.writeCopies(
        cpg,
        analyses,
        unit =>
            (unit +: sources.headersOwnedBy(unit)).map(f =>
                SourceFiles.toRelativePath(f.toString, config.inputPath)
            ),
        diffGraph
      )
end EdgBuildContextCopiesPass
