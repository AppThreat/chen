package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.passes.frontend.TypeRecoveryParserConfig
import io.appthreat.x2cpg.{PythonDepsMode, SourceFiles, X2Cpg, X2CpgConfig, X2CpgFrontend}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.utils.IOUtils
import org.slf4j.LoggerFactory

import java.nio.file.*
import scala.util.Try

case class Py2CpgOnFileSystemConfig(
  venvDir: Path = Paths.get(".venv"),
  ignoreVenvDir: Boolean = true,
  ignorePaths: Seq[Path] = Nil,
  ignoreDirNames: Seq[String] = Nil,
  requirementsTxt: String = "requirements.txt",
  strictParse: Boolean = false,
  pythonDeps: PythonDepsMode = PythonDepsMode.Disabled,
  pythonDepsRounds: Int = 2,
  typeshedDir: Option[Path] = None
) extends X2CpgConfig[Py2CpgOnFileSystemConfig]
    with TypeRecoveryParserConfig[Py2CpgOnFileSystemConfig]:
  def withVenvDir(venvDir: Path): Py2CpgOnFileSystemConfig =
      copy(venvDir = venvDir).withInheritedFields(this)

  def withIgnoreVenvDir(value: Boolean): Py2CpgOnFileSystemConfig =
      copy(ignoreVenvDir = value).withInheritedFields(this)

  def withIgnorePaths(value: Seq[Path]): Py2CpgOnFileSystemConfig =
      copy(ignorePaths = value).withInheritedFields(this)

  def withIgnoreDirNames(value: Seq[String]): Py2CpgOnFileSystemConfig =
      copy(ignoreDirNames = value).withInheritedFields(this)

  def withRequirementsTxt(text: String): Py2CpgOnFileSystemConfig =
      copy(requirementsTxt = text).withInheritedFields(this)

  /** Fail the run when any statement fails to parse, instead of only emitting an inline
    * ErrorStatement node. Parse errors are always summarized on stdout.
    */
  def withStrictParse(value: Boolean): Py2CpgOnFileSystemConfig =
      copy(strictParse = value).withInheritedFields(this)

  /** Select how dependency code is treated - `Disabled` (default), `Stubs` (signature-only),
    * `Summaries` (signatures plus flow summaries) or `Full` (parse the venv as internal code). A
    * case-class field, so it survives the `copy` chain like `pythonDeps`.
    */
  def withPythonDeps(value: PythonDepsMode): Py2CpgOnFileSystemConfig =
      copy(pythonDeps = value).withInheritedFields(this)

  /** How many transitive rounds of dependency-module import closure to ingest in
    * `stubs`/`summaries` mode. The default 2 covers the directly imported distributions' own
    * modules (measured: ~+17% nodes on a flask-scale project) - the stated growth budget; 3-4
    * follow werkzeug/jinja2-style runtime chains deep into transitive dependencies (measured: +70%
    * to +220%) and are opt-in depth, not the default.
    */
  def withPythonDepsRounds(value: Int): Py2CpgOnFileSystemConfig =
      copy(pythonDepsRounds = value).withInheritedFields(this)

  /** Directory holding a typeshed checkout (a `stdlib/` subtree of `.pyi` files) used by
    * `stubs`/`summaries` mode as the signature source for the standard library.
    */
  def withTypeshedDir(value: Path): Py2CpgOnFileSystemConfig =
      copy(typeshedDir = Some(value)).withInheritedFields(this)
end Py2CpgOnFileSystemConfig

object Py2CpgOnFileSystem:
  /** Leading path prefixes that mark build/packaging output. A `.py` file under one of these is a
    * *shadow* copy ONLY when the same logical module path also exists outside any build dir — see
    * [[Py2CpgOnFileSystem.dropShadowedBuildCopies]]. We deliberately do NOT ignore these dirs
    * outright, so analysing an unzipped `.egg`/`.tar.gz` (whose sources live entirely under `dist/`
    * or `build/`) still works.
    */
  private val BuildPrefixDirs: Set[String] = Set("build", "dist")

  /** A leading `src` segment (src-layout) is stripped when comparing logical paths, so
    * `src/pkg/x.py` and `build/lib/pkg/x.py` are recognised as the same module.
    */
  private val SrcLayoutDir = "src"

  /** Reduce a relative path to its logical module path: strip a leading build/dist prefix (and an
    * optional `lib` segment, as in `build/lib/...`), then a leading `src`. Returns the remaining
    * path, or `None` if nothing is left.
    */
  private def logicalModulePath(rel: Path): Option[Path] =
    var parts = (0 until rel.getNameCount).map(i => rel.getName(i).toString).toList
    if parts.headOption.exists(BuildPrefixDirs.contains) then
      parts = parts.tail
      if parts.headOption.contains("lib") then parts = parts.tail
    if parts.headOption.contains(SrcLayoutDir) then parts = parts.tail
    parts match
      case Nil          => None
      case head :: tail => Some(tail.foldLeft(Path.of(head))((p, s) => p.resolve(s)))

  private def isUnderBuildDir(rel: Path): Boolean =
      rel.getNameCount > 0 && BuildPrefixDirs.contains(rel.getName(0).toString)

  /** Drop `.py` files under a build/dist dir whose logical module path is ALSO provided by a
    * non-build file. Files that exist only under build/dist (e.g. an unzipped sdist) are kept.
    * `files` are absolute; compared relative to `inputPath`.
    */
  private[pysrc2cpg] def dropShadowedBuildCopies(
    files: Seq[Path],
    inputPath: Path
  ): Seq[Path] =
    val rels = files.map(f => f -> inputPath.relativize(f))
    // Logical module paths contributed by files NOT under a build dir.
    val nonBuildLogical: Set[Path] = rels.iterator
        .filterNot { case (_, rel) => isUnderBuildDir(rel) }
        .flatMap { case (_, rel) => logicalModulePath(rel) }
        .toSet
    rels.collect {
        case (abs, rel)
            if !isUnderBuildDir(rel) ||
                !logicalModulePath(rel).exists(nonBuildLogical.contains) =>
            abs
    }
end Py2CpgOnFileSystem

class Py2CpgOnFileSystem extends X2CpgFrontend[Py2CpgOnFileSystemConfig]:

  private val logger = LoggerFactory.getLogger(getClass)

  /** One file the frontend will parse: its absolute path, its package-relative name (what the
    * graph's FILE node and every derived full name are built from), the root it was determined
    * against (the input path, or an archive extraction root), and whether it is dependency code.
    */
  private case class IngestedFile(abs: Path, rel: String, root: Path, isDependency: Boolean)

  /** Entry point for files system based cpg generation from python code.
    * @param config
    *   Configuration for cpg generation.
    */
  override def createCpg(config: Py2CpgOnFileSystemConfig): Try[Cpg] =
      X2Cpg.withNewEmptyCpg(config.outputPath, config) { (cpg, _) =>
          // Archives (.whl/.egg/sdist/zipapp/pex) are unpacked into a per-run temp directory
          // BEFORE the file walk, so everything downstream (module naming, src/build shadow
          // handling, dependency attribution) applies to unpacked code unchanged. The temp
          // directory outlives parsing - providers are lazy readers - and is removed afterwards;
          // nothing is ever written into the user's input tree.
          io.appthreat.x2cpg.utils.FileUtil.usingTemporaryDirectory("chen-py-archives-") {
              tempDir =>
                val inputPath = Path.of(config.inputPath)
                val extracted = PythonArchiveHandler.extractArchives(inputPath, tempDir)

                // Placement rule (task 12 A.5), stated once and applied here only:
                //   - an archive given AS the input path is the code under analysis - internal;
                //   - an application container found INSIDE the input tree (.pyz/.pex - a program the
                //     user placed there) is also internal;
                //   - a distribution archive found inside the input tree (.whl/.egg/sdist) is
                //     dependency code: its files are marked isExternal via the externality pass, so
                //     `isLibrarySourcedFlow` keeps library-sourced findings out of reachables exactly
                //     as it does for venv-sourced code, while exploration still descends into the
                //     bodies because externality and explorability are separate notions.
                val inputIsArchive = PythonArchiveHandler.isArchive(inputPath)
                val (projectExtractions, dependencyExtractions) = extracted.partition { e =>
                    inputIsArchive || PythonArchiveHandler.isApplicationArchive(e.archiveFile)
                }

                val files = ingestFiles(
                  config,
                  inputPath,
                  projectExtractions.map(_.root),
                  dependencyExtractions.map(_.root)
                )

                val hasRequirementsTxt =
                    Files.isRegularFile(inputPath.resolve(config.requirementsTxt)) ||
                        projectExtractions.exists(e =>
                            Files.isRegularFile(e.root.resolve(config.requirementsTxt))
                        )

                // No silent empty atom (Task 12 A.1): an input that yields zero Python files is a
                // failure a script can detect, not an empty analysis. Measured shape of the bug: a
                // directory holding only `.whl`/`.tar.gz` archives produced exit 0 and a ~12 KB
                // meta-only atom, indistinguishable from a successful analysis of a codeless project.
                // A `requirements.txt`-only input IS analysable (ConfigFileCreationPass).
                if files.isEmpty && !hasRequirementsTxt then
                  throw RuntimeException(
                    s"No Python source files found under '$inputPath': 0 .py files and no " +
                        s"${config.requirementsTxt} after archive extraction and filters " +
                        "(ignore-paths, ignored dir names, venv exclusion)."
                  )

                // Each file's dotted module name is derived from the file set of ITS OWN root (the
                // `__init__.py` chain walk): a wheel root and the project root keep disjoint
                // namespaces, so one tree's packages can never anchor the other's module names.
                val moduleNames: Map[String, String] =
                    files.groupBy(_.root).flatMap { (root, rootFiles) =>
                      val rels = rootFiles.map(_.rel).toSet
                      rootFiles.flatMap { f =>
                          PythonModuleName.moduleFor(rels, f.rel).map(f.rel -> _)
                      }
                    }.toMap

                val inputProviders = files.map { f => () =>
                  val content = IOUtils.readLinesInFile(f.abs).mkString("\n")
                  Py2Cpg.InputPair(content, f.rel)
                }
                val py2Cpg = new Py2Cpg(
                  inputProviders,
                  cpg,
                  config.inputPath,
                  config.requirementsTxt,
                  config.schemaValidation,
                  strictParse = config.strictParse,
                  moduleNames = moduleNames
                )
                py2Cpg.buildCpg()
                // Dependency ingestion runs after the project itself is built. `stubs`/`summaries` grow
                // the graph by what the project's imports resolve to; `full` ingests the whole
                // dependency tree from the same origins, with bodies intact.
                config.pythonDeps match
                  case PythonDepsMode.Disabled => ()
                  case PythonDepsMode.Full =>
                      PythonDependencyStubs.ingestFull(cpg, inputPath, config)
                  case mode =>
                      PythonDependencyStubs.ingest(
                        cpg,
                        inputPath,
                        config,
                        summaries = mode == PythonDepsMode.Summaries
                      )

                // Externality is by path, regardless of mode: `ignore-venv-dir=false` walks the venv
                // with the project's own file walk, and whatever it parses must still be attributed as
                // dependency code (isExternal), or user scoping and reachables attribution lie about
                // every method in it. Full mode runs it as a belt-and-braces net for any venv-named
                // directory the walk still picked up. Files unpacked from in-tree distribution archives
                // are dependencies by the placement rule above, so the pass runs for them too. Where no
                // dependency file is in the graph this pass is a no-op.
                val archiveDependencyRels = files.filter(_.isDependency).map(_.rel).toSet
                if !config.ignoreVenvDir || config.pythonDeps == PythonDepsMode.Full ||
                  archiveDependencyRels.nonEmpty
                then
                  new PythonDependencyExternalityPass(
                    cpg,
                    inputPath,
                    PythonDependencyStubs.dependencyRoots(inputPath, config),
                    archiveDependencyRels
                  ).createAndApply()

                // Package identity (task 12 A.4): anything unpacked from an archive states its own
                // distribution name, version and top-level import names (RECORD / top_level.txt /
                // PKG-INFO) - no SBOM required. Tagging the mapped modules' methods with the purl is
                // the same shape `PythonDependencyPurlPass` writes for venv code and `CdxPass` writes
                // from an SBOM, so attribution consumers need no new channel.
                val purlByRel = files.groupBy(_.root).flatMap { (root, rootFiles) =>
                    PythonArchiveHandler.packageIdentity(root).iterator.flatMap { ident =>
                        rootFiles.collect {
                            case f if ident.importNames.contains(topSegment(f.rel)) =>
                                f.rel -> ident.purl
                        }
                    }
                }.toMap
                if purlByRel.nonEmpty then
                  new PythonDependencyPurlPass(cpg, purlByRel).createAndApply()
          }
      }
  end createCpg

  /** Determine the parse set: the input path's own files plus the unpacked archive roots', with
    * every root filtered by the same ignore rules and shadow-deduped against ITS OWN root's layout.
    * Cross-root name collisions resolve project-first (the project is what the interpreter loads
    * first for a same-named top-level module, and user attribution must never move), then
    * first-archive-wins in the deterministic sorted extraction order.
    */
  private def ingestFiles(
    config: Py2CpgOnFileSystemConfig,
    inputPath: Path,
    projectRoots: Seq[Path],
    dependencyRoots: Seq[Path]
  ): Seq[IngestedFile] =
    val venvIgnored =
        config.ignoreVenvDir || config.pythonDeps == PythonDepsMode.Full
    val venvIgnorePath =
        if venvIgnored then
          // An out-of-tree `venv-dir` does not name the in-tree `.venv`: in full mode the
          // conventional name is ignored in the walk as well, or a project venv would be
          // parsed TWICE - once by the walk under a `.venv/...`-prefixed name, once by the
          // dependency origins - with the walked copy escaping attribution as internal
          // project code.
          config.venvDir :: (
            if config.pythonDeps == PythonDepsMode.Full && config.venvDir != Paths.get(".venv")
            then Paths.get(".venv") :: Nil
            else Nil
          )
        else
          Nil
    val absoluteIgnorePaths = (config.ignorePaths ++ venvIgnorePath).map(inputPath.resolve)
    val ignoreDirNamesSet   = config.ignoreDirNames.toSet

    def filesOf(root: Path, isDependency: Boolean): Seq[IngestedFile] =
      val inputFiles = SourceFiles
          .determine(
            root.toString,
            Set(".py"),
            ignoredFilesRegex = Option(config.ignoredFilesRegex),
            ignoredFilesPath = Option(config.ignoredFiles)
          )
          .map(x => Path.of(x))
          .map(abs => IngestedFile(abs, root.relativize(abs).toString, root, isDependency))
          .filter { f =>
              // Judged on the path segments BELOW the owning root, never the absolute one:
              // `__pycache__`/`__pypackages__` inside an unpacked tree must be dropped the
              // same way they are in a venv (the 8.5 lesson).
              relDirSegments(f.rel).forall(!ignoreDirNamesSet.contains(_)) &&
              (isDependency || !absoluteIgnorePaths.exists(ignorePath =>
                  f.abs.startsWith(ignorePath)
              ))
          }
      // Build/dist shadow copies are deduped per tree: a sdist's build/lib duplicate of a
      // file the same sdist also ships under src/ is dropped; a file only under build/ is
      // kept (the unzipped-sdist case the function has always covered).
      Py2CpgOnFileSystem
          .dropShadowedBuildCopies(inputFiles.map(_.abs), root)
          .map(abs => IngestedFile(abs, root.relativize(abs).toString, root, isDependency))
    end filesOf

    val projectFiles = (inputPath +: projectRoots.filter(_ != inputPath))
        .filter(root => Files.isDirectory(root))
        .flatMap(filesOf(_, isDependency = false))
    val dependencyFiles = dependencyRoots.flatMap(filesOf(_, isDependency = true))

    // Collision resolution: the project's own names always win; among archives, the first
    // extraction (sorted archive order) wins. Same rule as full mode's project-wins filter.
    val byRel = scala.collection.mutable.LinkedHashMap.empty[String, IngestedFile]
    (projectFiles ++ dependencyFiles).foreach { f =>
        if !byRel.contains(f.rel) then byRel.update(f.rel, f)
    }
    val dropped = projectFiles.size + dependencyFiles.size - byRel.size
    if dropped > 0 then
      logger.info(
        s"archive ingestion: skipped $dropped unpacked file(s) whose package-relative name " +
            "collides with an already-ingested tree (project first, then sorted archive order)"
      )
    byRel.values.toSeq.sortBy(_.rel)
  end ingestFiles

  /** Delegated so the import name a file contributes is computed by ONE rule, shared with the side
    * that derives `importNames` from an archive's layout. Two local copies would drift, and the
    * symptom of drift here is silent: a purl that matches no module simply never gets applied.
    */
  private def topSegment(rel: String): String =
      PythonArchiveHandler.importTopOf(rel)

  private def relDirSegments(rel: String): Seq[String] =
      rel.split('/').dropRight(1).toSeq

end Py2CpgOnFileSystem
