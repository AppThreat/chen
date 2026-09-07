package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.summaries.{
    FlowSummaryComputer,
    FlowSummaryTags,
    MethodFlowSummary
}
import io.appthreat.pythonparser.ast
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.frontend.CacheControl
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, EvaluationStrategies, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import io.shiftleft.utils.IOUtils
import org.slf4j.LoggerFactory
import overflowdb.BatchedUpdate.DiffGraphBuilder
import overflowdb.NodeOrDetachedNode

import java.nio.file.{Files, Path, Paths}
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try, Using}

/** Opt-in dependency signature ingestion for `--frontend-args python-deps=stubs|summaries`.
  *
  * The two complaints this answers are the ANY type rate and calls that resolve to nothing: user
  * code calls into libraries the CPG has never seen, so neither receiver types nor callee full
  * names exist. Rather than parsing the whole venv as internal code (the all-or-nothing
  * `ignore-venv-dir=false`, now `python-deps=full`), this ingests ONLY the distributions the
  * project's imports actually resolve to, and reduces them to signatures:
  *
  *   - One loader, two inputs: an installed `site-packages` (preferred - it is what the code will
  *     really call) and a typeshed `stdlib/` checkout of `.pyi` stubs (`typeshed-dir` /
  *     `CHEN_TYPESHED_DIR`). Where `top_level.txt` would have mapped wheel names to import names,
  *     module-name == directory-name is the approximation; the real mapping is Task 9.
  *   - Dependency files are parsed by the production [[CodeToCpg]] with a site-packages-relative
  *     file name, so every METHOD/TYPE_DECL full name lands in exactly the shape the import
  *     resolver and type recovery generate as call candidates
  *     (`requests/__init__.py:<module>.get`). Function and class bodies are truncated at the
  *     parser-AST level ([[truncateForSignatures]]), so bodies and CFG never reach the graph -
  *     there is nothing to delete afterwards and nothing can dangle.
  *   - A signature pass marks the created nodes `isExternal` and synthesises re-export aliases
  *     under BOTH import spellings (`pkg/__init__.py:<module>.x` and `pkg.py:<module>.x`) - that is
  *     what `from pkg import x` and `import pkg` have to join against. The stub that must not be
  *     created twice is guarded: an alias is created only when neither spelling already defines the
  *     symbol.
  *   - In `summaries` mode the SAME files are re-parsed untruncated into a throwaway graph, the
  *     data-flow layer runs over it once, and
  *     [[io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryComputer]] extracts
  *     per-method facts; the facts are persisted as `flow-summary` tags on the signature methods
  *     (and their aliases) and the throwaway graph is discarded. Bodies never enter the real graph.
  *
  * Nothing here touches the project's own nodes: with `python-deps=none` (the default) this object
  * is never constructed.
  */
object PythonDependencyStubs:

  /** Parser-AST transform applied before conversion. Identity for every plain build. */
  type Transform = ast.Module => ast.Module

  private val logger = LoggerFactory.getLogger(getClass)

  /** The cache fingerprint stamped on dependency-signature fragments, so a truncated fragment can
    * never be served to a plain build (or vice versa) even from a shared cache directory.
    */
  /* Bump this whenever [[truncateForSignatures]] changes what it keeps: the cache key is the
   * source content hash, so without a bump a fragment truncated by the previous rules is a
   * legitimate hit for the new ones. v3 keeps imports-only `if TYPE_CHECKING:` blocks. */
  val CacheFingerprint: String = "dependency-signatures-v3"

  /** The cache fingerprint for `python-deps=full` fragments: bodies intact, so a fragment cached by
    * one mode can never be served to the other. The cache key is the source content hash, and the
    * per-package directory scopes it further; the fingerprint is what makes the two modes disjoint
    * in a shared `.chen/pydeps` tree.
    */
  val FullCacheFingerprint: String = "dependency-full-v1"

  /** Environment variable consulted for the typeshed `stdlib/` directory when the frontend arg is
    * not given.
    */
  val TypeshedDirEnv: String = "CHEN_TYPESHED_DIR"

  /** Environment variable consulted for extra site-packages directories (colon-separated absolute
    * paths) - poetry virtualenvs, Nix store paths, CI locations the fixed discovery cannot know.
    */
  val ExtraSitePackagesEnv: String = "CHEN_PYTHON_SITE_PACKAGES"

  /** Directory-segment names that mark a dependency root wherever they appear - the fallback for a
    * venv discovery miss. A project file merely NAMED like one of these (venv_utils.py) is not
    * affected: only directory segments are matched, never the file name.
    */
  val DependencyDirNames: Set[String] =
      Set(".venv", "venv", ".virtualenvs", "site-packages", "dist-packages")

  /** A directory whose `.py`/`.pyi` files are addressed package-relative: a `site-packages`
    * directory or a typeshed `stdlib` directory.
    */
  private case class Origin(root: Path, isTypeshed: Boolean)

  /** One resolved module file. */
  private case class ResolvedFile(origin: Origin, rel: String, abs: Path)

  /** Version of a top-level package, from the adjacent `<name>-<version>.dist-info` directory.
    * Site-packages only - typeshed stub versions are the stub's, not what the project resolved.
    */
  private def versionOf(origin: Origin, top: String): Option[String] =
      if origin.isTypeshed then None
      else
        Try {
            Using.resource(Files.newDirectoryStream(origin.root, s"$top-*.dist-info")) { stream =>
                stream.iterator().asScala.toSeq.headOption.flatMap { p =>
                  val n = p.getFileName.toString.stripSuffix(".dist-info")
                  n.split("-").takeRight(1).headOption
                }
            }
        }.toOption.flatten

  /** A raw import of an ingested file: `from where import what as alias`. */
  private[pysrc2cpg] case class DepImport(where: String, what: String, alias: String)

  /** A symbol to alias into a package's public namespace, from the package's `__init__.py`. */
  private[pysrc2cpg] case class AliasRequest(
    pkgName: String,
    localName: String,
    targetModuleRel: String,
    targetSymbol: String
  )

  /** Entry point. Parses the imported distributions as signatures, optionally computing flow
    * summaries from a throwaway full parse. Runs inside `Py2CpgOnFileSystem.createCpg`, after the
    * project's own code has been built.
    */
  def ingest(
    cpg: Cpg,
    inputPath: Path,
    config: Py2CpgOnFileSystemConfig,
    summaries: Boolean
  ): Unit =
    val origins = discoverOrigins(inputPath, config)
    if origins.isEmpty then
      logger.info(
        s"python-deps: no site-packages or typeshed found to ingest from (venv dir: ${config.venvDir}); " +
            "skipping dependency stubs"
      )
      return ()

    val t0        = System.currentTimeMillis()
    val ingested  = mutable.LinkedHashMap.empty[String, Path] // rel path -> absolute path
    val originsOf = mutable.HashMap.empty[String, Origin]     // rel path -> origin (for versions)
    val parsed    = mutable.LinkedHashSet.empty[String]       // top-level package names seen
    val cacheRoot = Paths.get(inputPath.toString, ".chen", "pydeps")

    def cacheDirFor(rel: String): String =
      val top    = rel.split('/').head
      val origin = originsOf.getOrElse(rel, origins.head)
      cacheRoot.resolve(versionOf(origin, top).map(v => s"$top-$v").getOrElse(top)).toString

    // Module-level import closure: round zero resolves the project's own imports to files;
    // every further round resolves the imports OF the ingested files the same way. Only
    // modules that are actually imported are ingested - never a whole distribution.
    var round    = 0
    var frontier = dependencyEntities(cpg, ingested.keySet, fromIngestedFiles = false)
    while frontier.nonEmpty && round < config.pythonDepsRounds do
      val nodesBefore = cpg.graph.nodeCount
      val resolved = frontier
          .map((importer, entity) => resolveEntity(importer, entity, origins, ingested.keySet))
          .collect { case Some(f) => f }
          .filter(f => !ingested.contains(f.rel))
          .distinct
      if resolved.isEmpty then frontier = Seq.empty
      else
        // Dependency fragments cache under their own `<pkg>-<version>` directory of the
        // project's `.chen` AST cache. Signatures are immutable per version and the cache
        // key is the file content hash, so a cache hit for the same package IS the same
        // version; the per-package subdirectory additionally scopes side-by-side projects.
        resolved.groupBy(f => cacheDirFor(f.rel)).foreach { case (cacheDir, files) =>
            parseInto(
              cpg,
              files.map(f => f.rel -> f.abs),
              inputPath,
              config,
              cacheDir,
              truncate = true
            )
        }
        resolved.foreach { f =>
          ingested.update(f.rel, f.abs)
          originsOf.update(f.rel, f.origin)
          parsed += f.rel.split('/').head
        }
        round += 1
        frontier = dependencyEntities(cpg, ingested.keySet, fromIngestedFiles = true)
        logger.info(
          s"python-deps: round $round ingested ${resolved.size} module file(s), graph grew " +
              s"${cpg.graph.nodeCount - nodesBefore} nodes"
        )
      end if
    end while

    val aliasRequests = planAliases(cpg, parsed.toSeq, ingested.keySet)
    val summaryMap: Map[String, MethodFlowSummary] =
        if summaries then computeSummariesViaThrowawayGraph(ingested, inputPath, config)
        else Map.empty

    new PythonDependencySignaturePass(
      cpg,
      ingested.keySet.toSet,
      aliasRequests,
      summaryMap
    ).createAndApply()
    logger.info(
      s"python-deps: ingested ${parsed.size} package(s), ${ingested.size} file(s) in " +
          s"${System.currentTimeMillis() - t0}ms, ${aliasRequests.size} alias request(s), " +
          s"${summaryMap.size} flow summary(ies); graph now ${cpg.graph.nodeCount} nodes"
    )
  end ingest

  // ---------------------------------------------------------------- full mode

  /** Directory names never mined for Python sources: packaging metadata and bytecode caches hold no
    * code that can run.
    */
  private val IgnoredDepDirSuffixes = Set("dist-info", "egg-info")

  private val IgnoredDepDirNames = Set("__pycache__", "__pypackages__")

  /** `python-deps=full`: the whole dependency tree, in the graph, connected. Every `.py`/`.pyi`
    * under every origin - NOT the import closure (a module imported only dynamically is exactly the
    * module the thin modes miss) - parsed with bodies intact, site-packages-relative names so every
    * full name joins the import resolver's candidates, and package identity attached so a flow
    * through a library can name the distribution and version it passed through.
    *
    * What this deliberately does NOT do: no `python-deps-rounds` bound (the bound exists to keep
    * the thin modes thin), no `truncateForSignatures` (bodies are the point), no synthetic
    * re-export aliases (the real `__init__.py` is in the graph and `ImportResolverPass` joins the
    * user's imports natively), and no flow summaries (`summaries` approximates bodies; `full` has
    * them - combining the two would replace exploration with an approximation of it).
    */
  def ingestFull(cpg: Cpg, inputPath: Path, config: Py2CpgOnFileSystemConfig): Unit =
    val origins = discoverOrigins(inputPath, config)
    if origins.isEmpty then
      logger.info(
        s"python-deps=full: no site-packages or typeshed found to ingest from " +
            s"(venv dir: ${config.venvDir}); nothing to ingest"
      )
      return ()

    val t0          = System.currentTimeMillis()
    val nodesBefore = cpg.graph.nodeCount

    // Every file under every origin. Within one origin a module that ships both `.py` and
    // `.pyi` is ingested once, as the `.pyi`; across origins an earlier origin wins (the
    // project's own site-packages before the system's, site-packages before typeshed).
    // The absolute path is the cross-origin identity: the same file reached through two
    // origins (the venv root and its site-packages) is one file.
    val selected = mutable.LinkedHashMap.empty[String, ResolvedFile] // rel -> file
    val seenAbs  = mutable.HashSet.empty[Path]
    origins.foreach { origin =>
        collectOriginFiles(origin).foreach { f =>
          val abs = f.abs.toAbsolutePath.normalize
          if seenAbs.add(abs) then selected.getOrElseUpdate(f.rel, f)
        }
    }

    if selected.isEmpty then
      logger.info("python-deps=full: no .py/.pyi files found under any origin; nothing to ingest")
      return ()

    // A dependency top-level module whose package-relative name collides with a project file
    // (`app.py` at the site-packages root vs the project's own `app.py`) would duplicate every
    // full name in it and - worse - flip the project's own nodes external via the shared file
    // name. The project wins: it is what the interpreter loads first for same-named top-level
    // modules, and user attribution must never move.
    val projectFiles = cpg.file.name.l.toSet
    val ingested     = mutable.LinkedHashMap.empty[String, ResolvedFile]
    selected.foreach { case (rel, f) =>
        if !projectFiles.contains(rel) then ingested.update(rel, f)
    }
    if ingested.size != selected.size then
      logger.info(
        s"python-deps=full: skipped ${selected.size - ingested.size} dependency file(s) whose " +
            "package-relative name collides with a project file (the project's own file wins)"
      )
    if ingested.isEmpty then
      logger.info("python-deps=full: nothing left to ingest after project-file collision filter")
      return ()

    // Package identity per top-level entry: distribution name and version from `.dist-info`,
    // mapped to import names as far as `top_level.txt` allows (the full wheel-name-vs-import
    // mapping is Task 9). A directory without any `.dist-info` (vendored code, a bare checkout)
    // is ingested all the same; it just carries no purl.
    val purlsByOrigin = origins.map(o => o -> packageIndex(o)).toMap
    val purlByRel     = mutable.HashMap.empty[String, String]
    ingested.values.toSeq.foreach { f =>
      // A package maps by its directory name; a single-file module (`carrier.py`) maps by
      // its module name (`carrier`).
      val tops = Seq(f.rel.split('/').head, f.rel.split('/').head.stripSuffix(".py"))
      purlsByOrigin.get(f.origin).foreach { idx =>
          tops.iterator.flatMap(idx.get).nextOption().foreach(p => purlByRel.update(f.rel, p))
      }
    }
    val purlCounts = purlByRel.values.toSeq.groupBy(identity).view.mapValues(_.size).toMap

    val cacheRoot = Paths.get(inputPath.toString, ".chen", "pydeps")
    ingested.values.toSeq
        .groupBy(f => cacheDirForFull(f, origins, purlByRel, cacheRoot))
        .foreach { case (cacheDir, files) =>
            parseInto(
              cpg,
              files.map(f => f.rel -> f.abs),
              inputPath,
              config,
              cacheDir,
              truncate = false
            )
        }

    // Externality (attribution) without opacity: every dependency method/type decl is external,
    // and the engine still descends into their bodies because explorability is its own
    // predicate now (semanticcpg `MethodExplorability`). Type canonicalization runs as in
    // stubs mode: annotation names must land on TYPE_DECL-backed full names for recovery.
    new PythonDependencySignaturePass(
      cpg,
      ingested.keySet.toSet,
      aliasRequests = Nil,
      summaryMap = Map.empty
    ).createAndApply()

    if purlByRel.nonEmpty then
      new PythonDependencyPurlPass(cpg, purlByRel.toMap).createAndApply()

    logger.info(
      s"python-deps=full: ingested ${ingested.size} file(s) from ${origins.size} origin(s) " +
          s"(${purlByRel.size} with package identity across ${purlCounts.size} distribution(s); " +
          s"${ingested.size - purlByRel.size} without) in " +
          s"${System.currentTimeMillis() - t0}ms; graph grew ${cpg.graph.nodeCount - nodesBefore} " +
          s"nodes to ${cpg.graph.nodeCount}"
    )
  end ingestFull

  /** Every `.py`/`.pyi` under `origin.root`, as package-relative `ResolvedFile`s. Where a module
    * ships both spellings the `.pyi` wins - the stub is the API contract; for stdlib modules it is
    * also the only spelling that exists. `__pycache__`, `*.dist-info` and `*.egg-info` are skipped.
    */
  private def collectOriginFiles(origin: Origin): Seq[ResolvedFile] =
    // One bounded walk per directory level would be clumsy; Files.walk is depth-unlimited but
    // the venv trees are finite and this runs once per build (cached afterwards).
    val all = Try {
        Files.walk(origin.root).iterator().asScala.toSeq
    }.getOrElse(Nil)
    val pyFiles = all.filter { p =>
      val n = p.getFileName.toString
      Files.isRegularFile(p) && (n.endsWith(".py") || n.endsWith(".pyi"))
    }
    pyFiles
        .map(p => ResolvedFile(origin, origin.root.relativize(p).toString.replace('\\', '/'), p))
        .filterNot { f =>
            // Judged on the path BELOW the origin, never the absolute one: a PDM origin lives
            // inside `__pypackages__`, so testing the absolute path's segments against the
            // ignore list would discard every file the origin exists to contribute. Only
            // directory segments count - the file name itself is dropped first, so a module
            // named `__pycache__.py` is not mistaken for the cache directory.
            f.rel.split('/').dropRight(1).exists { s =>
                IgnoredDepDirNames.contains(s) || IgnoredDepDirSuffixes.exists(s.endsWith)
            }
        }
        .groupBy(f => f.rel.stripSuffix(".py").stripSuffix(".pyi"))
        .view
        .mapValues { files =>
            files.find(_.rel.endsWith(".pyi")).getOrElse(files.head)
        }
        .values
        .toSeq
        .sortBy(_.rel)
  end collectOriginFiles

  /** Top-level entry name -> purl, for one site-packages origin: every `*.dist-info` contributes
    * its distribution name and version; `top_level.txt` supplies the import names it provides,
    * falling back to the normalized distribution name. Overlapping claims resolve to the first
    * dist-info alphabetically (rare; a and a's stubs package both claiming `a`).
    */
  private def packageIndex(origin: Origin): Map[String, String] =
    if origin.isTypeshed then Map.empty
    else
      val distInfos = Try {
          Files.list(origin.root).iterator().asScala.toSeq
              .filter(p => p.getFileName.toString.endsWith(".dist-info"))
              .filter(Files.isDirectory(_))
              .sortBy(_.getFileName.toString)
      }.getOrElse(Nil)
      distInfos.flatMap { d =>
        val n       = d.getFileName.toString.stripSuffix(".dist-info")
        val version = n.split("-").takeRight(1).headOption.getOrElse("")
        val dist    = n.split("-").dropRight(1).mkString("-")
        if dist.isEmpty then Nil
        else
          val importNames = topLevelOf(d).filter(_.nonEmpty).distinct match
            case names @ _ :: _ => names
            case Nil            => List(dist.replace('-', '_').stripPrefix("python_"))
          importNames.map(_ -> s"pkg:pypi/$dist@$version")
      }.toMap
    end if
  end packageIndex

  /** Import names from `top_level.txt`, one per line; an empty file or a missing file is `Nil`. */
  private def topLevelOf(distInfoDir: Path): List[String] =
    val f = distInfoDir.resolve("top_level.txt")
    if !Files.isRegularFile(f) then Nil
    else
      Try(IOUtils.readLinesInFile(f).map(_.trim).filter(_.nonEmpty).toList).getOrElse(Nil)

  /** Cache directory for one full-mode file: `<pkg>-<version>` when the file's top-level entry
    * carries package identity, else the bare top-level entry - same scoping as stubs mode, so a
    * venv reinstall to a new version can never be served the old fragments.
    */
  private def cacheDirForFull(
    f: ResolvedFile,
    origins: Seq[Origin],
    purlByRel: collection.Map[String, String],
    cacheRoot: Path
  ): String =
    val top = f.rel.split('/').head
    purlByRel.get(f.rel).map { purl =>
      val nameVersion = purl.stripPrefix("pkg:pypi/").replace('/', '_')
      cacheRoot.resolve(nameVersion).toString
    }.getOrElse(cacheRoot.resolve(top).toString)

  // ---------------------------------------------------------------- externality by path

  /** Absolute dependency roots for this project: every origin `discoverOrigins` returns, plus the
    * configured venv directory itself. These are the paths externality-by-path derives from, so
    * `full`, `stubs` and `summaries` cannot disagree about where dependencies live, and an
    * out-of-tree venv is recognised exactly like an in-tree one.
    */
  def dependencyRoots(inputPath: Path, config: Py2CpgOnFileSystemConfig): Seq[Path] =
    val venv =
        if config.venvDir.isAbsolute then config.venvDir else inputPath.resolve(config.venvDir)
    (discoverOrigins(inputPath, config).map(_.root) :+ venv)
        .map(_.toAbsolutePath.normalize)
        .distinct

  /** True when `fileName` (a graph FILE name, input-relative like `.venv/lib/...` or
    * package-relative like `flask/app.py`) sits under a dependency root or under any directory
    * named like a conventional one. The file's own name never counts: `venv_utils.py` stays
    * internal.
    */
  private[pysrc2cpg] def isDependencyFile(
    fileName: String,
    inputPath: Path,
    roots: Seq[Path]
  ): Boolean =
    val normalized = fileName.replace('\\', '/')
    if normalized.isEmpty || normalized == "N/A" then return false
    val abs = inputPath.resolve(normalized).toAbsolutePath.normalize
    if roots.exists(abs.startsWith) then return true
    // Path-segment fallback for venvs the discovery missed: `.venv`, `site-packages`, ... as a
    // DIRECTORY component. The last segment is the file name and is excluded.
    val segments = normalized.split('/').dropRight(1)
    segments.exists(DependencyDirNames.contains)

  // ---------------------------------------------------------------- AST truncation

  /** Truncate every function and class body to nothing: signatures only. Module-level statements
    * are kept - imports drive re-export aliasing, and module members are how `from pkg import name`
    * resolves variables.
    */
  def truncateForSignatures(module: ast.Module): ast.Module =
    // Imports guarded by a runtime check - `if t.TYPE_CHECKING:`, the PEP 484 idiom for
    // annotation-only imports - are where libraries bind the very names their annotations
    // use (`request: Request`). The guard never fires at runtime, but the binding is what
    // makes the annotation resolvable, so an If holding nothing but imports is kept.
    def importsOnly(stmts: mutable.Seq[ast.istmt]): Boolean = stmts.forall {
        case _: ast.Import | _: ast.ImportFrom => true
        case _                                 => false
    }
    def keepIf(i: ast.If): Boolean =
        i.body.nonEmpty && importsOnly(i.body) && importsOnly(i.orelse)
    // Module level keeps what signatures need: imports (re-export aliasing and closure),
    // defs and classes (truncated). Everything else - module-level setup code, constants,
    // decorated registration calls - is dropped; it is library internals, not API surface.
    def sigStmt(stmt: ast.istmt): ast.istmt = stmt match
      case f: ast.FunctionDef      => f.copy(body = mutable.Seq.empty)
      case f: ast.AsyncFunctionDef => f.copy(body = mutable.Seq.empty)
      case c: ast.ClassDef =>
          c.copy(body = c.body.collect {
              case fd: ast.FunctionDef      => fd.copy(body = mutable.Seq.empty)
              case fd: ast.AsyncFunctionDef => fd.copy(body = mutable.Seq.empty)
              case cd: ast.ClassDef         => cd.copy(body = mutable.Seq.empty)
              // Class attributes are API surface, not internals: `class Config: DEBUG = False`
              // is what `settings.DEBUG` resolves against.
              case a: ast.Assign          => a
              case a: ast.AnnAssign       => a
              case i: ast.If if keepIf(i) => i
          })
      case other => other
    module.copy(stmts = module.stmts.collect {
        case i: ast.Import           => sigStmt(i)
        case i: ast.ImportFrom       => sigStmt(i)
        case f: ast.FunctionDef      => sigStmt(f)
        case f: ast.AsyncFunctionDef => sigStmt(f)
        case c: ast.ClassDef         => sigStmt(c)
        // Module-level bindings ARE the package's API for a large share of real imports:
        // flask's `request`/`session`/`g`, requests' `codes`, django's `settings`. Dropping
        // them left `from flask import request` resolving to nothing while the graph now
        // positively knew the package had no such member - strictly worse than not having
        // ingested the package at all. The right-hand side is kept because it is the only
        // type evidence a plain assignment carries.
        case a: ast.Assign          => a
        case a: ast.AnnAssign       => a
        case i: ast.If if keepIf(i) => i
    })
  end truncateForSignatures

  // ---------------------------------------------------------------- origins & resolution

  /** Site-packages directories of the project's venv, plus the typeshed stdlib dir when one is
    * configured. Site-packages wins over typeshed for the same module name (an installed
    * distribution is what the code really calls).
    *
    * Beyond the project venv, the real-world layouts that hold installable code: a PDM
    * `__pypackages__` tree inside the project, the current conda environment (`$CONDA_PREFIX`),
    * extra site-packages directories named by `CHEN_PYTHON_SITE_PACKAGES` (colon-separated), and
    * the conventional system site-packages locations. Project-local origins are searched first, so
    * a project venv always wins over a system-wide one for the same module.
    */
  private def discoverOrigins(inputPath: Path, config: Py2CpgOnFileSystemConfig): Seq[Origin] =
    val venv =
        if config.venvDir.isAbsolute then config.venvDir else inputPath.resolve(config.venvDir)
    val pdmBase = inputPath.resolve("__pypackages__")
    // PEP 582 / PDM: `__pypackages__/<major.minor>/lib/<pkg>`; the version directory sits
    // directly under the base (PDM also accepts `python<major.minor>` spellings).
    val pdmLibDirs =
        if Files.isDirectory(pdmBase) then
          Files.list(pdmBase).iterator().asScala.toSeq
              .filter(p =>
                val n = p.getFileName.toString
                n.startsWith("python") || n.matches("""\d+\.\d+""")
              )
              .map(_.resolve("lib"))
              .filter(Files.isDirectory(_))
              .toSeq
        else Nil

    val condaPrefix = Option(System.getenv("CONDA_PREFIX")).filter(_.nonEmpty).map(Paths.get(_))

    val candidates =
        Seq(
          venv.resolve("lib").resolve("site-packages"),
          venv.resolve("Lib").resolve("site-packages"),
          venv.resolve("site-packages")
        ) ++ pythonLibDirs(venv) ++ pdmLibDirs ++
            condaPrefix.toList.flatMap { prefix =>
                Seq(
                  prefix.resolve("lib").resolve("site-packages"),
                  prefix.resolve("Lib").resolve("site-packages")
                ) ++ pythonLibDirs(prefix)
            } ++
            systemSitePackages() ++
            extraSitePackagesFromEnv() ++
            Seq(venv)

    val sitePackages = candidates
        .filter(p => Files.isDirectory(p))
        .map(Origin(_, isTypeshed = false))
        .distinctBy(_.root.toAbsolutePath.normalize)

    val typeshedRoot = config.typeshedDir.orElse(
      Option(System.getenv(TypeshedDirEnv)).filter(_.nonEmpty).map(Paths.get(_))
    )
    val typeshed = typeshedRoot.flatMap { dir =>
      val abs    = if dir.isAbsolute then dir else inputPath.resolve(dir)
      val stdlib = abs.resolve("stdlib")
      if Files.isDirectory(stdlib) then Some(Origin(stdlib, isTypeshed = true)) else None
    }

    sitePackages ++ typeshed.toSeq
  end discoverOrigins

  /** Conventional system site-packages locations, best-effort: Homebrew and system Python on macOS,
    * Debian-style `dist-packages` and `/usr/local` on Linux. Only directories that exist are
    * returned; a machine without them pays one stat each.
    */
  private def systemSitePackages(): Seq[Path] =
    val home = Option(System.getProperty("user.home")).getOrElse("")
    val fixed = Seq(
      "/opt/homebrew/lib",
      "/usr/local/lib",
      "/usr/lib/python3/dist-packages",
      "/Library/Python"
    )
    val homeFixed = Seq(
      s"$home/Library/Python",
      s"$home/.local/lib"
    )
    (fixed ++ homeFixed).iterator.flatMap { base =>
      val p = Paths.get(base)
      if !Files.isDirectory(p) then Nil
      else
        // `/opt/homebrew/lib/python3.13/site-packages`, `~/Library/Python/3.13/lib/python/site-packages`
        def scan(depth: Int, dir: Path): Seq[Path] =
            if depth == 0 then
              Seq(dir.resolve("site-packages"), dir.resolve("dist-packages"))
                  .filter(Files.isDirectory(_))
            else
              Try {
                  Files.list(dir).iterator().asScala.toSeq
                      .filter(_.getFileName.toString.startsWith("python"))
                      .flatMap(scan(depth - 1, _))
              }.getOrElse(Nil)
        scan(2, p)
    }.toSeq
  end systemSitePackages

  /** Extra site-packages directories from `CHEN_PYTHON_SITE_PACKAGES` (colon-separated absolute
    * paths) - the escape hatch for layouts the fixed list cannot know: poetry virtualenvs, Nix
    * store paths, CI-specific locations.
    */
  private def extraSitePackagesFromEnv(): Seq[Path] =
      Option(System.getenv(ExtraSitePackagesEnv)).toSeq
          .flatMap(_.split(':').toSeq)
          .filter(_.nonEmpty)
          .map(Paths.get(_))
          .filter(Files.isDirectory(_))

  /** `lib/python3.x/site-packages` layouts: enumerate the `python*` entries of `lib/`. */
  private def pythonLibDirs(venv: Path): Seq[Path] =
    val lib = venv.resolve("lib")
    if !Files.isDirectory(lib) then Nil
    else
      Files.list(lib).iterator().asScala.toSeq
          .filter(p => p.getFileName.toString.startsWith("python"))
          .map(_.resolve("site-packages"))
          .filter(p => Files.isDirectory(p))
          .toSeq

  /** Resolve one imported entity to a module file. `entity` is the raw import lowering string:
    * absolute (`flask.app.Flask`, `os`) or relative (`.app.Flask`, `..util.x`), with the importing
    * file's rel path to anchor relative imports. Candidates in preference order: the entity as a
    * module path (`a/b/c.py`, then `a/b/c/__init__.py`), then the entity without its last segment
    * (for `from a.b import c` where `c` is a name inside `a.b`, not a submodule). Site-packages
    * wins over typeshed by origin order.
    */
  private def resolveEntity(
    importerRel: String,
    entity: String,
    origins: Seq[Origin],
    ingested: collection.Set[String]
  ): Option[ResolvedFile] =
    val dotted: Option[String] =
        if entity.startsWith(".") then
          val dots = entity.takeWhile(_ == '.').length
          val rest = entity.drop(dots).stripPrefix(".")
          // current module dotted name: `flask/app.py` -> `flask.app`; `flask/__init__.py` -> `flask`
          val noExt  = importerRel.stripSuffix(".py").stripSuffix(".pyi")
          val base   = noExt.stripSuffix("/__init__").replace('/', '.')
          val parts  = base.split('.').toSeq
          val anchor = parts.dropRight(dots - 1)
          if anchor.isEmpty then None
          else
            Some((anchor.mkString(".") +: (if rest.isEmpty then Nil else Seq(rest))).mkString("."))
        else Some(entity)

    dotted.flatMap { modulePath =>
      val candidates: Seq[String] =
        val asIs   = modulePath
        val parent = modulePath.split('.').dropRight(1).mkString(".")
        if parent.isEmpty then Seq(asIs)
        else Seq(asIs, parent)
      candidates.iterator.flatMap { mod =>
        val dirPart = mod.replace('.', '/')
        origins.iterator.flatMap { origin =>
          val extension = if origin.isTypeshed then ".pyi" else ".py"
          val options = Seq(
            s"$dirPart$extension",
            s"$dirPart/__init__$extension"
          )
          options.iterator
              .map(rel => (origin, rel))
              .collect {
                  case (o, rel) if Files.isRegularFile(o.root.resolve(rel)) =>
                      ResolvedFile(o, rel, o.root.resolve(rel))
              }
        }.nextOption()
      }.filter(f => !ingested.contains(f.rel))
          .nextOption()
    }
  end resolveEntity
  // ---------------------------------------------------------------- import roots

  /** Top-level module names imported by the files in scope. Round one reads the PROJECT's own
    * imports; later rounds read the imports of the already-ingested dependency files for transitive
    * closure. Imports are read from the raw `import(...)` call lowering because the IMPORT nodes do
    * not exist until the frontend's ImportsPass runs after `createCpg`.
    */
  private def dependencyEntities(
    cpg: Cpg,
    ingested: collection.Set[String],
    fromIngestedFiles: Boolean
  ): Seq[(String, String)] =
      cpg.call.nameExact("import").iterator.flatMap { call =>
        val fileName = call.file.name.headOption.getOrElse("")
        val inScope  = ingested.contains(fileName) == fromIngestedFiles
        if !inScope then Iterator.empty
        else
          val literals: List[String] =
              call.argument.l.sortBy(_.argumentIndex).collect { case l: Literal => l.code }
          val entity = literals match
            case "" :: what :: _    => Some(what)
            case where :: what :: _ => Some(s"$where.$what")
            case _                  => None
          entity
              .filter(_.nonEmpty)
              .map(fileName -> _)
      }.toSeq
  end dependencyEntities

  // ---------------------------------------------------------------- parsing

  /** Parse dependency `files` (rel -> abs) into `target` via the production pipeline. The rel file
    * name (package-relative) is what makes every produced full name joinable: the import resolver
    * generates `requests/__init__.py:<module>...` candidates for `import requests`.
    */
  private def parseInto(
    target: Cpg,
    files: Seq[(String, Path)],
    inputPath: Path,
    config: Py2CpgOnFileSystemConfig,
    cacheDir: String,
    truncate: Boolean
  ): Unit = parseInto(
    target,
    files,
    inputPath,
    config,
    cacheDir,
    truncate,
    if truncate then CacheFingerprint else FullCacheFingerprint
  )

  private def parseInto(
    target: Cpg,
    files: Seq[(String, Path)],
    inputPath: Path,
    config: Py2CpgOnFileSystemConfig,
    cacheDir: String,
    truncate: Boolean,
    cacheFingerprint: String
  ): Unit =
    if files.isEmpty then return ()
    val providers = files.map { case (rel, abs) =>
        () => Py2Cpg.InputPair(IOUtils.readLinesInFile(abs).mkString("\n"), rel)
    }
    val moduleNames: Map[String, String] =
        files.view.map(_._1).flatMap { rel =>
            PythonModuleName.moduleFor(files.map(_._1).toSet, rel).map(rel -> _)
        }.toMap

    // AstCacheStore self-disables when the cache directory's parent does not exist, so the
    // `.chen/pydeps` root has to be materialised before the store is constructed. The cache is
    // enabled for BOTH modes: a venv is immutable between installs, so full-mode fragments are
    // exactly as reusable as signature fragments (the fingerprint keeps them disjoint).
    if cacheDir.nonEmpty then Files.createDirectories(Paths.get(cacheDir).getParent)
    val codeToCpg = new CodeToCpg(
      target,
      providers,
      config.schemaValidation,
      inputPath.toString,
      enableAstCache = cacheDir.nonEmpty && CacheControl.isEnabled(CacheControl.Ast),
      cacheDir = cacheDir,
      strictParse = config.strictParse,
      moduleNames = moduleNames,
      transformAst = if truncate then truncateForSignatures else identity,
      extraCacheFingerprint = cacheFingerprint
    )
    codeToCpg.createAndApply()
    val parseErrors = codeToCpg.getParseErrors
    if parseErrors.nonEmpty then
      logger.info(
        s"python-deps: ${parseErrors.size} statements failed to parse " +
            "(signatures from those statements are missing)"
      )
  end parseInto

  // ---------------------------------------------------------------- aliases

  /** For every ingested PACKAGE, read the re-export imports of its `__init__.py` and plan aliases
    * for both import spellings. Targets are resolved in the signature pass, against the full names
    * that actually exist in the graph.
    */
  private def planAliases(
    cpg: Cpg,
    pkgNames: Seq[String],
    ingested: collection.Set[String]
  ): Seq[AliasRequest] =
      pkgNames.flatMap { pkgName =>
        val initRel = s"$pkgName/__init__.py"
        if !ingested.contains(initRel) then Nil
        else
          importsOf(cpg, initRel).map { imp =>
              AliasRequest(pkgName, imp.alias, resolveModuleRel(pkgName, imp), imp.what)
          }
      }
  end planAliases

  /** Raw imports of one ingested file, read from the `import(...)` call lowering. */
  private[pysrc2cpg] def importsOf(cpg: Cpg, relPath: String): Seq[DepImport] =
      cpg.call.nameExact("import").iterator.filter { call =>
          call.file.name.headOption.exists(_ == relPath)
      }.flatMap(depImportOf).toSeq

  /** Every `import(...)` call of the graph grouped by the file that holds it - the same reduction
    * [[importsOf]] performs for ONE file, done once for all of them. A caller that needs the answer
    * per file for many files (the re-export chain walk) turns an O(imports) full-graph scan per
    * question into a map lookup.
    */
  private[pysrc2cpg] def importsByFile(cpg: Cpg): Map[String, Seq[DepImport]] =
      cpg.call.nameExact("import").iterator.toSeq
          .groupBy(_.file.name.headOption.getOrElse(""))
          .view.mapValues(_.flatMap(depImportOf)).toMap

  /** The one place an `import(...)` call's literal arguments become a [[DepImport]]. Shared by the
    * single-file and the indexed readers: two copies of this destructuring would drift, and the
    * symptom of drift is a resolver that silently disagrees with itself about what a file imports
    * depending on which accessor it happened to use.
    */
  private def depImportOf(call: Call): Option[DepImport] =
      call.argument.l.sortBy(_.argumentIndex).collect { case l: Literal => l.code } match
        case where :: what :: alias :: _ => Some(DepImport(where, what, alias))
        case where :: what :: Nil        => Some(DepImport(where, what, what))
        case _                           => None
  end depImportOf

  /** Module path (slash-separated) that `imp` refers to, as seen from `pkgName/__init__.py`.
    * Level-1 relative imports stay inside the package; deeper levels escape one level each.
    */
  private[pysrc2cpg] def resolveModuleRel(pkgName: String, imp: DepImport): String =
    val dots = imp.where.takeWhile(_ == '.').length
    val rest = imp.where.drop(dots).stripPrefix(".").replace('.', '/')
    if dots > 0 then
      val base = pkgName.split('/').dropRight(dots - 1).mkString("/")
      if rest.isEmpty then base else s"$base/$rest"
    else if rest.isEmpty then pkgName
    else rest

  // ---------------------------------------------------------------- summaries

  /** Flow summaries for the dependency methods, computed WITHOUT ever putting bodies into the real
    * graph: the same files are re-parsed untruncated into a throwaway graph, the data-flow layer
    * runs over it once, and the summaries are extracted by full name. The throwaway graph holds
    * nothing but dependency code, so `computeAll` (internal methods only) is exactly the dependency
    * scope.
    */
  private def computeSummariesViaThrowawayGraph(
    ingested: mutable.LinkedHashMap[String, Path],
    inputPath: Path,
    config: Py2CpgOnFileSystemConfig
  ): Map[String, MethodFlowSummary] =
    if ingested.isEmpty then return Map.empty
    val tempPath = Files.createTempFile("chen-pydeps-", ".odb")
    try
        X2Cpg.withNewEmptyCpg(tempPath.toString, config) { (tempCpg, _) =>
          // Seed the graph the way Py2Cpg does (meta data, global namespace): the data-flow
          // layer refuses to run without it.
          new Py2Cpg(
            Iterable.empty,
            tempCpg,
            inputPath.toString,
            "requirements.txt",
            config.schemaValidation
          ).buildCpg()
          parseInto(
            tempCpg,
            ingested.toSeq,
            inputPath,
            config,
            cacheDir = "",
            truncate = false
          )
          // The same overlay chain the fixture and atom run: base/CF/type/callgraph layers
          // (MethodRefLinker satisfies the METHOD_REF REF schema obligation) plus the
          // data-flow layer that produces the REACHING_DEF edges summaries are built from.
          X2Cpg.applyDefaultOverlays(tempCpg)
          new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(tempCpg))
        } match
          case Success(tempCpg) =>
              try dropUnsummarisable(
                    tempCpg,
                    FlowSummaryComputer.computeAll(
                      tempCpg,
                      DefaultSemantics()
                    )
                  )
              finally tempCpg.close()
          case Failure(ex) =>
              logger.warn("python-deps: flow summary computation failed; continuing without", ex)
              Map.empty
    finally
        Files.deleteIfExists(tempPath)
    end try
  end computeSummariesViaThrowawayGraph

  /** Drop the summaries whose method the data-dependence graph cannot honestly describe, so those
    * calls keep the engine's permissive default instead of gaining a semantic that under-reports.
    *
    * A summary becomes a declared flow semantic downstream, and a declared semantic is
    * authoritative: an argument it does not mention is treated as sanitized. That is the point -
    * but it makes the summary of a method whose real behaviour is not visible in its own
    * `REACHING_DEF` edges actively harmful. The case that matters in practice is the closure:
    *
    * {{{
    * def route(self, rule, **options):     # `rule` reaches no return statement here...
    *     def decorator(f):
    *         f.rule = rule                 # ...it is captured by the nested function instead
    *         return f
    *     return decorator
    * }}}
    *
    * `rule` reaches the return only through a nested METHOD, which is a separate method in the CPG
    * and therefore outside this method's intra-procedural reach. Summarising it as inert would
    * silently cut every flow through a decorator factory - and decorator factories are how half of
    * the Python web frameworks are written. A method that defines a nested function, or hands one
    * out as a value, is therefore left unsummarised.
    *
    * The check runs here, against the throwaway graph, because it is the only place the bodies
    * still exist: by the time the tags are read back the dependency methods are bodyless.
    */
  private def dropUnsummarisable(
    tempCpg: Cpg,
    summaries: Map[String, MethodFlowSummary]
  ): Map[String, MethodFlowSummary] =
    val closureCarrying = tempCpg.method.filter { m =>
        m.ast.isMethodRef.nonEmpty || m.astChildren.isBlock.astChildren.isMethod.nonEmpty
    }.fullName.toSet
    val kept = summaries -- closureCarrying
    if kept.size != summaries.size then
      logger.info(
        s"python-deps: ${summaries.size - kept.size} of ${summaries.size} dependency summaries " +
            "describe methods that define or return a nested function; those calls keep the " +
            "engine's permissive default rather than gaining an under-reporting semantic"
      )
    kept
  // ---------------------------------------------------------------- type bindings

  /** The full-name candidate for one (module, short-name) pair in dotted form: `mod.Name`.
    */
  private def typeNameCandidates(targetModuleDotted: String, shortName: String): Seq[String] =
      Seq(s"$targetModuleDotted.$shortName")
  end typeNameCandidates

  /** Bare annotation name -> full name, for the types an ingested file can honestly name.
    *
    * Two sources: the file's own import statements (`from .wrappers import Request` binds
    * `Request`), and type decls defined in the file itself. A binding is kept only when a TYPE_DECL
    * with that full name actually exists in the graph, so canonicalization can never invent a type
    * that no TYPE node backs.
    */
  private[pysrc2cpg] def typeBindingsOfFile(cpg: Cpg, rel: String): Map[String, String] =
    val bindings = mutable.LinkedHashMap.empty[String, String]

    def bind(name: String, targetModuleDotted: String, symbol: String): Unit =
        if name.nonEmpty && !bindings.contains(name) then
          typeNameCandidates(targetModuleDotted, symbol)
              .find(c => cpg.typeDecl.fullNameExact(c).nonEmpty)
              .foreach(full => bindings.update(name, full))
    end bind

    // Types defined in the file itself bind first: an import sits at the top of the file, so a
    // class statement after it re-binds the name in real Python, and only TYPE_DECLs defined
    // here carry the file's own meaning for the name.
    cpg.typeDecl
        .filenameExact(rel)
        .filter(_.name != ModuleScope)
        .foreach(td => bindings.update(td.name, td.fullName))
    // `from a.b import C as D` lowers to `import(a.b, C, D)` literals; the importing file's
    // rel path anchors relative imports at its own package (one package level per extra dot).
    val noExt = rel.stripSuffix(".py").stripSuffix(".pyi")
    val base  = noExt.stripSuffix("/__init__")
    val pkgDir =
        if noExt.endsWith("/__init__") || noExt == "__init__" then
          // An `__init__.py` IS its package.
          base.replace('/', '.')
        else base.split('/').dropRight(1).mkString(".")
    importsOf(cpg, rel).foreach { imp =>
      val where = imp.where match
        case w if w.startsWith(".") =>
            val dots  = w.takeWhile(_ == '.').length
            val rest  = w.drop(dots).replace('/', '.')
            val parts = pkgDir.split('.').toSeq
            val anchor =
                if dots <= 1 then pkgDir
                else parts.dropRight(dots - 1).mkString(".")
            if anchor.isEmpty then ""
            else if rest.isEmpty then anchor
            else s"$anchor.$rest"
        case w => w
      bind(imp.alias, where, imp.what)
    }
    bindings.toMap
  end typeBindingsOfFile

  /** The name both the module METHOD and its TYPE_DECL twin carry; the marker that distinguishes a
    * module's own scope from a class defined inside it.
    */
  private[pysrc2cpg] val ModuleScope = "<module>"
end PythonDependencyStubs

/** Marks the freshly ingested dependency signatures external and creates the re-export aliases. No
  * node is ever deleted here - bodies were truncated before conversion - so the pass only flips
  * properties on live nodes and adds alias stubs.
  */
class PythonDependencySignaturePass(
  cpg: Cpg,
  ingestedRelPaths: Set[String],
  aliasRequests: Seq[PythonDependencyStubs.AliasRequest],
  summaryMap: Map[String, MethodFlowSummary]
) extends CpgPass(cpg):

  private val ModuleScope    = PythonDependencyStubs.ModuleScope
  private val AnyType        = Constants.ANY
  private val AliasBaseOrder = 100000 // kept children use small orders; aliases go last

  /** Aliases created during THIS pass (the diff is not applied yet, so the cpg traversals cannot
    * see them) - the guard that keeps a duplicate import line from creating a duplicate stub.
    */
  private val createdAliases = mutable.Set.empty[String]
  private val skeletons      = mutable.Map.empty[String, NewBlock]

  /** Per-file bare-type-name bindings of the ingested files, computed on demand: the dependency
    * graph's MEMBER types and the alias copies are written from the parser's bare annotation names
    * (`request: Request` -> `Request`), and only a canonical full name that a TYPE_DECL in this
    * graph actually backs lets downstream member/call resolution work.
    */
  private val bindingsCache = mutable.HashMap.empty[String, Map[String, String]]

  private def bindingsFor(rel: String): Map[String, String] =
      bindingsCache.getOrElseUpdate(
        rel,
        PythonDependencyStubs.typeBindingsOfFile(cpg, rel)
      )

  /** The canonical full name for a bare annotation-derived type under `rel`'s imports, or the input
    * unchanged when no binding backs it.
    *
    * No separate "is this a bare name" test is needed: every binding KEY is a short name a Python
    * `class` statement or import alias introduced, so an already-canonical full name simply is not
    * in the map. The map lookup is the predicate.
    */
  private def canonicalizeType(rel: String, t: String): String =
      if t == AnyType then t else bindingsFor(rel).getOrElse(t, t)

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val depMethods   = cpg.method.filenameExact(ingestedRelPaths.toSeq*).l
    val depTypeDecls = cpg.typeDecl.filenameExact(ingestedRelPaths.toSeq*).l

    // Summary tags attach to the METHOD nodes and serialize with the atom, which is what
    // makes `summaries` mode consumable by ReachableSlicing.
    summaryMap.foreach { case (fullName, summary) =>
        cpg.method.fullNameExact(fullName).newTagNodePair(FlowSummaryTags.TagName, summary.encode)
            .store()(using dstGraph)
    }

    depMethods.foreach(m => dstGraph.setNodeProperty(m, PropertyNames.IS_EXTERNAL, true))
    depTypeDecls.foreach(td => dstGraph.setNodeProperty(td, PropertyNames.IS_EXTERNAL, true))

    // One query for EVERY untyped member of the ingested files, grouped by file. Under
    // `stubs` the per-file member query was cheap enough; under `full` it becomes one
    // unindexed member scan per file - thousands of files times millions of members - so the
    // scan is hoisted here and run exactly once.
    val anyMembersByFile = cpg.member
        .typeFullNameExact(AnyType)
        .filter(m => ingestedRelPaths.contains(nodeFilename(m)))
        .l
        .groupBy(nodeFilename)

    canonicalizeAnnotationTypes(depMethods, anyMembersByFile, dstGraph)

    createAliases(dstGraph)
  end run

  // ---------------------------------------------------------------- type canonicalization

  /** Turn the bare annotation names of an ingested file (`request: Flask`, `config: Config`) into
    * TYPE_DECL-backed full names.
    *
    * The parser writes an annotated assignment's hint onto the assignment TARGET IDENTIFIER and
    * creates the MEMBER nodes with `typeFullName = ANY`; the bare names reach the members only
    * later, through the recovery, and reach the user's `from flask import request` the same
    * indirect way. Canonicalizing the identifiers here - before any recovery runs - makes both
    * paths agree: the dep-file recovery persists the canonical name onto the member, and the user
    * file's import reads it back. Only names a TYPE_DECL in this graph backs are rewritten.
    */
  private def canonicalizeAnnotationTypes(
    depMethods: Seq[Method],
    anyMembersByFile: Map[String, Seq[Member]],
    dstGraph: DiffGraphBuilder
  ): Unit =
      depMethods.groupBy(_.filename).foreach { case (rel, methodsOfFile) =>
          if bindingsFor(rel).nonEmpty then
            // Read each node's bare type ONCE, up front. `dstGraph` is a pending diff - the
            // property reads below still see the pre-rewrite value - so re-reading a node after
            // queueing its rewrite would quietly start returning the old name for a new reason.
            // Carrying (node, name, canonical) removes the dependency on that ordering.
            def rewrite(n: StoredNode): Option[(StoredNode, String, String)] =
              val bare = n.property(PropertyNames.TYPE_FULL_NAME, AnyType)
              val full = canonicalizeType(rel, bare)
              Option.when(full != bare)((n, n.property(PropertyNames.NAME, ""), full))

            // Annotated assignment targets and their LOCALs carry the bare hint from the parser
            // (`request: Request`); anything else (`__builtin.str` from a literal value) is not a
            // binding key and stays untouched. Declared parameter and return types get the same
            // treatment - they are what a consumer reads at a call or a property load, and a bare
            // local class name (`-> MultiDict`) is exactly as unusable as a bare member
            // annotation. The later type-hint pass only refines these through file imports, so a
            // canonical name written here survives.
            val annotated = methodsOfFile.ast.flatMap {
                case i: Identifier => rewrite(i)
                case l: Local      => rewrite(l)
                case _             => None
            }.l
            val declared =
                methodsOfFile.flatMap(m => m.methodReturn +: m.parameter.l).flatMap(rewrite)

            (annotated ++ declared).foreach { case (n, _, full) =>
                dstGraph.setNodeProperty(n, PropertyNames.TYPE_FULL_NAME, full)
            }

            // Untyped members whose name an annotated assignment in this file declares inherit
            // the same canonical name (`request: Flask` types the MEMBER `request` with the full
            // name of `Flask`), so a user import can read them without racing the dep-file's own
            // recovery. A name annotated with two different types is ambiguous and stays untyped.
            val nameToCanonical = annotated
                .groupMap(_._2)(_._3)
                .collect { case (name, full +: rest) if rest.forall(_ == full) => name -> full }
            if nameToCanonical.nonEmpty then
              anyMembersByFile.getOrElse(rel, Nil).foreach { m =>
                  nameToCanonical.get(m.name).foreach { full =>
                      dstGraph.setNodeProperty(m, PropertyNames.TYPE_FULL_NAME, full)
                  }
              }
          end if
      }
  end canonicalizeAnnotationTypes

  // ---------------------------------------------------------------- aliases

  /** Create alias nodes for both import spellings. `from pkg import x` joins
    * `pkg/__init__.py:<module>.x` and `pkg.py:<module>.x`; `import pkg` joins the module type decls
    * themselves. An alias is created only where neither spelling already defines the symbol - a
    * real `__init__.py` definition must never gain a duplicate stub.
    */
  private def createAliases(dstGraph: DiffGraphBuilder): Unit =
      aliasRequests.foreach { req =>
        // Dotted names: the package's module scope is `pkg` (its `__init__.py` contributes
        // the directory), and the two file spellings of a target module (`pkg/x.py` and
        // `pkg/x/__init__.py`) are ONE dotted name - so there is a single base and a single
        // target spelling, where the file form needed two of each.
        val base         = req.pkgName.replace('/', '.')
        val dottedTarget = req.targetModuleRel.replace('/', '.')
        val target = Seq(
          cpg.method.fullNameExact(s"$dottedTarget.${req.targetSymbol}").headOption,
          cpg.typeDecl.fullNameExact(s"$dottedTarget.${req.targetSymbol}").headOption
        ).flatten.find(n => ingestedRelPaths.contains(nodeFilename(n)))
        target.foreach {
            case tm: Method =>
                createMethodAlias(tm, req.localName, s"$base.${req.localName}", base, dstGraph)
            case tt: TypeDecl =>
                createTypeAlias(tt, req.localName, s"$base.${req.localName}", base, dstGraph)
            case _ => ()
        }
      }
  end createAliases

  private def nodeFilename(n: AstNode): String = n match
    case m: Method   => m.filename
    case t: TypeDecl => t.filename
    case m: Member   => m.typeDecl.filename
    case _           => ""

  /** The AST parent for aliases: the package's own `<module>` block. In dotted form there is only
    * one spelling - the package's module method is named by the dotted package itself - so the
    * synthesised `pkg.py` skeleton machinery of the file form is gone.
    */
  private def aliasParentBlock(
    spellingBase: String,
    dstGraph: DiffGraphBuilder
  ): Option[NodeOrDetachedNode] =
      cpg.method.fullNameExact(spellingBase).headOption.flatMap(m => Option(m.block))

  /** Alias a method signature (module-level function re-export): METHOD + parameters + return +
    * type decl twin + binding, all external, plus the source method's flow summary.
    */
  private def createMethodAlias(
    target: Method,
    aliasName: String,
    aliasFullName: String,
    spellingBase: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
      if !createdAliases.contains(aliasFullName) &&
        cpg.method.fullNameExact(aliasFullName).isEmpty
      then
        // Claim the name only once a parent actually exists: marking it claimed first would
        // let a failed lookup permanently suppress a later, resolvable request for the same
        // symbol.
        aliasParentBlock(spellingBase, dstGraph).foreach { parent =>
          createdAliases += aliasFullName
          val rel = spellingBase.stripSuffix(s":$ModuleScope")
          val method = NewMethod()
              .name(aliasName).fullName(aliasFullName).filename(rel).isExternal(true)
              .order(AliasBaseOrder)
              .lineNumber(target.lineNumber.fold(1)(_.intValue))
              .columnNumber(target.columnNumber.fold(1)(_.intValue))
          dstGraph.addNode(method)
          dstGraph.addEdge(parent, method, EdgeTypes.AST)

          val block = NewBlock().code("").typeFullName(AnyType).order(1)
              .lineNumber(1).columnNumber(1)
          dstGraph.addNode(block)
          dstGraph.addEdge(method, block, EdgeTypes.AST)

          // The copy happens BEFORE the later type-hint canonicalization can see the alias:
          // the alias's synthetic file has no imports of its own, so the bare annotation name
          // the target declares (`-> BaseResponse`) would survive as-is. Resolve it against the
          // TARGET file's import bindings now.
          val mReturn = NewMethodReturn()
              .typeFullName(canonicalizeType(target.filename, target.methodReturn.typeFullName))
              .evaluationStrategy(EvaluationStrategies.BY_SHARING)
              .lineNumber(1).columnNumber(1)
          dstGraph.addNode(mReturn)
          dstGraph.addEdge(method, mReturn, EdgeTypes.AST)

          target.parameter.l.foreach { p =>
            val np = NewMethodParameterIn()
                .name(p.name).code(p.code)
                .evaluationStrategy(EvaluationStrategies.BY_SHARING)
                .typeFullName(canonicalizeType(target.filename, p.typeFullName))
                .isVariadic(p.isVariadic)
                .index(p.index)
                .lineNumber(1).columnNumber(1)
            dstGraph.addNode(np)
            dstGraph.addEdge(method, np, EdgeTypes.AST)
          }

          val td = NewTypeDecl()
              .name(aliasName).fullName(aliasFullName).filename(rel).isExternal(true)
              .inheritsFromTypeFullName(Seq(AnyType)).order(AliasBaseOrder)
              .lineNumber(1).columnNumber(1)
          dstGraph.addNode(td)
          dstGraph.addEdge(parent, td, EdgeTypes.AST)
          val binding = NewBinding().name("").signature("")
          dstGraph.addNode(binding)
          dstGraph.addEdge(td, binding, EdgeTypes.BINDS)
          dstGraph.addEdge(binding, method, EdgeTypes.REF)

          summaryMap.get(target.fullName).foreach(s => tagNode(method, s.encode, dstGraph))
        }
  end createMethodAlias

  /** Alias a type decl (class re-export, or a module-object import): external TYPE_DECL with the
    * target's inheritance. A class alias also exposes its `__init__`, because importing a
    * constructor makes the resolver look for `<alias>.__init__`.
    */
  private def createTypeAlias(
    target: TypeDecl,
    aliasName: String,
    aliasFullName: String,
    spellingBase: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
      if !createdAliases.contains(aliasFullName) &&
        cpg.typeDecl.fullNameExact(aliasFullName).isEmpty &&
        cpg.method.fullNameExact(aliasFullName).isEmpty
      then
        aliasParentBlock(spellingBase, dstGraph).foreach { parent =>
          createdAliases += aliasFullName
          val rel = spellingBase.stripSuffix(s":$ModuleScope")
          val td = NewTypeDecl()
              .name(aliasName).fullName(aliasFullName).filename(rel).isExternal(true)
              .inheritsFromTypeFullName(
                target.inheritsFromTypeFullName.map(canonicalizeType(target.filename, _))
              )
              .order(AliasBaseOrder)
              .lineNumber(target.lineNumber.fold(1)(_.intValue))
              .columnNumber(target.columnNumber.fold(1)(_.intValue))
          dstGraph.addNode(td)
          dstGraph.addEdge(parent, td, EdgeTypes.AST)

          cpg.method.fullNameExact(s"${target.fullName}.__init__").headOption.foreach { init =>
              createMethodAlias(
                init,
                "__init__",
                s"$aliasFullName.__init__",
                spellingBase,
                dstGraph
              )
          }
        }
  end createTypeAlias

  /** Attach a `flow-summary` tag to a NEWLY created method node (the stored-node path used by
    * [[FlowSummaryTagsPass]] cannot run here - the method is not in the graph yet).
    */
  private def tagNode(
    method: NewMethod,
    encodedSummary: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
    val tag = NewTag().name(FlowSummaryTags.TagName).value(encodedSummary)
    dstGraph.addNode(tag)
    dstGraph.addEdge(method, tag, EdgeTypes.TAGGED_BY)
end PythonDependencySignaturePass

/** Package identity for ingested dependency code: `pkg:pypi/<distribution>@<version>` tags on every
  * METHOD of each file, derived from the adjacent `.dist-info` and mapped to import names as far as
  * `top_level.txt` allows. This is the form the existing machinery already consumes - `CdxPass`
  * writes such tags on methods from an SBOM, and reachables/slicing collect them for attribution -
  * so a flow through a library can name the package and version it passed through without any
  * consumer changing. (TYPE_DECL is not a taggable node type; method tags are what call resolution
  * and parameter attribution read.)
  */
class PythonDependencyPurlPass(cpg: Cpg, purlByRel: Map[String, String]) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
      purlByRel.toSeq
          .groupBy { case (_, purl) => purl }
          .view
          .mapValues(_.map { case (rel, _) => rel })
          .foreach { case (purl, rels) =>
              cpg.method.filenameExact(rels*).newTagNode(purl).store()(using dstGraph)
          }

/** Externality is by path, everywhere: any method or type decl whose enclosing FILE sits under a
  * recognised dependency root becomes `isExternal = true` - regardless of mode. This is an
  * attribution fix only; whether the engine may descend into a method is explorability (semanticcpg
  * `MethodExplorability`), a separate notion, so marking one external never makes it opaque.
  *
  * The near-miss is the point as much as the hit: a project file named `venv_utils.py` stays
  * internal (only directory segments are matched), and a dependency method marked here remains
  * fully traversable.
  *
  * `archiveDependencyRels` names files unpacked from in-tree distribution archives (task 12 A.5):
  * those live in a per-run temp directory no path-prefix rule can know, so they are attributed by
  * their package-relative name directly.
  */
class PythonDependencyExternalityPass(
  cpg: Cpg,
  inputPath: Path,
  roots: Seq[Path],
  archiveDependencyRels: Set[String] = Set.empty
) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    // The decision is a property of the FILE, and full mode puts millions of methods into a few
    // thousand files. Deciding once per distinct file name - rather than resolving and
    // normalizing a Path per method - makes the pass proportional to the file count.
    val depFiles = cpg.file.name.toSet
        .filter(fileName =>
            archiveDependencyRels.contains(fileName) ||
                PythonDependencyStubs.isDependencyFile(fileName, inputPath, roots)
        )
    if depFiles.isEmpty then return ()
    cpg.method.filter { m =>
        !m.isExternal && depFiles.contains(m.filename)
    }.foreach(m => dstGraph.setNodeProperty(m, PropertyNames.IS_EXTERNAL, true))
    cpg.typeDecl.filter { td =>
        !td.isExternal && depFiles.contains(td.filename)
    }.foreach(td => dstGraph.setNodeProperty(td, PropertyNames.IS_EXTERNAL, true))
end PythonDependencyExternalityPass
