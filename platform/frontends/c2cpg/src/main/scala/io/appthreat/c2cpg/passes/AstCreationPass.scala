package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{
    CdtLogging,
    CdtParser,
    FileDefaults,
    HeaderFromOwner,
    ProjectSources
}
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.worker.{CdtWorker, CdtWorkerPool}
import io.appthreat.x2cpg.{AstCache, AstFragment, SourceFiles}
import io.appthreat.x2cpg.parse.{ParseReporter, UnitSettingsReporter}
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import io.appthreat.x2cpg.passes.frontend.CacheControl
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.StreamingCpgPass
import org.eclipse.cdt.core.dom.ast.IASTTranslationUnit
import org.slf4j.LoggerFactory
import upickle.default.readBinary

import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.*
import scala.concurrent.duration.*
import scala.util.Try

object AstCreationPass:
  // The parse pool exists only to give each parse a cancellable thread for the timeout below.
  // Concurrency (and therefore peak memory) is already bounded upstream by StreamingCpgPass's
  // producer semaphore (~0.7 * cores). Sizing this pool ABOVE that bound is essential: if it is
  // smaller, admitted files queue here while their `future.get(timeout)` clock is already running,
  // so a fast file can "time out" purely from waiting behind a couple of slow headers. Sizing to
  // the full core count guarantees a submitted parse starts immediately, so the timeout measures
  // real parse time rather than queue wait.
  private val maxConcurrentParsers = Math.max(4, Runtime.getRuntime.availableProcessors())

  /** Per-file parse/AST timeout. Defaults to 2 minutes; override via `CHEN_CDT_TIMEOUT` (seconds)
    * for projects with pathologically heavy translation units (e.g. template-heavy SDK headers).
    */
  private[c2cpg] val parseTimeout: FiniteDuration =
      sys.env.get("CHEN_CDT_TIMEOUT").flatMap(s => Try(s.trim.toInt).toOption).filter(_ > 0) match
        case Some(seconds) => seconds.seconds
        case None          => 2.minutes

  /** When `CHEN_CDT_DEBUG` is set, log the parse duration of any file that takes over a second.
    * Useful for pinpointing pathological headers / include-resolution blow-ups.
    */
  private[passes] val debugTiming: Boolean =
      sys.env.get("CHEN_CDT_DEBUG").exists(v => v == "1" || v.equalsIgnoreCase("true"))

  /** The set of source/header files the AST pass would process, in the same order. Shared with the
    * warm-restore path so it keys exactly the same parts.
    */
  def sourceFiles(config: Config): Array[String] = new ProjectSources(config).files

  /** The file system's own spelling of `path`: its real path when the file system answers, the
    * normalized absolute path otherwise. The preprocessor registers included content under real
    * paths (see [[CustomFileContentProvider]]), so a root that file names are relativized against
    * must be spelled the same way.
    */
  private[passes] def realPath(path: String): String =
      Try(Paths.get(path).toRealPath()).getOrElse(Paths.get(path).toAbsolutePath.normalize)
          .toString

  /** Bump whenever AST creation changes what it emits for unchanged source: a cached AST from an
    * older frontend is otherwise replayed as-is (a fragment cached before call-site `fn-attr` tags
    * existed would make a warm run silently lose every header attribute).
    */
  // 3: member layouts of header-defined types ride the used types
  // 4: C++ implicit calls linked to their METHODs, operator calls typed; sizeof-family operators
  //    and catch handlers in their own shapes
  // 5: destructors at scope exits, constructed objects assigned, condition declarations, C++20
  //    module units, header language from includers, compiler-predefined macros
  // 6: includes tagged with the file they resolved to and whether they name a system header, and
  //    calls with the header that declares their function
  // 7: designated initializers assign into the initialised object
  // 8: tags follow macro copies, constant expressions carry their value, host type sizes
  // 9: pointer arithmetic tagged, `i[a]` written as `a[i]`
  // 10: header struct layouts recorded with their defining header; array typedefs recorded
  // 11: macro invocations indexed and their arguments found by location and marked as copies;
  //     image locations on by default; a local declared outside a macro keeps its place
  // 12: a pointer-to-function parameter is named after its nested declarator; a function the
  //     file only declares is a METHOD_REF where its name is a value
  // 13: identifiers that read a header's global or enumerator, member calls, constructors and
  //     field accesses carry their declaring header; macro invocations name the macros nested in
  //     them
  // 14: a macro invocation's call carries its definition whatever the macro is named (NULL
  //     kept a bare name before)
  // 15: the GCC cleanup attribute on a local emits the call of its function at every scope exit
  // 16: an include in a branch the preprocessor skipped is tagged inactive, and a cleanup call's
  //     argument refers to the variable its declarator declared
  // 17: a template definition's METHOD is tagged template-pattern, a call of an instance is tagged
  //     template-args, and a dependent call lists the METHODs it reaches in the unit's instances;
  //     a header that cannot be parsed as a unit of its own is taken from its includer's parse
  private val AstFormatVersion = "c2cpg-ast-17"

  /** Everything outside a file that shapes its AST and is known up front: the frontend's output
    * format, the parser options (function bodies, inactive code, comments, image locations, trivial
    * expressions, the C++ standard, include discovery, the project index), the include paths a
    * header is resolved through, the defines that gate it, and the macro and include files every
    * file is preprocessed with. (A header's own content is not covered.)
    *
    * The parser options matter because one project directory serves several modes: atom's header
    * mode parses without function bodies, and a later full run must not replay those body-less
    * ASTs.
    */
  def cacheFingerprint(config: Config): String =
    // a macro or include file changes what every file preprocesses to: its path AND content
    // key the cache, or editing a `--macro-files` header replays the ASTs parsed without it
    def contentOf(kind: String)(p: String): String =
      val crc = new java.util.zip.CRC32()
      Try(Files.readAllBytes(Paths.get(p))).foreach(b => crc.update(b))
      s"$kind:$p:${crc.getValue}"
    val parserOptions = Seq(
      s"bodies=${config.includeFunctionBodies}",
      s"inactive=${config.parseInactiveCode}",
      s"comments=${config.includeComments}",
      s"imageLocations=${config.includeImageLocations}",
      s"trivial=${config.includeTrivialExpressions}",
      s"std=${config.cppStandard}",
      s"discovery=${config.includePathsAutoDiscovery}",
      s"externalPaths=${config.externalPaths}",
      s"index=${config.useProjectIndex}"
    )
    (AstFormatVersion +: (parserOptions ++ config.includePaths.toList.sorted ++
        config.defines.toList.sorted ++ config.macroFiles.toList.sorted.map(contentOf("macro")) ++
        config.includeFiles.toList.sorted.map(contentOf("include"))))
        .mkString("\u0000")
  end cacheFingerprint

  /** The cache fingerprint of one file: the run's, how the file itself is parsed (its language,
    * macros, include path and forced includes, which a compilation database sets per file), and for
    * a header the content of the unit whose parse the header may be read out of.
    */
  def fileFingerprint(config: Config, sources: ProjectSources, filename: String): String =
    val path      = Paths.get(filename)
    val ownerTerm = sources.ownerFingerprint(path)
    (Seq(cacheFingerprint(config), sources.settingsFor(path).fingerprint) ++
        Option(ownerTerm).filter(_.nonEmpty)).mkString("\u0000")

  /** The AST cache key for a file: absolute path identity + file content (matches what the AST pass
    * uses, so warm-restore finds the same `.frag`).
    */
  def fileCacheKey(filename: String): Option[CacheKey] =
      Try {
          val path = Paths.get(filename).toAbsolutePath
          CacheKey(path.toString, Files.readAllBytes(path))
      }.toOption

  /** The cache entry a file's AST lands in, under the same digest the store keys an entry by:
    * identity, fingerprint, the fragment revision for the fragment codec, and the file's bytes. The
    * worker mode reads the entry the worker process wrote; a run that collects the parse report
    * reads no entry through the store, which is why this exists beside it, and it must keep mixing
    * exactly what [[AstCacheStore]] mixes or the worker's entries are never found.
    */
  private[c2cpg] def entryHash(
    cacheKey: Option[CacheKey],
    fingerprint: String,
    fragments: Boolean
  ): Option[String] =
      cacheKey.flatMap { key =>
          Try {
              val digest = java.security.MessageDigest.getInstance("SHA-256")
              digest.update(key.identity.getBytes("UTF-8"))
              if fingerprint.nonEmpty then digest.update(fingerprint.getBytes("UTF-8"))
              if fragments then digest.update(AstFragment.CacheRevision.getBytes("UTF-8"))
              digest.update(key.content)
              digest.digest().map("%02x".format(_)).mkString
          }.toOption
      }

  /** The parsed unit for one file: its parse, the diff graph of its AST, and the type names
    * registered while building it. One shared body for the in-process run and the worker process,
    * so a unit's AST is the same whichever of them builds it.
    */
  private[c2cpg] def createUnitAst(
    config: Config,
    sources: ProjectSources,
    filename: String,
    timeoutDuration: FiniteDuration,
    parseTimeoutDuration: FiniteDuration,
    parseExecutor: ExecutorService
  ): Option[ParsedUnit] =
    val path             = Paths.get(filename).toAbsolutePath
    val relPath          = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val file2OffsetTable = new ConcurrentHashMap[String, Array[Int]]()
    val parser           = new CdtParser(config, sources.headerFileFinder, sources)
    val parseStart       = if debugTiming then System.nanoTime() else 0L
    try
      val parsed =
          try runWithTimeout(() => parser.parse(path), parseExecutor, parseTimeoutDuration)
          catch
            case e: TimeoutException =>
                // Cooperatively stop the CDT scanner/parser so the cancelled parse does not keep
                // a thread spinning in the background after future.cancel(true).
                parser.cancel()
                throw e
      if debugTiming then
        val ms = (System.nanoTime() - parseStart) / 1000000L
        if ms > 1000L then println(s"[c2cpg] parsed $relPath in ${ms}ms")
      parsed match
        case Some(translationUnit: IASTTranslationUnit) =>
            // a header that cannot stand alone reads its declarations out of the parse of the
            // unit that includes it; every other file reads them out of its own parse
            val ownerAst = ownerParseFor(
              path,
              translationUnit,
              parser,
              sources,
              parseExecutor,
              parseTimeoutDuration
            )
            // Included content is registered under the file's real path (see
            // [[CustomFileContentProvider]]), so a creator reading a header out of another unit's
            // parse names its files through real paths: against an input path spelled through a
            // symbolic link, no node location would relativize, and every declaration of the
            // header would read as belonging to another file and be dropped
            val (creatorConfig, creatorPath) = ownerAst match
              case Some(_) =>
                  val root = realPath(config.inputPath)
                  (
                    config.withInputPath(root),
                    SourceFiles.toRelativePath(
                      realPath(path.toString),
                      root
                    )
                  )
              case None => (config, relPath)
            val astCreator =
                new AstCreator(
                  creatorPath,
                  creatorConfig,
                  ownerAst.getOrElse(translationUnit),
                  file2OffsetTable,
                  // every file of the unit as the parser read it, in the unit's language
                  p => sources.textOf(p, sources.settingsFor(path).language)
                )(using config.schemaValidation)
            // resolving bindings and types while walking the AST runs CDT code that logs too
            val localDiff =
                runWithTimeout(
                  () => CdtLogging.captured(astCreator.createAst()),
                  parseExecutor,
                  timeoutDuration
                )
            Some(ParsedUnit(localDiff, astCreator.usedTypes))
        case _ => None
      end match
    catch
      case e: Throwable =>
          // The whole file is left out of the graph; at debug, like every lost-file message, and
          // never on stdout: this catch also carries the parse-timeout path.
          logger.debug(
            s"Exception processing file $path: ${e.getClass.getSimpleName} - ${e.getMessage}"
          )
          ParseReporter.record(
            ParseReporter.Frontend.C,
            relPath,
            ParseReporter.Outcome.Dropped,
            ParseReporter.Stage.Ast,
            ParseReporter.describe(e)
          )
          None
    end try
  end createUnitAst

  private val logger = LoggerFactory.getLogger(classOf[AstCreationPass])

  /** The parse a header's AST is built from when the header cannot stand alone (see
    * [[HeaderFromOwner]]): the parse of the unit that includes it, read with the unit's own
    * settings, out of which the header's declarations are taken with the header's own file and line
    * numbers. Detection reads the parses this pass already performs: the header's own parse for the
    * names it leaves unresolved and the presence of a guard, the owner's parse for the position the
    * header is included at and what is declared before it. None when the header keeps its own
    * parse.
    */
  private def ownerParseFor(
    header: Path,
    headerTu: IASTTranslationUnit,
    parser: CdtParser,
    sources: ProjectSources,
    parseExecutor: ExecutorService,
    parseTimeoutDuration: FiniteDuration
  ): Option[IASTTranslationUnit] =
      if !FileDefaults.isHeaderFile(header.toString) then None
      else
        sources.ownerOf(header) match
          case None        => None
          case Some(owner) =>
              // the owner is parsed again only for a header that may need it: one without a
              // guard, or one whose own parse leaves names unresolved, and only when the owner's
              // text leaves room for the header to depend on it
              val guarded    = HeaderFromOwner.isGuarded(headerTu)
              val unresolved = HeaderFromOwner.unresolvedNames(headerTu)
              val worthParsing = (!guarded || unresolved.nonEmpty) &&
                  HeaderFromOwner.ownerMayProvide(
                    sources.textOf(owner, sources.settingsFor(owner).language),
                    header,
                    guarded,
                    unresolved
                  )
              if !worthParsing then None
              else
                val ownerTu =
                    try
                      runWithTimeout(
                        () => parser.parseQuietly(owner),
                        parseExecutor,
                        parseTimeoutDuration
                      )
                    catch
                      // the owner's parse is not required: a header that cannot read it keeps
                      // today's graph from its own parse, and the cancelled parse stops at its
                      // next cancellation check
                      case _: TimeoutException =>
                          parser.cancel()
                          None
                ownerTu.filter(HeaderFromOwner.takenFromOwner(header, _, guarded, unresolved))
  end ownerParseFor

  private def runWithTimeout[T](
    block: () => T,
    parseExecutor: ExecutorService,
    timeout: FiniteDuration
  ): T =
    val future = parseExecutor.submit(new Callable[T]:
      override def call(): T = block()
    )
    try
      future.get(timeout.toMillis, TimeUnit.MILLISECONDS)
    catch
      case _: TimeoutException =>
          future.cancel(true)
          throw new TimeoutException(s"Operation timed out after $timeout")
      case e: InterruptedException =>
          future.cancel(true)
          val cause = e.getCause
          throw new InterruptedException(s"Operation interrupted - ${cause.getMessage}")
      case e =>
          future.cancel(true)
          throw e
  end runWithTimeout
end AstCreationPass

class AstCreationPass(
  cpg: Cpg,
  config: Config,
  timeoutDuration: FiniteDuration = AstCreationPass.parseTimeout,
  parseTimeoutDuration: FiniteDuration = AstCreationPass.parseTimeout,
  projectSources: ProjectSources = null
) extends StreamingCpgPass[String](cpg):

  import AstCreationPass.*

  private val logger = LoggerFactory.getLogger(getClass)

  /** Whether units are parsed in worker processes: asked for, and possible from this process. A
    * native image cannot start the Java processes the workers are, so there the run parses in its
    * own process as it would without the option, and says so.
    */
  private val isolate: Boolean =
      config.cIsolate && {
          val available = CdtWorkerPool.available
          if !available then
            logger.warn(
              "Isolated parsing needs a Java runtime to start worker processes with, and this " +
                  "process has none; parsing every unit in this process instead"
            )
          available
      }

  /** Set when no worker process could be started: the rest of the run parses in its own process. */
  private val workersUnavailable = new java.util.concurrent.atomic.AtomicBoolean(false)

  /** Whether the cache entries this run reads and writes are fragments (`.frag`) rather than the
    * classic bitcode (`.ast`). The worker mode always runs the fragment codec: an isolated unit's
    * AST crosses the process boundary as a cache entry, and the fragment codec is the one that
    * carries every node the AST creator writes, the tag nodes included. Read once: the codec the
    * workers write and the run reads must agree, and a run does not switch codecs halfway through.
    */
  private val fragments = isolate || CacheControl.useFragments

  /** Whether this run reads and writes the project's AST cache: what the store decides from the
    * same settings.
    */
  private lazy val cacheOn: Boolean =
      config.enableAstCache && CacheControl.isEnabled(CacheControl.Ast) &&
          Option(Paths.get(resolveCacheDir(config.inputPath, config.cacheDir)).getParent)
              .exists(Files.isDirectory(_))

  /** Where workers write the entries the run loads: the project's AST cache when the run caches, so
    * the entries serve later runs too, and otherwise a directory of this run's own, removed at the
    * end, so an uncached run leaves nothing in the project and never reads an entry an earlier run
    * left there.
    */
  private lazy val exchangeDir: String =
      if cacheOn then resolveCacheDir(config.inputPath, config.cacheDir)
      else
        val dir = Files.createTempDirectory("c2cpg-isolated")
        runExchangeDir = Some(dir)
        dir.toString

  /** The directory of this run's own that [[exchangeDir]] created, removed when the pass ends. */
  @volatile private var runExchangeDir: Option[Path] = None

  private val cacheStore = new AstCacheStore(
    config.enableAstCache,
    resolveCacheDir(config.inputPath, config.cacheDir),
    config.onlyAstCache,
    fragments
  )

  private val parseExecutor = Executors.newFixedThreadPool(maxConcurrentParsers)

  /** The files this pass turned into ASTs, freshly or from the AST cache, by absolute path: read by
    * edg2atom after the CDT fallback, to tell a file the fallback rescued from one it lost too.
    * Observability only.
    */
  val succeeded: java.util.Set[String] = ConcurrentHashMap.newKeySet[String]()

  private val sources = Option(projectSources).getOrElse(new ProjectSources(config))

  /** What a worker may spend on one unit: what the in-process run allows it, the parse, the parse
    * of a header's owner and the AST, with a little over for writing the entry.
    */
  private val unitBudget: FiniteDuration =
      parseTimeoutDuration * 2 + timeoutDuration + 30.seconds

  /** The worker pool, started on the first unit of an isolated run. A worker's start and its
    * reading of the project (the include graph, the compiler's macros) are not charged to its first
    * unit; they have a deadline of their own.
    */
  @volatile private var workersStarted = false
  private lazy val workers =
    workersStarted = true
    new CdtWorkerPool(
      exchangeDir,
      fragments,
      CdtWorker.WorkerConfig.from(config),
      unitBudget,
      (unitBudget * 2).max(5.minutes)
    )

  override def finish(): Unit =
      try
        parseExecutor.shutdownNow()
      catch
        case e: Exception => println(s"Error shutting down parse executor: ${e.getMessage}")
      finally
        if workersStarted then workers.close()
        runExchangeDir.foreach(dir =>
            Try(
              Files.walk(dir).sorted(java.util.Comparator.reverseOrder[Path]())
                  .forEach(Files.delete)
            )
        )
        super.finish()

  override def generateParts(): Array[String] = sources.files

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
    val produced =
        if isolate && !workersUnavailable.get then runOnPartWithWorkers(diffGraph, filename)
        else
          cacheStore.process(
            diffGraph,
            filename,
            cacheKey = AstCreationPass.fileCacheKey(filename),
            fingerprint = AstCreationPass.fileFingerprint(config, sources, filename),
            registerUsedTypes = registerUsedTypes,
            createAst = createAst(filename)
          )
    if produced then succeeded.add(Paths.get(filename).toAbsolutePath.toString)

  /** The isolated run of one file: a worker parses it and writes its cache entry, and the entry is
    * loaded the way a warm run loads one. A worker that exits, hangs past the parse timeout or runs
    * out of memory costs its unit a report record with the reason and a single retry in a fresh
    * worker; a unit that fails both times is left out of the graph, reported.
    */
  private def runOnPartWithWorkers(diffGraph: DiffGraphBuilder, filename: String): Boolean =
    val path        = Paths.get(filename).toAbsolutePath
    val relPath     = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val cacheKey    = AstCreationPass.fileCacheKey(filename)
    val fingerprint = AstCreationPass.fileFingerprint(config, sources, filename)
    // a warm entry loads through the store, the way every run loads one
    if cacheStore.process(
        diffGraph,
        filename,
        cacheKey = cacheKey,
        fingerprint = fingerprint,
        registerUsedTypes = registerUsedTypes,
        createAst = None
      )
    then true
    // while the parse report collects, the store reads no entry and every unit is parsed fresh:
    // the worker parses and rewrites the entry, and the run reads the bytes through the same
    // decoder a hit takes. A run without the cache reads no entry it did not ask a worker for.
    else if cacheOn && !ParseReporter.isEnabled && hasEntry(cacheKey, fingerprint) then
      loadEntry(diffGraph, cacheKey, fingerprint)
    else
      workers.parse(path, fingerprint) match
        case CdtWorkerPool.StartFailure(reason) =>
            // the run goes on in its own process: this unit and every later one
            if workersUnavailable.compareAndSet(false, true) then
              logger.warn(s"$reason; parsing the remaining units in this process")
            cacheStore.process(
              diffGraph,
              filename,
              cacheKey = cacheKey,
              fingerprint = fingerprint,
              registerUsedTypes = registerUsedTypes,
              createAst = createAst(filename)
            )
        case CdtWorkerPool.Completed(failures, units) =>
            replayRecords(failures, units)
            loadedOrReported(diffGraph, filename, relPath, cacheKey, fingerprint)
        case CdtWorkerPool.CleanFailure(reason, failures, units) =>
            replayRecords(failures, units)
            // the records a worker that parsed the unit but lost it made say so already; one
            // with neither record nor reason names the loss itself
            if failures.isEmpty && reason.nonEmpty then
              ParseReporter.record(
                ParseReporter.Frontend.C,
                relPath,
                ParseReporter.Outcome.Unparsed,
                ParseReporter.Stage.Parse,
                reason
              )
            false
        case CdtWorkerPool.WorkerFailure(reason) =>
            ParseReporter.record(
              ParseReporter.Frontend.C,
              relPath,
              ParseReporter.Outcome.Unparsed,
              ParseReporter.Stage.Parse,
              reason
            )
            workers.parse(path, fingerprint) match
              case CdtWorkerPool.StartFailure(reason) =>
                  if workersUnavailable.compareAndSet(false, true) then
                    logger.warn(s"$reason; parsing the remaining units in this process")
                  cacheStore.process(
                    diffGraph,
                    filename,
                    cacheKey = cacheKey,
                    fingerprint = fingerprint,
                    registerUsedTypes = registerUsedTypes,
                    createAst = createAst(filename)
                  )
              case CdtWorkerPool.Completed(failures, units) =>
                  replayRecords(failures, units)
                  loadedOrReported(diffGraph, filename, relPath, cacheKey, fingerprint)
              case CdtWorkerPool.CleanFailure(reason, failures, units) =>
                  replayRecords(failures, units)
                  if failures.isEmpty && reason.nonEmpty then
                    ParseReporter.record(
                      ParseReporter.Frontend.C,
                      relPath,
                      ParseReporter.Outcome.Unparsed,
                      ParseReporter.Stage.Parse,
                      reason
                    )
                  false
              case CdtWorkerPool.WorkerFailure(retryReason) =>
                  ParseReporter.record(
                    ParseReporter.Frontend.C,
                    relPath,
                    ParseReporter.Outcome.Unparsed,
                    ParseReporter.Stage.Parse,
                    s"$retryReason; the retry in a fresh worker failed the same way"
                  )
                  false
            end match
    end if
  end runOnPartWithWorkers

  /** The parse report records a worker made while reading its unit; they would die with the
    * worker's process, so the run replays them into its own reporters. The unit-settings reporter
    * keeps one record per unit, so a replayed unit record replaces the one the settings read
    * already made; the failure reporter keeps one record per loss, so a replayed failure record
    * joins the run's own (a file the first worker lost and whose retry's parse reported problems
    * appears under both facts).
    */
  private def replayRecords(
    failures: List[CdtWorker.FailureJson],
    units: List[CdtWorker.UnitJson]
  ): Unit =
    failures.foreach { f =>
      val record = CdtWorker.failureRecord(f)
      ParseReporter.record(
        record.frontend,
        record.file,
        record.outcome,
        record.stage,
        record.message
      )
    }
    units.foreach(u => UnitSettingsReporter.record(CdtWorker.unitRecord(u)))

  /** Whether the entry a worker's parse lands in is on disk. */
  private def hasEntry(cacheKey: Option[CacheKey], fingerprint: String): Boolean =
      AstCreationPass
          .entryHash(cacheKey, fingerprint, fragments)
          .exists(hash =>
              Files.exists(Paths.get(exchangeDir, entryName(hash)))
          )

  /** Loads the entry the worker wrote. The store takes it from here in an ordinary run; while the
    * parse report collects, or without the cache, the store reads nothing, so the same bytes go
    * through the same decoder here instead. A cache-warming run registers the types and adds
    * nothing to the graph, as the store does; a run without the cache removes the entry once read.
    */
  private def loadEntry(
    diffGraph: DiffGraphBuilder,
    cacheKey: Option[CacheKey],
    fingerprint: String
  ): Boolean =
      AstCreationPass.entryHash(cacheKey, fingerprint, fragments).exists { hash =>
        val entryFile = Paths.get(exchangeDir, entryName(hash))
        if !Files.exists(entryFile) then false
        else
          val staging = new DiffGraphBuilder
          val loaded =
              if fragments then
                AstFragment.decodeIntoDiffGraph(Files.readAllBytes(entryFile), staging)
              else
                Try(readBinary[AstCache.AstBitcode](Files.readAllBytes(entryFile))).toOption
                    .flatMap { bitcode =>
                        if AstCache.isCompatible(bitcode) then
                          AstCache.storeInDiffGraph(bitcode, staging)
                          Some(bitcode.usedTypes)
                        else None
                    }
          if !cacheOn then Try(Files.deleteIfExists(entryFile))
          loaded.exists { usedTypes =>
            registerUsedTypes(usedTypes)
            if !config.onlyAstCache then diffGraph.absorb(staging)
            true
          }
        end if
      }
  end loadEntry

  private def entryName(hash: String): String = s"$hash.${if fragments then "frag" else "ast"}"

  /** Loads the entry after a worker finished the unit: through the store, which finds it in an
    * ordinary run, or directly while the parse report collects. A unit whose entry cannot be read
    * back is reported, never silently left out.
    */
  private def loadedOrReported(
    diffGraph: DiffGraphBuilder,
    filename: String,
    relPath: String,
    cacheKey: Option[CacheKey],
    fingerprint: String
  ): Boolean =
    val loaded =
        if cacheOn && cacheStore.process(
            diffGraph,
            filename,
            cacheKey = cacheKey,
            fingerprint = fingerprint,
            registerUsedTypes = registerUsedTypes,
            createAst = None
          )
        then true
        else loadEntry(diffGraph, cacheKey, fingerprint)
    if !loaded then
      ParseReporter.record(
        ParseReporter.Frontend.C,
        relPath,
        ParseReporter.Outcome.Dropped,
        ParseReporter.Stage.Ast,
        "the unit's cached AST could not be read back"
      )
    loaded
  end loadedOrReported

  private def createAst(filename: String): Option[ParsedUnit] =
      AstCreationPass.createUnitAst(
        config,
        sources,
        filename,
        timeoutDuration,
        parseTimeoutDuration,
        parseExecutor
      )

  private def registerUsedTypes(usedTypes: Seq[String]): Unit =
      usedTypes.foreach(CGlobal.usedTypes.putIfAbsent(_, true))
end AstCreationPass
