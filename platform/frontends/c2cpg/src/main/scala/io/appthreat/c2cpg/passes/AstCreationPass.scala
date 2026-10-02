package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{CdtParser, ProjectSources}
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit, resolveCacheDir}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.StreamingCpgPass
import org.eclipse.cdt.core.dom.ast.IASTTranslationUnit

import java.nio.file.{Files, Paths}
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
  private[passes] val parseTimeout: FiniteDuration =
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

  /** Bump whenever AST creation changes what it emits for unchanged source: a cached AST from an
    * older frontend is otherwise replayed as-is (a fragment cached before call-site `fn-attr` tags
    * existed would make a warm run silently lose every header attribute).
    */
  // 3: member layouts of header-defined types ride the used types
  // 4: C++ implicit calls linked to their METHODs, operator calls typed; sizeof-family operators
  //    and catch handlers in their own shapes
  // 5: destructors at scope exits, constructed objects assigned, condition declarations, C++20
  //    module units, header language from includers, compiler-predefined macros
  private val AstFormatVersion = "c2cpg-ast-5"

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
      s"index=${config.useProjectIndex}"
    )
    (AstFormatVersion +: (parserOptions ++ config.includePaths.toList.sorted ++
        config.defines.toList.sorted ++ config.macroFiles.toList.sorted.map(contentOf("macro")) ++
        config.includeFiles.toList.sorted.map(contentOf("include"))))
        .mkString("\u0000")
  end cacheFingerprint

  /** The cache fingerprint of one file: the run's, and how the file itself is parsed (its language,
    * macros, include path and forced includes, which a compilation database sets per file).
    */
  def fileFingerprint(config: Config, sources: ProjectSources, filename: String): String =
      cacheFingerprint(config) + "\u0000" + sources.settingsFor(Paths.get(filename)).fingerprint

  /** The AST cache key for a file: absolute path identity + file content (matches what the AST pass
    * uses, so warm-restore finds the same `.frag`).
    */
  def fileCacheKey(filename: String): Option[CacheKey] =
      Try {
          val path = Paths.get(filename).toAbsolutePath
          CacheKey(path.toString, Files.readAllBytes(path))
      }.toOption
end AstCreationPass

class AstCreationPass(
  cpg: Cpg,
  config: Config,
  timeoutDuration: FiniteDuration = AstCreationPass.parseTimeout,
  parseTimeoutDuration: FiniteDuration = AstCreationPass.parseTimeout,
  projectSources: ProjectSources = null
) extends StreamingCpgPass[String](cpg):

  import AstCreationPass.*

  private val cacheStore = new AstCacheStore(
    config.enableAstCache,
    resolveCacheDir(config.inputPath, config.cacheDir),
    config.onlyAstCache
  )

  private val parseExecutor = Executors.newFixedThreadPool(maxConcurrentParsers)

  private val sources = Option(projectSources).getOrElse(new ProjectSources(config))

  override def finish(): Unit =
      try
        parseExecutor.shutdownNow()
      catch
        case e: Exception => println(s"Error shutting down parse executor: ${e.getMessage}")
      finally
        super.finish()

  override def generateParts(): Array[String] = sources.files

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
      cacheStore.process(
        diffGraph,
        filename,
        cacheKey = AstCreationPass.fileCacheKey(filename),
        fingerprint = AstCreationPass.fileFingerprint(config, sources, filename),
        registerUsedTypes = registerUsedTypes,
        createAst = createAst(filename)
      )

  private def createAst(filename: String): Option[ParsedUnit] =
    val path             = Paths.get(filename).toAbsolutePath
    val relPath          = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val file2OffsetTable = new ConcurrentHashMap[String, Array[Int]]()
    val parser           = new CdtParser(config, sources.headerFileFinder, sources)
    val parseStart       = if AstCreationPass.debugTiming then System.nanoTime() else 0L
    try
      val parsed =
          try runWithTimeout(() => parser.parse(path), parseTimeoutDuration)
          catch
            case e: TimeoutException =>
                // Cooperatively stop the CDT scanner/parser so the cancelled parse does not keep
                // a thread spinning in the background after future.cancel(true).
                parser.cancel()
                throw e
      if AstCreationPass.debugTiming then
        val ms = (System.nanoTime() - parseStart) / 1000000L
        if ms > 1000L then println(s"[c2cpg] parsed $relPath in ${ms}ms")
      parsed match
        case Some(translationUnit: IASTTranslationUnit) =>
            val astCreator =
                new AstCreator(
                  relPath,
                  config,
                  translationUnit,
                  file2OffsetTable,
                  // every file of the unit as the parser read it, in the unit's language
                  p => sources.textOf(p, sources.settingsFor(path).language)
                )(using config.schemaValidation)
            val localDiff = runWithTimeout(() => astCreator.createAst(), timeoutDuration)
            Some(ParsedUnit(localDiff, astCreator.usedTypes))
        case _ => None
    catch
      case e: Throwable =>
          println(s"Exception processing file $path: ${e.getClass.getSimpleName} - ${e.getMessage}")
          None
    end try
  end createAst

  private def registerUsedTypes(usedTypes: Seq[String]): Unit =
      usedTypes.foreach(CGlobal.usedTypes.putIfAbsent(_, true))

  private def runWithTimeout[T](block: () => T, timeout: FiniteDuration): T =
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
end AstCreationPass
