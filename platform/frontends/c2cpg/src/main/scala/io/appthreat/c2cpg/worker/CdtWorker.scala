package io.appthreat.c2cpg.worker

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.parser.ProjectSources
import io.appthreat.c2cpg.passes.AstCreationPass
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.parse.{
    ParseFailureRecord,
    ParseReporter,
    ParseUnitRecord,
    UnitSettingsReporter
}
import io.appthreat.x2cpg.passes.frontend.AstCacheStore
import io.appthreat.x2cpg.utils.{AtomicWrites, FileUtil}
import org.slf4j.LoggerFactory
import upickle.default.*

import java.io.{BufferedReader, BufferedWriter, InputStreamReader, OutputStreamWriter}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.atomic.{AtomicLong, AtomicReference}
import java.util.concurrent.{
    AbstractExecutorService,
    Callable,
    ConcurrentHashMap,
    ExecutorService,
    Executors,
    LinkedBlockingQueue,
    RunnableFuture,
    Semaphore,
    ThreadFactory,
    TimeUnit
}
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.{Properties, Try}
import scala.concurrent.duration.*

/** The process boundary of `--c-isolate`: the parent runs a small pool of long-lived worker
  * processes, and each worker parses the units it is sent with the same code the in-process run
  * uses ([[AstCreationPass.createUnitAst]], through its own [[AstCacheStore]] pointed at the same
  * cache directory). A unit therefore crosses the process boundary as the cache entry it would have
  * taken anyway: the worker writes `<hash>.frag`, and the parent loads it the way a warm run loads
  * a cached AST. No other serialisation of a unit exists between them.
  *
  * What does cross the boundary besides the cache entries is small control traffic in JSON: the
  * parent sends one job line per unit on the worker's standard input (which unit, its cache
  * fingerprint, where the reply goes, the settings the unit is parsed with), and the worker answers
  * by writing the reply file the job names (whether the unit was parsed, and the parse report
  * records it made, which would otherwise die with the worker's process). The worker keeps its own
  * project view per configuration, so the include graph, the header owners and the macro probing of
  * a run are computed once per worker, exactly as the in-process run computes them once per pass.
  *
  * The worker is replaced by the parent when it exits, runs out of memory or exceeds the parse
  * timeout; see [[CdtWorkerPool]] for that side. The `chen.cdtworker.parse-failure` system property
  * exists for tests: its value is `<mode>:<file name>`, and a worker asked for that file exits
  * (`exit`), spins without checking for interruption (`loop`) instead of parsing it, or exhausts
  * its heap inside the parse it runs for it (`oom`), so the out-of-memory path is the one a real
  * unit takes.
  */
object CdtWorker:

  /** The test-only failure switch: `<mode>:<file name>`, with the modes `exit`, `loop` and `oom`.
    * Read by the parent, which forwards it to every worker it starts, and by the worker, which acts
    * on it for the unit it names.
    */
  val TestFailureProperty = "chen.cdtworker.parse-failure"

  /** The settings one unit is parsed with, as the parent run holds them. Everything here shapes the
    * parse or its report: the project path, the compilation database, the macros, include paths and
    * standard, the parser options, and the files a run was told to ignore.
    */
  case class WorkerConfig(
    inputPath: String,
    compileCommands: String,
    cppStandard: String,
    includePaths: List[String],
    includeFiles: List[String],
    macroFiles: List[String],
    defines: List[String],
    includePathsAutoDiscovery: Boolean,
    includeFunctionBodies: Boolean,
    includeComments: Boolean,
    includeImageLocations: Boolean,
    includeTrivialExpressions: Boolean,
    parseInactiveCode: Boolean,
    useProjectIndex: Boolean,
    logProblems: Boolean,
    logPreprocessor: Boolean,
    ignoredFiles: List[String],
    ignoredFilesRegex: String,
    schemaValidation: String
  ) derives ReadWriter

  object WorkerConfig:

    /** The settings of the run, taken from the configuration the AST pass holds (already carrying
      * the census's defines, and the input path normalized).
      */
    def from(config: Config): WorkerConfig = WorkerConfig(
      config.inputPath,
      config.compileCommands,
      config.cppStandard,
      config.includePaths.toList.sorted,
      config.includeFiles.toList.sorted,
      config.macroFiles.toList.sorted,
      config.defines.toList.sorted,
      config.includePathsAutoDiscovery,
      config.includeFunctionBodies,
      config.includeComments,
      config.includeImageLocations,
      config.includeTrivialExpressions,
      config.parseInactiveCode,
      config.useProjectIndex,
      config.logProblems,
      config.logPreprocessor,
      config.ignoredFiles.toList.sorted,
      config.ignoredFilesRegex.toString,
      config.schemaValidation.toString
    )

    /** The configuration the settings describe, for the parser and creator the worker runs. The
      * input path is set first: a relative ignored-file entry resolves against it, as it did in the
      * parent.
      */
    def toConfig(settings: WorkerConfig): Config =
        Config()
            .withInputPath(settings.inputPath)
            .withCompileCommands(settings.compileCommands)
            .withCppStandard(settings.cppStandard)
            .withIncludePaths(settings.includePaths.toSet)
            .withIncludeFiles(settings.includeFiles.toSet)
            .withMacroFiles(settings.macroFiles.toSet)
            .withDefines(settings.defines.toSet)
            .withIncludePathsAutoDiscovery(settings.includePathsAutoDiscovery)
            .withFunctionBodies(settings.includeFunctionBodies)
            .withIncludeComments(settings.includeComments)
            .withImageLocations(settings.includeImageLocations)
            .withIncludeTrivialExpressions(settings.includeTrivialExpressions)
            .withParseInactiveCode(settings.parseInactiveCode)
            .withProjectIndexes(settings.useProjectIndex)
            .withLogProblems(settings.logProblems)
            .withLogPreprocessor(settings.logPreprocessor)
            .withIgnoredFiles(settings.ignoredFiles)
            .withIgnoredFilesRegex(settings.ignoredFilesRegex)
            .withSchemaValidation(ValidationMode.valueOf(settings.schemaValidation))
    end toConfig
  end WorkerConfig

  /** One unit the parent asks a worker to parse: the file, the cache fingerprint the parent
    * computed for it (so the entry the worker writes is the entry the parent looks for), the file
    * the reply goes to, the directory and codec the entry is written under (the run's AST cache
    * when the run caches, a directory of the run's own otherwise), whether that directory was
    * configured by the user (see [[AstCacheStore]]), and the run's settings.
    */
  case class Job(
    file: String,
    fingerprint: String,
    replyFile: String,
    cacheDir: String,
    fragments: Boolean,
    trustedCacheDir: Boolean = false,
    settings: WorkerConfig
  ) derives ReadWriter

  /** The parse report records the worker made while reading the unit, as they cross the process
    * boundary: a failure record names a file a front end lost or only partly read, a unit record
    * names how one was set up for parsing.
    */
  case class FailureJson(
    frontend: String,
    file: String,
    outcome: String,
    stage: String,
    message: String
  ) derives ReadWriter

  case class DatabaseCommandJson(directory: String, arguments: List[String]) derives ReadWriter

  case class UnitJson(
    frontend: String,
    file: String,
    driver: String,
    entry: String,
    macroSource: String,
    language: String,
    standard: String,
    macroFingerprint: String,
    includeDirectories: List[String],
    forcedIncludes: List[String],
    ownedHeaders: List[String],
    databaseCommands: List[DatabaseCommandJson],
    usedDatabaseCommand: Option[Int],
    edgaCommandLine: List[String]
  ) derives ReadWriter

  /** The worker's answer: `ok` when the unit's cache entry is in place, `failed` when the unit
    * produced no AST (a lost file, whose records say so), `lost` when the worker itself could not
    * finish the unit (out of memory, in the test-only failure mode). `reason` carries what the
    * report needs for `failed` and `lost`.
    */
  case class Reply(
    status: String,
    reason: String,
    failures: List[FailureJson],
    units: List[UnitJson]
  ) derives ReadWriter

  /** The report records collected since the last reset, for the reply. */
  def collectedFailures: List[FailureJson] =
      ParseReporter.records.map(r =>
          FailureJson(r.frontend, r.file, r.outcome, r.stage, r.message)
      )

  def collectedUnits: List[UnitJson] =
      UnitSettingsReporter.records.map { r =>
          UnitJson(
            r.frontend,
            r.file,
            r.driver,
            r.entry,
            r.macroSource,
            r.language,
            r.standard,
            r.macroFingerprint,
            r.includeDirectories.toList,
            r.forcedIncludes.toList,
            r.ownedHeaders.toList,
            r.databaseCommands.map(c => DatabaseCommandJson(c.directory, c.arguments.toList)).toList,
            r.usedDatabaseCommand,
            r.edgaCommandLine.toList
          )
      }

  def failureRecord(f: FailureJson): ParseFailureRecord =
      ParseFailureRecord(f.frontend, f.file, f.outcome, f.stage, f.message)

  def unitRecord(u: UnitJson): ParseUnitRecord =
      ParseUnitRecord(
        u.frontend,
        u.file,
        u.driver,
        u.entry,
        u.macroSource,
        u.language,
        u.standard,
        u.macroFingerprint,
        u.includeDirectories,
        u.forcedIncludes,
        u.ownedHeaders,
        u.databaseCommands.map(c =>
            io.appthreat.x2cpg.parse.DatabaseCommand(c.directory, c.arguments)
        ),
        u.usedDatabaseCommand,
        u.edgaCommandLine
      )

  /** The file a worker creates next to a job's reply once the unit's own work starts: the project
    * view is built and the parse is about to run. The parent times the unit from there, so the
    * start of a worker and the reading of the project are not charged to the first unit it parses.
    */
  def startedMarker(replyFile: String): Path = Paths.get(s"$replyFile.started")

  /** The executor the worker parses on: a single daemon thread, so a parse that ignores
    * interruption cannot keep the process alive after its input closes, and a record of the first
    * virtual machine error a task raised. The in-process code a unit runs reports every failure of
    * its tasks as a lost file; in a worker, an error such as running out of memory leaves the
    * process unfit for the next unit, so the worker reads the record and gives itself up.
    */
  private[worker] final class ParseExecutor extends AbstractExecutorService:
    private val delegate = Executors.newSingleThreadExecutor(new ThreadFactory:
      override def newThread(r: Runnable): Thread =
        val t = new Thread(r, "c2cpg-worker-parse")
        t.setDaemon(true)
        t
    )

    /** The first virtual machine error a task raised since the last [[clearError]]. */
    val error = new AtomicReference[VirtualMachineError]()

    /** A task that runs before the next one's own work, once: how the test-only `oom` switch makes
      * the parse itself run out of memory.
      */
    @volatile var beforeNextTask: Option[() => Unit] = None

    def clearError(): Unit = error.set(null)

    override protected def newTaskFor[T](callable: Callable[T]): RunnableFuture[T] =
        super.newTaskFor(new Callable[T]:
          override def call(): T =
              try
                val before = beforeNextTask
                beforeNextTask = None
                before.foreach(_.apply())
                callable.call()
              catch
                case e: VirtualMachineError =>
                    error.compareAndSet(null, e)
                    throw e
        )

    override def execute(command: Runnable): Unit        = delegate.execute(command)
    override def shutdown(): Unit                        = delegate.shutdown()
    override def shutdownNow(): java.util.List[Runnable] = delegate.shutdownNow()
    override def isShutdown: Boolean                     = delegate.isShutdown
    override def isTerminated: Boolean                   = delegate.isTerminated
    override def awaitTermination(timeout: Long, unit: TimeUnit): Boolean =
        delegate.awaitTermination(timeout, unit)
  end ParseExecutor

  /** The worker's entry point: one job line per unit on standard input until the parent closes it.
    * The project view is rebuilt when a job's settings differ from the previous job's, which in
    * practice never happens within one run.
    */
  def main(args: Array[String]): Unit =
    val reader   = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))
    val executor = new ParseExecutor
    val sources  = mutable.Map.empty[String, ProjectSources]
    try
      var line = reader.readLine()
      while line != null do
        runJob(line, sources, executor)
        line = reader.readLine()
    finally executor.shutdownNow()
    // a parse thread that ignores interruption is a daemon and does not hold the process
    System.exit(0)

  private def runJob(
    line: String,
    sources: mutable.Map[String, ProjectSources],
    executor: ParseExecutor
  ): Unit =
    val job     = read[Job](line)
    val failure = testFailureFor(job.file)
    // a job's records must be the records the job made
    ParseReporter.reset()
    UnitSettingsReporter.reset()
    CGlobal.reset()
    executor.clearError()
    try
      val config = WorkerConfig.toConfig(job.settings)
      val projectSources =
          sources.getOrElseUpdate(write(job.settings), new ProjectSources(config))
      AtomicWrites.bytes(startedMarker(job.replyFile), Array.emptyByteArray)
      failure match
        case Some("exit") =>
            System.exit(1)
        case Some("loop") =>
            // never checks for interruption: the parent's parse timeout is what ends this
            val spun = new java.util.concurrent.atomic.AtomicLong()
            while true do spun.incrementAndGet()
        case Some("oom") =>
            executor.beforeNextTask = Some(() => exhaustHeap())
        case _ =>
      val reply = answer(job, config, projectSources, executor)
      // the in-process code reports a task's failure as a lost file; a virtual machine error
      // behind it means this process must not parse another unit
      Option(executor.error.get).foreach(e => throw e)
      writeReply(job, reply)
    catch
      // a unit too big for the worker's heap, or any other virtual machine error, answers and
      // dies: the parent replaces the worker and retries the unit once in a fresh one
      case e: VirtualMachineError =>
          val reason = e match
            case _: OutOfMemoryError => "ran out of memory parsing the unit"
            case other => s"failed with ${other.getClass.getSimpleName} parsing the unit"
          Try(writeReply(job, Reply("lost", reason, collectedFailures, collectedUnits)))
          Runtime.getRuntime.halt(3)
    end try
    CGlobal.reset()
  end runJob

  /** The test-only failure this unit is named by, if its property names it. */
  private def testFailureFor(file: String): Option[String] =
      Option(System.getProperty(TestFailureProperty)).filter(_.nonEmpty).flatMap { value =>
          value.split(":", 2) match
            case Array(mode, named) if file.endsWith(named) => Some(mode)
            case _                                          => None
      }

  /** Allocates until the heap runs out; the error propagates to whoever runs it. */
  private def exhaustHeap(): Unit =
    val held  = new java.util.ArrayList[Array[Byte]]()
    val chunk = 32 * 1024 * 1024
    while true do held.add(Array.ofDim[Byte](chunk))

  private def answer(
    job: Job,
    config: Config,
    projectSources: ProjectSources,
    executor: ExecutorService
  ): Reply =
    val parsed = AstCreationPass.createUnitAst(
      config,
      projectSources,
      job.file,
      AstCreationPass.parseTimeout,
      AstCreationPass.parseTimeout,
      executor
    )
    val store = new AstCacheStore(
      enableAstCacheParam = true,
      job.cacheDir,
      onlyAstCache = false,
      useFragmentCache = job.fragments,
      trustedCacheDir = job.trustedCacheDir,
      // the anchor the parent judged the position against: the project's input path, which the
      // settings carry; without trust the worker checks the same components the parent did
      cacheDirAnchor = if job.trustedCacheDir then None else Some(config.inputPath)
    )
    val staging = new overflowdb.BatchedUpdate.DiffGraphBuilder
    val produced = store.process(
      staging,
      job.file,
      AstCreationPass.fileCacheKey(job.file),
      job.fingerprint,
      registerUsedTypes = _ => (),
      createAst = parsed
    )
    if produced then Reply("ok", "", collectedFailures, collectedUnits)
    else
      val reason =
          if parsed.isDefined then
            "the unit's AST could not be written to the cache the run reads"
          else "the unit produced no AST"
      Reply("failed", reason, collectedFailures, collectedUnits)
  end answer

  /** Writes the reply through an unpredictable temporary renamed onto the reply file, so a link
    * placed at that name is replaced rather than written through. The reply directory is this
    * run's own, but one writer pattern covers every fixed name the worker touches.
    */
  private[worker] def writeReply(job: Job, reply: Reply): Unit =
      AtomicWrites.bytes(
        Paths.get(job.replyFile),
        write(reply).getBytes(StandardCharsets.UTF_8)
      )
end CdtWorker

/** The parent's side of the worker mode: a small pool of long-lived worker processes, each running
  * [[CdtWorker]]. A unit is sent to one worker at a time; the worker that finishes it goes back to
  * the pool for the next unit, and the worker that exits, runs out of memory or exceeds the unit's
  * budget is destroyed and replaced, so the next unit starts in a fresh process.
  *
  * A unit's budget starts when the worker reports that the unit's own work began, and matches what
  * the in-process pass allows one unit (the parse, the parse of a header's owner, and the AST); the
  * start of a worker process and its reading of the project have a deadline of their own. The
  * test-only failure property shortens the unit's budget, so the tests of a hanging worker take
  * seconds instead of minutes.
  *
  * The workers' heaps together stay within half of this process's maximum heap, each between half a
  * gigabyte and four, and the pool is no larger than that budget holds. Two system properties
  * override the defaults: `chen.cdtworker.count` (the number of workers) and
  * `chen.cdtworker.heap-mb` (each worker's maximum heap in megabytes).
  */
object CdtWorkerPool:

  private val logger = LoggerFactory.getLogger(getClass)

  val CountProperty  = "chen.cdtworker.count"
  val HeapMbProperty = "chen.cdtworker.heap-mb"

  /** Whether worker processes can be started from this process: a native image has no `java`
    * executable to start them with, and no class path to give them.
    */
  def available: Boolean =
      System.getProperty("org.graalvm.nativeimage.imagecode") == null &&
          Option(System.getProperty("java.home")).exists(home =>
              Files.isExecutable(javaExecutable(home))
          )

  private[worker] def javaExecutable(home: String): Path =
      Paths.get(home, "bin", if Properties.isWin then "java.exe" else "java")

  /** The number of workers and each one's heap in megabytes, for a parent whose maximum heap is
    * `parentMaxBytes` on a machine with `cores` processors, unless the system properties say
    * otherwise.
    */
  private[worker] def sizing(parentMaxBytes: Long, cores: Int): (Int, Long) =
    val budgetMb = math.max(512L, parentMaxBytes / 2 / (1024 * 1024))
    val wanted   = math.max(1, math.min(4, cores / 2))
    val count = sys.props.get(CountProperty).flatMap(_.trim.toIntOption).filter(_ > 0).getOrElse(
      math.max(1, math.min(wanted, (budgetMb / 512L).toInt))
    )
    val heapMb =
        sys.props.get(HeapMbProperty).flatMap(_.trim.toLongOption).filter(_ >= 64).getOrElse(
          math.max(512L, math.min(budgetMb / count, 4096L))
        )
    (count, heapMb)

  /** The classpath a worker runs with: everything this process's classpath names, plus every
    * directory and jar the classes were loaded from. A forked test JVM carries the test classpath
    * in its loader rather than in `java.class.path`, so the loader chain is read as well; a
    * command-line run keeps its own classpath either way.
    */
  private[worker] def classpathFor(clazz: Class[?]): String =
    val entries = mutable.LinkedHashSet[String]()
    Option(System.getProperty("java.class.path")).foreach(
      _.split(java.io.File.pathSeparator).filter(_.nonEmpty).foreach(entries.add)
    )
    var loader = clazz.getClassLoader
    while loader != null do
      loader match
        case u: java.net.URLClassLoader =>
            u.getURLs.foreach { url =>
                entries.add(
                  Try(new java.io.File(url.toURI).getAbsolutePath).getOrElse(url.toString)
                )
            }
        case _ =>
      loader = loader.getParent
    entries.mkString(java.io.File.pathSeparator)

  /** What one unit's dispatch to a worker ended in. */
  sealed trait Attempt

  /** The unit's cache entry is in place, with the records the worker made reading it. */
  case class Completed(failures: List[CdtWorker.FailureJson], units: List[CdtWorker.UnitJson])
      extends Attempt

  /** The unit produced no AST; the worker itself is fine, and `reason` and the records say why it
    * was lost.
    */
  case class CleanFailure(
    reason: String,
    failures: List[CdtWorker.FailureJson],
    units: List[CdtWorker.UnitJson]
  ) extends Attempt

  /** The worker could not finish the unit: it exited, hung past its budget or ran out of memory. It
    * has been destroyed; the next unit starts in a fresh process.
    */
  case class WorkerFailure(reason: String) extends Attempt

  /** No worker could be started for the unit; the run parses in its own process instead. */
  case class StartFailure(reason: String) extends Attempt
end CdtWorkerPool

class CdtWorkerPool(
  exchangeDir: String,
  fragments: Boolean,
  trustedCacheDir: Boolean,
  settings: CdtWorker.WorkerConfig,
  unitBudget: FiniteDuration,
  startupBudget: FiniteDuration
):
  import CdtWorker.*
  import CdtWorkerPool.*

  private val (poolSize, heapMb) =
      sizing(Runtime.getRuntime.maxMemory, Runtime.getRuntime.availableProcessors())

  private val jobTimeout =
      if Option(System.getProperty(TestFailureProperty)).exists(_.nonEmpty) then 5.seconds
      else unitBudget

  private val replyDir         = Files.createTempDirectory("c2cpg-worker")
  private val replyCount       = new AtomicLong()
  private val idle             = new LinkedBlockingQueue[Worker]()
  private val live             = ConcurrentHashMap.newKeySet[Worker]()
  private val capacity         = new Semaphore(poolSize)
  @volatile private var closed = false

  /** Destroys the workers still running when this process exits without closing the pool: a worker
    * spinning in a parse must not outlive the run.
    */
  private val shutdownHook = new Thread(() => live.forEach(w => w.process.destroyForcibly()))
  shutdownHook.setName("c2cpg-worker-shutdown")
  Runtime.getRuntime.addShutdownHook(shutdownHook)

  /** Parses one unit in a worker, replacing the worker it used if that worker failed. */
  def parse(file: Path, fingerprint: String): Attempt =
    capacity.acquire()
    try
      val reused = Option(idle.poll()).flatMap { worker =>
          if closed then
            destroy(worker)
            None
          else Some(worker)
      }
      reused.map(Right(_)).getOrElse(Try(startWorker()).toEither) match
        case Left(e) =>
            StartFailure(s"no worker process could be started: ${e.getMessage}")
        case Right(worker) =>
            val (attempt, healthy) = dispatch(worker, file, fingerprint)
            if healthy && !closed then idle.add(worker)
            else destroy(worker)
            attempt
    finally capacity.release()

  /** Destroys every worker and the reply files. The reply directory is deleted without following
    * links, so a link planted inside it is removed as a link and its target is left alone.
    */
  def close(): Unit =
    closed = true
    idle.clear()
    live.forEach(destroy)
    Try(Runtime.getRuntime.removeShutdownHook(shutdownHook))
    FileUtil.delete(replyDir, swallowIoExceptions = true)

  /** The options of this process a worker takes as well: the thread stack size, which deep
    * expressions need in the parser as much in a worker as here.
    */
  private def forwardedJvmOptions: Seq[String] =
      Try(java.lang.management.ManagementFactory.getRuntimeMXBean.getInputArguments.asScala.toSeq)
          .getOrElse(Nil)
          .filter(_.startsWith("-Xss"))

  /** An argument file holding the class path, so the command line stays short whatever the class
    * path's length (Windows refuses command lines over 32,767 characters). Inside quotes a
    * backslash escapes the next character, so every backslash and quote of the path is escaped.
    * Written through an unpredictable temporary renamed onto the fixed name, like every other
    * fixed name in this directory.
    */
  private lazy val classpathArgFile: Path =
    val quoted = classpathFor(getClass).replace("\\", "\\\\").replace("\"", "\\\"")
    val file   = replyDir.resolve("worker-classpath.args")
    AtomicWrites.text(file, s"""-cp\n"$quoted"\n""")
    file

  private def startWorker(): Worker =
    val javaBin       = javaExecutable(System.getProperty("java.home")).toString
    val failureSwitch = Option(System.getProperty(TestFailureProperty)).filter(_.nonEmpty)
    // the parse report is enabled by a system property (what atom's --parse-report sets), and
    // system properties do not cross the process boundary: a worker whose reporters are off
    // would ship no records, and every unit it lost would be reported without its parse's own
    // reason. The CHEN_PARSE_REPORT environment variable crosses on its own.
    val reportSwitch = Option(System.getProperty("chen.parse.report")).filter(_.nonEmpty)
    // `java` runs the class the object's main is forwarded from: the singleton's own name
    // without its trailing dollar
    val mainClass = CdtWorker.getClass.getName.stripSuffix("$")
    val command = Seq(javaBin, s"-Xmx${heapMb}m") ++ forwardedJvmOptions ++
        failureSwitch.map(value => s"-D$TestFailureProperty=$value").toSeq ++
        reportSwitch.map(value => s"-Dchen.parse.report=$value").toSeq ++
        Seq(s"@$classpathArgFile", mainClass)
    val process = new ProcessBuilder(command.asJava)
        .redirectErrorStream(false)
        .start()
    drain(process.getInputStream, "standard output")
    drain(process.getErrorStream, "standard error")
    val worker = new Worker(
      process,
      new BufferedWriter(new OutputStreamWriter(process.getOutputStream, StandardCharsets.UTF_8))
    )
    live.add(worker)
    worker
  end startWorker

  private def dispatch(worker: Worker, file: Path, fingerprint: String): (Attempt, Boolean) =
    val replyFile = replyDir.resolve(s"reply-${replyCount.incrementAndGet()}.json").toString
    val job       =
        Job(file.toString, fingerprint, replyFile, exchangeDir, fragments, trustedCacheDir, settings)
    val marker    = startedMarker(replyFile)
    // the worker's start and its reading of the project have their own deadline; the unit's
    // budget runs from the moment the worker says the unit's own work began
    val startDeadline      = System.currentTimeMillis() + startupBudget.toMillis
    var unitDeadline: Long = Long.MaxValue
    try worker.send(write(job))
    catch
      case e: Exception =>
          logger.debug(s"worker stopped accepting units: ${e.getMessage}")
          return (WorkerFailure("the worker exited before the unit was parsed"), false)
    var answer: Option[(Attempt, Boolean)] = None
    while answer.isEmpty do
      // the reply first: an out-of-memory worker writes it while it can, then dies
      readReply(replyFile).foreach { reply =>
        Files.deleteIfExists(Paths.get(replyFile))
        answer = Some(reply match
          case Reply("ok", _, failures, units) => (Completed(failures, units), true)
          case Reply("failed", reason, failures, units) =>
              (CleanFailure(reason, failures, units), true)
          case Reply("lost", reason, _, _) => (WorkerFailure(s"the worker $reason"), false)
          case other =>
              (WorkerFailure(s"the worker answered in an unreadable form: ${other.status}"), false)
        )
      }
      if answer.isEmpty && !worker.process.isAlive then
        answer = Some(
          (
            WorkerFailure(
              s"the worker exited before the unit was parsed (exit code ${worker.process.exitValue()})"
            ),
            false
          )
        )
      if answer.isEmpty && unitDeadline == Long.MaxValue && Files.exists(marker) then
        unitDeadline = System.currentTimeMillis() + jobTimeout.toMillis
      if answer.isEmpty && System.currentTimeMillis() > unitDeadline then
        worker.process.destroyForcibly()
        answer =
            Some((WorkerFailure(s"the worker exceeded the parse timeout ($jobTimeout)"), false))
      if answer.isEmpty && unitDeadline == Long.MaxValue &&
        System.currentTimeMillis() > startDeadline
      then
        worker.process.destroyForcibly()
        answer = Some(
          (
            WorkerFailure(s"the worker did not start the unit within $startupBudget"),
            false
          )
        )
      if answer.isEmpty then Thread.sleep(25)
    end while
    Files.deleteIfExists(marker)
    answer.get
  end dispatch

  private def readReply(replyFile: String): Option[Reply] =
      Try {
          val path = Paths.get(replyFile)
          if Files.exists(path) then Some(read[Reply](Files.readString(path)))
          else None
      }.toOption.flatten

  private def drain(stream: java.io.InputStream, what: String): Unit =
    val t = new Thread(() =>
      val reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))
      var line   = reader.readLine()
      while line != null do
        logger.debug(s"worker $what: $line")
        line = reader.readLine()
    )
    t.setDaemon(true)
    t.setName("c2cpg-worker-drain")
    t.start()

  private def destroy(worker: Worker): Unit =
    live.remove(worker)
    Try(worker.stdin.close())
    Try {
        worker.process.destroyForcibly()
        worker.process.waitFor(5, TimeUnit.SECONDS)
    }

  private class Worker(val process: Process, val stdin: BufferedWriter):
    def send(line: String): Unit =
      stdin.write(line)
      stdin.write("\n")
      stdin.flush()
end CdtWorkerPool
