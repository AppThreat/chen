package io.appthreat.x2cpg.parse

import io.appthreat.x2cpg.SourceFiles

/** One file one frontend left out, or only partly read.
  *
  * @param frontend
  *   which frontend read (or failed to read) the file: one of [[Frontend]].
  * @param file
  *   the file, relative to the input root, with `/` as the separator on every platform.
  * @param outcome
  *   `unparsed` (no AST from the parser), `dropped` (parsed, but AST creation failed and the file
  *   is not in the graph) or `partial` (in the graph, but the parser reported errors or skipped
  *   parts).
  * @param stage
  *   `parse` or `ast`: where the file was lost.
  * @param message
  *   the parser's error text or the exception's class and message, never a stack trace.
  */
final case class ParseFailureRecord(
  frontend: String,
  file: String,
  outcome: String,
  stage: String,
  message: String
)

/** Opt-in collection of the files the frontends leave out (chen#255).
  *
  * Enabled by the `chen.parse.report` system property (what atom's `--parse-report` sets during
  * option parsing) or the `CHEN_PARSE_REPORT` environment variable. When neither is set, [[record]]
  * resolves the property once and returns - no message is built, nothing is stored, so the
  * instrument is genuinely zero-cost for every run that did not ask for it. The message parameter
  * is by name for exactly that reason: callers may interpolate parser output freely.
  *
  * The reporter only accumulates. The driver that enabled it (atom) reads [[records]] after the
  * frontend ran, even after a failed run, and writes the report in whatever form it wants; chen
  * itself writes nothing. Records are kept in memory behind a lock, which is enough: a run loses
  * whole files, not statements, so the count is the size of the project, not of its AST, and the
  * parallel AST passes call [[record]] from their worker threads.
  *
  * A file that failed is never cached (only ASTs that were built are), so it fails again on every
  * cached run and is recorded again; a cache hit never evaluates the code that could record
  * anything, so a healthy file is never reported. The AST cache therefore needs no changes for this
  * reporter to be truthful on warm runs.
  */
object ParseReporter:

  /** The names recorded in the `frontend` field. `c` and `edg` are the two C/C++ frontends so that
    * a report says which of them read a file, matching how atom names them.
    */
  object Frontend:
    val C       = "c"
    val Edg     = "edg"
    val JavaSrc = "javasrc"
    val Jimple  = "jimple"
    val JsSrc   = "jssrc"
    val Php     = "php"
    val Python  = "python"
    val Ruby    = "ruby"

  /** The values recorded in the `outcome` field. */
  object Outcome:
    val Unparsed = "unparsed"
    val Dropped  = "dropped"
    val Partial  = "partial"

  /** The values recorded in the `stage` field. */
  object Stage:
    val Parse = "parse"
    val Ast   = "ast"

  /** Parser error texts are capped the way astgen caps its own manifest records: long enough to
    * name the construct, short enough that one broken generator cannot drown the report.
    */
  private val MaxMessageLength = 500

  private val PropKey = "chen.parse.report"
  private val EnvKey  = "CHEN_PARSE_REPORT"

  private val lock = new Object

  /** The environment cannot change during a run, so it is read once; the system property is read
    * live because atom sets it while parsing options and the tests toggle it. Resolved per record
    * call, and a disabled run costs exactly one `System.getProperty`.
    */
  private lazy val envEnabled: Option[String] = sys.env.get(EnvKey).filter(_.nonEmpty)

  private def isEnabledPath: Option[String] =
      Option(System.getProperty(PropKey)).filter(_.nonEmpty).orElse(envEnabled)

  def isEnabled: Boolean = isEnabledPath.isDefined

  private var store: List[ParseFailureRecord] = Nil // guarded by `lock`

  /** Remember that `frontend` lost `file`. A no-op, down to the by-name message, when the reporter
    * is disabled. `file` may be absolute or already relative; its separators become `/` either way.
    */
  def record(
    frontend: String,
    file: String,
    outcome: String,
    stage: String,
    message: => String
  ): Unit =
    if isEnabledPath.isEmpty then return
    val normalized = file.replace('\\', '/')
    val trimmed = message
        .replaceAll("[\\r\\n]+", " ")
        .take(MaxMessageLength)
    lock.synchronized {
        store = ParseFailureRecord(frontend, normalized, outcome, stage, trimmed) :: store
    }

  /** The records collected so far, sorted by file. An empty list when disabled. */
  def records: List[ParseFailureRecord] =
      lock.synchronized(store).sortBy(r => (r.file, r.frontend, r.stage))

  /** Drop everything collected so far. The driver calls this once per run, so a second run in the
    * same process (the test suites do this) starts from empty.
    */
  def reset(): Unit =
      lock.synchronized {
          store = Nil
      }

  /** `path` relative to `rootPath`, with `/` as the separator on every platform:
    * `java.nio.file.Path.relativize` renders `\` on Windows, and a report is read by tools, not by
    * the platform it was written on. A path outside the root is returned as it came, with
    * separators normalized.
    */
  def relativeTo(rootPath: String, path: String): String =
      SourceFiles.toRelativePath(path, rootPath).replace('\\', '/')
end ParseReporter
