package io.appthreat.x2cpg.parse

/** One command a compilation database carries for a file, as the parse report names it. */
final case class DatabaseCommand(directory: String, arguments: Seq[String])

/** How one translation unit was set up for parsing, as the parse report's `units` section names it.
  *
  * @param frontend
  *   the frontend that parsed the unit: one of [[ParseReporter.Frontend]].
  * @param file
  *   the unit, relative to the input root, with `/` as the separator on every platform.
  * @param driver
  *   the compiler the unit's compile command names, as the command spells it; empty for a unit no
  *   compilation database names.
  * @param entry
  *   the driver table entry the command matched; `unknown` when the table knows no such driver, so
  *   the unit's settings are the host compiler's stand-in; empty for a unit no compilation database
  *   names.
  * @param macroSource
  *   where the unit's predefined macros came from: one of [[UnitSettingsReporter.MacroSource]].
  * @param language
  *   the language the unit is parsed as: one of [[UnitSettingsReporter.Language]].
  * @param standard
  *   the standard the unit's `-std` names, as the command spells it; empty when none does.
  * @param macroFingerprint
  *   a fingerprint of the macros the frontend was given (see
  *   [[UnitSettingsReporter.macroFingerprint]]). Units whose macros differ in any value carry
  *   different fingerprints.
  * @param includeDirectories
  *   the include search path in the order the frontend searches it.
  * @param forcedIncludes
  *   the files the build forces into the unit before its first line (`-include` and `-imacros`).
  * @param ownedHeaders
  *   the project headers written with this unit (see `ProjectSources.headerOwners` in the C/C++
  *   frontend).
  * @param databaseCommands
  *   every command the compilation database carries for the file, in database order, when the
  *   database names the file more than once; empty otherwise.
  * @param usedDatabaseCommand
  *   the position in `databaseCommands` of the command the settings came from.
  * @param edgaCommandLine
  *   for a unit the EDG frontend exported: the exact command line that ran, including the temporary
  *   file it wrote the document to.
  */
final case class ParseUnitRecord(
  frontend: String,
  file: String,
  driver: String,
  entry: String,
  macroSource: String,
  language: String,
  standard: String,
  macroFingerprint: String,
  includeDirectories: Seq[String],
  forcedIncludes: Seq[String],
  ownedHeaders: Seq[String],
  databaseCommands: Seq[DatabaseCommand] = Nil,
  usedDatabaseCommand: Option[Int] = None,
  edgaCommandLine: Seq[String] = Nil
)

/** Opt-in collection of how each translation unit was set up for parsing, the sibling of
  * [[ParseReporter]]'s failure records behind the parse report's `units` section.
  *
  * Enabled by the same `chen.parse.report` system property (what atom's `--parse-report` sets
  * during option parsing) or the `CHEN_PARSE_REPORT` environment variable, and as silently absent
  * as [[ParseReporter]] is when neither is set: the frontends check [[isEnabled]] before they build
  * anything for a record, so an ordinary run costs nothing but a property read per unit. While the
  * reporter is enabled, the AST cache reads no entry (see [[ParseReporter]]), so every unit is
  * parsed and reaches these records even on a run that would otherwise replay cached ASTs.
  *
  * The reporter only accumulates. The driver that enabled it (atom) reads [[records]] after the
  * frontend ran, even after a failed run, and writes the report in whatever form it wants; chen
  * itself writes nothing. One unit of one frontend holds one record: a frontend that learns more
  * about a unit later (the exact command line the EDG export ran, for one) replaces the record it
  * made, and a frontend that takes a unit over from the other (the EDG frontend exporting a unit
  * whose settings the shared settings code recorded for the C frontend) drops the record that would
  * have named the unit twice.
  */
object UnitSettingsReporter:

  /** The values recorded in the `macroSource` field: whether the unit's macros are the compiler the
    * build named (`probed`), a table that stands in where the compiler cannot be asked or no
    * database named one and the host was not asked (`table`), the host compiler's macros, which a
    * run with include auto-discovery enabled asks for when no database named one (`host`), or the
    * stand-in for a driver nothing recognizes (`unknown`).
    */
  object MacroSource:
    val Probed  = "probed"
    val Table   = "table"
    val Host    = "host"
    val Unknown = "unknown"

  /** The values recorded in the `language` field. */
  object Language:
    val C   = "c"
    val Cpp = "c++"

  private val lock = new Object

  private var store: Map[(String, String), ParseUnitRecord]        = Map.empty // guarded by `lock`
  private var duplicates: Map[String, (Seq[DatabaseCommand], Int)] = Map.empty // guarded by `lock`

  def isEnabled: Boolean = ParseReporter.isEnabled

  /** A fingerprint of the macros a unit is parsed with: the first half of the SHA-256 of the sorted
    * `NAME=value` lines. Two units whose macros differ in any value carry different fingerprints;
    * the report carries the fingerprint, not the macros themselves.
    */
  def macroFingerprint(macros: Map[String, String]): String =
    val text = macros.toSeq.sorted.map((name, value) => s"$name=$value").mkString("\n")
    java.security.MessageDigest
        .getInstance("SHA-256")
        .digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        .take(16)
        .map("%02x".format(_))
        .mkString

  /** Keep `unit` as the record of its unit and frontend, with the duplicate commands the
    * compilation database carries for the file attached when there are any. A record already kept
    * for the unit and frontend is replaced.
    */
  def record(unit: ParseUnitRecord): Unit =
      if !isEnabled then ()
      else
        lock.synchronized {
            val file       = normalizePath(unit.file)
            val normalized = unit.copy(file = file)
            val filled = duplicates.get(file).map { case (commands, used) =>
                normalized.copy(databaseCommands = commands, usedDatabaseCommand = Some(used))
            }.getOrElse(normalized)
            store = store.updated((unit.frontend, file), filled)
        }

  /** Add `command` to the EDG frontend's record of `file` as the exact command line that ran, or
    * keep it alone when no settings record exists for the unit.
    */
  def recordCommandLine(file: String, command: Seq[String]): Unit =
      if !isEnabled then ()
      else
        lock.synchronized {
            val key = (ParseReporter.Frontend.Edg, normalizePath(file))
            store.get(key) match
              case Some(unit) => store = store.updated(key, unit.copy(edgaCommandLine = command))
              case None =>
                  store = store.updated(
                    key,
                    ParseUnitRecord(
                      frontend = ParseReporter.Frontend.Edg,
                      file = normalizePath(file),
                      driver = "",
                      entry = "",
                      macroSource = "",
                      language = "",
                      standard = "",
                      macroFingerprint = "",
                      includeDirectories = Nil,
                      forcedIncludes = Nil,
                      ownedHeaders = Nil,
                      edgaCommandLine = command
                    )
                  )
            end match
        }

  /** Keep the commands the compilation database carries for `file` and the position of the one the
    * settings came from. Reported with the unit's record when one is kept.
    */
  def recordDatabaseDuplicates(file: String, commands: Seq[DatabaseCommand], usedIndex: Int): Unit =
      if !isEnabled then ()
      else
        lock.synchronized {
            duplicates = duplicates.updated(normalizePath(file), (commands, usedIndex))
        }

  /** Forget the record `frontend` kept for `file`: the unit belongs to another frontend now.
    * Nothing happens when no record is kept.
    */
  def drop(frontend: String, file: String): Unit =
      if !isEnabled then ()
      else lock.synchronized { store = store.removed((frontend, normalizePath(file))) }

  /** The records collected so far, sorted by file. An empty list when disabled. */
  def records: List[ParseUnitRecord] =
      lock.synchronized(store.values.toList).sortBy(unit => (unit.file, unit.frontend))

  /** Drop everything collected so far. The driver calls this once per run, so a second run in the
    * same process (the test suites do this) starts from empty.
    */
  def reset(): Unit =
      lock.synchronized {
          store = Map.empty
          duplicates = Map.empty
      }

  private def normalizePath(path: String): String = path.replace('\\', '/')
end UnitSettingsReporter
