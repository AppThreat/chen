package io.appthreat.c2cpg.parser

import org.slf4j.LoggerFactory

import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import java.util.concurrent.{ConcurrentHashMap, TimeUnit}
import java.util.concurrent.atomic.AtomicInteger
import scala.io.Source
import scala.util.Try

/** A compiler as one translation unit uses it: the executable, its family, the language and the
  * options that change which macros it predefines.
  */
final case class CompilerIdentity(
  executable: String,
  family: CompilerFamily,
  language: SourceLanguage,
  options: Seq[String]
)

/** What a compiler predefines for a translation unit: its macros, and the directories it searches
  * for system headers.
  */
final case class CompilerFacts(macros: Map[String, String], systemIncludePaths: Seq[Path])

/** The macros a real compiler predefines, so a translation unit preprocesses as it does in the
  * build: the compiler's identity and version, the target's type sizes and features, the language
  * standard, and options such as `-O2` that turn on `__OPTIMIZE__` (and with it the C library's
  * `_FORTIFY_SOURCE` wrappers).
  *
  * The compiler is asked once per identity (`<cc> <options> -x <lang> -dM -E -v -`), which prints
  * the macros and the system include search path together. The answer is kept for the process and,
  * when a cache directory is given, on disk under a key that includes the compiler's `--version`
  * output, so a different or upgraded compiler is asked again.
  *
  * When the compiler cannot be run (a compilation database from another machine, or MSVC, whose
  * `cl.exe` cannot list its macros), a table for its family and target is used: the tables were
  * generated from real compilers by `tools/predefined-macros/generate.sh` and list their
  * provenance. Their format is the one the EDG C/C++ front end uses for `predefined_macros.txt`:
  * `mode[,mode] cannot_redefine name value`, where a mode selects C or C++ for the table's
  * compiler.
  */
object PredefinedMacros:

  private val logger = LoggerFactory.getLogger(getClass)

  private val processCache = new ConcurrentHashMap[String, Option[CompilerFacts]]()

  /** How many times a compiler was run for its macros in this process (tests count them). */
  val compilerRuns = new AtomicInteger()

  private val runTimeoutSeconds = 30L

  def clearProcessCache(): Unit = processCache.clear()

  /** The facts `identity` reports, from the process cache, the disk cache or by running it. None
    * when it cannot be run.
    */
  def ofCompiler(identity: CompilerIdentity, cacheDir: Option[Path]): Option[CompilerFacts] =
      if identity.family == CompilerFamily.Msvc then None
      else
        val key = identityKey(identity)
        processCache.computeIfAbsent(key, _ => lookup(identity, key, cacheDir))

  private def identityKey(identity: CompilerIdentity): String =
      (identity.executable +: identity.language.toString +: identity.options).mkString("\u0000")

  private def lookup(
    identity: CompilerIdentity,
    key: String,
    cacheDir: Option[Path]
  ): Option[CompilerFacts] =
      version(identity.executable).flatMap { versionText =>
        val digest = sha256(key + "\u0000" + versionText)
        val cached = cacheDir.map(_.resolve("compilers").resolve(s"$digest.macros"))
        cached.flatMap(read).orElse {
            val facts = run(identity)
            for f <- facts; file <- cached do write(file, f)
            facts
        }
      }

  private def version(executable: String): Option[String] =
      exec(Seq(executable, "--version")).collect { case (0, out, _) => out.trim }

  private def run(identity: CompilerIdentity): Option[CompilerFacts] =
    compilerRuns.incrementAndGet()
    val lang = identity.language match
      case SourceLanguage.C   => "c"
      case SourceLanguage.Cpp => "c++"
    val command =
        (identity.executable +: identity.options) ++ Seq("-x", lang, "-dM", "-E", "-v", "-")
    exec(command) match
      case Some((0, out, err)) =>
          Some(CompilerFacts(parseDefines(out.linesIterator), searchPath(err.linesIterator.toSeq)))
      case Some((code, _, err)) =>
          logger.debug(s"'${command.mkString(" ")}' exited with $code: ${err.take(500)}")
          None
      case None => None

  /** Runs `command` with an empty standard input: its exit code, standard output and error. */
  private def exec(command: Seq[String]): Option[(Int, String, String)] =
      Try {
          val process = new ProcessBuilder(command*).start()
          process.getOutputStream.close()
          val out = readAsync(process.getInputStream)
          val err = readAsync(process.getErrorStream)
          if !process.waitFor(runTimeoutSeconds, TimeUnit.SECONDS) then
            process.destroyForcibly()
            throw new RuntimeException(s"'${command.head}' did not finish")
          (process.exitValue(), out.join(), err.join())
      }.toOption

  private def readAsync(stream: InputStream): java.util.concurrent.CompletableFuture[String] =
      java.util.concurrent.CompletableFuture.supplyAsync(() =>
          new String(stream.readAllBytes(), StandardCharsets.UTF_8)
      )

  /** `#define NAME VALUE` lines, as the compiler prints them for `-dM`. */
  def parseDefines(lines: Iterator[String]): Map[String, String] =
      lines.flatMap { line =>
        val t = line.trim
        if !t.startsWith("#define ") then None
        else
          val rest = t.stripPrefix("#define ")
          // a function-like macro's name runs to its closing parenthesis
          val idEnd = rest.indexWhere(c => !(c.isLetterOrDigit || c == '_'))
          val nameEnd =
              if idEnd < 0 then rest.length
              else if rest.charAt(idEnd) == '(' then rest.indexOf(')', idEnd) + 1
              else idEnd
          Some(rest.take(nameEnd) -> rest.drop(nameEnd).trim)
      }.toMap

  /** The directories between `#include <...> search starts here:` and `End of search list.`. */
  def searchPath(lines: Seq[String]): Seq[Path] =
    val start = lines.indexWhere(_.contains("#include <...> search starts here:"))
    val end   = lines.indexWhere(_.startsWith("End of search list."), start + 1)
    if start < 0 || end < 0 then Nil
    else
      lines.slice(start + 1, end).map(_.trim).filter(_.nonEmpty)
          // macOS lists framework directories with a suffix
          .map(_.stripSuffix(" (framework directory)"))
          .flatMap(p => Try(Paths.get(p).toAbsolutePath.normalize).toOption)

  private def read(file: Path): Option[CompilerFacts] =
      Try {
          val lines = Files.readAllLines(file, StandardCharsets.UTF_8).toArray(Array.empty[String])
          val (includes, defines) = lines.partition(_.startsWith("include "))
          CompilerFacts(
            parseDefines(defines.iterator),
            includes.map(l => Paths.get(l.stripPrefix("include "))).toSeq
          )
      }.toOption

  private def write(file: Path, facts: CompilerFacts): Unit =
      Try {
          Files.createDirectories(file.getParent)
          val text = facts.systemIncludePaths.map(p => s"include $p") ++
              facts.macros.toSeq.sortBy(_._1).map((k, v) => s"#define $k $v")
          val tmp = Files.createTempFile(file.getParent, file.getFileName.toString, ".tmp")
          Files.writeString(tmp, text.mkString("\n") + "\n")
          Files.move(
            tmp,
            file,
            java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            java.nio.file.StandardCopyOption.ATOMIC_MOVE
          )
      }.failed.foreach(e => logger.debug(s"Cannot cache compiler macros in $file", e))

  private def sha256(text: String): String =
      MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))
          .take(16).map("%02x".format(_)).mkString

  /** A table of predefined macros for a compiler family and target. */
  final case class Table(name: String, family: CompilerFamily, os: String, arch: String)

  val tables: Seq[Table] = Seq(
    Table("gcc-linux-x86_64", CompilerFamily.Gcc, "linux", "x86_64"),
    Table("gcc-linux-aarch64", CompilerFamily.Gcc, "linux", "aarch64"),
    Table("clang-linux-x86_64", CompilerFamily.Clang, "linux", "x86_64"),
    Table("clang-linux-aarch64", CompilerFamily.Clang, "linux", "aarch64"),
    Table("clang-macos-arm64", CompilerFamily.Clang, "macos", "aarch64"),
    Table("clang-macos-x86_64", CompilerFamily.Clang, "macos", "x86_64"),
    Table("msvc-windows-x64", CompilerFamily.Msvc, "windows", "x86_64"),
    Table("msvc-windows-arm64", CompilerFamily.Msvc, "windows", "aarch64")
  )

  private val tableCache = new ConcurrentHashMap[(String, SourceLanguage), Map[String, String]]()

  /** The table for `family` on the target a `--target=` option names (the host's when none), for
    * `language`. A compiler of unknown family on Windows is taken for MSVC, elsewhere for GCC.
    */
  def fallback(
    family: CompilerFamily,
    language: SourceLanguage,
    options: Seq[String]
  ): Map[String, String] =
    val target =
        options.collectFirst { case o if o.startsWith("--target=") => o.stripPrefix("--target=") }
    val (os, arch) = target.map(platformOfTriple).getOrElse(hostPlatform)
    val wanted = family match
      case CompilerFamily.Unknown =>
          if os == "windows" then CompilerFamily.Msvc else CompilerFamily.Gcc
      case f => f
    val candidates = tables.filter(_.family == wanted)
    val table = candidates.find(t => t.os == os && t.arch == arch)
        .orElse(candidates.find(_.arch == arch))
        .orElse(candidates.headOption)
    table.map(t => tableCache.computeIfAbsent((t.name, language), _ => loadTable(t, language)))
        .getOrElse(Map.empty)

  private def platformOfTriple(triple: String): (String, String) =
    val t = triple.toLowerCase
    val arch =
        if t.startsWith("x86_64") || t.startsWith("amd64") then "x86_64"
        else if t.startsWith("aarch64") || t.startsWith("arm64") then "aarch64"
        else t.takeWhile(_ != '-')
    val os =
        if t.contains("windows") || t.contains("msvc") || t.contains("mingw") then "windows"
        else if t.contains("darwin") || t.contains("macos") || t.contains("apple") then "macos"
        else "linux"
    (os, arch)

  private lazy val hostPlatform: (String, String) =
    val osName = System.getProperty("os.name", "").toLowerCase
    val os =
        if osName.contains("win") then "windows"
        else if osName.contains("mac") then "macos"
        else "linux"
    val arch = System.getProperty("os.arch", "").toLowerCase match
      case "amd64" | "x86_64"  => "x86_64"
      case "aarch64" | "arm64" => "aarch64"
      case other               => other
    (os, arch)

  /** The modes a table line can name, active for its compiler and `language` (the names the EDG
    * front end's tables use).
    */
  private def activeModes(family: CompilerFamily, language: SourceLanguage): Set[String] =
    val cpp  = language == SourceLanguage.Cpp
    val base = Set("all") ++ (if cpp then Set("cpp") else Set.empty)
    base ++ (family match
      case CompilerFamily.Gcc => Set("gnu", "gnu_or_clang") + (if cpp then "gpp" else "gcc")
      case CompilerFamily.Clang =>
          Set("clang", "gnu_or_clang") + (if cpp then "clang_cpp" else "clang_c")
      case _ => Set("microsoft") + (if cpp then "microsoft_cpp" else "microsoft_c")
    )

  private def loadTable(table: Table, language: SourceLanguage): Map[String, String] =
    val modes  = activeModes(table.family, language)
    val stream = Option(getClass.getResourceAsStream(s"/predefined-macros/${table.name}.txt"))
    stream.map { s =>
      val source = Source.fromInputStream(s, "UTF-8")
      try
          source.getLines().map(_.trim).filter(l => l.nonEmpty && !l.startsWith("#")).flatMap {
              line =>
                  line.split("\\s+", 4) match
                    case Array(modeList, _, name, value) => Some((modeList, name, value))
                    case Array(modeList, _, name)        => Some((modeList, name, ""))
                    case _                               => None
          }.filter { (modeList, _, _) =>
              modeList.split(',').exists(m =>
                  if m.startsWith("!") then !modes.contains(m.drop(1)) else modes.contains(m)
              )
          }.map((_, name, value) => name -> value).toMap
      finally source.close()
    }.getOrElse(Map.empty)
  end loadTable
end PredefinedMacros
