package io.appthreat.c2cpg.parser

import io.appthreat.x2cpg.utils.AtomicWrites
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
    * when it cannot be run: the MSVC family, whose `cl.exe` has no macro-dump option, and the
    * toolchains whose drivers the settings never ask for (their table stands in).
    */
  def ofCompiler(identity: CompilerIdentity, cacheDir: Option[Path]): Option[CompilerFacts] =
      if RunnableFamilies.contains(identity.family) then
        val key = identityKey(identity)
        processCache.computeIfAbsent(key, _ => lookup(identity, key, cacheDir))
      else None

  /** The compilers asked for their macros: the GCC and Clang drivers, which answer `-dM -E`. A
    * command of any other family is not run (its table stands in), so a compilation database cannot
    * have an arbitrary program started.
    */
  private val RunnableFamilies = Set(CompilerFamily.Gcc, CompilerFamily.Clang)

  private def identityKey(identity: CompilerIdentity): String =
      (identity.executable +: identity.language.toString +: identity.options).mkString("\u0000")

  /** The directory under a cache directory the macro files live in, so a caller that checks the
    * cache's position can check the position it actually writes to.
    */
  val CacheSubdir: String = "compilers"

  private def lookup(
    identity: CompilerIdentity,
    key: String,
    cacheDir: Option[Path]
  ): Option[CompilerFacts] =
      version(identity.executable).flatMap { versionText =>
        val digest = sha256(key + "\u0000" + versionText)
        val cached = cacheDir.map(_.resolve(CacheSubdir).resolve(s"$digest.macros"))
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
    // the probe the driver table spells for the compiler: the GCC and Clang drivers are asked
    // exactly as they always were, a two-word driver through its subcommand
    val probe = Toolchains
        .entryForFamily(identity.family)
        .flatMap(_.probe)
        .getOrElse(Toolchains.Probe(args = Seq("-x", "<lang>", "-dM", "-E", "-v")))
    val command =
        (Seq(identity.executable) ++ probe.prefixArgs ++ identity.options ++
            probe.args.map(arg => if arg == "<lang>" then lang else arg)) :+ "-"
    exec(command) match
      case Some((0, out, err)) =>
          Some(CompilerFacts(parseDefines(out.linesIterator), searchPath(err.linesIterator.toSeq)))
      case Some((code, _, err)) =>
          logger.debug(s"'${command.mkString(" ")}' exited with $code: ${err.take(500)}")
          None
      case None => None
  end run

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

  /** Reads a process's output on a thread of its own. The caller can be a worker of the common pool
    * whose sibling workers all wait for it (a parallel pass asking for the same compiler's macros),
    * so a read queued on the common pool would never run.
    */
  private def readAsync(stream: InputStream): java.util.concurrent.CompletableFuture[String] =
      java.util.concurrent.CompletableFuture.supplyAsync(
        () => new String(stream.readAllBytes(), StandardCharsets.UTF_8),
        readers
      )

  private lazy val readers = java.util.concurrent.Executors.newCachedThreadPool { task =>
    val thread = new Thread(task, "compiler-output-reader")
    thread.setDaemon(true)
    thread
  }

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

  /** Reads a cached macro file. A link at the cache name is a miss: the target, wherever the link
    * points, is never read. The write beside this goes through [[AtomicWrites]] too.
    */
  private def read(file: Path): Option[CompilerFacts] =
      AtomicWrites.readRegular(file).flatMap { bytes =>
          Try {
              val lines               = String(bytes, StandardCharsets.UTF_8).linesIterator.toArray
              val (includes, defines) = lines.partition(_.startsWith("include "))
              CompilerFacts(
                parseDefines(defines.iterator),
                includes.map(l => Paths.get(l.stripPrefix("include "))).toSeq
              )
          }.toOption
      }

  private def write(file: Path, facts: CompilerFacts): Unit =
      Try {
          Files.createDirectories(file.getParent)
          val text = facts.systemIncludePaths.map(p => s"include $p") ++
              facts.macros.toSeq.sortBy(_._1).map((k, v) => s"#define $k $v")
          AtomicWrites.text(file, text.mkString("\n") + "\n")
      }.failed.foreach(e => logger.debug(s"Cannot cache compiler macros in $file", e))

  private def sha256(text: String): String =
      MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))
          .take(16).map("%02x".format(_)).mkString

  /** A table of predefined macros for a compiler family and target. A table that names the target
    * triples or the command options it belongs to is selected by those, ahead of the host's
    * platform (armclang's triple, the bare-metal ARM options, clang's MSVC driver mode).
    */
  final case class Table(
    name: String,
    family: CompilerFamily,
    os: String,
    arch: String,
    triples: Seq[String] = Nil,
    optionPrefixes: Seq[String] = Nil
  )

  val tables: Seq[Table] = Seq(
    Table("gcc-linux-x86_64", CompilerFamily.Gcc, "linux", "x86_64"),
    Table("gcc-linux-aarch64", CompilerFamily.Gcc, "linux", "aarch64"),
    Table("clang-linux-x86_64", CompilerFamily.Clang, "linux", "x86_64"),
    Table("clang-linux-aarch64", CompilerFamily.Clang, "linux", "aarch64"),
    Table("clang-macos-arm64", CompilerFamily.Clang, "macos", "aarch64"),
    Table("clang-macos-x86_64", CompilerFamily.Clang, "macos", "x86_64"),
    Table("msvc-windows-x64", CompilerFamily.Msvc, "windows", "x86_64"),
    Table("msvc-windows-arm64", CompilerFamily.Msvc, "windows", "aarch64"),
    Table(
      "clangcl-windows-x64",
      CompilerFamily.Msvc,
      "windows",
      "x86_64",
      optionPrefixes = Seq("--driver-mode=cl")
    ),
    Table(
      "clangcl-windows-arm64",
      CompilerFamily.Msvc,
      "windows",
      "aarch64",
      optionPrefixes = Seq("--driver-mode=cl")
    ),
    Table(
      "gcc-arm-none-eabi",
      CompilerFamily.Gcc,
      "none",
      "arm",
      optionPrefixes = Seq(
        "-mthumb",
        "-mcpu=cortex-m",
        "-mcpu=cortex-r",
        "-march=armv4",
        "-march=armv5",
        "-march=armv6",
        "-march=armv7"
      )
    ),
    Table(
      "armclang-arm-none-eabi",
      CompilerFamily.Clang,
      "none",
      "arm",
      triples = Seq("arm-arm-none-eabi")
    ),
    Table("tinycc-linux-x86_64", CompilerFamily.TinyC, "linux", "x86_64"),
    Table("tinycc-linux-aarch64", CompilerFamily.TinyC, "linux", "aarch64"),
    Table("emscripten-wasm32", CompilerFamily.Emscripten, "emscripten", "wasm32"),
    Table("intel-llvm-linux-x86_64", CompilerFamily.IntelLlvm, "linux", "x86_64"),
    Table("intel-llvm-linux-aarch64", CompilerFamily.IntelLlvm, "linux", "aarch64"),
    Table("iccarm-arm", CompilerFamily.Iar, "none", "arm"),
    Table("ti-arm", CompilerFamily.TiArm, "none", "arm"),
    Table("ti-msp430", CompilerFamily.TiMsp430, "none", "msp430"),
    Table("nvcc-own", CompilerFamily.Nvcc, "any", "any")
  )

  private val tableCache = new ConcurrentHashMap[(String, SourceLanguage), Map[String, String]]()

  /** The table for `family` on the target a `--target=` option names (the host's when none), for
    * `language`. A compiler of unknown family on Windows is taken for MSVC, elsewhere for GCC.
    * nvcc's macros are the host compiler's table with nvcc's own merged over it.
    */
  def fallback(
    family: CompilerFamily,
    language: SourceLanguage,
    options: Seq[String]
  ): Map[String, String] =
    family match
      case CompilerFamily.Nvcc =>
          val host = Toolchains.hostFamilyOf(options).getOrElse {
              val target =
                  options.collectFirst {
                      case o if o.startsWith("--target=") =>
                          o.stripPrefix("--target=")
                  }
              val os = target.map(t => platformOfTriple(t)._1).getOrElse(hostPlatform._1)
              if os == "windows" then CompilerFamily.Msvc else CompilerFamily.Gcc
          }
          select(host, language, options) ++ select(family, language, options)
      case f => select(f, language, options)
    end match
  end fallback

  /** The table of one family for `language`, selected by the options the command carries, then by
    * the target triple, then by the target's or the host's platform. Among the tables the options
    * select (clang's MSVC mode against the bare-metal ARM options), the target's architecture
    * decides; the stem the driver table's family entry names (`fallbackTable`) narrows what the
    * platform finds fall back to, so the tables of another toolchain sharing the family are only
    * reached through their own options or triples.
    */
  private def select(
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
    val stem       = Toolchains.entryForFamily(wanted).flatMap(_.fallbackTable)
    val candidates = tables.filter(_.family == wanted)
    val byOption = candidates.filter(t =>
        t.optionPrefixes.nonEmpty &&
            options.exists(o => t.optionPrefixes.exists(o.startsWith))
    )
    val byStem = candidates.filter(t => stem.forall(t.name.startsWith))
    val table = byOption.find(t => t.os == os && t.arch == arch)
        .orElse(byOption.find(_.arch == arch))
        .orElse(byOption.headOption)
        .orElse(candidates.find(t =>
            target.exists(triple => t.triples.contains(triple.toLowerCase))
        ))
        .orElse(byStem.find(t => t.os == os && t.arch == arch))
        .orElse(byStem.find(_.arch == arch))
        .orElse(byStem.headOption)
    table.map(t => tableCache.computeIfAbsent((t.name, language), _ => loadTable(t, language)))
        .getOrElse(Map.empty)
  end select

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
    * front end's tables use). The clang-based toolchains carry clang's modes; the ones with tables
    * of their own spell their family.
    */
  private def activeModes(family: CompilerFamily, language: SourceLanguage): Set[String] =
    val cpp  = language == SourceLanguage.Cpp
    val base = Set("all") ++ (if cpp then Set("cpp") else Set.empty)
    base ++ (family match
      case CompilerFamily.Gcc | CompilerFamily.Nvcc =>
          Set("gnu", "gnu_or_clang") + (if cpp then "gpp" else "gcc")
      case CompilerFamily.Clang | CompilerFamily.IntelLlvm | CompilerFamily.Emscripten =>
          Set("clang", "gnu_or_clang") + (if cpp then "clang_cpp" else "clang_c")
      case CompilerFamily.TinyC =>
          Set("tinycc") + (if cpp then "tinycc_cpp" else "tinycc_c")
      case CompilerFamily.Iar =>
          Set("iar") + (if cpp then "iar_cpp" else "iar_c")
      case CompilerFamily.TiArm =>
          Set("ti_arm") + (if cpp then "ti_arm_cpp" else "ti_arm_c")
      case CompilerFamily.TiMsp430 =>
          Set("ti_msp430") + (if cpp then "ti_msp430_cpp" else "ti_msp430_c")
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
