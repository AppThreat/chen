package io.appthreat.c2cpg.parser

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.utils.ExecutableLookup
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.resolveCacheDir

import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern
import scala.util.Try
import scala.util.matching.Regex

/** How one file is preprocessed and parsed: its language, the macros defined before its first line,
  * the include search path (user directories first, then system ones), and the files forced into it
  * (`-include`) or read for their macros (`-imacros`).
  */
final case class UnitSettings(
  language: SourceLanguage,
  definedSymbols: Map[String, String],
  includePaths: Seq[Path],
  includeFiles: Seq[Path],
  macroFiles: Seq[Path],
  /** The compiler the unit's macros came from, when one was run for them. */
  compiler: Option[CompilerIdentity] = None,
  /** The standard the unit is compiled for, as its `-std` spells it (`c11`, `gnu++17`). */
  standard: Option[String] = None
):
  /** Everything here that shapes the file's AST, for the AST cache key. */
  lazy val fingerprint: String =
    def withContent(p: Path): String =
      val crc = new java.util.zip.CRC32()
      Try(Files.readAllBytes(p)).foreach(b => crc.update(b))
      s"$p:${crc.getValue}"
    (Seq(language.toString) ++ definedSymbols.toSeq.sorted.map((k, v) => s"$k=$v") ++
        includePaths.map(_.toString) ++ includeFiles.map(withContent) ++
        macroFiles.map(withContent)).mkString("\u0001")
end UnitSettings

object UnitSettings:

  /** Function-like operators compilers evaluate in `#if` that the parser does not: as 0, a header
    * testing them takes its portable branch instead of failing to preprocess.
    */
  val FeatureTests: Map[String, String] = Map(
    "__has_feature(x)"            -> "0",
    "__has_extension(x)"          -> "0",
    "__has_builtin(x)"            -> "0",
    "__has_attribute(x)"          -> "0",
    "__has_cpp_attribute(x)"      -> "0",
    "__has_c_attribute(x)"        -> "0",
    "__has_declspec_attribute(x)" -> "0",
    "__has_warning(x)"            -> "0",
    "__is_identifier(x)"          -> "1",
    "__building_module(x)"        -> "0",
    "__is_target_arch(x)"         -> "0",
    "__is_target_os(x)"           -> "0",
    "__is_target_environment(x)"  -> "0"
  )

  /** Whether a `-std` spelling names C23 or a later C standard. */
  def isC23OrLater(standard: String): Boolean =
      Set("23", "2x", "2y", "iso9899:2024").contains(
        standard.toLowerCase.stripPrefix("gnu").stripPrefix("c")
      )

  /** The value `__cplusplus` has for a `-std`/`/std:` spelling, if it names a C++ standard. */
  def cplusplusFor(standard: String): Option[String] =
      standard.toLowerCase.stripPrefix("gnu").stripPrefix("c") match
        case "++98" | "++03" => Some("199711L")
        case "++11" | "++0x" => Some("201103L")
        case "++14" | "++1y" => Some("201402L")
        case "++17" | "++1z" => Some("201703L")
        case "++20" | "++2a" => Some("202002L")
        case "++23" | "++2b" => Some("202302L")
        case "++26" | "++2c" => Some("202400L")
        case "++latest"      => Some("202302L")
        case other if other.endsWith("l") && other.forall(c => c.isDigit || c == 'l') =>
            Some(standard)
        case _ => None

  /** The user's `--define`s: gcc's `-DNAME` is `NAME=1`, as `true` is not a keyword to the C
    * preprocessor and `#if NAME` would otherwise evaluate to 0.
    */
  def userDefines(config: Config): Map[String, String] =
      config.defines.map {
          case define if define.contains("=") =>
              val s = define.split("=", 2)
              s.head -> s(1)
          case define => define -> "1"
      }.toMap
end UnitSettings

/** The files c2cpg parses for a project, and how it parses each of them.
  *
  * Without a compilation database every source and header under the input path is parsed; with one
  * (`--compile-commands`), the translation units it compiles and the project's headers (only the
  * units with `--compile-commands-only`). A unit from the database is parsed with its own include
  * path, macros and language; any other file with the configured ones.
  *
  * A header takes the language, and with a database the flags, of the first unit that includes it
  * (see [[IncludeGraph]]): a `.h` file included from C++ is parsed as C++. A header no unit
  * includes is C in a project without C++ sources, C++ in one without C sources, and otherwise C++
  * only when it reads as C++.
  *
  * The predefined macros come from the unit's compiler (see [[PredefinedMacros]]): the database's
  * compiler for its units, and the host's GCC or Clang when include discovery is on. Otherwise the
  * GCC identity in [[DefaultDefines]] stands in, so headers still see the function attributes they
  * gate on `__GNUC__`.
  */
final class ProjectSources(val config: Config):

  import ProjectSources.*

  val database: Option[CompileDatabase] =
      Option(config.compileCommands).filter(_.nonEmpty).flatMap { requested =>
        val located =
            CompileDatabase.locate(requested, Paths.get(config.inputPath).toAbsolutePath.normalize)
        if located.isEmpty then
          println(s"No compilation database found at '$requested'; parsing without one")
        located.map(CompileDatabase.load)
      }

  private val root = Paths.get(config.inputPath).toAbsolutePath.normalize

  lazy val headerFileFinder: HeaderFileFinder = new HeaderFileFinder(config.inputPath)

  private val cacheDir: Option[Path] =
      Option.when(config.enableAstCache)(
        Paths.get(resolveCacheDir(config.inputPath, config.cacheDir))
      )

  /** Every file that may be parsed, before a database narrows the set. */
  private lazy val candidates: Array[String] =
      SourceFiles
          .determine(
            config.inputPath,
            FileDefaults.SOURCE_FILE_EXTENSIONS ++ FileDefaults.HEADER_FILE_EXTENSIONS ++
                CppModules.ModuleUnitExtensions,
            ignoredDefaultRegex = Option(DefaultIgnoredFolders),
            ignoredFilesRegex = Option(config.ignoredFilesRegex),
            ignoredFilesPath = Option(config.ignoredFiles)
          )
          .toArray

  /** The files to parse, in the order the AST pass takes them. With a compilation database the
    * units it compiles and the project headers those units include, directly or through other
    * headers: a header the project defines functions in is where those bodies live (leveldb's
    * `port/port_stdcxx.h`), and parsing it as its own unit is the only way the CDT frontend slices
    * them. A header no compiled unit includes (another platform's port, a test helper) is not
    * parsed, and system headers are never candidates - they are not under the input path.
    */
  lazy val files: Array[String] =
    val selected = database match
      case None => candidates
      case Some(db) =>
          val compiled = candidates.filter(f =>
              !FileDefaults.isHeaderFile(f) && db.commandFor(Paths.get(f)).isDefined
          )
          val candidateHeaders = candidates.filter(FileDefaults.isHeaderFile)
          val graph = new IncludeGraph(
            (candidateHeaders ++ compiled).map(normalized).toSet,
            unit => includePathsFor(unit),
            headerFileFinder
          )
          val included = compiled.flatMap(u => graph.reachableFrom(normalized(u))).toSet
          compiled ++ candidateHeaders.filter(h => included.contains(normalized(h)))
    selected.sortWith(_.compareToIgnoreCase(_) > 0)

  private lazy val units: Seq[Path] =
      files.filterNot(FileDefaults.isHeaderFile).map(normalized).toSeq.sortBy(_.toString)

  private lazy val headers: Set[Path] =
      files.filter(FileDefaults.isHeaderFile).map(normalized).toSet

  lazy val modules: CppModules.ModuleIndex =
      new CppModules.ModuleIndex(
        units.filter(p => CppModules.isModuleUnitFile(p.toString)),
        units.filter(p => languageOfUnit(p) == SourceLanguage.Cpp)
      )

  private def flagsOf(file: Path): Option[CompileFlags] =
      database.flatMap(_.commandFor(file)).map(_.flags)

  /** A unit's language: what its compile command says, else its extension. */
  private def languageOfUnit(file: Path): SourceLanguage =
      flagsOf(file).flatMap(_.language).getOrElse {
          val name = file.toString
          val msvc = flagsOf(file).exists(_.family == CompilerFamily.Msvc)
          if FileDefaults.isCPPFile(name) || CppModules.isModuleUnitFile(name) then
            SourceLanguage.Cpp
          else if msvc && !name.endsWith(FileDefaults.C_EXT) then SourceLanguage.Cpp
          else SourceLanguage.C
      }

  /** The first unit of each language that includes each header. Only needed when headers can
    * differ: a project with units of both languages, or a database whose flags a header takes.
    */
  private lazy val includers: Map[Path, Map[SourceLanguage, Path]] =
      if database.isEmpty && projectLanguages.size <= 1 then Map.empty
      else includeGraph.includers(units.map(u => u -> languageOfUnit(u)))

  private lazy val includeGraph =
      new IncludeGraph(headers ++ units, unit => includePathsFor(unit), headerFileFinder)

  /** The include roots the project's includes are spelled from but no include path names, as the
    * CDT frontend finds headers by their trailing path segments (see IncludeGraph).
    */
  lazy val inferredIncludeRoots: Seq[Path] =
    units.foreach(u => includeGraph.reachableFrom(u))
    includeGraph.inferredIncludeRoots

  /** The project headers a translation unit includes, directly or through other headers. */
  def projectIncludes(unit: Path): Seq[Path] = includeGraph.reachableFrom(normalized(unit.toString))

  /** The unit each project header belongs to when a frontend writes a header with the first unit
    * that includes it: the first unit, in path order, of the header's language, else of any
    * language. A header no unit includes has none.
    */
  lazy val headerOwners: Map[Path, Path] =
    val byPath = units.toSeq.sortBy(_.toString)
    includeGraph.includers(byPath.map(u => u -> languageOfUnit(u))).flatMap {
        (header, byLanguage) =>
            byLanguage.get(headerContext(header)._1).orElse(
              byLanguage.values.minByOption(_.toString)
            )
                .map(header -> _)
    }

  private def includePathsFor(unit: Path): Seq[Path] =
      flagsOf(unit).map(_.includePaths).getOrElse(Nil) ++ configIncludePaths

  private lazy val configIncludePaths: Seq[Path] =
      config.includePaths.toSeq.map(p => Paths.get(p).toAbsolutePath.normalize)
          // CDT probes the search path in order: shallow directories first resolve the common
          // `<pkg/...>` includes with fewer failed probes, in a deterministic order
          .sortBy(p => (p.getNameCount, p.toString))

  private lazy val projectLanguages: Set[SourceLanguage] = units.map(languageOfUnit).toSet

  private val headerContexts = new ConcurrentHashMap[Path, (SourceLanguage, Option[Path])]()

  /** A header's language, and the unit whose flags it is parsed with. */
  private def headerContext(header: Path): (SourceLanguage, Option[Path]) =
      headerContexts.computeIfAbsent(header, resolveHeaderContext)

  private def resolveHeaderContext(header: Path): (SourceLanguage, Option[Path]) =
    val byLanguage = includers.getOrElse(header, Map.empty)
    val language =
        if FileDefaults.isCPPFile(header.toString) || byLanguage.contains(SourceLanguage.Cpp) then
          SourceLanguage.Cpp
        else if byLanguage.contains(SourceLanguage.C) then SourceLanguage.C
        else if !projectLanguages.contains(SourceLanguage.Cpp) then SourceLanguage.C
        else if !projectLanguages.contains(SourceLanguage.C) then SourceLanguage.Cpp
        else if IncludeGraph.readsAsCpp(header) then SourceLanguage.Cpp
        else SourceLanguage.C
    (language, byLanguage.get(language))

  private val settingsCache =
      new ConcurrentHashMap[(SourceLanguage, Option[CompileFlags]), UnitSettings]()

  /** How `file` is parsed. */
  def settingsFor(file: Path): UnitSettings =
    val path = normalized(file.toString)
    val (language, flags) =
        if headers.contains(path) || FileDefaults.isHeaderFile(path.toString) then
          val (lang, includer) = headerContext(path)
          (lang, includer.flatMap(flagsOf))
        else (languageOfUnit(path), flagsOf(path))
    settingsCache.computeIfAbsent(
      (language, flags),
      _ => ProjectSources.settings(config, language, flags, cacheDir)
    )

  /** The content of `file` as a unit of `language` reads it: a C++ file's module syntax rewritten.
    */
  def textOf(file: Path, language: SourceLanguage): Array[Char] =
      rewrite(file, CdtParser.readFileChars(file), language)

  /** `chars` of `file` with the dialect rewrites of `language`, module syntax included for C++. */
  def rewrite(file: Path, chars: Array[Char], language: SourceLanguage): Array[Char] =
      if language == SourceLanguage.Cpp then modules.rewrite(file, DialectRewrites.forCpp(chars))
      else DialectRewrites.forC(chars)
end ProjectSources

object ProjectSources:

  private val EscapedFileSeparator = Pattern.quote(java.io.File.separator)

  val DefaultIgnoredFolders: List[Regex] = List(
    "\\..*".r,
    s"(.*[$EscapedFileSeparator])?tests?[$EscapedFileSeparator].*".r,
    s"(.*[$EscapedFileSeparator])?CMakeFiles[$EscapedFileSeparator].*".r
  )

  private def normalized(file: String): Path = Paths.get(file).toAbsolutePath.normalize

  /** The settings of a file of `language` compiled with `flags` (none: the configured ones). The
    * compiler `flags` name is looked up in the directories `pathEnvironment` lists, the host's
    * `PATH` by default.
    */
  def settings(
    config: Config,
    language: SourceLanguage,
    flags: Option[CompileFlags],
    cacheDir: Option[Path],
    pathEnvironment: String = ExecutableLookup.currentPath()
  ): UnitSettings =
    val cpp = language == SourceLanguage.Cpp
    val identity: Option[CompilerIdentity] = flags match
      case Some(f) =>
          f.compiler.filter(_ => RunnableFamilies.contains(f.family))
              .flatMap(trustedExecutable(_, config, pathEnvironment)).map(exe =>
                  CompilerIdentity(exe, f.family, language, f.targetOptions)
              )
      case None if config.includePathsAutoDiscovery => hostCompiler(config, language)
      case None                                     => None
    val facts = identity.flatMap(PredefinedMacros.ofCompiler(_, cacheDir))
    val family =
        flags.map(_.family).orElse(identity.map(_.family)).getOrElse(CompilerFamily.Unknown)
    val predefined: Map[String, String] = facts.map(_.macros).orElse(
      flags.map(f => PredefinedMacros.fallback(f.family, language, f.targetOptions))
    ).filter(_.nonEmpty).getOrElse(DefaultDefines.GNU_COMPILER ++ DefaultDefines.HOST_TYPE_SIZES)
    // MSVC's keywords are spelled out for MSVC, and wherever the real compiler is not known
    val msvcKeywords =
        if family == CompilerFamily.Msvc || facts.isEmpty && flags.isEmpty then
          DefaultDefines.DEFAULT_CALL_CONVENTIONS
        else Map.empty[String, String]
    val fromFlags = flags.toSeq.flatMap(_.macros).foldLeft(Map.empty[String, Option[String]]) {
        case (acc, MacroChange.Define(name, value)) => acc + (name -> Some(value))
        case (acc, MacroChange.Undefine(name))      => acc + (name -> None)
    }
    val undefined = fromFlags.collect { case (name, None) => name }.toSet
    var symbols = UnitSettings.FeatureTests ++ predefined ++ msvcKeywords ++
        fromFlags.collect { case (name, Some(v)) => name -> v } -- undefined ++
        UnitSettings.userDefines(config)
    if cpp then
      val std = Option(config.cppStandard).filter(_.nonEmpty).flatMap(UnitSettings.cplusplusFor)
          .orElse(Option(config.cppStandard).filter(_.nonEmpty))
      std match
        case Some(value)                              => symbols += "__cplusplus" -> value
        case None if !symbols.contains("__cplusplus") => symbols += "__cplusplus" -> "201703L"
        case None                                     =>
      // `export` marks an exported declaration of a module interface unit; see CppModules
      if !symbols.contains("export") then symbols += "export" -> ""
    else
      symbols -= "__cplusplus"
      // C23's `typeof_unqual` is no keyword to the parser; GCC's `__typeof__` names the same
      // type but for its qualifiers, which no declared type here keeps
      if flags.flatMap(_.standard).exists(UnitSettings.isC23OrLater) then
        for kw <- Seq("typeof_unqual", "__typeof_unqual__") if !symbols.contains(kw) do
          symbols += kw -> "__typeof__"
      // C11's `_Noreturn` is no keyword to the parser either; GCC's attribute declares the same
      // function, and what calls it then reads that the path ends there
      if !symbols.contains("_Noreturn") then symbols += "_Noreturn" -> "__attribute__((noreturn))"
    // the compiler's own search order: a C++ library's wrapper headers (`<cstdlib>`'s
    // `<stdlib.h>`) must be found before the C library's, and `#include_next` relies on it
    val systemIncludes = facts.map(_.systemIncludePaths).filter(_.nonEmpty).getOrElse(
      if cpp then IncludeAutoDiscovery.discoverIncludePathsCPP(config).toSeq.sortBy(_.toString)
      else IncludeAutoDiscovery.discoverIncludePathsC(config).toSeq.sortBy(_.toString)
    )
    val configIncludes = config.includePaths.toSeq.map(p => Paths.get(p).toAbsolutePath.normalize)
        .sortBy(p => (p.getNameCount, p.toString))
    UnitSettings(
      language,
      symbols,
      (flags.toSeq.flatMap(_.includePaths) ++ configIncludes ++
          flags.toSeq.flatMap(_.systemIncludePaths) ++ systemIncludes).distinct,
      flags.toSeq.flatMap(_.includeFiles) ++
          config.includeFiles.toSeq.sorted.map(p => Paths.get(p).toAbsolutePath),
      flags.toSeq.flatMap(_.macroFiles) ++
          config.macroFiles.toSeq.sorted.map(p => Paths.get(p).toAbsolutePath),
      identity,
      flags.flatMap(_.standard)
    )
  end settings

  /** The compilers asked for their macros: the GCC and Clang drivers, which answer `-dM -E`. A
    * command of any other name is not run (its family's table stands in), so a compilation database
    * cannot have an arbitrary program started.
    */
  private val RunnableFamilies = Set(CompilerFamily.Gcc, CompilerFamily.Clang)

  /** The compiler a compile command names, when it may be run: a command found in one of the `PATH`
    * directories, or an absolute path to a file in one of them, outside the project. A relative
    * path, any other absolute path, or anything inside the project tree is never run (its table
    * stands in). A compilation database can come with the code it describes, and that code is not
    * confined to the input path: the rest of a checkout whose subdirectory is scanned can be named
    * by an absolute path too. Only absolute `PATH` entries count, as a relative one depends on the
    * working directory. Only the options that change which macros are predefined are passed to it
    * (see [[CompileCommand.parseArguments]]).
    */
  private[parser] def trustedExecutable(
    compiler: String,
    config: Config,
    pathEnvironment: String = ExecutableLookup.currentPath()
  ): Option[String] =
    val inputPath = Paths.get(config.inputPath).toAbsolutePath.normalize
    // real paths are compared: the project may be reached through a symbolic link
    val root     = Try(inputPath.toRealPath()).getOrElse(inputPath)
    val pathDirs = ExecutableLookup.absolutePathDirectories(pathEnvironment)
    val named    = Try(Paths.get(compiler)).toOption
    val candidates: Seq[Path] = named match
      case Some(p) if p.isAbsolute =>
          // `..` segments are folded before the file system is asked, so the lookup cannot pass
          // through directories the compiler path merely names
          val normalized = p.normalize
          Option(normalized.getParent).filter(isPathDirectory(_, pathDirs)).map(_ =>
              normalized
          ).toSeq
      case Some(p) if p.getNameCount == 1 && !compiler.contains('/') && !compiler.contains('\\') =>
          val suffixes = if scala.util.Properties.isWin then Seq("", ".exe") else Seq("")
          pathDirs.flatMap(dir => suffixes.map(sfx => dir.resolve(compiler + sfx)))
      case _ => Nil
    candidates.filter(p => Files.isRegularFile(p) && Files.isExecutable(p))
        .flatMap(p => Try(p.toRealPath()).toOption.map(p -> _))
        .find((p, real) => !real.startsWith(root) && !p.startsWith(inputPath))
        .map(_._2.toString)
  end trustedExecutable

  /** Whether `dir` is one of the `PATH` directories `pathDirs`: the same path, or the same
    * directory reached through a symbolic link (the same device and inode).
    */
  private def isPathDirectory(dir: Path, pathDirs: Seq[Path]): Boolean =
    def key(p: Path) = if scala.util.Properties.isWin then p.toString.toLowerCase else p.toString
    pathDirs.exists(p => key(p) == key(dir)) || Files.isDirectory(dir) && inodeKnown(dir) &&
    pathDirs.exists(p => Try(Files.isDirectory(p) && Files.isSameFile(p, dir)).getOrElse(false))

  /** False for a file system that reports inode 0, where every file would look the same. */
  private def inodeKnown(path: Path): Boolean =
      Try(Files.getAttribute(path, "unix:ino")).toOption match
        case Some(ino: java.lang.Long) => ino.longValue != 0L
        case Some(_)                   => true
        case None                      => true

  /** The C++ standard a unit without a compile command is parsed as, unless one is configured. */
  val DefaultCppStandard = "gnu++17"

  /** The host's GCC (or Clang when there is no GCC), as include discovery uses it, asked for the
    * configured C++ standard (C++17 when none is): a compiler's own default can be older, and the
    * standard library hides what a newer standard adds.
    */
  private def hostCompiler(config: Config, language: SourceLanguage): Option[CompilerIdentity] =
    val std =
        if language != SourceLanguage.Cpp then Nil
        else
          val configured = Option(config.cppStandard).map(_.trim.toLowerCase)
              .filter(s => s.startsWith("c++") || s.startsWith("gnu++"))
          Seq(s"-std=${configured.getOrElse(DefaultCppStandard)}")
    if IncludeAutoDiscovery.gccAvailable() then
      IncludeAutoDiscovery.gccExecutable().map(CompilerIdentity(
        _,
        CompilerFamily.Gcc,
        language,
        std
      ))
    else if IncludeAutoDiscovery.clangAvailable() then
      IncludeAutoDiscovery.clangExecutable().map(
        CompilerIdentity(_, CompilerFamily.Clang, language, std)
      )
    else None
end ProjectSources
