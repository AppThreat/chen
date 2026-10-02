package io.appthreat.c2cpg.parser

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery
import io.appthreat.x2cpg.SourceFiles
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
  macroFiles: Seq[Path]
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

  /** The files to parse, in the order the AST pass takes them. */
  lazy val files: Array[String] =
    val selected = database match
      case None => candidates
      case Some(db) =>
          candidates.filter { f =>
              if FileDefaults.isHeaderFile(f) then !config.compileCommandsOnly
              else db.commandFor(Paths.get(f)).isDefined
          }
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
      else
        val projectFiles = headers ++ units
        val graph = new IncludeGraph(projectFiles, unit => includePathsFor(unit), headerFileFinder)
        graph.includers(units.map(u => u -> languageOfUnit(u)))

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
    val chars = CdtParser.readFileChars(file)
    if language == SourceLanguage.Cpp then modules.rewrite(file, chars) else chars
end ProjectSources

object ProjectSources:

  private val EscapedFileSeparator = Pattern.quote(java.io.File.separator)

  val DefaultIgnoredFolders: List[Regex] = List(
    "\\..*".r,
    s"(.*[$EscapedFileSeparator])?tests?[$EscapedFileSeparator].*".r,
    s"(.*[$EscapedFileSeparator])?CMakeFiles[$EscapedFileSeparator].*".r
  )

  private def normalized(file: String): Path = Paths.get(file).toAbsolutePath.normalize

  /** The settings of a file of `language` compiled with `flags` (none: the configured ones). */
  def settings(
    config: Config,
    language: SourceLanguage,
    flags: Option[CompileFlags],
    cacheDir: Option[Path]
  ): UnitSettings =
    val cpp = language == SourceLanguage.Cpp
    val identity: Option[CompilerIdentity] = flags match
      case Some(f) =>
          f.compiler.flatMap(trustedExecutable(_, config)).map(exe =>
              CompilerIdentity(exe, f.family, language, f.targetOptions)
          )
      case None if config.includePathsAutoDiscovery => hostCompiler(config, language)
      case None                                     => None
    val facts = identity.flatMap(PredefinedMacros.ofCompiler(_, cacheDir))
    val family =
        flags.map(_.family).orElse(identity.map(_.family)).getOrElse(CompilerFamily.Unknown)
    val predefined: Map[String, String] = facts.map(_.macros).orElse(
      flags.map(f => PredefinedMacros.fallback(f.family, language, f.targetOptions))
    ).filter(_.nonEmpty).getOrElse(DefaultDefines.GNU_COMPILER)
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
    else symbols -= "__cplusplus"
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
          config.macroFiles.toSeq.sorted.map(p => Paths.get(p).toAbsolutePath)
    )
  end settings

  /** The compiler a compile command names, when it may be run: a command found on the `PATH`, or an
    * absolute path to an executable, outside the project. A compilation database can come with the
    * code it describes, so a compiler inside the project tree, or named by a relative path that
    * resolves into it, is never run (its table stands in). Only the options that change which
    * macros are predefined are passed to it (see [[CompileCommand.parseArguments]]).
    */
  private def trustedExecutable(compiler: String, config: Config): Option[String] =
    val root = Try(Paths.get(config.inputPath).toRealPath()).getOrElse(
      Paths.get(config.inputPath).toAbsolutePath.normalize
    )
    val named = Try(Paths.get(compiler)).toOption
    val candidates: Seq[Path] = named match
      case Some(p) if p.isAbsolute => Seq(p)
      case Some(p) if p.getNameCount == 1 && !compiler.contains('/') && !compiler.contains('\\') =>
          val suffixes = if scala.util.Properties.isWin then Seq("", ".exe") else Seq("")
          sys.env.getOrElse("PATH", "").split(java.io.File.pathSeparator).toSeq.filter(_.nonEmpty)
              .flatMap(dir => suffixes.map(sfx => Paths.get(dir).resolve(compiler + sfx)))
      case _ => Nil
    candidates.find(p => Files.isRegularFile(p) && Files.isExecutable(p))
        .flatMap(p => Try(p.toRealPath()).toOption)
        .filterNot(_.startsWith(root))
        .map(_.toString)

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
      Some(CompilerIdentity("gcc", CompilerFamily.Gcc, language, std))
    else if IncludeAutoDiscovery.clangAvailable() then
      Some(CompilerIdentity("clang", CompilerFamily.Clang, language, std))
    else None
end ProjectSources
