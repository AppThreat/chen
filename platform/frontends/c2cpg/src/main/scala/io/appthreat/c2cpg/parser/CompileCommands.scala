package io.appthreat.c2cpg.parser

import org.slf4j.LoggerFactory

import java.nio.file.{Files, Path, Paths}
import scala.collection.mutable
import scala.util.Try

/** The language a translation unit is compiled as. */
enum SourceLanguage:
  case C, Cpp

/** The family of a compiler driver, which decides how its command line is read and which predefined
  * macros it has. The families the driver table names for other toolchains carry their own macro
  * tables and dialects (see [[Toolchains]]); an unrecognized driver is an `Unknown` one, and its
  * settings fall back to the host compiler's, as they always have.
  */
enum CompilerFamily:
  case Gcc, Clang, Msvc, Nvcc, IntelLlvm, Emscripten, TinyC, Iar, TiArm, TiMsp430, Unknown

/** A preprocessor definition or removal from a command line, applied in order. */
enum MacroChange:
  case Define(name: String, value: String)
  case Undefine(name: String)

/** What a compile command says about how one file is compiled: the compiler, the language and
  * standard, the include search path, the macros, and the files forced into the translation unit.
  * Paths are absolute.
  */
final case class CompileFlags(
  compiler: Option[String] = None,
  family: CompilerFamily = CompilerFamily.Unknown,
  language: Option[SourceLanguage] = None,
  standard: Option[String] = None,
  includePaths: Seq[Path] = Nil,
  systemIncludePaths: Seq[Path] = Nil,
  macros: Seq[MacroChange] = Nil,
  includeFiles: Seq[Path] = Nil,
  macroFiles: Seq[Path] = Nil,
  /** The options that change which macros the compiler predefines (target, sysroot, machine,
    * optimisation and feature options), passed on when the compiler is asked for them.
    */
  targetOptions: Seq[String] = Nil,
  /** The driver table entry the command's driver matched, by name; empty when the table does not
    * know the driver, whose settings then fall back to the host compiler's.
    */
  entry: Option[String] = None
)

/** One entry of a JSON compilation database (`compile_commands.json`). */
final case class CompileCommand(directory: Path, file: Path, arguments: Seq[String]):
  lazy val flags: CompileFlags = CompileCommand.parseArguments(arguments, directory)

object CompileCommand:

  /** Splits a command string the way the shell its driver runs under would: the Windows rules of
    * `CommandLineToArgvW` when the command names Windows paths, POSIX quoting otherwise. A compile
    * database recorded on Windows names them whatever driver the entry runs, `cc` as much as
    * `cl.exe`, and there the backslash of a path is the separator no shell ate, where the POSIX
    * reading loses it and the option's value with it (`-IC:\lib` read as `-IC:lib`).
    */
  def tokenize(command: String): Seq[String] =
    val first = posixWords(command).headOption.getOrElse("")
    if windowsPaths(command) || familyOf(first) == CompilerFamily.Msvc then windowsWords(command)
    else posixWords(command)

  /** Whether the command names a path in the Windows spelling: a drive letter, then a single
    * backslash (`-IC:\Users\...`, or a driver under `C:\msys64`). One backslash it is in such a
    * database, for the recorder wrote the command line as the build ran it; a doubled one stays a
    * POSIX entry, where the shell that ran it doubled every literal backslash (`-DX=a\\b`), and the
    * escape reading is the faithful one.
    */
  private def windowsPaths(command: String): Boolean =
      command.matches("""(?s).*[A-Za-z]:\\(?!\\).*""")

  /** POSIX shell word splitting: whitespace separates words, single quotes keep everything, double
    * quotes keep everything but `\"`, `\\`, `\$` and `` \` ``, and a backslash outside quotes
    * escapes the next character.
    */
  def posixWords(command: String): Seq[String] =
    val words   = mutable.ArrayBuffer.empty[String]
    val current = new StringBuilder
    var inWord  = false
    var i       = 0
    val n       = command.length
    while i < n do
      val c = command.charAt(i)
      c match
        case ' ' | '\t' | '\n' | '\r' =>
            if inWord then
              words += current.toString
              current.clear()
              inWord = false
        case '\'' =>
            inWord = true
            val end  = command.indexOf('\'', i + 1)
            val stop = if end < 0 then n else end
            current.append(command.substring(i + 1, stop))
            i = stop
        case '"' =>
            inWord = true
            i += 1
            while i < n && command.charAt(i) != '"' do
              val d = command.charAt(i)
              if d == '\\' && i + 1 < n && "\"\\$`".indexOf(command.charAt(i + 1)) >= 0 then
                current.append(command.charAt(i + 1))
                i += 1
              else current.append(d)
              i += 1
        case '\\' if i + 1 < n =>
            inWord = true
            current.append(command.charAt(i + 1))
            i += 1
        case other =>
            inWord = true
            current.append(other)
      end match
      i += 1
    end while
    if inWord then words += current.toString
    words.toSeq
  end posixWords

  /** Windows command-line splitting (the rules of `CommandLineToArgvW`, which `cl.exe` follows):
    * `2n` backslashes before a quote give `n` backslashes and toggle quoting, `2n+1` give `n`
    * backslashes and a literal quote, and backslashes elsewhere are literal.
    */
  def windowsWords(command: String): Seq[String] =
    val words    = mutable.ArrayBuffer.empty[String]
    val current  = new StringBuilder
    var inWord   = false
    var inQuotes = false
    var i        = 0
    val n        = command.length
    while i < n do
      val c = command.charAt(i)
      if (c == ' ' || c == '\t') && !inQuotes then
        if inWord then
          words += current.toString
          current.clear()
          inWord = false
        i += 1
      else if c == '\\' then
        var slashes = 0
        while i < n && command.charAt(i) == '\\' do
          slashes += 1
          i += 1
        inWord = true
        if i < n && command.charAt(i) == '"' then
          current.append("\\" * (slashes / 2))
          if slashes % 2 == 1 then
            current.append('"')
            i += 1
        else current.append("\\" * slashes)
      else if c == '"' then
        inWord = true
        if inQuotes && i + 1 < n && command.charAt(i + 1) == '"' then
          current.append('"')
          i += 2
        else
          inQuotes = !inQuotes
          i += 1
      else
        inWord = true
        current.append(c)
        i += 1
      end if
    end while
    if inWord then words += current.toString
    words.toSeq
  end windowsWords

  /** The family of the compiler a driver path names: the driver table's entry, or an unknown family
    * when no entry matches.
    */
  def familyOf(driver: String): CompilerFamily =
      Toolchains.entryFor(Seq(driver)).flatMap(_.family).getOrElse(CompilerFamily.Unknown)

  /** Whether the driver compiles every file as C++, whatever its extension: what its table entry
    * says, else what its name spells (`g++`, `clang++`, the two-word `zig c++`).
    */
  private def isCppDriver(driver: String): Boolean =
    val name = Paths.get(driver.replace('\\', '/')).getFileName match
      case null => ""
      case p    => p.toString.toLowerCase.stripSuffix(".exe")
    Toolchains.entryFor(Seq(driver)).flatMap(_.alwaysCpp).getOrElse(
      name.endsWith("++") || name.contains("++-") || name.endsWith("clang++")
    )

  private def languageOf(value: String): Option[SourceLanguage] = value match
    case "c" | "c-header" | "cpp-output"                        => Some(SourceLanguage.C)
    case "c++" | "c++-header" | "c++-cpp-output" | "c++-module" => Some(SourceLanguage.Cpp)
    case _                                                      => None

  private def macroChange(definition: String): MacroChange =
      definition.split("=", 2) match
        case Array(name, value) => MacroChange.Define(name, value)
        // `-DNAME` defines NAME as 1
        case Array(name) => MacroChange.Define(name, "1")

  /** Reads the options that shape how a file is preprocessed from a compile command's arguments.
    * Relative paths are resolved against `directory`. Unknown options are ignored.
    */
  def parseArguments(arguments: Seq[String], directory: Path): CompileFlags =
    val args   = arguments.dropWhile(Toolchains.isWrapper)
    val driver = args.headOption
    val entry  = Toolchains.entryFor(args)
    var family =
        if args.contains("--driver-mode=cl") then CompilerFamily.Msvc
        else entry.flatMap(_.family).orElse(driver.map(familyOf)).getOrElse(CompilerFamily.Unknown)
    // a two-word driver's always-C++ spelling lives in its second word (`zig c++`), so the name
    // rule reads the joined name for an entry that matched two arguments
    val cppDriver = entry.flatMap(_.alwaysCpp).orElse(driver.map(isCppDriver))
    var language: Option[SourceLanguage] =
        cppDriver.collect { case true => SourceLanguage.Cpp }
    var standard: Option[String] = None
    val includes                 = mutable.ArrayBuffer.empty[Path]
    val quoteIncludes            = mutable.ArrayBuffer.empty[Path]
    val systemIncludes           = mutable.ArrayBuffer.empty[Path]
    val afterIncludes            = mutable.ArrayBuffer.empty[Path]
    val macros                   = mutable.ArrayBuffer.empty[MacroChange]
    val includeFiles             = mutable.ArrayBuffer.empty[Path]
    val macroFiles               = mutable.ArrayBuffer.empty[Path]
    val targetOptions            = mutable.ArrayBuffer.empty[String]
    val positional               = mutable.ArrayBuffer.empty[String]

    def path(p: String): Path = directory.resolve(p.replace('\\', '/')).normalize
    val rest                  = args.drop(1).toIndexedSeq
    var i                     = 0
    // an option's value: joined (`-Ifoo`, `-I=foo`) or the next argument (`-I foo`)
    def valueOf(arg: String, option: String): Option[String] =
      val joined = arg.substring(option.length)
      if joined.nonEmpty then Some(joined)
      else if i + 1 < rest.length then
        i += 1
        Some(rest(i))
      else None
    val msvc = family == CompilerFamily.Msvc
    while i < rest.length do
      val arg = rest(i)
      // the target the driver is asked to compile for, and the driver mode it runs with, are
      // kept whatever option spelling the family reads: they decide which predefined macro
      // table the fallback selects (clang's MSVC mode) and which target it stands for
      if arg.startsWith("--target=") then targetOptions += arg
      else if arg.startsWith("--driver-mode=") then
        if arg == "--driver-mode=g++" then language = Some(SourceLanguage.Cpp)
        targetOptions += arg
      else if msvc && (arg.startsWith("/") || arg.startsWith("-")) && arg.length > 1 then
        val opt = arg.substring(1)
        if opt.startsWith("I") then valueOf(arg, arg.take(2)).foreach(v => includes += path(v))
        else if opt.startsWith("external:I") then
          valueOf(arg, arg.take(11)).foreach(v => systemIncludes += path(v))
        else if opt.startsWith("D") then
          valueOf(arg, arg.take(2)).foreach(v => macros += macroChange(v))
        else if opt.startsWith("U") then
          valueOf(arg, arg.take(2)).foreach(v => macros += MacroChange.Undefine(v))
        else if opt.startsWith("FI") then
          valueOf(arg, arg.take(3)).foreach(v => includeFiles += path(v))
        else if opt.startsWith("std:") then standard = Some(opt.stripPrefix("std:"))
        else if opt == "TP" || opt.startsWith("Tp") then language = Some(SourceLanguage.Cpp)
        else if opt == "TC" || opt.startsWith("Tc") then language = Some(SourceLanguage.C)
        else if opt.startsWith("arch:") || opt.startsWith("Zc:") || opt == "EHsc" || opt == "GR" ||
          opt == "GR-" || opt.startsWith("MD") || opt.startsWith("MT") || opt.startsWith("O")
        then targetOptions += arg
      else if arg.startsWith("-iquote") then
        valueOf(arg, "-iquote").foreach(v => quoteIncludes += path(v))
      else if arg.startsWith("-isystem") then
        valueOf(arg, "-isystem").foreach(v => systemIncludes += path(v))
      else if arg.startsWith("-idirafter") then
        valueOf(arg, "-idirafter").foreach(v => afterIncludes += path(v))
      else if arg.startsWith("-isysroot") then
        valueOf(arg, "-isysroot").foreach(v => targetOptions ++= Seq("-isysroot", path(v).toString))
      else if arg.startsWith("-imacros") then
        valueOf(arg, "-imacros").foreach(v => macroFiles += path(v))
      else if arg == "-include" || arg.startsWith("-include=") then
        valueOf(arg, if arg.startsWith("-include=") then "-include=" else "-include")
            .foreach(v => includeFiles += path(v))
      else if arg.startsWith("-I") then
        valueOf(arg, "-I").map(_.stripPrefix("=")).foreach(v => includes += path(v))
      else if arg.startsWith("-D") then valueOf(arg, "-D").foreach(v => macros += macroChange(v))
      else if arg.startsWith("-U") then
        valueOf(arg, "-U").foreach(v => macros += MacroChange.Undefine(v))
      else if arg.startsWith("-std=") then
        standard = Some(arg.stripPrefix("-std="))
        targetOptions += arg
      else if arg.startsWith("-x") then
        valueOf(arg, "-x").flatMap(languageOf).foreach(l => language = Some(l))
      else if arg == "-target" || arg == "--target" then
        valueOf(arg, arg).foreach(v => targetOptions ++= Seq("--target=" + v))
      else if arg == "-arch" then valueOf(arg, arg).foreach(v => targetOptions ++= Seq("-arch", v))
      else if arg == "--sysroot" then
        valueOf(arg, arg).foreach(v => targetOptions += s"--sysroot=${path(v)}")
      else if arg.startsWith("--sysroot=") then
        targetOptions += s"--sysroot=${path(arg.stripPrefix("--sysroot="))}"
      // the host compiler nvcc runs its .cu files' compilation with, kept in the spelling the
      // driver accepts for its own options
      else if arg == "-ccbin" || arg == "--compiler-bindir" then
        valueOf(arg, arg).foreach(v => targetOptions += s"-ccbin=$v")
      else if arg.startsWith("-ccbin=") || arg.startsWith("--compiler-bindir=") then
        targetOptions += s"-ccbin=${arg.substring(arg.indexOf('=') + 1)}"
      else if arg.startsWith("-m") || arg.startsWith("-O") || arg == "-ansi" ||
        arg == "-pthread" || arg.startsWith("-fsanitize") || arg.startsWith("-fno-") ||
        isMacroAffectingFeature(arg)
      then targetOptions += arg
      else if !arg.startsWith("-") then positional += arg
      end if
      i += 1
    end while
    // a driver the table maps from one extension to C++ (nvcc's .cu units) says so itself
    if entry.exists(e =>
          e.cppByExtension.exists(ext =>
              positional.exists(_.toLowerCase.stripSuffix(".exe").endsWith(ext))
          )
      )
    then language = Some(SourceLanguage.Cpp)
    CompileFlags(
      compiler = driver,
      family = family,
      language = language,
      standard = standard,
      // gcc searches -iquote directories for "" includes only, then -I, -isystem, -idirafter
      includePaths = (quoteIncludes ++ includes).distinct.toSeq,
      systemIncludePaths = (systemIncludes ++ afterIncludes).distinct.toSeq,
      macros = macros.toSeq,
      includeFiles = includeFiles.toSeq,
      macroFiles = macroFiles.toSeq,
      targetOptions = targetOptions.toSeq,
      entry = entry.map(_.name)
    )
  end parseArguments

  /** `-f` options that set a predefined macro (`__PIC__`, `__EXCEPTIONS`, `__GXX_RTTI`, ...). */
  private def isMacroAffectingFeature(arg: String): Boolean =
      Seq(
        "-fPIC",
        "-fpic",
        "-fPIE",
        "-fpie",
        "-fexceptions",
        "-frtti",
        "-fshort-wchar",
        "-fshort-enums",
        "-funsigned-char",
        "-fsigned-char",
        "-fopenmp",
        "-fms-extensions",
        "-fms-compatibility",
        "-fchar8_t",
        "-fcoroutines",
        "-fmodules",
        "-ffast-math",
        "-ffreestanding",
        "-fgnu89-inline",
        "-fstack-protector"
      ).exists(arg.startsWith)
end CompileCommand

/** How a compile command's driver is recognised, read from the module's driver table
  * (`toolchains.json` in the resources). Every entry names the drivers it covers, the family its
  * commands are read as, whether every file compiles as C++, the command a runnable compiler is
  * asked with for its macros and include directories, the fallback macro table for when it cannot
  * be run, and the dialect the parsers and the EDG front end are given. The GCC, Clang and MSVC
  * entries carry the matchers those families have always answered to, so their drivers keep their
  * behaviour.
  *
  * The first entry whose matcher accepts a command wins, so specific drivers (`clang-cl`, the
  * two-word `zig cc`) stand before the families that would otherwise swallow them.
  */
object Toolchains:

  private val logger = LoggerFactory.getLogger(getClass)

  /** The dialect the EDG front end emulates for a compiler: `host` reads it from the compiler's own
    * macros, as the GCC, Clang and MSVC families always have; `none` leaves the front end's default
    * dialect, for compilers whose dialect the front end has no emulation of.
    */
  enum EdgDialect:
    case Host, Gnu, Clang, Microsoft, None

  /** How an entry recognises the drivers it covers. */
  enum Matcher:
    /** The driver's file name; a two-word driver is spelled with its second word (`zig cc`). */
    case Name(value: String)
    case Contains(value: String)
    case Prefix(value: String)
    case Suffix(value: String)

    /** The command carries `--driver-mode=<value>`. */
    case DriverMode(value: String)

  /** The command a runnable compiler is asked with for its macros and its include search path:
    * `<executable> <prefixArgs> <options> <args, with <lang> replaced> -`. A two-word driver runs
    * through its subcommand (`zig cc`).
    */
  final case class Probe(prefixArgs: Seq[String] = Nil, args: Seq[String])

  /** One entry of the driver table. */
  final case class Entry(
    name: String,
    family: Option[CompilerFamily],
    matches: Seq[Matcher],
    wrapper: Boolean = false,
    /** Whether every file is compiled as C++, whatever its extension. */
    alwaysCpp: Option[Boolean] = None,
    /** The file extensions this driver compiles as C++ by its own rule (nvcc's `.cu` units). */
    cppByExtension: Seq[String] = Nil,
    probe: Option[Probe] = None,
    /** The option naming the host compiler whose macros a unit is preprocessed with (nvcc's
      * `-ccbin`).
      */
    hostOption: Option[String] = None,
    /** The fallback macro tables' name stem, for when the compiler cannot be run: the tables of the
      * compiler's family whose names start with it (see [[PredefinedMacros]]).
      */
    fallbackTable: Option[String] = None,
    edgDialect: EdgDialect = EdgDialect.Host
  )

  private lazy val entries: Seq[Entry] =
      Try(ujson.read(getClass.getResourceAsStream("/toolchains.json"))).toOption match
        case Some(json) =>
            Try(json.obj("drivers").arr.toSeq.map(readEntry)).getOrElse {
                logger.warn("The driver table resource is malformed; no driver is recognised")
                Nil
            }
        case None =>
            logger.warn("The driver table resource is missing; no driver is recognised")
            Nil

  private def readEntry(value: ujson.Value): Entry =
    val obj = value.obj
    Entry(
      name = obj("name").str,
      family = obj.get("family").map(v => CompilerFamily.valueOf(v.str)),
      matches = obj("matches").arr.toSeq.map(readMatcher),
      wrapper = obj.get("wrapper").exists(_.bool),
      alwaysCpp = obj.get("alwaysCpp").map(_.bool),
      cppByExtension = obj.get("cppByExtension").map(_.arr.toSeq.map(_.str)).getOrElse(Nil),
      probe = obj.get("probe").map(readProbe),
      hostOption = obj.get("hostOption").map(_.str),
      fallbackTable = obj.get("fallbackTable").map(_.str),
      edgDialect = obj
          .get("edgDialect")
          .map(v => EdgDialect.valueOf(v.str.capitalize))
          .getOrElse(EdgDialect.Host)
    )

  private def readMatcher(value: ujson.Value): Matcher =
    val spelled = value.str
    val kind    = spelled.takeWhile(_ != ':')
    val rest    = spelled.drop(kind.length + 1)
    kind match
      case "name"       => Matcher.Name(rest.toLowerCase)
      case "contains"   => Matcher.Contains(rest.toLowerCase)
      case "prefix"     => Matcher.Prefix(rest.toLowerCase)
      case "suffix"     => Matcher.Suffix(rest.toLowerCase)
      case "driverMode" => Matcher.DriverMode(rest)
      case other =>
          throw new IllegalArgumentException(s"unknown driver matcher '$other' in $spelled")

  private def readProbe(value: ujson.Value): Probe =
    val obj = value.obj
    Probe(
      prefixArgs = obj.get("prefixArgs").map(_.arr.toSeq.map(_.str)).getOrElse(Nil),
      args = obj("args").arr.toSeq.map(_.str)
    )

  /** The file name a driver word is recognised by: the base name, without its Windows suffix,
    * lowercased. Read as text rather than as a Path, since a command word need not be a valid path
    * on the host (`-IC:/inc` is not one on Windows).
    */
  private def nameOf(driver: String): String =
    val slashed = driver.replace('\\', '/').stripSuffix("/")
    slashed.substring(slashed.lastIndexOf('/') + 1).toLowerCase.stripSuffix(".exe")

  private def matches(
    matcher: Matcher,
    driver: Option[String],
    arguments: Seq[String]
  ): Boolean =
      matcher match
        case Matcher.Name(value) =>
            driver.exists(_ == value) ||
            // a two-word driver ("zig cc"): the joined first two arguments of the command
            (arguments.size >= 2 && s"${nameOf(arguments.head)} ${arguments(1).toLowerCase}" == value)
        case Matcher.Contains(value) => driver.exists(_.contains(value))
        case Matcher.Prefix(value)   => driver.exists(_.startsWith(value))
        case Matcher.Suffix(value)   => driver.exists(_.endsWith(value))
        case Matcher.DriverMode(value) =>
            arguments.contains(s"--driver-mode=$value")
  end matches

  /** The entry a compile command's arguments are read as: the first entry whose matcher accepts the
    * command's driver, whether by its name, a part of it, or an option the command carries.
    */
  def entryFor(arguments: Seq[String]): Option[Entry] =
      entries.find(e =>
          !e.wrapper && e.matches.exists(matches(_, arguments.headOption.map(nameOf), arguments))
      )

  /** The entry of that name, as a compile command keeps it. */
  def entryNamed(name: String): Option[Entry] = entries.find(e => e.name == name && !e.wrapper)

  /** The entry of a family the family's own questions are asked with (the probe for its macros, the
    * stem of its fallback tables): the entry named after the family itself, so the order of the
    * specific drivers around it cannot change what plain compilers of that family are asked. A
    * family with no entry of its own name keeps its first entry.
    */
  def entryForFamily(family: CompilerFamily): Option[Entry] =
    val ofFamily = entries.filter(e => e.family.contains(family) && !e.wrapper)
    ofFamily.find(e => e.name.equalsIgnoreCase(family.toString)).orElse(ofFamily.headOption)

  /** Whether the argument is a compiler wrapper that runs the compiler named by the next argument.
    */
  def isWrapper(argument: String): Boolean =
      entries.exists(e =>
          e.wrapper && e.matches.exists {
              case Matcher.Name(value) => nameOf(argument) == value
              case _                   => false
          }
      )

  /** The family of the host compiler a driver's unit is preprocessed with, when a table entry names
    * the option that spells it (nvcc's `-ccbin`) and the command carries it.
    */
  def hostFamilyOf(options: Seq[String]): Option[CompilerFamily] =
      entries.flatMap(e => e.hostOption.map(option => (option, e))).collectFirst {
          case (option, _)
              if options.exists(o => o.startsWith(option + "=")) =>
              options.collectFirst {
                  case o if o.startsWith(option + "=") =>
                      if o.stripPrefix(option + "=").toLowerCase.contains("clang") then
                        CompilerFamily.Clang
                      else CompilerFamily.Gcc
              }.getOrElse(CompilerFamily.Gcc)
      }
end Toolchains

/** A JSON compilation database: the compile command of every translation unit of a build. */
final class CompileDatabase private (val path: Path, commands: Seq[CompileCommand]):

  private val byFile: Map[Path, CompileCommand] =
      commands.reverse.map(c => CompileDatabase.key(c.file) -> c).toMap

  /** Every command the database carries for a file, in database order: a database may compile one
    * file more than once, and each entry is one build context of the file.
    */
  private val byFileAll: Map[Path, Seq[CompileCommand]] =
      commands.groupBy(c => CompileDatabase.key(c.file))

  /** The translation units the database compiles, in database order and without duplicates. */
  val files: Seq[Path] = commands.map(_.file).distinctBy(CompileDatabase.key)

  def commandFor(file: Path): Option[CompileCommand] = byFile.get(CompileDatabase.key(file))

  /** The commands the database carries for `file`, in database order. A file named once has its one
    * command; a file named more than once has one per entry, each entry a build context of the file
    * (see [[io.appthreat.c2cpg.passes.BuildContextPass]]).
    */
  def commandsFor(file: Path): Seq[CompileCommand] =
      byFileAll.getOrElse(CompileDatabase.key(file), Nil)
end CompileDatabase

object CompileDatabase:

  private val logger = LoggerFactory.getLogger(getClass)

  val FileName = "compile_commands.json"

  private def key(file: Path): Path =
      Try(file.toRealPath()).getOrElse(file.toAbsolutePath.normalize)

  /** The database a `--compile-commands` value names: the file itself, or `compile_commands.json`
    * in the directory, or in its `build` subdirectory. A relative value is taken from the working
    * directory, then from the project root.
    */
  def locate(fileOrDirectory: String, projectRoot: Path): Option[Path] =
    val value = Paths.get(fileOrDirectory)
    val bases =
        if value.isAbsolute then Seq(value)
        else Seq(value.toAbsolutePath, projectRoot.resolve(value))
    bases.map(_.normalize).flatMap { requested =>
        if Files.isRegularFile(requested) then Some(requested)
        else if Files.isDirectory(requested) then
          Seq(requested.resolve(FileName), requested.resolve("build").resolve(FileName))
              .find(Files.isRegularFile(_))
        else None
    }.headOption

  def load(path: Path): CompileDatabase =
    val entries = Try(ujson.read(Files.readString(path))).toOption match
      case Some(ujson.Arr(items)) => items.toSeq
      case _ =>
          logger.warn(s"$path is not a JSON compilation database (an array of entries)")
          Nil
    val commands = entries.flatMap { entry =>
        Try {
            val obj       = entry.obj
            val directory = Paths.get(obj("directory").str.replace('\\', '/'))
            val dir =
                if directory.isAbsolute then directory
                else path.getParent.resolve(directory).normalize
            val file = dir.resolve(obj("file").str.replace('\\', '/')).normalize
            val arguments = obj.get("arguments") match
              case Some(ujson.Arr(args)) => args.map(_.str).toSeq
              case _ => obj.get("command").map(c => CompileCommand.tokenize(c.str)).getOrElse(Nil)
            CompileCommand(dir, file, arguments)
        }.toOption
    }
    new CompileDatabase(path, commands)
  end load
end CompileDatabase
