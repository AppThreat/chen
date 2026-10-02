package io.appthreat.c2cpg.parser

import org.slf4j.LoggerFactory

import java.nio.file.{Files, Path, Paths}
import scala.collection.mutable
import scala.util.Try

/** The language a translation unit is compiled as. */
enum SourceLanguage:
  case C, Cpp

/** The family of a compiler driver, which decides how its command line is read and which predefined
  * macros it has.
  */
enum CompilerFamily:
  case Gcc, Clang, Msvc, Unknown

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
  targetOptions: Seq[String] = Nil
)

/** One entry of a JSON compilation database (`compile_commands.json`). */
final case class CompileCommand(directory: Path, file: Path, arguments: Seq[String]):
  lazy val flags: CompileFlags = CompileCommand.parseArguments(arguments, directory)

object CompileCommand:

  /** Splits a command string the way the shell its driver runs under would: POSIX quoting, or the
    * Windows rules of `cl.exe` and `clang-cl`.
    */
  def tokenize(command: String): Seq[String] =
    val first = posixWords(command).headOption.getOrElse("")
    if familyOf(first) == CompilerFamily.Msvc then windowsWords(command) else posixWords(command)

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

  /** The family of the compiler a driver path names. */
  def familyOf(driver: String): CompilerFamily =
    val name = Paths.get(driver.replace('\\', '/')).getFileName match
      case null => ""
      case p    => p.toString.toLowerCase.stripSuffix(".exe")
    if name == "cl" || name == "clang-cl" || name.endsWith("-cl") then CompilerFamily.Msvc
    else if name.contains("clang") then CompilerFamily.Clang
    else if name.contains("gcc") || name.contains("g++") || name == "cc" || name == "c++" ||
      name.endsWith("-cc") || name.endsWith("-c++")
    then CompilerFamily.Gcc
    else CompilerFamily.Unknown

  /** Drivers that compile every file as C++, whatever its extension. */
  private def isCppDriver(driver: String): Boolean =
    val name = Paths.get(driver.replace('\\', '/')).getFileName match
      case null => ""
      case p    => p.toString.toLowerCase.stripSuffix(".exe")
    name.endsWith("++") || name.contains("++-") || name.endsWith("clang++")

  /** Compiler wrappers that run the real compiler named by the next argument. */
  private val Wrappers = Set("ccache", "sccache", "distcc", "icecc", "buildcache")

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
    val args = arguments.dropWhile(a =>
        Wrappers.contains(a.replace('\\', '/').split('/').last.toLowerCase.stripSuffix(".exe"))
    )
    val driver = args.headOption
    var family =
        if args.contains("--driver-mode=cl") then CompilerFamily.Msvc
        else driver.map(familyOf).getOrElse(CompilerFamily.Unknown)
    var language: Option[SourceLanguage] =
        driver.filter(isCppDriver).map(_ => SourceLanguage.Cpp)
    var standard: Option[String] = None
    val includes                 = mutable.ArrayBuffer.empty[Path]
    val quoteIncludes            = mutable.ArrayBuffer.empty[Path]
    val systemIncludes           = mutable.ArrayBuffer.empty[Path]
    val afterIncludes            = mutable.ArrayBuffer.empty[Path]
    val macros                   = mutable.ArrayBuffer.empty[MacroChange]
    val includeFiles             = mutable.ArrayBuffer.empty[Path]
    val macroFiles               = mutable.ArrayBuffer.empty[Path]
    val targetOptions            = mutable.ArrayBuffer.empty[String]

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
      if msvc && (arg.startsWith("/") || arg.startsWith("-")) && arg.length > 1 then
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
      else if arg.startsWith("--driver-mode=") then
        if arg == "--driver-mode=g++" then language = Some(SourceLanguage.Cpp)
        targetOptions += arg
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
      else if arg.startsWith("--target=") then targetOptions += arg
      else if arg == "-arch" then valueOf(arg, arg).foreach(v => targetOptions ++= Seq("-arch", v))
      else if arg == "--sysroot" then
        valueOf(arg, arg).foreach(v => targetOptions += s"--sysroot=${path(v)}")
      else if arg.startsWith("--sysroot=") then
        targetOptions += s"--sysroot=${path(arg.stripPrefix("--sysroot="))}"
      else if arg.startsWith("-m") || arg.startsWith("-O") || arg == "-ansi" ||
        arg == "-pthread" || arg.startsWith("-fsanitize") || arg.startsWith("-fno-") ||
        isMacroAffectingFeature(arg)
      then targetOptions += arg
      end if
      i += 1
    end while
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
      targetOptions = targetOptions.toSeq
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

/** A JSON compilation database: the compile command of every translation unit of a build. */
final class CompileDatabase private (val path: Path, commands: Seq[CompileCommand]):

  private val byFile: Map[Path, CompileCommand] =
      commands.reverse.map(c => CompileDatabase.key(c.file) -> c).toMap

  /** The translation units the database compiles, in database order and without duplicates. */
  val files: Seq[Path] = commands.map(_.file).distinctBy(CompileDatabase.key)

  def commandFor(file: Path): Option[CompileCommand] = byFile.get(CompileDatabase.key(file))

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
