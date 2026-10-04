package io.appthreat.edg2atom.parser

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{
    CompilerFamily,
    CompilerIdentity,
    PredefinedMacros,
    ProjectSources,
    SourceLanguage,
    UnitSettings
}
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery
import org.slf4j.LoggerFactory

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.{ConcurrentHashMap, TimeUnit}
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** Runs edga, the EDG-based exporter, on one translation unit and reads what it writes.
  *
  * The binary is the `edga.path` system property, else `EDGA_PATH`, else `edga` on the `PATH`. Each
  * unit is parsed as the project's compiler would: the compiler's own predefined macros (as the CDT
  * frontend collects them) instead of the front end's tables, its system include directories as
  * system directories, and the project's includes and defines.
  */
final class EdgaRunner(config: Config, sources: ProjectSources):

  private val logger = LoggerFactory.getLogger(getClass)

  private val root = Paths.get(config.inputPath).toAbsolutePath.normalize

  private val macroFiles = new ConcurrentHashMap[String, Path]()

  val executable: Option[String] = EdgaRunner.locate()

  /** The unit's document, or None when edga could not be run or wrote nothing. */
  def exportUnit(file: Path, timeoutSeconds: Long): Option[EdgaUnit] =
      executable.flatMap { exe =>
        val out = Files.createTempFile("edga-", ".json")
        try
          val command = (Seq(exe) ++ arguments(file) ++ Seq(
            "--edga-root",
            root.toString,
            "--edga-out",
            out.toString,
            file.toString
          )).asJava
          val process = new ProcessBuilder(command)
              .redirectErrorStream(true)
              .redirectOutput(ProcessBuilder.Redirect.DISCARD)
              .start()
          if !process.waitFor(timeoutSeconds, TimeUnit.SECONDS) then
            process.destroyForcibly()
            logger.warn(s"edga timed out on $file")
            None
          else if Files.size(out) == 0 then None
          else Some(EdgaUnit.parse(Files.readString(out, StandardCharsets.UTF_8)))
        catch
          case e: Exception =>
              logger.warn(s"edga failed on $file: ${e.getMessage}")
              None
        finally Files.deleteIfExists(out)
        end try
      }

  /** The front end's options for `file`. */
  def arguments(file: Path): Seq[String] =
    val settings = sources.settingsFor(file)
    val cpp      = settings.language == SourceLanguage.Cpp
    val identity = EdgaRunner.hostIdentity(config, settings.language)
    val facts    = identity.flatMap(PredefinedMacros.ofCompiler(_, None))
    val macros   = facts.map(_.macros).getOrElse(settings.definedSymbols)
    val dialect  = EdgaRunner.dialectOptions(macros, cpp)
    // the type-trait builtins (`__is_same(T, U)` and the rest), which C++ standard libraries use
    // without a feature check: every compiler the macros come from has them, but the front end
    // enables them only above the GNU 4.2.1 clang reports
    val standard =
        if cpp then
          Seq(EdgaRunner.cppStandardOption(config.cppStandard), "--type_traits_helpers")
        else Seq("--c17")
    val systemDirs =
        facts.map(_.systemIncludePaths).getOrElse(Seq.empty).map(_.toAbsolutePath.normalize)
    val (projectIncludes, otherIncludes) =
        settings.includePaths.map(_.toAbsolutePath.normalize).filterNot(systemDirs.contains)
            .partition(_.startsWith(root))
    val includes = projectIncludes.flatMap(p => Seq("-I", p.toString)) ++
        (otherIncludes ++ systemDirs).distinct.flatMap(p => Seq("--sys_include", p.toString))
    // the compiler's macros, without those the front end defines from its own options
    val predefinedFile = macroFile(macros)
    val userDefines = settings.definedSymbols.filterNot((k, _) =>
        macros.contains(k) || EdgaRunner.ParserShims(k)
    )
        .toSeq.sorted.flatMap((k, v) => Seq("--define_macro", if v.isEmpty then k else s"$k=$v"))
    // libc++'s vectorized algorithms are alias templates of clang's dependent-size vector types,
    // which the front end cannot instantiate; libc++ leaves them out when optimizing for size
    val libcxx =
        if cpp && (otherIncludes ++ systemDirs).exists(_.endsWith(Paths.get("c++", "v1"))) then
          Seq("--define_macro", "__OPTIMIZE_SIZE__")
        else Seq.empty
    val forced = settings.includeFiles.flatMap(f => Seq("--preinclude", f.toString)) ++
        settings.macroFiles.flatMap(f => Seq("--preinclude_macros", f.toString))
    // a compiler macro the front end also defines keeps the front end's value, which describes what
    // it implements, without an error for the attempted redefinition
    Seq("--clear_flag=use_predefined_macro_file", "--diag_suppress=46") ++ dialect ++ standard ++
        Seq("--preinclude_macros", predefinedFile.toString) ++ includes ++ userDefines ++ libcxx ++
        forced
  end arguments

  private def macroFile(macros: Map[String, String]): Path =
    val text = macros.toSeq.sorted.filterNot((k, _) =>
        EdgaRunner.FrontEndOwned(k.takeWhile(_ != '('))
    ).map {
        (k, v) => s"#define $k $v"
    }.mkString("", "\n", "\n")
    macroFiles.computeIfAbsent(
      text,
      t =>
        val f = Files.createTempFile("edga-macros-", ".h")
        f.toFile.deleteOnExit()
        Files.writeString(f, t)
        f
    )
end EdgaRunner

object EdgaRunner:

  /** Macros the front end defines from its own options, or cannot honour. */
  val FrontEndOwned: Set[String] = Set(
    "__STDC__",
    "__STDC_VERSION__",
    "__STDC_HOSTED__",
    "__cplusplus",
    "__FILE__",
    "__LINE__",
    "__DATE__",
    "__TIME__",
    "__COUNTER__",
    "__BASE_FILE__",
    "__INCLUDE_LEVEL__",
    // Apple's blocks extension, which the front end does not parse
    "__BLOCKS__"
  )

  /** What the C/C++ parser settings define only because that parser cannot evaluate them, all of
    * which the front end implements: the `#if` operators compilers provide (`__has_builtin(x)` and
    * the rest), and `export` as nothing for module interface units.
    */
  val ParserShims: Set[String] =
      UnitSettings.FeatureTests.keySet ++ Set("__has_include(x)", "__has_include_next(x)", "export")

  /** The front end's option for a `-std` spelling (`c++17`, `gnu++2a`, `c++latest`), C++17 when
    * none is given or the front end has no mode for it.
    */
  def cppStandardOption(standard: String): String =
      Option(standard).map(_.trim.toLowerCase.stripPrefix("gnu").stripPrefix("c")).getOrElse(
        ""
      ) match
        case "++98" | "++03"                                => "--c++03"
        case "++11" | "++0x"                                => "--c++11"
        case "++14" | "++1y"                                => "--c++14"
        case "++20" | "++2a"                                => "--c++20"
        case "++23" | "++2b" | "++26" | "++2c" | "++latest" => "--c++23"
        case _                                              => "--c++17"

  def locate(): Option[String] =
      sys.props.get("edga.path").orElse(sys.env.get("EDGA_PATH")).filter(p =>
          new File(p).canExecute
      )
          .orElse(sys.env.get("PATH").toSeq.flatMap(_.split(File.pathSeparator)).map(d =>
              new File(d, "edga")
          ).find(_.canExecute).map(_.getAbsolutePath))

  /** The compiler the CDT frontend asks for its macros when no compilation database names one. */
  def hostIdentity(config: Config, language: SourceLanguage): Option[CompilerIdentity] =
    val std =
        if language != SourceLanguage.Cpp then Nil
        else
          val configured = Option(config.cppStandard).map(_.trim.toLowerCase)
              .filter(s => s.startsWith("c++") || s.startsWith("gnu++"))
          Seq(s"-std=${configured.getOrElse("c++17")}")
    if IncludeAutoDiscovery.gccAvailable() then
      Some(CompilerIdentity("gcc", CompilerFamily.Gcc, language, std))
    else if IncludeAutoDiscovery.clangAvailable() then
      Some(CompilerIdentity("clang", CompilerFamily.Clang, language, std))
    else None

  /** The front end's emulation of the compiler the macros came from. */
  def dialectOptions(macros: Map[String, String], cpp: Boolean): Seq[String] =
    def version(keys: String*): Option[Int] =
      val parts = keys.map(k => macros.get(k).flatMap(_.trim.toIntOption))
      Option.when(parts.headOption.flatten.isDefined)(
        parts.zip(Seq(10000, 100, 1)).map((p, w) => p.getOrElse(0) * w).sum
      )
    val gnu = version("__GNUC__", "__GNUC_MINOR__", "__GNUC_PATCHLEVEL__")
    version("__clang_major__", "__clang_minor__", "__clang_patchlevel__") match
      // the GNU version clang reports (4.2.1) is not its feature level: the front end sets the one
      // that matches its clang emulation
      case Some(clang) => Seq("--clang", s"--clang_version=$clang")
      case None =>
          gnu match
            case Some(g) => Seq(if cpp then "--g++" else "--gcc", s"--gnu_version=$g")
            case None    => Seq.empty
end EdgaRunner
