package io.appthreat.c2cpg.parser

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery
import io.appthreat.x2cpg.SourceFiles

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import scala.collection.mutable
import scala.util.Try

/** A lexical pre-pass over a C/C++ tree that finds the build-configuration macros hiding code from
  * the parser. A project built by `configure`, CMake, Meson or Kconfig gets names such as
  * `CONFIG_WAV_DEMUXER` or `HAVE_O_CLOEXEC` from a generated header the checkout does not contain;
  * without it every `#if CONFIG_X` evaluates to 0 and the parser never sees the code it gates.
  *
  * The census reads every conditional directive in the tree and keeps the macros that nothing
  * defines: not the tree, not the headers the tree includes (resolved through the include paths and
  * the system include paths, transitively), not the user. For each one it counts the code lines
  * that defining it to 1 would make visible, less the lines it would hide. Lines are counted as the
  * parser would see them: an inner block the baseline hides (`#ifdef _WIN32`, `#if 0`) adds
  * nothing, and a block inside a hidden one reveals nothing. A condition it cannot read as a single
  * macro test (`#if A && B`, `#if X >= 2`) is a `mixed` use and earns no gain.
  *
  * Each external macro gets one tier:
  *   - [[Tier.Auto]]: strong evidence it is a build switch. A configure/CMake/Meson template in the
  *     tree declares it as a switch (`#undef X`, valueless `#cmakedefine X`, `#cmakedefine01 X`,
  *     `#mesondefine X`), or it follows the build-option naming (`CONFIG_`, `ENABLE_`), and
  *     defining it shows more code than it hides. `--auto-defines` applies these.
  *   - [[Tier.Suggest]]: it shows more code than it hides, but nothing says it is a build switch (a
  *     `HAVE_` probe with no template, a debug switch, a name the tree defines only under another
  *     condition). Reported for a person or agent to choose.
  *   - [[Tier.Skip]]: compiler, platform and CPU-feature macros, errno names, macros owned by a
  *     dependency whose headers are not on any include path (`MBEDTLS_...` for an unresolvable
  *     `<mbedtls/...>`), template names that carry a value, and anything that shows no more code
  *     than it hides. Listed with the reason, never defined.
  */
object MacroCensus:

  enum Tier:
    case Auto, Suggest, Skip

  final case class Entry(
    name: String,
    tier: Tier,
    reason: String,
    evidence: String,
    gainLines: Int,
    positiveUses: Int,
    negativeUses: Int,
    mixedUses: Int,
    files: Int
  )

  final case class Report(entries: List[Entry], scannedFiles: Int):
    def auto: List[Entry]    = entries.filter(_.tier == Tier.Auto)
    def suggest: List[Entry] = entries.filter(_.tier == Tier.Suggest)

    /** the defines `--auto-defines` adds, in `NAME=1` form */
    def autoDefines: Set[String] = auto.map(e => s"${e.name}=1").toSet

    def toJson: String =
      def q(s: String) = "\"" + s.flatMap {
          case '"'          => "\\\""
          case '\\'         => "\\\\"
          case c if c < ' ' => f"\\u${c.toInt}%04x"
          case c            => c.toString
      } + "\""
      entries
          .map { e =>
              s"""  {"macro": ${q(e.name)}, "tier": ${q(
                    e.tier.toString.toLowerCase
                  )}, "reason": ${q(
                    e.reason
                  )}, "evidence": ${q(e.evidence)}, "gain_lines": ${e.gainLines}, "positive_uses": ${e
                      .positiveUses}, "negative_uses": ${e.negativeUses}, "mixed_uses": ${e
                      .mixedUses}, "files": ${e.files}}"""
          }
          .mkString(s"""{"scanned_files": $scannedFiles, "macros": [\n""", ",\n", "\n]}\n")

    /** a header `--macro-files` accepts: the auto tier active, the suggest tier commented out */
    def toMacroHeader: String =
      val sb = new StringBuilder
      sb.append(s"$GeneratedMarker Review before use.\n")
      sb.append(" * Pass with --macro-files; uncomment a suggestion to enable it. */\n\n")
      auto.foreach(e =>
          sb.append(s"#define ${e.name} 1 /* +${e.gainLines} lines, ${e.evidence} */\n")
      )
      if suggest.nonEmpty then sb.append("\n/* suggestions */\n")
      suggest.foreach(e =>
          sb.append(s"/* #define ${e.name} 1 */ /* +${e.gainLines} lines, ${e.reason} */\n")
      )
      sb.toString

    /** a short human summary: counts and the largest entries of each defined tier */
    def summary(limit: Int = 10): String =
      val sb = new StringBuilder
      sb.append(
        s"Macro census: $scannedFiles files, ${entries.size} undefined condition macros; " +
            s"${auto.size} auto, ${suggest.size} suggested (line gains are per macro and overlap)\n"
      )
      def rows(title: String, es: List[Entry]) =
          if es.nonEmpty then
            sb.append(s"  $title:\n")
            es.take(limit).foreach(e =>
                sb.append(f"    ${e.name}%-44s +${e.gainLines}%-6d ${e.evidence}\n")
            )
            if es.size > limit then sb.append(s"    ... ${es.size - limit} more\n")
      rows("auto", auto)
      rows("suggested", suggest)
      sb.toString
  end Report

  /** The first line of every header the census writes: a tree scan skips such a file, so a report
    * written inside the tree does not define its own names away on the next run.
    */
  val GeneratedMarker = "/* Generated by the macro census."

  private val SourceExtensions =
      Set(".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".inc", ".ipp", ".tcc")
  private val TemplateSuffixes = Set(".h.in", ".h.cmake", ".hin", ".h.meson", ".hpp.in")
  private val MaxHeaderBytes   = 8L * 1024 * 1024
  private val MaxIncludeDepth  = 16

  /** OS, architecture, CPU-feature and toolchain words, matched as whole `_`-separated tokens so
    * `HAVE_ALARM` is not an ARM macro and `HAVE_POSIX_MEMALIGN` is a probe, not a platform.
    */
  private val PlatformTokens = Set(
    "WIN",
    "WIN32",
    "WIN64",
    "WINDOWS",
    "WINAPI",
    "WINSOCK",
    "WINSOCK2",
    "W32",
    "MINGW",
    "MINGW32",
    "MINGW64",
    "CYGWIN",
    "MSVC",
    "APPLE",
    "MACOS",
    "MACOSX",
    "OSX",
    "DARWIN",
    "IOS",
    "TVOS",
    "WATCHOS",
    "ANDROID",
    "LINUX",
    "GLIBC",
    "FREEBSD",
    "NETBSD",
    "OPENBSD",
    "DRAGONFLY",
    "SOLARIS",
    "SUNOS",
    "HAIKU",
    "FUCHSIA",
    "EMSCRIPTEN",
    "WASM",
    "WASI",
    "AIX",
    "HPUX",
    "QNX",
    "OS2",
    "X86",
    "X64",
    "AMD64",
    "I386",
    "I686",
    "IA32",
    "IA64",
    "AARCH64",
    "ARM",
    "ARM64",
    "ARMV5",
    "ARMV6",
    "ARMV7",
    "ARMV8",
    "THUMB",
    "NEON",
    "VFP",
    "MIPS",
    "MIPS64",
    "MIPSEL",
    "POWERPC",
    "PPC",
    "PPC64",
    "ALTIVEC",
    "VSX",
    "RISCV",
    "RV64",
    "SPARC",
    "S390",
    "S390X",
    "LOONGARCH",
    "LOONGSON",
    "MMX",
    "MMXEXT",
    "SSE",
    "SSE2",
    "SSE3",
    "SSSE3",
    "SSE4",
    "SSE41",
    "SSE42",
    "AVX",
    "AVX2",
    "AVX512",
    "FMA3",
    "FMA4",
    "SVE",
    "SVE2",
    "SME",
    "LSX",
    "LASX",
    "ENDIAN",
    "BIGENDIAN",
    "GNUC",
    "CLANG"
  )
  private val PlatformPhrases = Seq("X86_64", "INLINE_ASM", "BIG_ENDIAN", "LITTLE_ENDIAN")

  /** errno names a build host's `<errno.h>` may lack (Linux-only ones are the common case): a
    * `#ifdef ENOMEDIUM` is a portability probe, never a build switch. The standard ones are found
    * through the included headers.
    */
  private val ErrnoNames = Set(
    "EADV",
    "EBADE",
    "EBADFD",
    "EBADMSG",
    "EBADR",
    "EBADRQC",
    "EBADSLT",
    "EBFONT",
    "ECHRNG",
    "ECOMM",
    "EDEADLOCK",
    "EDOTDOT",
    "EHWPOISON",
    "EISNAM",
    "EKEYEXPIRED",
    "EKEYREJECTED",
    "EKEYREVOKED",
    "EL2HLT",
    "EL2NSYNC",
    "EL3HLT",
    "EL3RST",
    "ELIBACC",
    "ELIBBAD",
    "ELIBEXEC",
    "ELIBMAX",
    "ELIBSCN",
    "ELNRNG",
    "EMEDIUMTYPE",
    "EMULTIHOP",
    "ENAVAIL",
    "ENOANO",
    "ENOCSI",
    "ENODATA",
    "ENOKEY",
    "ENOLINK",
    "ENOMEDIUM",
    "ENONET",
    "ENOPKG",
    "ENOSR",
    "ENOSTR",
    "ENOTNAM",
    "ENOTRECOVERABLE",
    "ENOTSUP",
    "ENOTUNIQ",
    "EOWNERDEAD",
    "EPROTO",
    "EREMCHG",
    "EREMOTEIO",
    "ERESTART",
    "ERFKILL",
    "ESRMNT",
    "ESTRPIPE",
    "ETIME",
    "EUCLEAN",
    "EUNATCH",
    "EXFULL",
    "ECANCELED",
    "EOVERFLOW",
    "EILSEQ",
    "ETXTBSY",
    "ESTALE",
    "EDQUOT",
    "EWOULDBLOCK"
  )

  /** macros the compiler defines with a value the census cannot know */
  private val CompilerPredefines = Set(
    "__GNUC__",
    "__GNUC_MINOR__",
    "__GNUC_PATCHLEVEL__",
    "__cplusplus",
    "__STDC__",
    "__STDC_VERSION__",
    "__STDC_HOSTED__"
  )

  /** Configure-style names that gate optional code in the project itself. `HAVE_` is not one: it is
    * a probe of the host, and needs a template to count as a build option.
    */
  private val BuildOptionPrefixes = Seq("CONFIG_", "ENABLE_")

  private val DirectivePattern =
      """(?s)^\s*#\s*(ifdef|ifndef|if|elifdef|elifndef|elif|else|endif|define|undef|include_next|include|import)\b(.*)$""".r
  private val TemplateDirective =
      """(?s)^\s*#\s*(cmakedefine01|cmakedefine|mesondefine|undef|define)\s+([A-Za-z_]\w*)(.*)$""".r
  private val NamePattern    = """(?s)^\s*([A-Za-z_]\w*)(.*)$""".r
  private val IncludeTarget  = """^\s*([<"])([^>"]+)[>"]""".r.unanchored
  private val Identifier     = """(?<![\w.'])[A-Za-z_]\w*""".r
  private val HasFeatureCall = """__has_\w+\s*\([^)]*\)""".r
  private val AngleOrString  = """<[^<>]*>|"(?:\\.|[^"\\])*"""".r
  private val ExprToken      = """[A-Za-z_]\w*|\d\w*|&&|\|\||[!()]|\S""".r
  private val SingleTest     = """^[\s!(]*(?:defined\s*\(?\s*)?([A-Za-z_]\w*)[\s)]*$""".r
  private val SwitchValue    = """(?s)^\s*[01]?\s*$""".r

  /** Lines that are not code the analysis could look at: blank, braces, `(void)x;` stubs, bare
    * `return`/`break`/`continue`, labels. A disabled branch of such lines hides nothing.
    */
  private val TrivialLine =
      """^\s*(?:[{}();,]*|\(void\)\s*[\w.\->\[\]]+\s*;|return\s*(?:-?\w+)?\s*;|break\s*;|continue\s*;|else|do|default\s*:|case\s+[\w']+\s*:|\w+\s*:)\s*$""".r

  private def isTrivialLine(line: String): Boolean = TrivialLine.matches(line)

  private val DeclaredName = """#\s*(?:define|undef)\s+([A-Za-z_]\w*)""".r
  private val TestPathPattern =
      """(^|/)(tests?|testing|unittests?|benchmarks?)(/|$)|(_test|_unittest|_benchmark|_bench)\.[^/]+$""".r

  /** Run the census over the config's input path, honouring its ignore settings. System include
    * paths are consulted for the names the included headers define whether or not the analysis
    * itself auto-discovers them. Files the census itself wrote are never scanned.
    */
  def run(config: Config): Report =
    val root    = Paths.get(config.inputPath).toAbsolutePath.normalize
    val reports = reportPaths(config).map(_.toAbsolutePath.normalize).toSet
    val userDefined = config.defines.map(_.takeWhile(_ != '=')) ++
        (config.macroFiles ++ config.includeFiles).flatMap(p => namesDeclaredIn(Paths.get(p)))
    val discovery = config.withIncludePathsAutoDiscovery(true)
    val systemRoots =
        Try(
          IncludeAutoDiscovery.discoverIncludePathsC(discovery).toList ++
              IncludeAutoDiscovery.discoverIncludePathsCPP(discovery).toList
        ).getOrElse(Nil)
    val files = Try(
      SourceFiles.determineWithConfig(root.toString, SourceExtensions ++ TemplateSuffixes, config)
    ).getOrElse(Nil).map(p => Paths.get(p).toAbsolutePath.normalize).filterNot(reports.contains)
    analyse(
      root,
      files,
      config.includePaths.toList.map(p => Paths.get(p).toAbsolutePath.normalize),
      systemRoots.map(_.toAbsolutePath.normalize),
      userDefined
    )
  end run

  /** The two report files a `--macro-census <base>` writes. */
  def reportPaths(config: Config): List[Path] =
      if config.macroCensusReport.isEmpty then Nil
      else
        val base = reportBase(config.macroCensusReport)
        List(Paths.get(s"$base.json"), Paths.get(s"$base.h"))

  /** `census`, `census.json` and `census.h` all name the same pair of reports. */
  def reportBase(path: String): String = path.stripSuffix(".json").stripSuffix(".h")

  /** The census over a directory with default settings, for tests. */
  def analyseTree(root: Path, externalRoots: List[Path], userDefined: Set[String]): Report =
    val abs = root.toAbsolutePath.normalize
    val files = SourceFiles.determine(abs.toString, SourceExtensions ++ TemplateSuffixes)
        .map(p => Paths.get(p).toAbsolutePath.normalize)
    analyse(abs, files, externalRoots.map(_.toAbsolutePath.normalize), Nil, userDefined)

  // ---- the census proper ----

  private final class Stats:
    var gain     = 0
    var positive = 0
    var negative = 0
    var mixed    = 0
    val files    = mutable.HashSet.empty[String]

  private final case class Include(target: String, quoted: Boolean, from: Path)

  /** What the scan knows about a name, for evaluating a condition at baseline. */
  private final case class Knowledge(defined: Set[String], tree: Set[String]):
    // `defined(X)`: true for a name an included header or the user defines; unknown for one the
    // tree defines (include order decides - a header's own include guard is the common case) and
    // for a candidate; false for a platform name nothing defines
    def definedTri(name: String): Tri =
        if defined.contains(name) then Tri.T
        else if tree.contains(name) || CompilerPredefines.contains(name) then Tri.U
        else if isPlatformName(name) || ErrnoNames.contains(name) then Tri.F
        else Tri.U
    // `X` in an `#if`: an undefined name is 0; a defined one has a value the census does not
    // track, and a candidate may be defined to 1
    def valueTri(name: String): Tri = definedTri(name) match
      case Tri.F => Tri.F
      case _     => Tri.U

  private def analyse(
    root: Path,
    files: List[Path],
    userRoots: List[Path],
    systemRoots: List[Path],
    userDefined: Set[String]
  ): Report =
    val (templates, rest) = files.partition(isTemplate)
    val sources           = rest.filter(isSource).filterNot(isGenerated)
    val templateSwitches  = mutable.HashSet.empty[String]
    val templateValued    = mutable.HashSet.empty[String]
    val treeDefined       = mutable.HashSet.empty[String]
    val conditionally     = mutable.HashSet.empty[String]
    val includes          = mutable.ArrayBuffer.empty[Include]

    // a template declares a switch (`#undef X`, `#cmakedefine01 X`, a valueless `#cmakedefine X`
    // or `#define X`) or gives the name a value (`#cmakedefine X "@X@"`)
    templates.foreach(f =>
        logicalLines(f).foreach {
            case TemplateDirective(kind, name, value) =>
                kind match
                  case "undef" | "cmakedefine01" | "mesondefine" => templateSwitches += name
                  case _ =>
                      if SwitchValue.matches(value) then templateSwitches += name
                      else templateValued += name
            case _ => ()
        }
    )

    // pass 1: what the tree defines (and whether only under some other condition), and what it
    // includes
    sources.foreach { f =>
      val isTest = isTestPath(root, f)
      val lines  = logicalLines(f)
      val guard  = includeGuardOf(lines)
      val stack  = mutable.Stack.empty[List[String]]
      lines.foreach {
          case DirectivePattern(kind, rest) =>
              kind match
                case "if" | "ifdef" | "ifndef" => stack.push(conditionNames(rest))
                case "elif" | "elifdef" | "elifndef" =>
                    if stack.nonEmpty then stack.push(stack.pop() ++ conditionNames(rest))
                case "endif" => if stack.nonEmpty then stack.pop()
                case "define" | "undef" =>
                    rest match
                      case NamePattern(name, _) if !isTest =>
                          // the include guard is transparent, and a `#ifndef X / #define X ...`
                          // default defines X on every path
                          val enclosing = stack.toList.reverse match
                            case g :: tail if guard.contains(g) => tail
                            case all                            => all
                          if enclosing.forall(_ == List(name)) then treeDefined += name
                          else conditionally += name
                      case _ => ()
                case "include" | "include_next" | "import" =>
                    rest match
                      case IncludeTarget(open, target) =>
                          includes += Include(target.trim, open == "\"", f.getParent)
                      case _ => ()
                case _ => ()
          case _ => ()
      }
    }

    // the headers the tree includes from outside itself, transitively: what they define is not
    // missing. Only the included ones: a system root holds other projects' config headers too
    val roots = (userRoots ++ systemRoots).distinct
    def resolve(inc: Include): Option[Path] =
      val local = if inc.quoted && inc.from != null then List(inc.from) else Nil
      (local ++ (root :: roots)).iterator
          .map(r => Try(r.resolve(inc.target).normalize).toOption)
          .collectFirst { case Some(p) if Try(Files.isRegularFile(p)).getOrElse(false) => p }
    val externalDefined = mutable.HashSet.empty[String]
    val unresolvedTops  = mutable.HashSet.empty[String]
    val visited         = mutable.HashSet.empty[Path]
    var frontier        = mutable.ArrayBuffer.empty[Path]
    includes.foreach { inc =>
        resolve(inc) match
          case Some(p) => if !p.startsWith(root) && visited.add(p) then frontier += p
          case None =>
              if inc.target.contains('/') then
                unresolvedTops += inc.target.takeWhile(_ != '/').toLowerCase
    }
    var depth = 0
    while frontier.nonEmpty && depth < MaxIncludeDepth do
      val next = mutable.ArrayBuffer.empty[Path]
      frontier.foreach { h =>
          if Try(Files.size(h)).getOrElse(Long.MaxValue) <= MaxHeaderBytes then
            logicalLines(h).foreach {
                case DirectivePattern("define", NamePattern(name, _)) => externalDefined += name
                case DirectivePattern(
                      "include" | "include_next" | "import",
                      IncludeTarget(open, target)
                    ) =>
                    resolve(Include(target.trim, open == "\"", h.getParent)).foreach(p =>
                        if !p.startsWith(root) && visited.add(p) then next += p
                    )
                case _ => ()
            }
      }
      frontier = next
      depth += 1

    // pass 2: every conditional, with the lines it shows and hides as the parser would see them
    val knowledge =
        Knowledge((externalDefined ++ userDefined).toSet, (treeDefined ++ conditionally).toSet)
    val stats = mutable.HashMap.empty[String, Stats]
    sources.foreach { f =>
      val rel = root.relativize(f).toString.replace('\\', '/')
      collectConditions(logicalLines(f), isTestPath(root, f), knowledge, stats, rel)
    }

    val candidates = stats.keySet.toSet -- treeDefined -- userDefined -- externalDefined
    val entries = candidates.toList.map { name =>
      val s = stats(name)
      val evidence =
          if templateSwitches.contains(name) then "template"
          else if BuildOptionPrefixes.exists(name.startsWith) then "build-option name"
          else "undefined"
      val owner = name.takeWhile(_ != '_').toLowerCase
      val (tier, reason) =
          if isPlatformName(name) then (Tier.Skip, "compiler or platform")
          else if ErrnoNames.contains(name) then (Tier.Skip, "errno constant")
          else if unresolvedTops.contains(owner) then
            (Tier.Skip, s"owned by the unresolved <$owner/...> dependency")
          else if templateValued.contains(name) && !templateSwitches.contains(name) then
            (Tier.Skip, "the template gives it a value")
          else if s.gain <= 0 then (Tier.Skip, "shows no more code than it hides")
          else if conditionally.contains(name) then
            (Tier.Suggest, "defined in the tree under another condition")
          else if evidence != "undefined" then (Tier.Auto, evidence)
          else (Tier.Suggest, "no build-option evidence")
      Entry(
        name = name,
        tier = tier,
        reason = reason,
        evidence = evidence,
        gainLines = s.gain,
        positiveUses = s.positive,
        negativeUses = s.negative,
        mixedUses = s.mixed,
        files = s.files.size
      )
    }
    Report(entries.sortBy(e => (e.tier.ordinal, -e.gainLines, e.name)), sources.size)
  end analyse

  /** Names a user-provided macro or include file decides: defined, undefined, or left commented out
    * (`/* #undef HAVE_X */`, a census header's suggestion) - the census overrides none of them.
    */
  private def namesDeclaredIn(f: Path): Set[String] =
      Try(new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1)).toOption.toSet
          .flatMap(text => DeclaredName.findAllMatchIn(text).map(_.group(1)))

  /** The file's include guard: a leading `#ifndef G` (or `#if !defined(G)`) directly followed by
    * `#define G`. Its block is transparent to the define scan.
    */
  private def includeGuardOf(lines: IndexedSeq[String]): Option[List[String]] =
    val first = lines.iterator.collect { case DirectivePattern(k, r) => (k, r) }.take(2).toList
    first match
      case List(("ifndef", g), ("define", NamePattern(d, _))) if g.trim == d => Some(List(d))
      case List(("if", c), ("define", NamePattern(d, _)))
          if c.replaceAll("[\\s()]", "") == s"!defined$d" => Some(List(d))
      case _ => None

  private enum Tri:
    case T, F, U

  private def not(t: Tri): Tri = t match
    case Tri.T => Tri.F
    case Tri.F => Tri.T
    case Tri.U => Tri.U

  private final class Open(val kind: String, val condition: String, val reachable: Boolean):
    val branches = mutable.ArrayBuffer(0) // code lines per branch, as the parser would see them
    val values   = mutable.ArrayBuffer.empty[Tri]
    var hasElif  = false
    val names    = mutable.LinkedHashSet.empty[String]
    // a branch the parser takes at baseline: its condition is not false and no earlier one is true
    def visible(i: Int): Boolean = values(i) != Tri.F && !values.take(i).contains(Tri.T)
    def currentVisible: Boolean  = visible(values.size - 1)

  private def collectConditions(
    lines: IndexedSeq[String],
    isTest: Boolean,
    knowledge: Knowledge,
    stats: mutable.HashMap[String, Stats],
    file: String
  ): Unit =
    val stack                = mutable.Stack.empty[Open]
    def visibleHere: Boolean = stack.forall(_.currentVisible)
    def close(o: Open): Unit =
      // an inner block contributes the lines of its baseline-visible branches to its parent
      if stack.nonEmpty then
        stack.top.branches(stack.top.branches.size - 1) +=
            o.branches.indices.filter(o.visible).map(o.branches).sum
      val single =
          if o.hasElif then None
          else
            o.kind match
              case "ifdef" | "ifndef" => Identifier.findFirstIn(o.condition)
              case _ =>
                  o.condition match
                    case SingleTest(name) if name != "defined" => Some(name)
                    case _                                     => None
      o.names.foreach { name =>
        val s = stats.getOrElseUpdate(name, new Stats)
        s.files += file
        single.filter(_ == name) match
          case Some(_) =>
              val negated = o.kind == "ifndef" ||
                  (o.kind == "if" && o.condition.count(_ == '!') % 2 == 1)
              val shown   = o.branches.headOption.getOrElse(0)
              val other   = o.branches.drop(1).sum
              if negated then s.negative += 1 else s.positive += 1
              // test code is not what the analysis is for, and a block inside a hidden one
              // reveals nothing: neither earns nor costs a macro its gain
              if !isTest && o.reachable then
                s.gain += (if negated then other - shown else shown - other)
          case None => s.mixed += 1
      }
    end close

    lines.foreach {
        case DirectivePattern(kind, rest) =>
            kind match
              case "if" | "ifdef" | "ifndef" =>
                  val o = new Open(kind, rest.trim, visibleHere)
                  o.values += evaluate(kind, rest, knowledge)
                  o.names ++= conditionNames(rest)
                  stack.push(o)
              case "elif" | "elifdef" | "elifndef" if stack.nonEmpty =>
                  val o = stack.top
                  o.hasElif = true
                  o.branches += 0
                  o.values += evaluate(
                    if kind == "elif" then "if" else kind.drop(2),
                    rest,
                    knowledge
                  )
                  o.names ++= conditionNames(rest)
              case "else" if stack.nonEmpty =>
                  stack.top.branches += 0
                  stack.top.values += Tri.T
              case "endif" if stack.nonEmpty => close(stack.pop())
              case _                         => ()
        case line =>
            if stack.nonEmpty && !isTrivialLine(line) then
              stack.top.branches(stack.top.branches.size - 1) += 1
    }
    // a block left open at the end of the file still records its uses
    while stack.nonEmpty do close(stack.pop())
  end collectConditions

  /** Three-valued evaluation of a condition at baseline over `defined`, `!`, `&&`, `||`,
    * parentheses, integer literals and single names; anything else is unknown.
    */
  private def evaluate(kind: String, cond: String, k: Knowledge): Tri =
      kind match
        case "ifdef" => Identifier.findFirstIn(cond).map(k.definedTri).getOrElse(Tri.U)
        case "ifndef" =>
            Identifier.findFirstIn(cond).map(n => not(k.definedTri(n))).getOrElse(Tri.U)
        case _ =>
            val tokens =
                ExprToken.findAllIn(HasFeatureCall.replaceAllIn(cond, s" $HasFeature ")).toList
            new ExprParser(tokens, k).parse()

  private final class ExprParser(tokens: List[String], k: Knowledge):
    private var rest              = tokens
    private def isName(t: String) = t.headOption.exists(c => c.isLetter || c == '_')
    def parse(): Tri =
      val r = or()
      if rest.nonEmpty then Tri.U else r
    private def or(): Tri =
      var l = and()
      while rest.headOption.contains("||") do
        rest = rest.tail
        val r = and()
        l =
            if l == Tri.T || r == Tri.T then Tri.T
            else if l == Tri.F && r == Tri.F then Tri.F
            else Tri.U
      l
    private def and(): Tri =
      var l = unary()
      while rest.headOption.contains("&&") do
        rest = rest.tail
        val r = unary()
        l =
            if l == Tri.F || r == Tri.F then Tri.F
            else if l == Tri.T && r == Tri.T then Tri.T
            else Tri.U
      l
    private def fail(): Tri =
      rest = List("?")
      Tri.U
    private def unary(): Tri = rest match
      case "!" :: tail =>
          rest = tail
          not(unary())
      case "(" :: tail =>
          rest = tail
          val r = or()
          if rest.headOption.contains(")") then
            rest = rest.tail
            r
          else fail()
      case "defined" :: "(" :: name :: ")" :: tail if isName(name) =>
          rest = tail
          k.definedTri(name)
      case "defined" :: name :: tail if isName(name) =>
          rest = tail
          k.definedTri(name)
      // `__has_include(...)` and friends: the host decides
      case HasFeature :: tail =>
          rest = tail
          Tri.U
      case n :: tail if n.headOption.exists(_.isDigit) =>
          rest = tail
          integerLiteral(n) match
            case Some(v) => if v == 0 then Tri.F else Tri.T
            case None    => Tri.U
      case name :: tail if isName(name) && name != "defined" =>
          rest = tail
          k.valueTri(name)
      case _ => fail()
  end ExprParser

  private val HasFeature = "__census_has_feature__"

  /** `0`, `0x10`, `017`, `1UL`: the value of a C integer literal, suffixes dropped */
  private def integerLiteral(n: String): Option[BigInt] =
    val digits = n.replaceAll("(?i)[ul]+$", "")
    Try {
        if digits.matches("(?i)0x[0-9a-f]+") then BigInt(digits.drop(2), 16)
        else if digits.matches("0[0-7]*") then
          BigInt(if digits.length > 1 then digits.drop(1) else "0", 8)
        else BigInt(digits)
    }.toOption

  private def isPlatformName(name: String): Boolean =
      name.startsWith("_") ||
          (name.exists(_.isLower) && !name.exists(_.isUpper)) ||
          name.split('_').exists(PlatformTokens.contains) ||
          PlatformPhrases.exists(name.contains)

  private def conditionNames(cond: String): List[String] =
    val cleaned = AngleOrString.replaceAllIn(HasFeatureCall.replaceAllIn(cond, " "), " ")
    Identifier.findAllIn(cleaned).filterNot(_ == "defined").toList.distinct

  private def isTestPath(root: Path, f: Path): Boolean =
    val rel = Try(root.relativize(f).toString).getOrElse(f.toString).replace('\\', '/')
    TestPathPattern.findFirstIn(rel).nonEmpty

  private def isSource(p: Path): Boolean =
    val n = p.getFileName.toString.toLowerCase
    SourceExtensions.exists(n.endsWith) && !TemplateSuffixes.exists(n.endsWith)

  private def isTemplate(p: Path): Boolean =
    val n = p.getFileName.toString.toLowerCase
    TemplateSuffixes.exists(n.endsWith)

  private def isGenerated(p: Path): Boolean =
      Try {
          val in = Files.newInputStream(p)
          try new String(in.readNBytes(GeneratedMarker.length), StandardCharsets.ISO_8859_1)
          finally in.close()
      }.toOption.contains(GeneratedMarker)

  private[parser] def logicalLines(f: Path): IndexedSeq[String] =
      logicalLinesOf(
        Try(new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1)).getOrElse("")
      )

  /** The text's logical lines as the preprocessor sees them, one entry per physical line: a line
    * ending in `\` is spliced with the next before comments are removed (as in C), a comment
    * becomes a space (string and character literals are respected), and a directive whose block
    * comment runs past the end of its line continues until the comment closes. Lines consumed into
    * an earlier one are left empty, so every entry keeps its physical line number. CR, CRLF and LF
    * all end a line; a UTF-8 byte-order mark is dropped.
    */
  private[parser] def logicalLinesOf(text0: String): IndexedSeq[String] =
    val text     = text0.stripPrefix("ï»¿").stripPrefix("﻿")
    val physical = text.split("\r\n|\n|\r", -1)
    val out      = Array.fill(physical.length)("")
    // splice backslash-newlines first, as translation phase 2 does
    val spliced = mutable.ArrayBuffer.empty[(Int, String)]
    var i       = 0
    while i < physical.length do
      val start = i
      val sb    = new StringBuilder(physical(i))
      while sb.nonEmpty && sb.last == '\\' && i + 1 < physical.length do
        sb.setLength(sb.length - 1)
        i += 1
        sb.append(physical(i))
      spliced += ((start, sb.toString))
      i += 1
    var inComment                               = false
    var directive: Option[(Int, StringBuilder)] = None
    spliced.foreach { case (start, line) =>
        val startsDirective = !inComment && directive.isEmpty && line.trim.startsWith("#")
        val sb              = new StringBuilder
        var j               = 0
        var quote: Char     = 0
        while j < line.length do
          val c    = line.charAt(j)
          val next = if j + 1 < line.length then line.charAt(j + 1) else 0.toChar
          if inComment then
            if c == '*' && next == '/' then
              inComment = false
              j += 2
            else j += 1
          else if quote != 0 then
            sb.append(c)
            if c == '\\' && j + 1 < line.length then
              sb.append(next)
              j += 2
            else
              if c == quote then quote = 0
              j += 1
          else if c == '/' && next == '*' then
            inComment = true
            sb.append(' ')
            j += 2
          else if c == '/' && next == '/' then j = line.length
          // a quote opens a literal, except a C++14 digit separator (`1'000`)
          else if c == '"' || (c == '\'' && !(j > 0 && line.charAt(j - 1).isLetterOrDigit)) then
            quote = c
            sb.append(c)
            j += 1
          else
            sb.append(c)
            j += 1
          end if
        end while
        directive match
          case Some((at, acc)) =>
              acc.append(' ').append(sb)
              if !inComment then
                out(at) = acc.toString
                directive = None
          case None =>
              if startsDirective && inComment then
                directive = Some((start, new StringBuilder(sb.toString)))
              else out(start) = sb.toString
    }
    directive.foreach { case (at, acc) => out(at) = acc.toString }
    out.toIndexedSeq
  end logicalLinesOf
end MacroCensus
