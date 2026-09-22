package io.appthreat.dataflowengineoss

import io.appthreat.dataflowengineoss.semantics.{JavaFrameworkSemantics, PhpFrameworkSemantics}
import io.appthreat.dataflowengineoss.semanticsloader.{FlowSemantic, PassThroughMapping, Semantics}
import io.shiftleft.codepropertygraph.generated.{Languages, Operators}

import scala.annotation.unused

object DefaultSemantics:

  /** @return
    *   a default set of common external procedure calls for all languages.
    *
    * This list is LANGUAGE NEUTRAL on purpose. `FlowSemantic.from` matches on the exact
    * `methodFullName` with no language scoping, so a language-specific summary for a bare name (C's
    * `free`/`read`/`getc`, PHP's `e`, `esc_html`, `htmlspecialchars`) would silently clear taint
    * for an unrelated function of the same name in a Java/JS/Python graph. Language-specific flows
    * are added per graph by [[flowsForLanguage]], which `OssDataFlow` applies using the CPG's own
    * `metaData.language`.
    */
  def apply(): Semantics =
    val list = operatorFlows ++ javaFlows
    Semantics.fromList(list)

  /** A memoised [[apply]], for use where an implicit default argument would otherwise do.
    *
    * Scala re-evaluates a default argument expression on every call that omits it, and the DDG
    * steps (`ddgIn`, `ddgInPathElem`) are invoked as bare `_.ddgIn` inside slicing `repeat`
    * worklists - once per DDG edge per path. Rebuilding the table (several hundred `FlowSemantic`
    * objects plus a fresh `mutable.Map`) at that rate was measured at ~28 GB/s of garbage - 4.5 TB
    * allocated in 155 s - while slicing FFmpeg's libavformat. A shared instance also keeps the
    * regex-result cache warm: a fresh instance starts with an empty cache, so regex semantics were
    * re-matched forever and the cache never paid for itself.
    *
    * Sharing is safe because the instance is read-only after construction - the only mutation is
    * [[Semantics.loadRegexSemantics]], which each pipeline runs once, before queries start.
    */
  lazy val memoised: Semantics = apply()

  /** Languages that get the JVM request-reader flows.
    *
    * NB: `ChennaiTagsPass` gates route tagging on a shorter list (no ANDROID/APK/DEX). The lists
    * are deliberately not shared - aligning them is a behaviour change, not a refactor.
    */
  private val JvmLanguages: Set[String] =
      Set(Languages.JAVA, Languages.JAVASRC, "JAR", "JIMPLE", "ANDROID", "APK", "DEX")

  /** Flow semantics that must only be applied to graphs of the given language.
    *
    * @param language
    *   a `MetaData.language` value (see `io.shiftleft.codepropertygraph.generated.Languages`).
    * @return
    *   the extra flows for that language, or an empty list when there are none.
    */
  def flowsForLanguage(language: String): List[FlowSemantic] =
      language match
        case Languages.PHP                => phpFlows
        case Languages.C | Languages.NEWC => cFlows
        case lang if JvmLanguages.contains(lang) =>
            javaRequestReaderFlows
        case _ => List.empty

  private def F = (x: String, y: List[(Int, Int)]) => FlowSemantic.from(x, y)

  /** `StringBuilder`/`StringBuffer` mutator `name`, for every overload: each argument taints the
    * builder it is appended to (and the returned builder, which is the same object), and the
    * builder keeps whatever it already held. Arguments 1 to 3 cover every overload in the JDK.
    *
    * A CHAINED call (`sb.append(a).append(tainted)`) is not covered: there the tainted argument
    * reaches the inner call's result, and identifying that result with the `sb` the chain started
    * from is an aliasing question a mapping table cannot answer. The unchained form - which is what
    * a loop-built or statement-by-statement string looks like - is the one carried here.
    */
  private def stringBuilderAccumulator(name: String): FlowSemantic =
      FlowSemantic.from(
        "java\\.lang\\.String(Builder|Buffer)\\." + name + ":.*",
        List((0, 0), (0, -1)) ++ (1 to 3).toList.flatMap(i => List((i, 0), (i, -1))),
        regex = true
      )

  private def PTF(x: String, ys: List[(Int, Int)] = List.empty): FlowSemantic =
      FlowSemantic(x).copy(mappings = FlowSemantic.from(x, ys).mappings :+ PassThroughMapping)

  def operatorFlows: List[FlowSemantic] = List(
    F(Operators.addition, List((1, -1), (2, -1))),
    F(Operators.addressOf, List((1, -1))),
    F(Operators.assignment, List((2, 1), (2, -1))),
    F(Operators.assignmentAnd, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentArithmeticShiftRight, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentDivision, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentExponentiation, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentLogicalShiftRight, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentMinus, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentModulo, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentMultiplication, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentOr, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentPlus, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentShiftLeft, List((2, 1), (1, 1), (2, -1))),
    F(Operators.assignmentXor, List((2, 1), (1, 1), (2, -1))),
    F(Operators.cast, List((1, -1), (2, -1))),
    F(Operators.computedMemberAccess, List((1, -1))),
    F(Operators.conditional, List((2, -1), (3, -1))),
    F(Operators.elvis, List((1, -1), (2, -1))),
    F(Operators.notNullAssert, List((1, -1))),
    F(Operators.fieldAccess, List((1, -1))),
    F(Operators.getElementPtr, List((1, -1))),

    // TODO does this still exist?
    F("<operator>.incBy", List((1, 1), (2, 1), (3, 1), (4, 1))),
    F(Operators.indexAccess, List((1, -1))),
    F(Operators.indirectComputedMemberAccess, List((1, -1))),
    F(Operators.indirectFieldAccess, List((1, -1))),
    F(Operators.indirectIndexAccess, List((1, -1), (2, 1))),
    F(Operators.indirectMemberAccess, List((1, -1))),
    F(Operators.indirection, List((1, -1))),
    F(Operators.memberAccess, List((1, -1))),
    F(Operators.pointerShift, List((1, -1))),
    F(Operators.postDecrement, List((1, 1), (1, -1))),
    F(Operators.postIncrement, List((1, 1), (1, -1))),
    F(Operators.preDecrement, List((1, 1), (1, -1))),
    F(Operators.preIncrement, List((1, 1), (1, -1))),
    F(Operators.sizeOf, List.empty[(Int, Int)]),
    // PEP 750 t-strings (Python 3.14): a t-string is not a concatenation. The interpolations
    // are held unevaluated in the Template object, so no argument may flow into the literal's
    // result - that boundary is the entire point of the PEP (libraries escape/parameterise
    // values instead of receiving an already-substituted string). The value expressions ARE
    // evaluated, which `<operator>.interpolation` (unlisted, so permissive) keeps intact; only
    // the step from an interpolation to the template object is closed here. A renderer that
    // consumes a literal template (`str(t"...")`) re-exposes the interpolations: that half is
    // carried by pysrc2cpg's PythonTemplateRenderPass bridge edges (task 12 D.1), not by a
    // semantic - a semantic cannot express "flow only when rendered".
    F("<operator>.templateString", List.empty[(Int, Int)]),

    //  some of those operators have duplicate mappings due to a typo
    //  - see https://github.com/ShiftLeftSecurity/codepropertygraph/pull/1630

    F("<operators>.assignmentExponentiation", List((2, 1), (1, 1))),
    F("<operators>.assignmentModulo", List((2, 1), (1, 1))),
    F("<operators>.assignmentShiftLeft", List((2, 1), (1, 1))),
    F("<operators>.assignmentLogicalShiftRight", List((2, 1), (1, 1))),
    F("<operators>.assignmentArithmeticShiftRight", List((2, 1), (1, 1))),
    F("<operators>.assignmentAnd", List((2, 1), (1, 1))),
    F("<operators>.assignmentOr", List((2, 1), (1, 1))),
    F("<operators>.assignmentXor", List((2, 1), (1, 1))),

    // Language specific operators
    PTF("<operator>.tupleLiteral"),
    PTF("<operator>.dictLiteral"),
    PTF("<operator>.setLiteral"),
    PTF("<operator>.listLiteral")
  )

  /** Semantic summaries for common external C/C++ calls.
    *
    * These are keyed on BARE names (`strncpy`, `free`), because that is how c2cpg names libc calls.
    * They are therefore NOT part of [[apply]]: a bare name would collide with a same-named function
    * in a Java/JS/PHP graph (PHP's `e` sanitizer defect is the precedent). They reach a C/C++ graph
    * through [[flowsForLanguage]] keyed on `Languages.C`/`Languages.NEWC`.
    *
    * Mapping conventions used below, for `f(dst, src, ...)`:
    *   - every argument keeps its own definition: the identity mappings `(i, i)`;
    *   - a buffer writer maps `(src, dst)` so the copied-from argument taints the destination, plus
    *     `(src, -1)` when the function returns its destination;
    *   - an untrusted source (read/recv/fgets family) maps its stream/fd argument to the buffer it
    *     fills, so the flow starts at the stream identifier rather than at the destination;
    *   - an allocator maps its size arguments to the returned pointer.
    *
    * @see
    *   <a
    *   href="https://www.ibm.com/docs/en/i/7.3?topic=extensions-standard-c-library-functions-table-by-name">Standard
    *   C Library Functions</a>
    */
  def cFlows: List[FlowSemantic] = List(
    F("abs", List((1, 1), (1, -1))),
    F("abort", List.empty[(Int, Int)]),
    F("accept", List((1, 1), (2, 2), (3, 3), (1, 2), (1, 3), (1, -1))),
    F("alloca", List((1, 1), (1, -1))),
    F("aligned_alloc", List((1, 1), (2, 2), (2, -1))),
    F("asctime", List((1, 1), (1, -1))),
    F("asctime_r", List((1, 1), (1, -1))),
    F("asprintf", List((1, 1), (2, 2), (2, 1), (2, -1)) ++ variadicSources(3, 1)),
    F("atof", List((1, 1), (1, -1))),
    F("atoi", List((1, 1), (1, -1))),
    F("atol", List((1, 1), (1, -1))),
    F("bcopy", List((1, 1), (2, 2), (3, 3), (1, 2))),
    F("calloc", List((1, 1), (2, 2), (1, -1), (2, -1))),
    F("ceil", List((1, 1), (1, 1))),
    F("clock", List.empty[(Int, Int)]),
    F("ctime", List((1, -1))),
    F("ctime64", List((1, -1))),
    F("ctime_r", List((1, -1))),
    F("ctime64_r", List((1, -1))),
    F("difftime", List((1, -1), (2, -1))),
    F("difftime64", List((1, -1), (2, -1))),
    PTF("div"),
    F("exit", List((1, 1))),
    F("exp", List((1, -1))),
    F("fabs", List((1, -1))),
    F("fclose", List((1, 1), (1, -1))),
    F("fdopen", List((1, -1), (2, -1))),
    F("feof", List((1, 1), (1, -1))),
    F("ferror", List((1, 1), (1, -1))),
    F("fflush", List((1, 1), (1, -1))),
    F("fgetc", List((1, 1), (1, -1))),
    F("fgets", List((1, 1), (2, 2), (3, 3), (3, 1), (1, -1), (3, -1))),
    F("fread", List((1, 1), (2, 2), (3, 3), (4, 4), (4, 1), (3, -1))),
    F("free", List((1, 1))),
    F("fscanf", scanFlows(3)),
    F("fwrite", List((1, 1), (1, -1), (2, -1), (3, -1), (4, -1))),
    F("getc", List((1, 1))),
    F("getdelim", List((1, 1), (2, 2), (3, 3), (4, 4), (4, 1), (4, 2), (4, -1))),
    F("getenv", List((1, 1), (1, -1))),
    F("getline", List((1, 1), (2, 2), (3, 3), (3, 1), (3, 2), (3, -1))),
    F("gets", List((1, 1), (1, -1))),
    F("malloc", List((1, 1), (1, -1))),
    F("memcpy", List((1, 1), (2, 2), (3, 3), (2, 1), (1, -1), (2, -1))),
    F("memmove", List((1, 1), (2, 2), (3, 3), (2, 1), (1, -1), (2, -1))),
    F("mempcpy", List((1, 1), (2, 2), (3, 3), (2, 1), (1, -1), (2, -1))),
    F("mmap", List((1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6), (2, -1), (5, -1))),
    F("pread", List((1, 1), (2, 2), (3, 3), (4, 4), (1, 2), (3, -1))),
    F("read", List((1, 1), (2, 2), (3, 3), (1, 2), (3, -1))),
    F("readlink", List((1, 1), (2, 2), (3, 3), (1, 2), (3, -1), (1, -1))),
    F("realloc", List((1, 1), (2, 2), (1, -1), (2, -1))),
    F("reallocarray", List((1, 1), (2, 2), (3, 3), (1, -1), (2, -1), (3, -1))),
    F("recv", List((1, 1), (2, 2), (3, 3), (4, 4), (1, 2), (3, -1))),
    F(
      "recvfrom",
      List((1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6), (1, 2), (1, 5), (1, 6), (3, -1))
    ),
    F("recvmsg", List((1, 1), (2, 2), (3, 3), (1, 2), (1, -1))),
    F("scanf", List((1, 1), (1, -1)) ++ (2 to 6).toList.flatMap(i => List((i, i), (1, i)))),
    F("snprintf", List((1, 1), (2, 2), (3, 3), (3, 1), (1, -1), (3, -1)) ++ variadicSources(4, 1)),
    F("sprintf", List((1, 1), (2, 2), (2, 1), (1, -1), (2, -1)) ++ variadicSources(3, 1)),
    F("sscanf", List((1, 1), (2, 2), (1, -1)) ++ scanFlows(3)),
    F("stpcpy", List((1, 1), (2, 2), (2, 1), (1, -1), (2, -1))),
    F("strcasecmp", List((1, 1), (1, -1), (2, 2), (2, -1))),
    F("strcat", List((1, 1), (2, 2), (2, 1), (1, -1), (2, -1))),
    F("strcmp", List((1, 1), (1, -1), (2, 2), (2, -1))),
    F("strcpy", List((1, 1), (2, 2), (2, 1), (1, -1), (2, -1))),
    F("strdup", List((1, 1), (1, -1))),
    F("strlen", List((1, 1), (1, -1))),
    F("strncat", List((1, 1), (2, 2), (3, 3), (1, -1), (2, -1), (2, 1))),
    F("strncmp", List((1, 1), (1, -1), (2, 2), (2, -1), (3, 3))),
    F("strncpy", List((1, 1), (2, 2), (3, 3), (1, -1), (2, -1), (2, 1))),
    F("strndup", List((1, 1), (2, 2), (1, -1), (2, -1))),
    F("strtok", List((1, 1), (2, 2), (1, -1))),
    F("strtok_r", List((1, 1), (2, 2), (3, 3), (1, 3), (1, -1))),
    F("vsnprintf", List((1, 1), (2, 2), (3, 3), (4, 4), (3, 1), (4, 1), (1, -1), (3, -1), (4, -1))),
    F("vsprintf", List((1, 1), (2, 2), (3, 3), (2, 1), (3, 1), (1, -1), (2, -1), (3, -1)))
  ) ++ clampingMacroFlows

  /** Semantics for the common clamping macros (`FFMIN`, `FFMAX`, `FFABS`, `av_clip`), so that a
    * clamp the frontend left unexpanded as an opaque call still propagates "the result is derived
    * from - and bounded by - its arguments" instead of being an unknown function. Real builds
    * always have a mix of expanded and unexpanded macro sites, so both halves are needed: the CFG
    * wiring (c2cpg `cfgForInlinedCall`) makes the expansion visible, these summaries make the
    * unexpanded call safe.
    *
    * A macro invocation is emitted as a CALL with a location-encoded fullName
    * (`path/to/header.h:49:49:FFMIN:2`), hence the regexes: the bare name cannot be keyed.
    */
  private def clampingMacroFlows: List[FlowSemantic] =
      List(
        FlowSemantic.from(".*:FFMIN:\\d+$", List((1, 1), (2, 2), (1, -1), (2, -1)), regex = true),
        FlowSemantic.from(".*:FFMAX:\\d+$", List((1, 1), (2, 2), (1, -1), (2, -1)), regex = true),
        FlowSemantic.from(".*:FFABS:\\d+$", List((1, 1), (1, -1)), regex = true),
        FlowSemantic.from(
          ".*:av_clip:\\d+$",
          List((1, 1), (2, 2), (3, 3), (1, -1), (2, -1), (3, -1)),
          regex = true
        )
      )

  /** Mappings for the variadic tail of a printf-style writer: every source argument `i` in
    * `from..from+5` keeps its own definition and taints the destination `dst` and the return value.
    * The fixed arguments (destination, size, format) are spelled out at each entry.
    */
  private def variadicSources(from: Int, dst: Int): List[(Int, Int)] =
      (from to from + 5).toList.flatMap(i => List((i, i), (i, dst), (i, -1)))

  /** Mappings for a scanf-style reader whose output arguments start at `from`: the input (stream,
    * subject string) and the format both taint every output pointer, which is what makes a scanned
    * value carry the input's taint.
    */
  private def scanFlows(from: Int): List[(Int, Int)] =
      (from to from + 4).toList.flatMap(i => List((1, i), (2, i), (i, i)))

  /** Semantic summaries for common external Java calls.
    *
    * Includes the framework sanitizers and carriers of
    * [[io.appthreat.dataflowengineoss.semantics.JavaFrameworkSemantics]]: every entry there is
    * fully qualified, so the summaries are language-neutral-safe (a bare name cannot collide with a
    * same-named function in a C/JS/PHP graph).
    */
  def javaFlows: List[FlowSemantic] = List(
    PTF("java.lang.String.split:java.lang.String[](java.lang.String)", List((0, 0))),
    PTF("java.lang.String.split:java.lang.String[](java.lang.String,int)", List((0, 0))),
    PTF("java.lang.String.compareTo:int(java.lang.String)", List((0, 0))),
    // A string builder accumulates into its RECEIVER, which is the one direction the permissive
    // default for an unknown external call cannot express: it taints the return value only, so
    // `sb.append(tainted); sink(sb.toString())` lost the flow entirely - and that is how most
    // hand-built SQL and command strings are assembled. Regex entries because `append`, `insert`
    // and `replace` are overloaded across every primitive and `Object`, and the resolved
    // methodFullName carries the signature.
    stringBuilderAccumulator("append"),
    stringBuilderAccumulator("insert"),
    stringBuilderAccumulator("replace"),
    F("java.io.PrintWriter.print:void(java.lang.String)", List((0, 0), (1, 1))),
    F("java.io.PrintWriter.println:void(java.lang.String)", List((0, 0), (1, 1))),
    F("java.io.PrintStream.println:void(java.lang.String)", List((0, 0), (1, 1))),
    PTF("java.io.PrintStream.print:void(java.lang.String)", List((0, 0))),
    F("android.text.TextUtils.isEmpty:boolean(java.lang.String)", List((0, -1), (1, -1))),
    F(
      "java.sql.PreparedStatement.prepareStatement:java.sql.PreparedStatement(java.lang.String)",
      List((1, -1))
    ),
    F("java.sql.PreparedStatement.prepareStatement:setDouble(int,double)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setFloat(int,float)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setInt(int,int)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setLong(int,long)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setShort(int,short)", List((1, 1), (2, 2))),
    F(
      "java.sql.PreparedStatement.prepareStatement:setString(int,java.lang.String)",
      List((1, 1), (2, 2))
    ),
    F(
      "org.apache.http.HttpRequest.<init>:void(org.apache.http.RequestLine)",
      List((1, 1), (1, 0))
    ),
    F(
      "org.apache.http.HttpRequest.<init>:void(java.lang.String,java.lang.String)",
      List((1, 1), (1, 0), (2, 0))
    ),
    F(
      "org.apache.http.HttpRequest.<init>:void(java.lang.String,java.lang.String,org.apache.http.ProtocolVersion)",
      List((1, 1), (1, 0), (2, 2), (2, 0), (3, 3), (3, 0))
    ),
    F("org.apache.http.HttpResponse.getStatusLine:org.apache.http.StatusLine()", List((0, -1))),
    F(
      "org.apache.http.HttpResponse.setStatusLine:void(org.apache.http.StatusLine)",
      List((1, 0), (1, 1), (0, -1))
    ),
    F(
      "org.apache.http.HttpResponse.setReasonPhrase:void(java.lang.String)",
      List((1, 0), (1, 1), (0, -1))
    ),
    F("org.apache.http.HttpResponse.getEntity:org.apache.http.HttpEntity()", List((0, -1))),
    F(
      "org.apache.http.HttpResponse.setEntity:void(org.apache.http.HttpEntity)",
      List((1, 0), (1, 1), (1, 0))
    )
  ) ++ javaFrameworkFlows

  /** Sanitizers (empty mappings: taint does not pass) and carriers (arg taint reaches the result)
    * from [[io.appthreat.dataflowengineoss.semantics.JavaFrameworkSemantics]].
    *
    * Sanitizers are declared with an empty mapping list - a declared semantic is authoritative, so
    * the argument no longer flows to the result. Carriers use `PTF`, whose PassThroughMapping flows
    * every non-receiver parameter to the return: a deserialised object is its input. The two string
    * builders are declared with explicit index mappings because their receiver (arg 0)
    * participates.
    */
  def javaFrameworkFlows: List[FlowSemantic] =
      JavaFrameworkSemantics.allSanitizerFullNames.toList.sorted.map(
        F(_, List.empty[(Int, Int)])
      ) ++
          List(
            F(
              "java.lang.String.format:java.lang.String(java.lang.String,java.lang.Object[])",
              List((1, -1), (2, -1))
            ),
            F("java.lang.String.concat:java.lang.String(java.lang.String)", List((0, -1), (1, -1)))
          ) ++
          JavaFrameworkSemantics.allCarrierFullNames.toList.map(name => PTF(name))

  /** Semantic summaries for PHP framework sanitizers (Laravel, Symfony, WordPress).
    *
    * These entries model the taint-clearing behaviour of common framework sanitizers. A sanitizer
    * is declared with an EMPTY mapping list: because a declared semantic is authoritative, only the
    * mappings listed propagate taint. With no mapping, the argument does NOT flow to the return, so
    * a value that is passed through the sanitizer before reaching a sink breaks the tainted flow
    * (see MethodFlowSummary: an undeclared parameter is treated as sanitized).
    *
    * The `methodFullName` values match how php2atom names free-function calls: a builtin or bare
    * function call `foo(...)` is named `foo` (its own name is used as the fullName). The names come
    * from [[PhpFrameworkSemantics.allSanitizerNames]], which is the single home of the PHP
    * framework taint vocabulary (php-support-upgrade design §2.7):
    *   - Laravel: `e()` (HTML entity encode)
    *   - WordPress: `esc_html()`, `sanitize_text_field()`, ...
    *   - PHP: `htmlspecialchars()`, `htmlentities()`
    *
    * Symfony has no single canonical string-sanitizer function in the design (escaping is done by
    * the templating layer / parameter binding), so it contributes no sanitizer entry; the Symfony
    * unsanitized source->sink flow is still enforced by the tests.
    *
    * These are deliberately NOT part of [[apply]]: the names are bare, so applying them to a
    * non-PHP graph would clear taint for any same-named function (a C/JS `e()` helper). They are
    * added per graph by [[flowsForLanguage]].
    */
  def phpFlows: List[FlowSemantic] =
      PhpFrameworkSemantics.allSanitizerNames.toList.sorted.map(F(_, List.empty[(Int, Int)]))

  /** Request-reader summaries for Java graphs, from
    * [[io.appthreat.dataflowengineoss.semantics.JavaFrameworkSemantics.RequestReaders]]: the value
    * returned by a request accessor is request data, so the receiver's taint flows to the return.
    *
    * Two shapes, for the two resolution states of a Java graph: receiver-qualified REGEX entries
    * for resolved calls, and bare names for unresolved ones. The bare names are why the whole list
    * is language-gated (see [[flowsForLanguage]]) - a `getParameter` on a non-request receiver
    * inside a Java graph is conservatively treated as request data, while graphs of other languages
    * are unaffected.
    */
  def javaRequestReaderFlows: List[FlowSemantic] =
    val readers = JavaFrameworkSemantics.RequestReaders
    // Bare names (unresolved calls) + receiver-qualified REGEX entries (resolved calls,
    // whose methodFullName carries a `:signature` suffix, so only a regex can match across
    // overloads): the receiver (parameter 0) flows to the return, because the returned
    // value IS request data.
    readers.callNames.toList.sorted.map(F(_, List((0, -1)))) ++
        readers.fullNames.toList.sorted.map(name =>
            FlowSemantic.from(
              java.util.regex.Pattern.quote(name) + ":.*",
              List((0, -1)),
              regex = true
            )
        )

  /** @return
    *   procedure semantics for operators and common external Java calls only.
    */
  @unused
  def javaSemantics(): Semantics = Semantics.fromList(operatorFlows ++ javaFlows)

  /** @return
    *   the semantics a C/C++ graph should be analysed with: the language-neutral defaults plus the
    *   libc summaries from [[cFlows]].
    */
  def cSemantics(): Semantics = Semantics.fromList(operatorFlows ++ javaFlows ++ cFlows)

  /** @return
    *   the semantics a PHP graph should be analysed with: the language-neutral defaults plus the
    *   PHP framework sanitizers (and none of the C summaries - a bare PHP `free` helper must not
    *   pick up libc `free`'s summary).
    */
  def phpSemantics(): Semantics =
      Semantics.fromList(operatorFlows ++ javaFlows ++ phpFlows)
end DefaultSemantics
