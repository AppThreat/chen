package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Two weakness classes outside allocation state, read straight off the AST and CFG:
  *
  *   - **MS-FMT-001** (CWE-134) - a printf-family call whose format is not a constant: a parameter
  *     (some caller passes a non-literal for it) or a local with a non-literal definition. A
  *     variadic or `va_list` forwarder passing its own format parameter on is the wrapper idiom,
  *     not the bug: its callers' formats are what matters.
  *   - **MS-INIT-001** (CWE-457) - a read of a local that NO path from the method entry initialises:
  *     a forward maybe-initialised dataflow over the CFG, per variable and per struct field (`s.a =
  *     1; use(s.b)` reads an uninitialised member). Taking the address (`&x`, an out-parameter) or
  *     writing any part counts as initialising it; static locals are zero-initialised. Arrays and
  *     class types are left alone - a constructor or a fill loop initialises what this cannot see.
  */
object InitAndFormatRules:

  /** printf-family names and the 1-based index of their format argument. */
  val FormatArgIndex: Map[String, Int] = Map(
    "printf"      -> 1,
    "vprintf"     -> 1,
    "wprintf"     -> 1,
    "scanf"       -> 1,
    "warn"        -> 1,
    "warnx"       -> 1,
    "fprintf"     -> 2,
    "vfprintf"    -> 2,
    "fwprintf"    -> 2,
    "dprintf"     -> 2,
    "vdprintf"    -> 2,
    "sprintf"     -> 2,
    "vsprintf"    -> 2,
    "asprintf"    -> 2,
    "vasprintf"   -> 2,
    "fscanf"      -> 2,
    "sscanf"      -> 2,
    "syslog"      -> 2,
    "vsyslog"     -> 2,
    "err"         -> 2,
    "errx"        -> 2,
    "snprintf"    -> 3,
    "vsnprintf"   -> 3,
    "swprintf"    -> 3,
    "av_log"      -> 3,
    "av_vlog"     -> 3,
    "av_bprintf"  -> 2,
    "av_asprintf" -> 1
  )

  private def unwrapCasts(e: Expression): Expression = e match
    case c: Call if c.name == "<operator>.cast" =>
        c.argument.l.collect { case x: Expression => x }.lastOption.map(unwrapCasts).getOrElse(c)
    case other => other

  private def isStringLiteral(e: Expression): Boolean = unwrapCasts(e) match
    case l: Literal => true
    case c: Call if c.name == "<operator>.conditional" =>
        c.argument.l.drop(1).collect { case x: Expression => x }.forall(isStringLiteral)
    case _ => false

  private def isForwarder(m: Method): Boolean =
      m.parameter.l.exists(p =>
          p.typeFullName.contains("va_list") || p.code.contains("...") || p.isVariadic
      ) || Option(m.signature).exists(_.contains("..."))

  def formatString(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.call.filter(c => FormatArgIndex.contains(c.name)).foreach { call =>
          call.argumentOption(FormatArgIndex(call.name)).collect { case e: Expression => e }
              .map(unwrapCasts)
              .foreach {
                  case i: Identifier if !isStringLiteral(i) =>
                      val method = call.method
                      method.parameter.nameExact(i.name).l.headOption match
                        case Some(param) =>
                            if !isForwarder(method) && someCallerPassesNonLiteral(method, param.index)
                            then record(i, MemorySafetyFindingPass.RuleFormatString)
                        case None if method.local.nameExact(i.name).nonEmpty =>
                            val defs = OverlayFacts.reachingDefsIn(i)
                                .collect { case d: Identifier => d }
                                .flatMap(_._astIn.collectFirst {
                                    case a: Call if a.name == "<operator>.assignment" => a
                                })
                                .flatMap(_.argumentOption(2))
                                .collect { case e: Expression => e }
                            if defs.nonEmpty && !defs.forall(isStringLiteral) then
                              record(i, MemorySafetyFindingPass.RuleFormatString)
                        case None => () // a global table or a macro constant
                  case _ => ()
              }
      }

  /** A method nobody in the tree calls is an entry point: its caller is outside and passes
    * anything. Otherwise some call site must pass a non-literal at `index`.
    */
  private def someCallerPassesNonLiteral(method: Method, index: Int): Boolean =
    val sites = method.callIn.l
    sites.isEmpty || sites.exists(
      _.argumentOption(index).collect { case e: Expression => e }.forall(a => !isStringLiteral(a))
    )

  // ---- MS-INIT-001 ----

  private val ScalarType =
      """(?:const\s+|volatile\s+|unsigned\s+|signed\s+)*(?:bool|_Bool|char|short|int|long|long\s+long|float|double|size_t|ssize_t|ptrdiff_t|u?int(?:8|16|32|64)_t|intptr_t|uintptr_t|off_t)(?:\s+int)?""".r

  private def isPointer(t: String): Boolean = t.trim.endsWith("*")

  /** A plain-old-data struct: a TYPE_DECL with members and no methods of its own. */
  private def isPodStruct(atom: Cpg, t: String): Boolean =
    val name = t.trim.stripPrefix("struct ").trim
    atom.typeDecl.fullNameExact(name).l.headOption.orElse(
      atom.typeDecl.nameExact(name.split("[.:]").last).l.headOption
    ).exists(td => td.member.nonEmpty && td.method.isEmpty && !td.isExternal)

  /** A `struct S { ... } s;` declared INSIDE the function: the frontend keeps no members for it
    * (only a bare external stub, or nothing), so [[isPodStruct]] cannot see the body. The local's
    * own `struct` keyword is the evidence this is a C struct defined right here - no constructor,
    * no fill loop the analysis cannot see - and the per-field question is askable from the field
    * accesses the function itself makes. An unknown non-struct type (a C++ class through the C
    * frontend, a header type the tree does not carry) keeps no such keyword and stays out.
    */
  private def isLocalStructDefinition(atom: Cpg, t: String, localCode: String): Boolean =
    localCode.trim.startsWith("struct ") && {
        val name = t.trim.stripPrefix("struct ").trim
        atom.typeDecl.fullNameExact(name).l.headOption.orElse(
          atom.typeDecl.nameExact(name.split("[.:]").last).l.headOption
        ).forall(td => td.member.isEmpty && td.method.isEmpty)
    }

  private def candidateType(atom: Cpg, t: String, localCode: String = ""): Boolean =
    val n = t.trim
    !n.contains("[") && (ScalarType.matches(n) || isPointer(n) || isPodStruct(atom, n) ||
        isLocalStructDefinition(atom, n, localCode))

  private def isStatic(l: Local): Boolean =
      l.code.trim.startsWith("static") ||
          l.tag.nameExact(MemorySemanticsPass.TagStorage).value.l.contains(
            MemorySemanticsPass.StorageStatic
          )

  private def parentCall(n: AstNode): Option[Call] = n._astIn.collectFirst { case c: Call => c }

  private def isLhsOf(n: AstNode, c: Call): Boolean =
      c.name.startsWith("<operator>.assignment") && c.argumentOption(1).exists(_.id == n.id)

  /** `s.b` / `s->b` with `s` an identifier: (base, field). */
  private def fieldPath(c: Call): Option[(String, String)] =
      if c.name == "<operator>.fieldAccess" then
        (c.argumentOption(1), c.argumentOption(2)) match
          case (Some(b: Identifier), Some(f: FieldIdentifier)) => Some(b.name -> f.canonicalName)
          case _                                               => None
      else None

  /** `s.f` for `s.f`, `s.f.g`, `s.f.g.h`: the candidate-level member a nested access touches. */
  private def rootFieldPath(c: Call): Option[(String, String)] =
      fieldPath(c).orElse(
        if c.name == "<operator>.fieldAccess" then
          c.argumentOption(1).collect { case b: Call => b }.flatMap(rootFieldPath)
        else None
      )

  /** The outermost access of a member chain `f` is the base of: `s.f` inside `s.f.g.h`. */
  private def outermostAccess(f: Call): Call =
      parentCall(f).filter(p => p.name == "<operator>.fieldAccess" && p.argumentOption(1).exists(_.id == f.id))
          .map(outermostAccess).getOrElse(f)

  private def insideUnevaluated(n: AstNode): Boolean =
      n.inAst.collectAll[Call].exists(c =>
          c.name == "<operator>.sizeOf" || c.name == "<operator>.addressOf" ||
              c.name == "sizeof" || c.name == "offsetof"
      ) || insideMacroArgument(n)

  /** Inside a macro invocation - an INLINED call, its argument copies or its expansion. The
    * arguments are copies (`GET_UTF16(val, ...)` assigns val in its expansion; the copy is no read)
    * and the expansion's CFG is stitched in, not built from the source: its locals and loops
    * (GET_UTF8, FFSWAP, DEFINE_CKSUM_LINE) made up nearly every FFmpeg report. A must-uninitialised
    * claim there is not one this rule can make.
    */
  private def insideMacroArgument(n: AstNode): Boolean =
      n.inAst.collectAll[Call].exists(_.dispatchType == "INLINED")

  /** `x = x` - FFmpeg's `av_uninit(x)`, the compiler-warning silencer: a declaration, not a read. */
  private def isSelfAssignmentRhs(i: Identifier, parent: Option[Call]): Boolean =
      parent.exists(p =>
          p.name == "<operator>.assignment" && p.argumentOption(2).exists(_.id == i.id) &&
              p.argumentOption(1).exists {
                  case l: Identifier => l.name == i.name
                  case _             => false
              }
      )

  def uninitialisedReads(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.method.isExternal(false).foreach { method =>
          val locals = method.local.l
          // a macro may assign what it is handed (`GET_V(count, ...)`, `bn_hex2bn(p, hex, ret)`)
          // and its expansion's CFG is stitched, not built: a name a macro invocation mentions,
          // or a local its body declares, is out of reach. So is a name declared twice (an inner
          // scope's `int i` shadowing another) or shadowing a parameter - a name is the key here
          val inlined = method.ast.collectAll[Call].filter(_.dispatchType == "INLINED").l
          val macroNames = inlined.flatMap(_.ast.collectAll[Identifier].name.l).toSet
          val params     = method.parameter.name.toSet
          val declaredTwice = locals.groupBy(_.name).collect { case (n, ls) if ls.size > 1 => n }.toSet
          val candidates = locals
              .filter(l => !isStatic(l) && candidateType(atom, l.typeFullName, l.code))
              .filterNot(l => l.inAst.collectAll[Call].exists(_.dispatchType == "INLINED"))
              .map(_.name)
              .toSet -- macroNames -- params -- declaredTwice
          // declared on the line it is read on: hand-written C does not do that, a macro that
          // defines a whole function (GET_STR16, RTP_G726_HANDLER) does - its lines are all one
          val declLine = locals.flatMap(l => l.lineNumber.map(n => l.name -> n.toInt)).toMap
          if candidates.nonEmpty then analyse(method, candidates, declLine, record)
      }

  private def analyse(
    method: Method,
    candidates: Set[String],
    declLine: Map[String, Int],
    record: (StoredNode, String) => Unit
  ): Unit =
    val nodes = method.ast.isCfgNode.l
    if nodes.isEmpty || nodes.size > 20000 then return
    // the definition each CFG node makes, and the read it performs (checked on entry)
    val gen   = mutable.LongMap.empty[Set[String]]
    val reads = mutable.ListBuffer.empty[(CfgNode, String, Set[String])] // node, shown, accepted
    nodes.foreach {
        case c: Call if c.name.startsWith("<operator>.assignment") =>
            c.argumentOption(1).foreach {
                case i: Identifier if candidates.contains(i.name) =>
                    gen(c.id()) = Set(i.name)
                // `s.f.g = x` initialises (part of) s.f: partly initialised is not uninitialised
                case f: Call =>
                    rootFieldPath(f).filter(p => candidates.contains(p._1)).foreach { case (b, fl) =>
                        gen(c.id()) = Set(s"$b.$fl")
                    }
                case _ => ()
            }
        case c: Call if c.name == "<operator>.addressOf" =>
            c.argumentOption(1).foreach {
                case i: Identifier if candidates.contains(i.name) => gen(c.id()) = Set(i.name)
                case f: Call =>
                    fieldPath(f).filter(p => candidates.contains(p._1)).foreach { case (b, _) =>
                        gen(c.id()) = Set(b)
                    }
                case _ => ()
            }
        case i: Identifier if candidates.contains(i.name) =>
            val parent = parentCall(i)
            val isWrite = parent.exists(p =>
                isLhsOf(i, p) && p.name == "<operator>.assignment"
            )
            val isFieldBase = parent.exists(_.name == "<operator>.fieldAccess")
            val voided = parent.exists(p =>
                p.name == "<operator>.cast" && p.code.replace(" ", "").startsWith("(void)")
            )
            if !isWrite && !isFieldBase && !voided && !isSelfAssignmentRhs(i, parent) &&
              !insideUnevaluated(i)
            then
              reads += ((i, i.name, Set(i.name, s"${i.name}.*")))
        case f: Call if f.name == "<operator>.fieldAccess" =>
            fieldPath(f).filter(p => candidates.contains(p._1)).foreach { case (b, fl) =>
                val top     = outermostAccess(f)
                val parent  = parentCall(top)
                val isWrite = parent.exists(p => isLhsOf(top, p) && p.name == "<operator>.assignment")
                if !isWrite && !insideUnevaluated(f) then reads += ((f, s"$b.$fl", Set(b, s"$b.$fl")))
            }
        case _ => ()
    }
    if reads.isEmpty then return
    // a field written is `s.f`, and `s.*` for a whole-value read of s (partly initialised is not
    // uninitialised); `s` itself only from an assignment to, or the address of, all of s
    def genOf(n: CfgNode): Set[String] =
        gen.getOrElse(n.id(), Set.empty).flatMap(g =>
            if g.contains('.') then Set(g, s"${g.takeWhile(_ != '.')}.*") else Set(g)
        )
    val in       = mutable.LongMap.empty[Set[String]]
    val out      = mutable.LongMap.empty[Set[String]]
    val worklist = mutable.Queue.from(nodes)
    val queued   = mutable.HashSet.from(nodes.map(_.id()))
    var steps    = 0
    while worklist.nonEmpty && steps < 400000 do
      steps += 1
      val n = worklist.dequeue()
      queued -= n.id()
      val preds = n._cfgIn.collectAll[CfgNode].l
      val inSet = preds.foldLeft(Set.empty[String])((acc, p) => acc ++ out.getOrElse(p.id(), Set.empty))
      in(n.id()) = inSet
      val o = inSet ++ genOf(n)
      if !out.get(n.id()).contains(o) then
        out(n.id()) = o
        n._cfgOut.collectAll[CfgNode].foreach { s =>
            if queued.add(s.id()) then worklist.enqueue(s)
        }
    if worklist.nonEmpty then return // did not converge: say nothing
    // only nodes the method entry reaches: a node cut off from it (a CFG the frontend could not
    // wire, dead code) has an empty in-set that proves nothing
    val reachable = mutable.HashSet.empty[Long]
    val frontier  = mutable.Stack[CfgNode](method)
    while frontier.nonEmpty do
      val n = frontier.pop()
      if reachable.add(n.id()) then n._cfgOut.collectAll[CfgNode].foreach(frontier.push)
    reads.foreach { case (node, shown, accepted) =>
        in.get(node.id()).foreach { s =>
            val sameLine = node.lineNumber.exists(n => declLine.get(shown.takeWhile(_ != '.')).contains(n.toInt))
            if reachable.contains(node.id()) && !sameLine && !accepted.exists(s.contains) then
              record(node, MemorySafetyFindingPass.RuleUninitialisedRead)
        }
    }
  end analyse
end InitAndFormatRules
