package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.appthreat.x2cpg.Defines
import io.shiftleft.semanticcpg.language.*

import scala.annotation.tailrec
import scala.collection.mutable

/** Two weakness classes outside allocation state, read straight off the AST and CFG:
  *
  *   - **MS-FMT-001** (CWE-134) - a printf-family call whose format is not a constant: a parameter
  *     (some caller passes a non-literal for it) or a local with a non-literal definition. A
  *     variadic or `va_list` forwarder passing its own format parameter on is the wrapper idiom,
  *     not the bug: its callers' formats are what matters.
  *   - **MS-INIT-001** (CWE-457) - a read of a local that NO path from the method entry
  *     initialises: a forward maybe-initialised dataflow over the CFG, per variable and per struct
  *     field (`s.a = 1; use(s.b)` reads an uninitialised member). Taking the address (`&x`, an
  *     out-parameter) or writing any part counts as initialising it; static locals are
  *     zero-initialised, and a C++ handler's exception binding (`catch (int e)`) is initialised by
  *     the throw. Arrays and class types are left alone - a constructor or a fill loop initialises
  *     what this cannot see.
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
    "av_asprintf" -> 1,
    // the C library's _FORTIFY_SOURCE wrappers take a flag (and a destination size) first
    "__printf_chk"    -> 2,
    "__vprintf_chk"   -> 2,
    "__fprintf_chk"   -> 3,
    "__vfprintf_chk"  -> 3,
    "__dprintf_chk"   -> 3,
    "__vdprintf_chk"  -> 3,
    "__asprintf_chk"  -> 3,
    "__vasprintf_chk" -> 3,
    "__syslog_chk"    -> 3,
    "__vsyslog_chk"   -> 3,
    "__sprintf_chk"   -> 4,
    "__vsprintf_chk"  -> 4,
    "__snprintf_chk"  -> 5,
    "__vsnprintf_chk" -> 5
  )

  /** The format argument of a printf-family call, in any spelling: a compiler builtin
    * (`__builtin_sprintf`, `__builtin___sprintf_chk`) takes the arguments of the function it names.
    */
  def formatArgIndex(callName: String): Option[Int] =
      FormatArgIndex.get(callName).orElse(FormatArgIndex.get(callName.stripPrefix("__builtin_")))

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
      // actual variadicity: a `va_list` parameter or a signature that still carries the
      // ellipsis. A parameter's own flag is not evidence - a template's pack parameter is
      // flagged variadic by the front end while the instance's signature holds the expanded
      // types, and that instance's printf is a call with concrete arguments, not a forward
      m.parameter.l.exists(_.typeFullName.contains("va_list")) ||
          Option(m.signature).exists(_.contains("..."))

  /** The call a printf-family macro expands to (`snprintf` defined as `__builtin___snprintf_chk`
    * under `_FORTIFY_SOURCE`): the macro's call carries the format, on the arguments as written;
    * checking both would report every finding twice.
    */
  private def expandsFormatMacro(call: Call): Boolean =
      call.dispatchType != DispatchTypes.INLINED &&
          call.inAst.collectAll[Call].exists(m =>
              m.dispatchType == DispatchTypes.INLINED && formatArgIndex(m.name).isDefined
          )

  def formatString(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.call.filter(c => formatArgIndex(c.name).isDefined && !expandsFormatMacro(c)).foreach {
          call =>
              call.argumentOption(formatArgIndex(call.name).get).collect { case e: Expression => e }
                  .map(unwrapCasts)
                  .foreach {
                      case i: Identifier if !isStringLiteral(i) =>
                          val method = call.method
                          method.parameter.nameExact(i.name).l.headOption match
                            case Some(param) =>
                                if !isForwarder(method) && someCallerPassesNonLiteral(
                                    method,
                                    param.index
                                  )
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

  /** A plain-old-data struct: a TYPE_DECL with members and no methods of its own, none of them an
    * array (a fill loop or a `memcpy(s.buf, ...)` initialises what this cannot see), a member with
    * a default initialiser (`size_t n = 0;`: the implicit constructor runs it), or an object a
    * constructor initialises. The member's code is its declarator as written.
    */
  /** A type's methods: those in its TYPE_DECL, and those written on their own (a class template
    * instance's member functions, kept once for the whole tree), by the full name they are members
    * of.
    */
  private def hasMethods(atom: Cpg, td: TypeDecl): Boolean =
      // a bare `<clinit>` is the frontend's own static-initialiser artifact for a record with
      // file-scope initialisation, not a member function: a C struct carrying one is still a
      // plain aggregate
      td.method.nameNot("<clinit>").nonEmpty || methodOwners(atom).contains(td.fullName)

  private val methodOwnersOf = new java.util.WeakHashMap[Cpg, Set[String]]()

  private def methodOwners(atom: Cpg): Set[String] = methodOwnersOf.synchronized {
      Option(methodOwnersOf.get(atom)).getOrElse {
          val owners =
              atom.method.isExternal(false).nameNot("<clinit>").fullName.l.flatMap { fullName =>
                val qualified = fullName.takeWhile(_ != ':')
                var depth     = 0
                var last      = -1
                qualified.indices.foreach { i =>
                    qualified(i) match
                      case '<'               => depth += 1
                      case '>'               => depth -= 1
                      case '.' if depth == 0 => last = i
                      case _                 =>
                }
                Option.when(last > 0)(qualified.substring(0, last))
              }.toSet
          methodOwnersOf.put(atom, owners)
          owners
      }
  }

  private def isPodStruct(atom: Cpg, t: String): Boolean =
    val name = t.trim.stripPrefix("struct ").trim
    podCandidates(atom, name).exists { td =>
      val members = OverlayFacts.membersOfTypeDecl(td)
      // an array member is initialised element-wise (`s.buf[i] = x` counts through
      // unwrapElements) or whole (`memcpy(s.buf, ...)`, which hands it out), so it keeps the
      // struct a candidate; a default initialiser or a constructed member does not
      members.nonEmpty && !hasMethods(atom, td) && !td.isExternal &&
      !members.exists(m =>
          hasDefaultInitializer(m) || isConstructed(atom, m.typeFullName, Set(name))
      )
    }

  /** An array type, spelled as one or hidden behind a typedef (`typedef int32_t fe[10]`). */
  private def isArrayType(atom: Cpg, t: String): Boolean =
    val n = t.trim
    n.endsWith("]") || OverlayFacts.typedefTarget(atom, n).exists(_.endsWith("]"))

  private def hasDefaultInitializer(m: Member): Boolean =
    val rest = m.code.trim.stripPrefix(m.name).trim
    rest.startsWith("=") || rest.startsWith("{")

  /** An object of type `t` (or an array of them) is initialised by a constructor: its class has
    * methods of its own, or a member that is. A struct holding one (`struct Output { uint64_t
    * number; InternalKey smallest; }`) gets an implicit constructor that runs it.
    */
  private def isConstructed(atom: Cpg, t: String, seen: Set[String]): Boolean =
    val name = t.trim.stripPrefix("struct ").replaceAll("""(\s*\[[^\]]*\])+$""", "").trim
    !name.endsWith("*") && !seen.contains(name) && podCandidates(atom, name).exists(td =>
        !td.isExternal && (hasMethods(atom, td) || OverlayFacts.membersOfTypeDecl(td).exists(m =>
            isConstructed(atom, m.typeFullName, seen + name)
        ))
    )

  /** The type declarations `name` may denote: a full-name match when one exists, else the bare
    * name. Read over ALL of them - a same-named pair (definition + stub, or two files' structs)
    * would answer differently depending on which node a traversal returned first.
    */
  private def podCandidates(atom: Cpg, name: String): List[TypeDecl] =
    val byFull = atom.typeDecl.fullNameExact(name).l
    if byFull.nonEmpty then byFull
    else atom.typeDecl.nameExact(name.split("[.:]").last).l

  /** A `struct S { ... } s;` declared INSIDE the function: the frontend keeps only an external stub
    * for it (bare, or carrying the member layout the AST pass recorded), so [[isPodStruct]], which
    * reads parsed definitions only, cannot see the body. The local's own `struct` keyword is the
    * evidence this is a C struct defined right here - no constructor, no fill loop the analysis
    * cannot see - and the per-field question is askable from the field accesses the function itself
    * makes. An unknown non-struct type (a C++ class through the C frontend, a header type the tree
    * does not carry) keeps no such keyword and stays out.
    */
  private def isLocalStructDefinition(atom: Cpg, t: String, localCode: String): Boolean =
      localCode.trim.startsWith("struct ") && {
          val name = t.trim.stripPrefix("struct ").trim
          podCandidates(atom, name).forall(td =>
              (OverlayFacts.membersOfTypeDecl(td).isEmpty || td.isExternal) && td.method.isEmpty
          )
      }

  private def candidateType(atom: Cpg, t: String, localCode: String = ""): Boolean =
    val n = t.trim
    !n.contains("[") && (ScalarType.matches(n) || isPointer(n) || isPodStruct(atom, n) ||
        isLocalStructDefinition(atom, n, localCode))

  private def isUnionMember(m: Member): Boolean =
      m.tag.nameExact(Defines.TypeStorageTag).value.l.contains(Defines.TypeStorageUnion)

  /** A local of a union: its members all overlay one storage, so a store to any one of them
    * initialises them all. The type says so when it is spelled as one (the CDT frontend's
    * elaborated and both frontends' anonymous spelling), the EDG frontend tags the local, or the
    * type's members carry the tag both frontends write. A union a constructor builds (a C++ union
    * with member functions, or with a member a constructor initialises) is left to it, as a class
    * is.
    */
  private def isUnionLocal(atom: Cpg, l: Local): Boolean =
    val n = l.typeFullName.trim
    n == "union" || n.startsWith("union ") ||
    l.tag.nameExact(Defines.TypeStorageTag).value.l.contains(Defines.TypeStorageUnion) || {
        val name = n.stripPrefix("union ").trim
        name.nonEmpty && !name.contains("[") && podCandidates(atom, name).exists { td =>
          val members = OverlayFacts.membersOfTypeDecl(td)
          !td.isExternal && !hasMethods(atom, td) && members.exists(isUnionMember) &&
          !members.exists(m => isConstructed(atom, m.typeFullName, Set(name)))
        }
    }

  /** The member sets of a struct whose members share storage: an anonymous union declared inside
    * it, which both frontends write as a TYPE_DECL child of the struct's with tagged members.
    */
  private def unionMemberGroups(atom: Cpg, t: String): List[Set[String]] =
    val name = t.trim.stripPrefix("struct ").trim
    if name.isEmpty then Nil
    else
      podCandidates(atom, name).flatMap { td =>
          if td.isExternal then Nil
          else
            td.astChildren.collectAll[TypeDecl]
                .filter(c => OverlayFacts.membersOfTypeDecl(c).exists(isUnionMember))
                .map(c => OverlayFacts.membersOfTypeDecl(c).map(_.name).toSet)
                .filter(_.nonEmpty)
                .l
      }.distinct

  private def isStatic(l: Local): Boolean =
      l.code.trim.startsWith("static") ||
          l.tag.nameExact(MemorySemanticsPass.TagStorage).value.l.contains(
            MemorySemanticsPass.StorageStatic
          )

  private def parentCall(n: AstNode): Option[Call] = n._astIn.collectFirst { case c: Call => c }

  /** The exception a C++ handler binds: a local of a handler block inside the `catch` group of a
    * TRY (the handler's own locals are in its body block). The thrown object initialises it.
    */
  private def isCatchBinding(l: Local): Boolean =
      l._astIn.collectFirst { case handler: Block => handler }.exists(handler =>
          handler._astIn.collectFirst { case group: Block => group }.exists(group =>
              group.code == "catch" && group._astIn.collectFirst { case t: ControlStructure =>
                  t
              }.exists(_.controlStructureType == "TRY")
          )
      )

  private def isLhsOf(n: AstNode, c: Call): Boolean =
      OverlayFacts.isAssignmentOperator(c.name) && c.argumentOption(1).exists(_.id == n.id)

  /** The expression a macro invocation stands for: its expansion, the INLINED call's last child
    * (after the copies of its arguments), through the blocks that wrap it and the invocations it
    * expands to in turn.
    */
  private def macroValue(m: Call): Option[AstNode] =
    @tailrec
    def valueOf(n: AstNode): Option[AstNode] = n match
      case b: Block => b.astChildren.l.maxByOption(_.order) match
            case Some(last) => valueOf(last)
            case None       => None
      case c: Call if c.dispatchType == DispatchTypes.INLINED =>
          c.astChildren.l.maxByOption(_.order) match
            case Some(last) => valueOf(last)
            case None       => None
      case other => Some(other)
    m.astChildren.l.maxByOption(_.order).flatMap(valueOf)

  /** The name a macro invocation on an assignment's left side stores to (`XX0` in `X(0) = l`, with
    * `#define X(i) XX##i`): a write, not a read. Names the expansion only reads (an index) stay
    * reads.
    */
  private def isMacroStoreTarget(i: Identifier): Boolean =
    @tailrec
    def up(n: AstNode): Boolean = n._astIn.nextOption() match
      case Some(b: Block) => up(b)
      case Some(m: Call) if m.dispatchType == DispatchTypes.INLINED =>
          if parentCall(m).exists(p => p.name == "<operator>.assignment" && isLhsOf(m, p)) then
            macroValue(m).exists(_.id == i.id)
          else up(m)
      case _ => false
    up(i)

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

  /** The expression an element access reads its container through: `s.f[i]` is `s.f`, an array
    * element of a union being one storage with its other members.
    */
  private def unwrapElements(c: Call): Call =
      if c.name == "<operator>.indexAccess" || c.name == "<operator>.indirectIndexAccess" then
        c.argumentOption(1).collect { case x: Call => unwrapElements(x) }.getOrElse(c)
      else c

  /** A call the program writes, or one through a function pointer, not an operator the frontend
    * derived (`<operator>.*`, and the compound assignments' `<operators>.*`) nor a macro's inline
    * expansion (the calls its expansion makes are calls in their own right): the callee may write
    * the storage an argument points into.
    */
  /** An argument position a call binds by reference: argument 0 of a member call (the receiver,
    * held by reference in C++), or a position whose RESOLVED callee declares a non-const reference
    * parameter. A by-value or const-reference binding reads; this one may write. The reference is
    * read out of the callee's FULL NAME - a parameter node's own type, and some graphs' signature
    * property, drop it, while the full name every frontend writes keeps it.
    */
  private def boundByReference(c: Call, index: Int): Boolean =
    import io.shiftleft.semanticcpg.language.NoResolve
    if index == 0 && c.name != "<operator>.pointerCall" then true
    else
      c.callee(using NoResolve).collectFirst { case m: Method => m }.exists { m =>
          signatureParameter(m.fullName, index).exists(t =>
            val trimmed = t.trim
            (trimmed.endsWith("&") || trimmed.endsWith("&&")) &&
            !trimmed.startsWith("const")
          )
      }

  /** An identifier a call receives as storage it may write: bound by reference, or an array -
    * spelled out or through a typedef (`pniels_t twop`) - that decays to a pointer into itself.
    */
  private def handedAsStorage(atom: Cpg, c: Call, i: Identifier): Boolean =
      boundByReference(c, i.argumentIndex) || isArrayType(atom, i.typeFullName)

  /** The `index`-th parameter's type as the method's signature spells it, splitting the parameter
    * list at the commas outside angle brackets and parentheses.
    */
  private def signatureParameter(signature: String, index: Int): Option[String] =
    val open  = signature.indexOf('(')
    val close = signature.lastIndexOf(')')
    if open < 0 || close <= open then None
    else
      val params = signature.substring(open + 1, close)
      if params.trim.isEmpty then None
      else
        val parts   = mutable.ArrayBuffer.empty[String]
        val current = new StringBuilder
        var depth   = 0
        params.foreach { ch =>
            ch match
              case '<' | '('         => depth += 1; current += ch
              case '>' | ')'         => depth -= 1; current += ch
              case ',' if depth == 0 => parts += current.toString; current.clear()
              case other             => current += other
        }
        parts += current.toString
        parts.lift(index - 1)
  end signatureParameter

  private def handsOut(c: Call): Boolean =
      c.name == "<operator>.pointerCall" ||
          (!c.name.startsWith("<operator") && c.dispatchType != DispatchTypes.INLINED)

  /** An array member (`u.c`, which decays to a pointer into the object) handed on as a call
    * argument, possibly through the casts and pointer arithmetic written around it (`f((T *)u.c)`,
    * `f(u.c + 16)`): its base, whose storage the callee may write. A member passed by value - a
    * scalar, a pointer, an element - is a read, and names nothing here.
    */
  private def handedBaseOf(atom: Cpg, e: Expression): Option[String] = e match
    case c: Call if c.name == "<operator>.fieldAccess" =>
        // the member's DECLARED type decides: the access itself is typed as what it decays to
        // (a pointer) in some graphs, and an array member decays wherever it is handed over
        val memberIsArray = isArrayType(atom, c.typeFullName) ||
            OverlayFacts.memberRefOf(atom, c).exists(m => isArrayType(atom, m.typeFullName))
        fieldPath(c).filter(_ => memberIsArray).map(_._1)
    case c: Call if c.name == "<operator>.cast" =>
        c.argument.l.lastOption.flatMap(handedBaseOf(atom, _))
    case c: Call if c.name == "<operator>.addition" || c.name == "<operator>.subtraction" =>
        c.argument.l.flatMap(handedBaseOf(atom, _)).headOption
    case _ => None

  /** The array member access is an argument of a call that may write it, through casts and pointer
    * arithmetic: handing it over is not a read.
    */
  @tailrec
  private def handedToCall(n: AstNode): Boolean =
      parentCall(n) match
        case Some(p)
            if p.name == "<operator>.cast" || p.name == "<operator>.addition" ||
                p.name == "<operator>.subtraction" =>
            handedToCall(p)
        case Some(p) => handsOut(p)
        case None    => false

  /** The outermost access of a member or element chain `f` is the base of: `s.f` inside `s.f.g.h`,
    * `s.f` inside `s.f[i] = x` (whose left side is a write, not a read).
    */
  private def outermostAccess(f: Call): Call =
      parentCall(f).filter(p =>
          (p.name == "<operator>.fieldAccess" || p.name == "<operator>.indexAccess" ||
              p.name == "<operator>.indirectIndexAccess") &&
              p.argumentOption(1).exists(_.id == f.id)
      )
          .map(outermostAccess).getOrElse(f)

  private def insideUnevaluated(n: AstNode): Boolean =
      n.inAst.collectAll[Call].exists(c =>
          c.name == "<operator>.sizeOf" || c.name == "<operator>.addressOf" ||
              c.name == "sizeof" || c.name == "offsetof"
      ) || insideMacroArgument(n)

  /** A copy of a macro argument (the frontend marks each node of the INLINED call's argument
    * subtrees): the expansion holds the same expression, and the copy is not a second read.
    */
  private def insideMacroArgument(n: AstNode): Boolean =
      n.tag.nameExact(io.appthreat.x2cpg.Defines.MacroArgumentCopyTag).nonEmpty

  /** `x = x` - FFmpeg's `av_uninit(x)`, the compiler-warning silencer: a declaration, not a read.
    */
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
        // a macro's expansion is on the path (an assignment it makes to what it is handed,
        // `GET_V(count, ...)`, is a definition) and its argument copies are marked, so a name a
        // macro mentions is analysed like any other; a local a macro's body declares is not, nor
        // a name declared twice (an inner scope's `int i` shadowing another) or shadowing a
        // parameter - a name is the key here
        val params = method.parameter.name.toSet
        val declaredTwice =
            locals.groupBy(_.name).collect { case (n, ls) if ls.size > 1 => n }.toSet
        val candidates = locals
            .filter(l =>
                !isStatic(l) && !isCatchBinding(l) && (candidateType(
                  atom,
                  l.typeFullName,
                  l.code
                ) ||
                    isUnionLocal(atom, l))
            )
            .filterNot(l => l.inAst.collectAll[Call].exists(_.dispatchType == "INLINED"))
            .map(_.name)
            .toSet -- params -- declaredTwice -- capturedByLambdas(method)
        // declared on the line it is read on: hand-written C does not do that, a macro that
        // defines a whole function (GET_STR16, RTP_G726_HANDLER) does - its lines are all one
        val declLine = locals.flatMap(l => l.lineNumber.map(n => l.name -> n.toInt)).toMap
        if candidates.nonEmpty then
          val unions = locals
              .filter(l => candidates.contains(l.name) && isUnionLocal(atom, l))
              .map(_.name)
              .toSet
          val groups = locals
              .filter(l => candidates.contains(l.name) && !unions.contains(l.name))
              .flatMap(l => unionMemberGroups(atom, l.typeFullName).map(g => l.name -> g))
              .groupBy(_._1)
              .view
              .mapValues(_.map(_._2))
              .toMap
          analyse(atom, method, candidates, unions, groups, declLine, record)
      }

  /** The names the method's lambdas use from it: a capture by reference may write the local (`[&] {
    * inserted = true; }()`), out of this method's sight.
    */
  private def capturedByLambdas(method: Method): Set[String] =
      method.ast.isMethodRef.l.flatMap(_._refOut.collectFirst { case m: Method => m }).flatMap {
          lambda =>
            val own = (lambda.local.name ++ lambda.parameter.name).toSet
            lambda.ast.isIdentifier.name.filterNot(own.contains).l
      }.toSet

  private def analyse(
    atom: Cpg,
    method: Method,
    candidates: Set[String],
    unions: Set[String],
    groups: Map[String, List[Set[String]]],
    declLine: Map[String, Int],
    record: (StoredNode, String) => Unit
  ): Unit =
    // the paths a constant condition leaves closed prove nothing: `if (0) { return x; }` reads
    // x on no path, and a write only a dead branch makes is no write at all
    val live  = OverlayFacts.feasibleCfgNodes(method)
    val nodes = method.ast.isCfgNode.l.filter(n => live.contains(n.id))
    if nodes.isEmpty || nodes.size > 20000 then return
    // the definition each CFG node makes, and the read it performs (checked on entry)
    val gen   = mutable.LongMap.empty[Set[String]]
    val reads = mutable.ListBuffer.empty[(CfgNode, String, Set[String])] // node, shown, accepted
    /** The storage a write to `b.fl` initialises: the whole of `b` for a union (its members share
      * one storage), the union's members for a field of an anonymous union inside the struct, the
      * field itself otherwise.
      */
    def storageOf(b: String, fl: String): Set[String] =
        if unions.contains(b) then Set(b)
        else
          groups.get(b).flatMap(_.find(_.contains(fl))).map(g => g.map(m => s"$b.$m"))
              .getOrElse(Set(s"$b.$fl"))

    /** The storage a store to `lhs` initialises. */
    def stored(lhs: AstNode): Option[Set[String]] = lhs match
      case i: Identifier if candidates.contains(i.name) => Some(Set(i.name))
      // a macro invocation on the left (`X(0) = l`, `#define X(i) XX##i`): the store its expansion
      // spells
      case m: Call if m.dispatchType == DispatchTypes.INLINED => macroValue(m).flatMap(stored)
      // `s.f.g = x` initialises (part of) s.f: partly initialised is not uninitialised; so does
      // `s.f[i] = x` on a union, whose elements are one storage with the rest
      case f: Call =>
          rootFieldPath(unwrapElements(f)).filter(p => candidates.contains(p._1)).map {
              case (b, fl) => storageOf(b, fl)
          }
      case _ => None
    nodes.foreach {
        case c: Call if OverlayFacts.isAssignmentOperator(c.name) =>
            c.argumentOption(1).flatMap(stored).foreach(s => gen(c.id()) = s)
        // an ARRAY member handed to a call: it decays to a pointer into the object, so the
        // callee may write that storage (`memcpy(t.c, iv, 16)`, `strncpy(f.tail, user, n)` on a
        // plain struct as much as on a union - a scalar or pointer member passed by value is a
        // read, and names nothing here). An object handed over BY REFERENCE - the receiver of a
        // member call, or an argument bound to a non-const reference parameter of the method the
        // graph resolves - is its callee's to write, exactly as an out-parameter is.
        case c: Call if handsOut(c) =>
            val bases = c.argument.l.flatMap(handedBaseOf(atom, _)).toSet
            val byReference = c.argument.l.collect {
                case i: Identifier
                    if candidates.contains(i.name) && handedAsStorage(atom, c, i) =>
                    i.name
            }.toSet
            val written = bases ++ byReference
            if written.nonEmpty then gen(c.id()) = written
        // the address of a local, a member or an element (`&s.f[i]`): an out-parameter
        case c: Call if c.name == "<operator>.addressOf" =>
            c.argumentOption(1).foreach {
                case i: Identifier if candidates.contains(i.name) => gen(c.id()) = Set(i.name)
                case f: Call =>
                    rootFieldPath(unwrapElements(f)).filter(p => candidates.contains(p._1))
                        .foreach { case (b, _) => gen(c.id()) = Set(b) }
                case _ => ()
            }
        case i: Identifier if candidates.contains(i.name) =>
            val parent = parentCall(i)
            val isWrite = parent.exists(p =>
                isLhsOf(i, p) && p.name == "<operator>.assignment"
            )
            val isFieldBase = parent.exists(_.name == "<operator>.fieldAccess")
            // handed over by reference: the callee holds the storage, this is not a read
            val handedOver = parent.exists(p => handsOut(p) && handedAsStorage(atom, p, i))
            val voided = parent.exists(p =>
                p.name == "<operator>.cast" && p.code.replace(" ", "").startsWith("(void)")
            )
            if !isWrite && !isFieldBase && !handedOver && !voided &&
              !isSelfAssignmentRhs(i, parent) && !insideUnevaluated(i) && !isMacroStoreTarget(i)
            then
              reads += ((i, i.name, Set(i.name, s"${i.name}.*")))
        case f: Call if f.name == "<operator>.fieldAccess" =>
            fieldPath(f).filter(p => candidates.contains(p._1)).foreach { case (b, fl) =>
                val top    = outermostAccess(f)
                val parent = parentCall(top)
                val isWrite =
                    parent.exists(p => isLhsOf(top, p) && p.name == "<operator>.assignment")
                // an ARRAY member handed to a call is handed as storage wherever it is
                // declared - a union's or a plain struct's alike; a scalar or pointer member
                // passed by value is a read
                val memberIsArray = isArrayType(atom, top.typeFullName) ||
                    OverlayFacts.memberRefOf(atom, f).exists(m => isArrayType(atom, m.typeFullName))
                val handedOut = memberIsArray && handedToCall(top)
                if !isWrite && !handedOut && !insideUnevaluated(f) then
                  reads += ((f, s"$b.$fl", Set(b, s"$b.$fl")))
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
      // a predecessor only a dead branch reaches contributes nothing: its writes are on no path
      val preds = n._cfgIn.collectAll[CfgNode].l.filter(p => live.contains(p.id()))
      val inSet =
          preds.foldLeft(Set.empty[String])((acc, p) => acc ++ out.getOrElse(p.id(), Set.empty))
      in(n.id()) = inSet
      val o = inSet ++ genOf(n)
      if !out.get(n.id()).contains(o) then
        out(n.id()) = o
        n._cfgOut.collectAll[CfgNode].filter(s => live.contains(s.id())).foreach { s =>
            if queued.add(s.id()) then worklist.enqueue(s)
        }
    if worklist.nonEmpty then return // did not converge: say nothing
    // every read judged here is on a path from the entry: `nodes` holds only `live` ones
    reads.foreach { case (node, shown, accepted) =>
        in.get(node.id()).foreach { s =>
          val sameLine =
              node.lineNumber.exists(n => declLine.get(shown.takeWhile(_ != '.')).contains(n.toInt))
          if !sameLine && !accepted.exists(s.contains) then
            record(node, MemorySafetyFindingPass.RuleUninitialisedRead)
        }
    }
  end analyse
end InitAndFormatRules
