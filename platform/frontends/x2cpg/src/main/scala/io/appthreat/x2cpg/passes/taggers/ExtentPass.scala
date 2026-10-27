package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** How big is this buffer, as a fact on the graph.
  *
  * For every destination argument of a memory-writing call ([[MemoryApiPass]]'s `mem-dst`), derive
  * the buffer's capacity and tag it `extent` (valued) plus the `memory-safety` umbrella:
  *
  *   - `const:128` - a declared array (`char buf[128]`, through a `#define`, and struct members:
  *     `int[16]` is in `typeFullName`);
  *   - `const:N-k` - a copy into `buf + k` for a literal k: the remaining capacity of the same
  *     buffer from the write's start;
  *   - `const:N` too for the destination size a FORTIFY wrapper (`__memcpy_chk`) was given, when
  *     the compiler knew it, and the extent of the object `__builtin_object_size(p, k)` names;
  *   - `offset:<extent>` - somewhere inside (or, for `base - k`, before) a buffer whose extent is
  *     `<extent>`, reduced by an unknown amount. NOT an extent: a rule that needs a capacity must
  *     reject it exactly as it rejects `unknown`. It exists so a later rule can tell "inside a
  *     128-byte buffer" apart from "no idea at all";
  *   - `sizeof:<expr>` - `sizeof(x)` in the allocation that produced the pointer, or as the copy's
  *     own length argument against the same buffer;
  *   - `alloc:<id>` - the size argument of the `mem-alloc`/`mem-realloc` call that produced the
  *     pointer;
  *   - `param:<name>` - a capacity parameter paired with a buffer parameter (adjacent in the
  *     signature, pointer then integral);
  *   - `field:<name>` - a struct member holding the length beside the buffer (`payload` /
  *     `payload_len`);
  *   - `unknown` - everything else.
  *
  * `unknown` is load-bearing: a detector that needs an extent must not fire when it sees it. A pass
  * that quietly guesses here is worse than one that admits ignorance, because the guess becomes a
  * false positive nobody can trace - so the fallback is an explicit tag, not silence.
  *
  * The declaration the extent came from (Local, Member, or the buffer's paired MethodParameterIn)
  * is tagged with the same value, so a guard comparison can be matched against a buffer's extent
  * without re-deriving it. Follows the MemoryApiPass conventions: one traversal, matches
  * accumulated per tag, single batched emit, C/C++ graphs only.
  */
class ExtentPass(atom: Cpg) extends CpgPass(atom):

  import ExtentPass.*
  import OverlayFacts.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return
    val argExtents  = mutable.LinkedHashMap.empty[StoredNode, String]
    val declExtents = mutable.LinkedHashMap.empty[StoredNode, String]

    // report buckets, over the destination arguments whose shape is a (direct or indirect)
    // field access - the bucket whose ceiling is the member-extent map
    var fieldDsts           = 0
    var fieldKnown          = 0
    var fieldAllocSomewhere = 0
    var fieldNoAlloc        = 0
    var fieldUnresolvable   = 0

    OverlayFacts
        .memoryArgumentSites(atom)
        .groupBy { case (call, _, _) => call }
        .foreach { case (call, rows) =>
            val dstArgs = rows.collect { case (_, e, MemoryApiPass.TagDst) => e }
            val lenArg  = rows.collectFirst { case (_, e, MemoryApiPass.TagLen) => e }

            dstArgs.foreach { dst =>
              // The copy's own `sizeof(buf)` length is an extent fact about buf.
              val sizeofInCopy =
                  for
                    len     <- lenArg
                    operand <- sizeOfOperand(len)
                    dstKey  <- variableKey(dst)
                    lenKey  <- variableKey(operand)
                    if dstKey == lenKey
                  yield s"$ValueSizeof:${operand.code}"

              extentOf(dst, call.method, sizeofInCopy)
                  .orElse(objectSizeExtentOf(call, dst, call.method)) match
                case Some((value, decls)) =>
                    argExtents(dst) = value
                    decls.foreach(d => declExtents(d) = value)
                case None =>
                    argExtents(dst) = ValueUnknown
            }

            dstArgs.foreach { dst =>
              val isFieldShape = dst match
                case c: Call =>
                    c.name == "<operator>.fieldAccess" ||
                    c.name == "<operator>.indirectFieldAccess"
                case _ => false
              if isFieldShape then
                fieldDsts += 1
                argExtents.get(dst) match
                  case Some(v) if v != ValueUnknown =>
                      fieldKnown += 1
                  case _ =>
                      OverlayFacts.memberRefOf(atom, dst.asInstanceOf[Call]) match
                        case None =>
                            fieldUnresolvable += 1
                        case Some(member) =>
                            if memberAllocs.contains(member) then fieldAllocSomewhere += 1
                            else fieldNoAlloc += 1
            }
        }

    // The base of an array index is a buffer access, so its extent is the same fact it is
    // for a memcpy destination. Memory-call destinations are resolved first and never
    // overwritten: their resolution saw the copy's own sizeof evidence.
    atom.call
        .name("<operator>.indexAccess|<operator>.indirectIndexAccess")
        .l
        .foreach { access =>
            access.argumentOption(1).foreach { base =>
                if !argExtents.contains(base) then
                  extentOf(base, access.method, None) match
                    case Some((value, decls)) =>
                        argExtents(base) = value
                        decls.foreach(d => declExtents(d) = value)
                    case None =>
                        argExtents(base) = ValueUnknown
            }
        }

    OverlayFacts.emitTags(
      dstGraph,
      (argExtents.toList ++ declExtents.toList).map { case (node, value) =>
          (node, TagExtent, value)
      }
    )

    if fieldDsts > 0 then
      println(
        s"ExtentPass: field-access destinations $fieldDsts: " +
            s"${fieldKnown} with a known extent, $fieldAllocSomewhere allocated somewhere in the " +
            s"tree but no single capacity, $fieldNoAlloc with no allocation found, " +
            s"$fieldUnresolvable whose member could not be resolved"
      )
  end run

  /** The member-extent facts are not method-local, so they are built once, up front. The search is
    * whole-graph in BOTH dimensions: it reads every assignment in the tree (an `init` may allocate
    * `ctx->buf` that a `read_packet` writes), and it follows two shapes beyond a same-expression
    * match - the allocation stashed in a local before it reaches the member, and the allocation
    * made THROUGH the member's own address (`av_reallocp(&ctx->buf, n)`). Sizes are kept per member
    * even when they conflict: a member allocated at two different sizes gets no extent (no single
    * capacity exists), but it is still a member with an allocation somewhere in the tree - the
    * split the field-destination report draws.
    */
  private lazy val memberAllocs: Map[Member, mutable.LinkedHashSet[String]] = memberAllocsOf(atom)

  private lazy val memberExtents: Map[Member, String] =
      memberAllocs.collect {
          case (member, values) if values.size == 1 =>
              member -> values.head
      }.toMap

  private def memberAllocsOf(cpg: Cpg): Map[Member, mutable.LinkedHashSet[String]] =
    val sizes = mutable.LinkedHashMap.empty[Member, mutable.LinkedHashSet[String]]
    def note(member: Member, value: String): Unit =
        sizes.getOrElseUpdate(member, mutable.LinkedHashSet.empty[String]).add(value)
    def memberOfLhs(lhs: Expression): Option[Member] = lhs match
      case fa: Call => OverlayFacts.memberRefOf(cpg, fa)
      case _        => None

    // the allocation assigned to the member: directly, or through a local that holds it
    cpg.call.name("<operator>.assignment").foreach { assignment =>
        assignment.argumentOption(1).flatMap(memberOfLhs).foreach { member =>
          allocationSizeValueOf(assignment.argumentOption(2)).foreach(note(member, _))
          assignment.argumentOption(2).flatMap(allocExtentOf).foreach(note(member, _))
        }
    }

    // the allocation made through the member's own address: av_reallocp(&member, n)
    val allocCallNodes = (cpg.tag.name(MemoryApiPass.TagAlloc).l ++
        cpg.tag.name(MemoryApiPass.TagRealloc).l)
        .flatMap(_._taggedByIn.collectAll[Call].l)
        .distinct
    allocCallNodes.foreach { alloc =>
        alloc.argumentOption(1).collect {
            case addr: Call if addr.name == "<operator>.addressOf" =>
                addr
        }.flatMap(addr => addr.argumentOption(1).flatMap(memberOfLhs))
            .foreach(member => sizeArgValueOf(alloc).foreach(note(member, _)))
    }

    sizes.toMap
  end memberAllocsOf

  /** The extent value of the allocation a right-hand side expression produces, through casts. A
    * realloc produces the pointer too: `ctx->buf = av_realloc(ctx->buf, n)` is how the member's
    * capacity grows.
    */
  private def allocationSizeValueOf(rhs: Option[Expression]): Option[String] =
    def allocCallOf(e: Expression): Option[Call] = e match
      case c: Call if isAllocationCall(c) => Some(c)
      case c: Call if c.name.startsWith("<operator>.cast") =>
          c.argument.l.collectFirst { case inner: Call => inner }.flatMap(allocCallOf)
      case _ => None
    rhs.flatMap(allocCallOf).flatMap(alloc => sizeArgValueOf(alloc))

  /** The capacity an allocation establishes, from its length arguments.
    *
    * A count-by-size allocator tags BOTH factors `mem-len`, and then NO single argument is the
    * capacity - `calloc(n, sizeof(x))` holds `n * sizeof(x)` bytes, and naming either factor
    * reports a capacity the buffer does not have. When every factor is a constant the allocation is
    * still named (`alloc:`), and a reader multiplies its size arguments into bytes; `const:` would
    * read as a declared array's element count. The rest answer `unknown`: an extent that is one
    * element wide would present as a known capacity to the index rules, which is the shape the
    * overlay never emits (a fact we do not have, dressed as one we do).
    */
  private def sizeArgValueOf(alloc: Call): Option[String] =
      // a C++ new carries no `len` role (its count is ELEMENTS, not bytes): the array form's
      // extent argument after the type is its count, and the scalar form's capacity is the one
      // element it constructs. Both reference an id the rules value with the element size
      if alloc.name == "<operator>.new" then
        arrayNewCountOf(alloc).orElse(
          Option.when(
            !alloc.tag.name(io.appthreat.x2cpg.Defines.AllocFormTag).value.l
                .contains(io.appthreat.x2cpg.Defines.AllocFormArray)
          )(s"$ValueAlloc:${alloc.id}")
        )
      else
        val lenArgs = alloc.argument.l.filter(_.tag.name(MemoryApiPass.TagLen).l.nonEmpty)
        def valueOf(arg: Expression): String = arg match
          case sz: Call if sz.name.startsWith("<operator>.sizeOf") => s"$ValueSizeof:${sz.code}"
          case sizeArg                                             => s"$ValueAlloc:${sizeArg.id}"
        lenArgs match
          case Nil        => None
          case List(only) => Some(valueOf(only))
          case several    =>
              // every factor a constant: the product IS knowable, in bytes, from the allocation
              Option.when(several.forall(IndexRange.literal(_).isDefined))(
                s"$ValueAlloc:${several.head.id}"
              )

  private def isAllocationCall(c: Call): Boolean =
      c.tag.name(MemoryApiPass.TagAlloc).l.nonEmpty ||
          c.tag.name(MemoryApiPass.TagRealloc).l.nonEmpty

  /** The capacity a FORTIFY wrapper (`__memcpy_chk`) was given for its destination: a constant is
    * the size the compiler worked out (`(size_t)-1` when it could not, which is no capacity), and
    * `__builtin_object_size(p, k)` (or the dynamic form) is the capacity of the object it names.
    */
  private def objectSizeExtentOf(
    call: Call,
    dst: Expression,
    method: Method
  ): Option[(String, List[StoredNode])] =
    def withoutCasts(e: AstNode): AstNode = e match
      case c: Call if c.name == "<operator>.cast" =>
          c.argument.l.lastOption.map(withoutCasts).getOrElse(c)
      case other => other
    call.argument.l.find(_.tag.name(MemoryApiPass.TagObjectSize).nonEmpty).map(withoutCasts)
        .flatMap {
            case c: Call if ObjectSizeBuiltins.contains(c.name) =>
                c.argumentOption(1).collect { case e: Expression => e }
                    .filterNot(_ == dst)
                    .flatMap(extentOf(_, method, None))
            case other =>
                IndexRange.literal(other).filter(v => v > 0 && v < MaxObjectSize)
                    .map(v => (s"$ValueConst:$v", List.empty[StoredNode]))
        }
  end objectSizeExtentOf

  /** Resolve the capacity of a `mem-dst` argument expression. Returns the extent value and, where
    * one exists, the declaration nodes it was derived from.
    */
  private def extentOf(
    dst: Expression,
    method: Method,
    sizeofInCopy: Option[String]
  ): Option[(String, List[StoredNode])] =
      dst match
        case c: Call if c.name == "<operator>.addressOf" =>
            // `&buf[k]` for a literal k is `buf + k`: the capacity left from the element on
            c.argumentOption(1) match
              case Some(ix: Call)
                  if (ix.name == "<operator>.indexAccess" ||
                      ix.name == "<operator>.indirectIndexAccess") &&
                      ix.argumentOption(2).flatMap(IndexRange.literal).exists(_ > 0) =>
                  val k = ix.argumentOption(2).flatMap(IndexRange.literal).get
                  ix.argumentOption(1).flatMap(extentOf(_, method, None)).map { case (v, _) =>
                      val reduced = v match
                        case c if c.startsWith(s"$ValueConst:") =>
                            c.stripPrefix(s"$ValueConst:").toLongOption.filter(_ > k)
                                .map(n => s"$ValueConst:${n - k}")
                                .getOrElse(s"$ValueOffset:$v")
                        case other if knownExtentPrefixes.exists(other.startsWith) =>
                            s"$ValueOffset:$other"
                        case other => other
                      (reduced, List.empty[StoredNode])
                  }
              // the copy's own sizeof evidence is evidence about the address target too:
              // memcpy(&dst, src, sizeof(dst)) is a correctly bounded copy
              case other => other.flatMap(extentOf(_, method, sizeofInCopy))
        case c: Call
            if c.name == "<operator>.indexAccess" || c.name == "<operator>.indirectIndexAccess" =>
            // &buf[off] still writes into buf's capacity
            c.argumentOption(1)
                .flatMap(extentOf(_, method, sizeofInCopy))
                .orElse(sizeofInCopy.map(v => (v, List.empty[StoredNode])))
        case i: Identifier =>
            extentOfVariable(i.name, i, method, sizeofInCopy)
        case c: Call
            if c.name == "<operator>.addition" || c.name == "<operator>.subtraction" =>
            additiveExtentOf(c, method, sizeofInCopy)
        case c: Call
            if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
            extentOfField(c).orElse(sizeofInCopy.map(v => (v, List.empty[StoredNode])))
        case c: Call if isGetAccessor(c) =>
            // a smart pointer's `.get()` hands out its own storage: the receiver's extent is
            // the result's. The receiver resolves through every extent arm, so this yields
            // one only where the receiver itself has a capacity (an array view, a smart
            // pointer's construction) - an arbitrary accessor named get stays unknown
            c.argument.l.collectFirst { case i: Identifier => i } match
              case Some(receiver) => extentOf(receiver, method, sizeofInCopy)
              case None           => sizeofInCopy.map(v => (v, List.empty[StoredNode]))
        case _ =>
            sizeofInCopy.map(v => (v, List.empty[StoredNode]))

  /** Pointer arithmetic over a buffer, as the frontend tagged it: the pointer operand is the base.
    * `base + k` for a constant k shrinks a known capacity by k (`const:N` -> `const:N-k`); every
    * other shape - a non-constant offset, a subtraction whose start may be negative, a constant
    * offset at or past the capacity - says only "at an unknown distance inside `<base extent>`":
    * the `offset:` value, never presented as a capacity. A base that itself resolves to nothing
    * stays `unknown`: there is no capacity to reduce, and neither is there for arithmetic that
    * moves no pointer.
    */
  private def additiveExtentOf(
    arith: Call,
    method: Method,
    sizeofInCopy: Option[String]
  ): Option[(String, List[StoredNode])] =
    val base = OverlayFacts.pointerOperandOf(arith)
    val offset = OverlayFacts.pointerArithmeticOf(arith).flatMap((_, i) =>
        arith.argumentOption(3 - i).collect { case e: Expression => e }
    ).flatMap(IndexRange.literal).filter(_.isValidLong).map(_.toLong)
    base.flatMap(extentOf(_, method, sizeofInCopy)).map { case (baseValue, _) =>
        // the distance the write starts inside the capacity; a subtraction or a negative
        // literal may start BEFORE the buffer, which no capacity describes
        val inwards = (arith.name, offset) match
          case ("<operator>.addition", Some(k)) if k >= 0 => Some(k)
          case _                                          => None
        val declaredSize = Option.when(baseValue.startsWith(s"$ValueConst:"))(
          baseValue.stripPrefix(s"$ValueConst:").toLongOption
        ).flatten
        val reduced = (inwards, declaredSize) match
          case (Some(k), Some(n)) if k < n => s"$ValueConst:${n - k}"
          case _ if knownExtentPrefixes.exists(baseValue.startsWith) =>
              s"$ValueOffset:$baseValue"
          case _ => baseValue
        // the arithmetic reshapes the write's extent, not the buffer's: the declaration keeps
        // its own (full) fact, so a guard against the declared capacity still matches it
        (reduced, List.empty[StoredNode])
    }
  end additiveExtentOf

  private val knownExtentPrefixes: Set[String] =
      Set(ValueConst, ValueSizeof, ValueAlloc, ValueParam, ValueField, ValueVla).map(_ + ":")

  /** A nullary `get` accessor call (`p.get()`), resolved or not: its only expression argument is
    * the receiver.
    */
  private def isGetAccessor(c: Call): Boolean =
    val callee = c.methodFullName
    val last   = callee.substring(callee.lastIndexOf('.') + 1).takeWhile(c => c != ':')
    last == "get" && c.argument.l.collect { case e: Expression => e }.sizeIs <= 1

  private def extentOfVariable(
    name: String,
    use: Expression,
    method: Method,
    sizeofInCopy: Option[String]
  ): Option[(String, List[StoredNode])] =
    // A declared array beats everything else: the size is in the type. The declaration is the
    // method's own one the use refers to: a function may declare two buffers of one name in two
    // blocks
    val declared = use match
      case i: Identifier =>
          i.refsTo.collectFirst { case l: Local => l }.filter(l =>
              method.local.exists(_.id == l.id) || OverlayFacts.capturedLocal(i).exists(
                _.id == l.id
              )
          )
      case _ => None
    declared.orElse(method.local.name(name).headOption).flatMap { local =>
        // a variable-length array: its bound, evaluated where it is declared, is its capacity -
        // a value the program holds, not a declared count
        local.tag.nameExact(io.appthreat.x2cpg.Defines.VlaSizeTag).value.headOption
            .map(bound => (s"$ValueVla:${bound.trim}", List(local)))
            .orElse(arrayExtent(local.typeFullName).map(n => (s"$ValueConst:$n", List(local))))
    }.orElse {
        // A member read without `this->`: the frontend types the identifier with the OWNER
        // class, so the member's declared array extent is the buffer's, with the member as
        // the declaration a guard matches against
        use match
          case i: Identifier =>
              for
                member <- OverlayFacts.implicitMemberOf(atom, i)
                n      <- arrayExtent(member.typeFullName)
                // a trailing zero- or one-element array is a flexible member: the allocation,
                // not the declaration, sizes it (`next_[1]` in a node allocated with its levels)
                if n > 1 || !OverlayFacts.isTrailingMember(member)
              yield (s"$ValueConst:$n", List(member))
          case _ => None
    }.orElse {
        // A buffer parameter with an adjacent capacity parameter. The
        // parameter declaration carries the extent so guards can match against it.
        for
          param <- method.parameter.name(name).headOption
          cap   <- paramExtentOf(param)
        yield (s"$ValueParam:$cap", List(param))
    }.orElse {
        sizeofInCopy.map(v => (v, List.empty))
    }.orElse {
        // A pointer that VIEWS an array: `auto p = buf` (the array decays into the pointer) or
        // `int *pair = (int[]){x, 0}` (a compound literal's element count is its extent). The
        // pointer holds no storage of its own - every definition must name the same element
        // count, or there is no single capacity to read
        arrayViewExtentOf(use).map(v => (v, List.empty[StoredNode]))
    }.orElse {
        // The extent a smart pointer's own storage has: `std::unique_ptr<T[]>(new T[n])`,
        // `std::make_unique<T[]>(n)`, and `std::array<T, N>`'s constant N. The array form is
        // the instance's template argument as the resolved callee spells it - never the
        // source's own spelling
        smartPointerExtentOf(use).map(v => (v, List.empty[StoredNode]))
    }.orElse {
        // A pointer whose definition is an inventoried allocation.
        allocExtentOf(use).map(v => (v, List.empty))
    }
  end extentOfVariable

  /** The definitions of the used variable itself. The reaching-definition walk is transitive, so it
    * also returns the definitions of whatever fed them (`server = host` behind `found =
    * strstr(no_proxy, server)`): only the ones that write the used name are its own.
    */
  private def ownDefinitionsOf(use: Expression): List[Identifier] =
      use match
        case u: Identifier =>
            OverlayFacts.reachingDefsIn(use).collect {
                case d: Identifier if d.name == u.name => d
            }
        case _ => Nil

  /** The extent a pointer's definitions view: every definition is an identifier of an array (a
    * declared array local), or a compound literal written as an initializer list. All the
    * definitions must agree on the element count.
    */
  /** How deep the view question is nested: `p = q + 1; q = r + 1; ...` walks definition to
    * definition, and a pointer defined from itself (`p = p + 1`) would never end.
    */
  private var viewDepth = 0

  private def arrayViewExtentOf(use: Expression): Option[String] =
    if viewDepth >= 4 then return None
    viewDepth += 1
    try arrayViewExtentOfNested(use)
    finally viewDepth -= 1

  private def arrayViewExtentOfNested(use: Expression): Option[String] =
    val defs = ownDefinitionsOf(use)
    if defs.isEmpty then return None
    val rhsValues = defs.flatMap { defNode =>
        defNode._astIn.collectFirst { case a: Call if a.name == "<operator>.assignment" => a }
    }.flatMap(_.argumentOption(2)).toSet
    if rhsValues.isEmpty then return None
    val values = rhsValues.flatMap { rhs =>
        rhs match
          // a compound literal: the cast's own type names the array (EDG writes the computed
          // count, `int[2]`; CDT the unsized `int[]`), and the initializer list under an
          // unsized array type carries the element count. A record literal (`(struct point){x,
          // y}`) is not an array and gives no extent
          case c: Call if c.name == "<operator>.cast" =>
              val castType = String.valueOf(c.property("TYPE_FULL_NAME")).trim
              arrayExtent(castType).map(n => s"$ValueConst:$n").orElse {
                  Option.when(castType.endsWith("[]"))(
                    c.argument.l.collectFirst {
                        case init: Call if init.name == "<operator>.arrayInitializer" => init
                    }.map(init => s"$ValueConst:${init.argument.l.size}")
                  ).flatten
              }
          case i: Identifier =>
              arrayExtentOfIdentifier(i, use.method)
          // `p = buf + k`, `p = &buf[k]`: the view starts k elements in, and what is left of
          // the array from there is the pointer's capacity
          case c: Call if c.name == "<operator>.addition" || c.name == "<operator>.addressOf" =>
              extentOf(c, use.method, None).map(_._1).filter(_.startsWith(s"$ValueConst:"))
          case _ => None
    }
    Option.when(values.nonEmpty && values.size == 1)(values.head)
  end arrayViewExtentOfNested

  /** The declared element count an identifier names: its own array local. */
  private def arrayExtentOfIdentifier(i: Identifier, method: Method): Option[String] =
      i.refsTo.collectFirst { case l: Local => l }
          .orElse(method.local.name(i.name).headOption)
          .flatMap(l => arrayExtent(l.typeFullName))
          .map(n => s"$ValueConst:$n")

  /** The instance spellings of the array-form smart pointers, as the resolved callee (or the
    * local's own instance type) writes them: `unique_ptr<char[]>`, `make_unique<char[]>`. The
    * template argument belongs to the instance the front end resolved, never to the source's
    * spelling of it.
    */
  private val ArrayFormInstance = "(unique_ptr|make_unique)<[^>]*\\[\\]".r

  /** `std::array<T, N>`: the instance's second template argument is the constant count. */
  private val StdArrayInstance = "std\\.array<[^,>]+,\\s*(\\d+)>".r

  /** The extent a smart pointer's own storage has:
    *   - `std::array<T, N>` - the instance's N, a declared count;
    *   - `std::unique_ptr<T[]>(new T[n])` - the array new's extent argument;
    *   - `std::make_unique<T[]>(n)` - the factory's count argument.
    * Every definition must state the same count.
    */
  private def smartPointerExtentOf(use: Expression): Option[String] =
    val declared = use match
      case i: Identifier =>
          i.refsTo.collectFirst { case l: Local => l }
              .orElse(use.method.local.name(i.name).headOption)
              .flatMap(l => StdArrayInstance.findFirstMatchIn(l.typeFullName))
              .map(m => s"$ValueConst:${m.group(1)}")
      case _ => None
    declared.orElse {
        val defs = ownDefinitionsOf(use)
        val rhsCall = defs.flatMap { defNode =>
            defNode._astIn.collectFirst { case a: Call if a.name == "<operator>.assignment" => a }
        }.flatMap(_.argumentOption(2)).collect { case c: Call => c }.toSet
        val values = rhsCall.flatMap(smartPointerCountOf)
        Option.when(values.nonEmpty && values.size == 1)(values.head)
    }

  private def smartPointerCountOf(ctor: Call): Option[String] =
    val callee = ctor.methodFullName
    // the definition's rhs is itself the array new (the construction folded into the
    // assignment): the new's extent argument is the count
    if ctor.name == "<operator>.new" &&
      ctor.tag.name(io.appthreat.x2cpg.Defines.AllocFormTag).value.l
          .contains(io.appthreat.x2cpg.Defines.AllocFormArray)
    then arrayNewCountOf(ctor)
    else if ArrayFormInstance.findFirstIn(callee).isEmpty then None
    else if callee.contains("make_unique") then
      // the factory's count argument: the value the array was constructed with
      ctor.argument.l.collect { case e: Expression => e }
          .filterNot(_.isInstanceOf[Call])
          .find(e => IndexRange.literal(e).isDefined || e.isInstanceOf[Identifier])
          .map(e => s"$ValueAlloc:${e.id}")
    else
      // the constructor's array new: the new's own extent argument is the count
      ctor.argument.l.collect { case nc: Call => nc }
          .find(nc =>
              nc.name == "<operator>.new" && nc.tag
                  .name(io.appthreat.x2cpg.Defines.AllocFormTag)
                  .value
                  .l
                  .contains(io.appthreat.x2cpg.Defines.AllocFormArray)
          )
          .flatMap(arrayNewCountOf)
    end if
  end smartPointerCountOf

  /** The count an array `new T[n]` states: the extent argument the frontend wired in after the type
    * (argument index 2 onward, before the element constructor's call).
    */
  private def arrayNewCountOf(newCall: Call): Option[String] =
    val lens = newCall.argument.l.collect { case e: Expression => e }
        .filter(a => a.tag.name(MemoryApiPass.TagLen).nonEmpty)
    lens.headOption
        .map(e => s"$ValueAlloc:${e.id}")
        .orElse {
            newCall.argument.l.collect { case e: Expression => e }
                .filter(a => a.argumentIndex > 1 && !a.isInstanceOf[Call])
                .find(IndexRange.literal(_).isDefined)
                .map(e => s"$ValueAlloc:${e.id}")
        }.orElse {
            // a count held in a variable (`new char[dataBytes]`): the first argument after the
            // element type. An arithmetic count (`new char[size + 5]`) stays unknown - the offset
            // rules would read its sum as a capacity they cannot compare
            newCall.argument.l.collect { case e: Identifier => e }
                .find(a => a.argumentIndex == 2)
                .map(e => s"$ValueAlloc:${e.id}")
        }

  /** The capacity parameter beside a buffer parameter: adjacency in the signature plus the
    * pointer/integral type pattern. Names are deliberately not consulted.
    */
  private def paramExtentOf(buf: MethodParameterIn): Option[String] =
    val params = buf.method.parameter.l.sortBy(_.index)
    params.sliding(2).collectFirst {
        case Seq(l, r) if l == buf && isIntegral(r.typeFullName) => r.name
        case Seq(l, r) if r == buf && isIntegral(l.typeFullName) => l.name
    }

  /** `alloc:<size-argument id>`, or `sizeof:<expr>` when the size argument is a sizeof. The
    * pointer's producer may be a realloc - `p = av_realloc(p, n)` sizes p exactly like a malloc
    * does. The allocation may also sit under a cast (`p = (char *)malloc(n)`); missing it would
    * leave `buf = (char *)malloc(10)` with extent `unknown` and a constant overflow of it invisible
    * to every bounds rule.
    */
  private def allocExtentOf(use: Expression): Option[String] =
      OverlayFacts
          .reachingDefsIn(use)
          .collect { case d: Identifier => d }
          .flatMap { defNode =>
              defNode._astIn.collectFirst { case a: Call if a.name == "<operator>.assignment" => a }
          }
          .flatMap(assignment => assignment.argumentOption(2).flatMap(allocCallOf))
          .flatMap(sizeArgValueOf)
          .headOption

  /** The allocation call an expression produces, through casts - shared by the member-extent scan
    * and the def walk.
    */
  private def allocCallOf(e: Expression): Option[Call] = e match
    case c: Call if isAllocationCall(c) => Some(c)
    case c: Call if c.name.startsWith("<operator>.cast") =>
        c.argument.l.collectFirst { case inner: Call => inner }.flatMap(allocCallOf)
    case _ => None

  private def extentOfField(fieldAccess: Call): Option[(String, List[StoredNode])] =
    // the access's own type, when the frontend gives it as an array, names this member's bound
    // exactly. The member lookup goes by type name, and every per-function anonymous union of a
    // file shares one (`<unnamed>`): bn_nist.c's 192-bit union lent its `bn[3]` to the 256-bit one.
    // It corrects a member the lookup found; it never gives an extent to one the lookup missed
    val ownCount = arrayExtent(fieldAccess.typeFullName).filter(_ > 0)
    OverlayFacts.memberRefOf(atom, fieldAccess).flatMap { member =>
        Option.when(roomlessTrailingMember(fieldAccess, member))(
          (s"$ValueConst:0", List(member))
        ).orElse(flexibleRoomOf(fieldAccess, member).map(v => (v, List(member))))
            .orElse(ownCount.orElse(arrayExtent(member.typeFullName))
                // GNU's zero-length trailing array is the flexible member written before C99: its
                // storage is what the allocation adds past the record, not a declared capacity
                .filterNot(n => n == 0 && OverlayFacts.isTrailingMember(member))
                .map(n => (s"$ValueConst:$n", List(member)))
                .orElse(siblingLengthOf(member).map(sib => (s"$ValueField:$sib", List(member))))
                // a pointer member's capacity is wherever its allocation is
                .orElse(memberExtents.get(member).map(v => (v, List(member)))))
    }

  /** A flexible array member reached through a pointer whose every allocation is the record plus a
    * size: `malloc(sizeof(*m) + n)` leaves the member the n bytes past the record (C99 6.7.2.1p18 -
    * the member is as long as the object's bytes past its offset allow). The extent names the
    * allocation's added size, `alloc:<n>`, as an allocation's own size argument would.
    */
  private def flexibleRoomOf(fieldAccess: Call, member: Member): Option[String] =
    val flexible = member.tag.nameExact(io.appthreat.x2cpg.Defines.FlexibleMemberTag).nonEmpty ||
        OverlayFacts.isTrailingMember(member) &&
        (arrayExtent(member.typeFullName).contains(0) || member.typeFullName.trim.endsWith("[]"))
    if !flexible || fieldAccess.name != "<operator>.indirectFieldAccess" then return None
    fieldAccess.argumentOption(1).collect { case base: Identifier => base }.flatMap { base =>
      val stores = OverlayFacts.reachingDefsIn(base).collect {
          case d: Identifier if d.name == base.name =>
              d._astIn.collectFirst {
                  case a: Call
                      if a.name == "<operator>.assignment" && a.argumentOption(1).exists(
                        _.id == d.id
                      ) => a
              }
      }.flatten
      val added = stores.map { store =>
          store.argumentOption(2).flatMap(allocationCallOf).flatMap { alloc =>
              alloc.argument.l.filter(_.tag.name(MemoryApiPass.TagLen).l.nonEmpty) match
                case List(sum: Call) if sum.name == "<operator>.addition" =>
                    val operands = sum.argument.l.collect { case e: Expression => e }
                    val (records, rest) = operands.partition {
                        case sz: Call => sz.name.startsWith("<operator>.sizeOf")
                        case _        => false
                    }
                    Option.when(records.size == 1 && rest.size == 1)(rest.head)
                case _ => None
          }
      }
      Option.when(stores.nonEmpty && added.forall(_.isDefined))(added.flatten)
          .filter(_.map(_.code).distinct.size == 1)
          .flatMap(_.headOption)
          .map(n =>
              IndexRange.literal(n).map(v => s"$ValueConst:$v").getOrElse(s"$ValueAlloc:${n.id}")
          )
    }
  end flexibleRoomOf

  private def allocationCallOf(e: AstNode): Option[Call] = e match
    case c: Call if isAllocationCall(c) => Some(c)
    case c: Call if c.name.startsWith("<operator>.cast") =>
        c.argument.l.collectFirst { case inner: Call => inner }.flatMap(allocationCallOf)
    case _ => None

  /** A flexible trailing member (`char data[]`, GNU's `char data[0]`) reached through a pointer
    * whose every allocation reaching the access is exactly the record - `malloc(sizeof(*p))` or
    * `malloc(sizeof(struct T))`, nothing added: the member has no storage at all. Any other
    * allocation, a definition that is none, or another base says nothing.
    */
  private def roomlessTrailingMember(fieldAccess: Call, member: Member): Boolean =
    val flexible = OverlayFacts.isTrailingMember(member) &&
        (arrayExtent(member.typeFullName).contains(0) || member.typeFullName.trim.endsWith("[]"))
    def sizedAsRecord(alloc: Call, base: String): Boolean =
        alloc.argument.l.filter(_.tag.name(MemoryApiPass.TagLen).l.nonEmpty) match
          case List(sz: Call) if sz.name.startsWith("<operator>.sizeOf") =>
              sz.argument.l match
                case List(deref: Call) if deref.name == "<operator>.indirection" =>
                    deref.argument.l.collect { case i: Identifier => i.name } == List(base)
                // `sizeof(struct T)`, or of an object of the record's type
                case List(operand: Expression) =>
                    Option(member.typeDecl).exists(td =>
                        operand.property("TYPE_FULL_NAME") == td.fullName
                    )
                case _ => false
          case _ => false
    flexible && fieldAccess.name == "<operator>.indirectFieldAccess" &&
    (fieldAccess.argumentOption(1) match
      case Some(base: Identifier) =>
          // the stores that define the pointer: an assignment whose target is it
          val stores = OverlayFacts.reachingDefsIn(base).collect { case d: Identifier =>
              d._astIn.collectFirst {
                  case a: Call if a.name == "<operator>.assignment" && d.argumentIndex == 1 => a
              }
          }.flatten.distinct
          val allocations = stores.map(_.argumentOption(2).flatMap(allocCallOf))
          stores.nonEmpty && allocations.forall(_.exists(sizedAsRecord(_, base.name)))
      case _ => false
    )
  end roomlessTrailingMember

  /** A struct member holding the length beside a pointer member, by the C `_len`/`_size` suffix
    * convention (`payload` / `payload_len`).
    */
  private def siblingLengthOf(member: Member): Option[String] =
    val wanted = Set(s"${member.name}_len", s"${member.name}_size")
    Option(member.typeDecl).toList
        .flatMap(td => OverlayFacts.membersOfTypeDecl(td))
        .filter(m => m != member && isIntegral(m.typeFullName))
        .find(m => wanted.contains(m.name))
        .map(_.name)

  private def sizeOfOperand(len: Expression): Option[Expression] = len match
    case c: Call if c.name.startsWith("<operator>.sizeOf") => c.argumentOption(1)
    case _                                                 => None
end ExtentPass

object ExtentPass:
  final val TagExtent = "extent"

  final val ValueConst   = "const"
  final val ValueOffset  = "offset"
  final val ValueSizeof  = "sizeof"
  final val ValueAlloc   = "alloc"
  final val ValueParam   = "param"
  final val ValueField   = "field"
  final val ValueUnknown = "unknown"

  /** `vla:<bound>` - a variable-length array, whose capacity is its bound as written, evaluated
    * once where the array is declared: a capacity the program holds at run time, like an
    * allocation's size argument.
    */
  final val ValueVla = "vla"

  /** The compiler builtins that evaluate to the size of the object a pointer addresses. */
  final val ObjectSizeBuiltins = Set("__builtin_object_size", "__builtin_dynamic_object_size")

  /** A FORTIFY object size at or above this (`(size_t)-1`) says the compiler did not know it. */
  private[taggers] val MaxObjectSize = BigInt(Long.MaxValue)

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end ExtentPass
