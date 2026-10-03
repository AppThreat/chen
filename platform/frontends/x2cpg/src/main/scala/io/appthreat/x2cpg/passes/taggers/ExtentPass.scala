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
            // the copy's own sizeof evidence is evidence about the address target too:
            // memcpy(&dst, src, sizeof(dst)) is a correctly bounded copy
            c.argumentOption(1).flatMap(extentOf(_, method, sizeofInCopy))
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
      Set(ValueConst, ValueSizeof, ValueAlloc, ValueParam, ValueField).map(_ + ":")

  private def extentOfVariable(
    name: String,
    use: Expression,
    method: Method,
    sizeofInCopy: Option[String]
  ): Option[(String, List[StoredNode])] =
      // A declared array beats everything else: the size is in the type.
      method.local.name(name).headOption.flatMap { local =>
          arrayExtent(local.typeFullName).map(n => (s"$ValueConst:$n", List(local)))
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
          // A pointer whose definition is an inventoried allocation.
          allocExtentOf(use).map(v => (v, List.empty))
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
      OverlayFacts.memberRefOf(atom, fieldAccess).flatMap { member =>
          arrayExtent(member.typeFullName)
              .map(n => (s"$ValueConst:$n", List(member)))
              .orElse(siblingLengthOf(member).map(sib => (s"$ValueField:$sib", List(member))))
              // a pointer member's capacity is wherever its allocation is
              .orElse(memberExtents.get(member).map(v => (v, List(member))))
      }

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

  /** The compiler builtins that evaluate to the size of the object a pointer addresses. */
  final val ObjectSizeBuiltins = Set("__builtin_object_size", "__builtin_dynamic_object_size")

  /** A FORTIFY object size at or above this (`(size_t)-1`) says the compiler did not know it. */
  private[taggers] val MaxObjectSize = BigInt(Long.MaxValue)

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
