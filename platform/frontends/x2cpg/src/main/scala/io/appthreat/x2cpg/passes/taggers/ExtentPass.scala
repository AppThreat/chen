package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS2: how big is this buffer, as a fact on the graph.
  *
  * For every destination argument of a memory-writing call ([[MemoryApiPass]]'s `mem-dst`), derive
  * the buffer's capacity and tag it `extent` (valued) plus the `memory-safety` umbrella:
  *
  *   - `const:128` - a declared array (`char buf[128]`, through a `#define`, and struct members:
  *     `int[16]` is in `typeFullName`, confirmed by part-1 task A5);
  *   - `const:N-k` - a copy into `buf + k` for a literal k: the remaining capacity of the same
  *     buffer from the write's start;
  *   - `offset:<extent>` - somewhere inside (or, for `base - k`, before) a buffer whose extent is
  *     `<extent>`, reduced by an unknown amount. NOT an extent: a rule that needs a capacity must
  *     reject it exactly as it rejects `unknown`. It exists so a later rule can tell "inside a
  *     128-byte buffer" apart from "no idea at all";
  *   - `sizeof:<expr>` - `sizeof(x)` in the allocation that produced the pointer, or as the copy's
  *     own length argument against the same buffer;
  *   - `alloc:<id>` - the size argument of the `mem-alloc`/`mem-realloc` call that produced the
  *     pointer;
  *   - `param:<name>` - a capacity parameter paired with a buffer parameter (the R1 adjacent-pair
  *     detection promoted out of the prototype query, predicate unchanged);
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

    // D4 report buckets, over the destination arguments whose shape is a (direct or indirect)
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

              extentOf(dst, call.method, sizeofInCopy) match
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

    // C4: the base of an array index is a buffer access, so its extent is the same fact it is
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

  /** C1 (part 4, D4): the member-extent facts are not method-local, so they are built once, up
    * front. The search is whole-graph in BOTH dimensions now: it reads every assignment in the tree
    * (an `init` may allocate `ctx->buf` that a `read_packet` writes), and it follows two more
    * shapes than the same-expression match part 3 shipped - the allocation stashed in a local
    * before it reaches the member, and the allocation made THROUGH the member's own address
    * (`av_reallocp(&ctx->buf, n)`). Sizes are kept per member even when they conflict: a member
    * allocated at two different sizes gets no extent (no single capacity exists), but it is still a
    * member with an allocation somewhere in the tree - the split the D4 deliverable asks for.
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
    * realloc produces the pointer too (D1): `ctx->buf = av_realloc(ctx->buf, n)` is how the
    * member's capacity grows.
    */
  private def allocationSizeValueOf(rhs: Option[Expression]): Option[String] =
    def allocCallOf(e: Expression): Option[Call] = e match
      case c: Call if isAllocationCall(c) => Some(c)
      case c: Call if c.name.startsWith("<operator>.cast") =>
          c.argument.l.collectFirst { case inner: Call => inner }.flatMap(allocCallOf)
      case _ => None
    rhs.flatMap(allocCallOf).flatMap(alloc => sizeArgValueOf(alloc))

  /** The byte-size factor of an allocation's length arguments. A count-by-size allocator tags BOTH
    * factors `mem-len` (D1); the capacity is the byte size, which in every inventoried signature is
    * either the `sizeof` or the trailing factor.
    */
  private def sizeArgValueOf(alloc: Call): Option[String] =
    val lenArgs = alloc.argument.l.filter(_.tag.name(MemoryApiPass.TagLen).l.nonEmpty)
    lenArgs
        .collectFirst {
            case sz: Call if sz.name.startsWith("<operator>.sizeOf") =>
                s"$ValueSizeof:${sz.code}"
        }
        .orElse(lenArgs.lastOption.map {
            case sz: Call if sz.name.startsWith("<operator>.sizeOf") =>
                s"$ValueSizeof:${sz.code}"
            case sizeArg => s"$ValueAlloc:${sizeArg.id}"
        })

  private def isAllocationCall(c: Call): Boolean =
      c.tag.name(MemoryApiPass.TagAlloc).l.nonEmpty ||
          c.tag.name(MemoryApiPass.TagRealloc).l.nonEmpty

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

  /** Pointer arithmetic over a buffer. `base + k` for a literal k shrinks a known capacity by k
    * (`const:N` -> `const:N-k`); every other shape - a non-literal offset, a subtraction whose
    * start may be negative, a literal offset at or past the capacity - says only "at an unknown
    * distance inside `<base extent>`": the `offset:` value, never presented as a capacity. A base
    * that itself resolves to nothing stays `unknown`: there is no capacity to reduce.
    */
  private def additiveExtentOf(
    arith: Call,
    method: Method,
    sizeofInCopy: Option[String]
  ): Option[(String, List[StoredNode])] =
    def literalOf(e: Option[Expression]): Option[Long] = e.flatMap {
        case l: Literal => l.code.toLongOption
        case _          => None
    }
    val (base, offset) =
        (arith.argumentOption(1), arith.argumentOption(2)) match
          case (b, o) if literalOf(o).isDefined => (b, literalOf(o))
          case (b, o) if literalOf(b).isDefined => (o, literalOf(b))
          case (b, _)                           => (b, None)
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
          // A buffer parameter with an adjacent capacity parameter (the R1 pairing). The
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
    * pointer/integral type pattern, exactly the predicate the prototype query validated against the
    * real CVE. Names are deliberately not consulted.
    */
  private def paramExtentOf(buf: MethodParameterIn): Option[String] =
    val params = buf.method.parameter.l.sortBy(_.index)
    params.sliding(2).collectFirst {
        case Seq(l, r) if l == buf && isIntegral(r.typeFullName) => r.name
        case Seq(l, r) if r == buf && isIntegral(l.typeFullName) => l.name
    }

  /** `alloc:<size-argument id>`, or `sizeof:<expr>` when the size argument is a sizeof. The
    * pointer's producer may be a realloc (D1) - `p = av_realloc(p, n)` sizes p exactly like a
    * malloc does.
    */
  private def allocExtentOf(use: Expression): Option[String] =
      OverlayFacts
          .reachingDefsIn(use)
          .collect { case d: Identifier => d }
          .flatMap { defNode =>
              defNode._astIn.collectFirst { case a: Call if a.name == "<operator>.assignment" => a }
          }
          .flatMap { assignment =>
              assignment.argumentOption(2).collect { case alloc: Call => alloc }
          }
          .find(isAllocationCall)
          .flatMap(sizeArgValueOf)

  private def extentOfField(fieldAccess: Call): Option[(String, List[StoredNode])] =
      OverlayFacts.memberRefOf(atom, fieldAccess).flatMap { member =>
          arrayExtent(member.typeFullName)
              .map(n => (s"$ValueConst:$n", List(member)))
              .orElse(siblingLengthOf(member).map(sib => (s"$ValueField:$sib", List(member))))
              // C1: a pointer member's capacity is wherever its allocation is
              .orElse(memberExtents.get(member).map(v => (v, List(member))))
      }

  /** A struct member holding the length beside a pointer member, by the C `_len`/`_size` suffix
    * convention (`payload` / `payload_len`).
    */
  private def siblingLengthOf(member: Member): Option[String] =
    val wanted = Set(s"${member.name}_len", s"${member.name}_size")
    member.typeDecl.member.l
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

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
