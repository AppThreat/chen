package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** The closed range an integer expression can take, from facts that bound it by CONSTRUCTION rather
  * than by a guard: the declared range of the call that produced it (the vocabulary's
  * `returnRange`: FFmpeg's `avio_r8` is 0..255), a mask (`x & 0x1fff`), a modulus, a shift,
  * arithmetic over bounded operands, the declared width of its type (`uint8_t`), and - for a
  * parameter - the ranges every caller passes. MS-BOUND-003/004 ask it whether an index can reach a
  * constant capacity at all: a byte read into `frame_code[256]` cannot, into `new_extradata[4]` it
  * can.
  *
  * Every answer is sound or absent. An expression this class cannot bound returns None, never a
  * guess; a range built from several definitions is their union; and every definition edge -
  * assignment, parameter binding, cast - CONVERTS the value into the target's type. A byte stored
  * in a `signed char` is -128..127, and an `unsigned int` bound to an `int` parameter can arrive
  * negative: without the conversion both read as non-negative, which is exactly the lower bound the
  * one-sided rule (CVE-2026-75146's shape) asks about.
  *
  * One instance per finding pass: answers are memoised per (node, depth), since the same index,
  * argument and parameter are asked about from many call sites.
  *
  * @param typeOf
  *   the declared type of an expression (the rule's resolver, which reads a field access's member
  *   type)
  * @param isEnum
  *   whether a type name is an enum: C converts an integer into an enum implicitly, preserving the
  *   value
  * @param callersOf
  *   the call sites a method's parameters are bound at, or None when they cannot all be seen (an
  *   address-taken method has callers through its function pointer)
  */
private[taggers] final class IndexRange(
  typeOf: Expression => String,
  isEnum: String => Boolean,
  callersOf: Method => Option[List[Call]]
):
  import IndexRange.*

  private val memo = mutable.HashMap.empty[(Long, Int), Option[Range]]

  /** @param depth
    *   how many definition or call-site hops the answer may cross
    */
  def of(e: Expression, depth: Int = 3): Option[Range] =
      if depth < 0 then None
      else
        val key = (e.id(), depth)
        memo.get(key) match
          case Some(known) => known
          case None =>
              val computed = compute(e, depth)
              memo(key) = computed
              computed

  /** The value `r` takes once converted into type `target`: unchanged when it fits, the whole of
    * the target's range when it does not (an unsigned target wraps, a signed one is implementation-
    * defined or undefined - either way the target's range is all that is known). An enum keeps the
    * value when it fits an int or an unsigned int. A target this class cannot size gives None.
    */
  def convert(r: Option[Range], target: String): Option[Range] =
    val norm = OverlayFacts.normalizeTypeName(Option(target).getOrElse("").trim)
    TypeRanges.get(norm) match
      case Some((fit, full)) =>
          r match
            case Some(x) if x.lo >= fit.lo && x.hi <= fit.hi => Some(x)
            // a signed counter that only grows keeps its lower end: running past the top would be
            // signed overflow, which the program does not get to rely on
            case Some(x) if x.hi >= Unbounded && full.lo < 0 && x.lo >= fit.lo && x.lo <= fit.hi =>
                Some(Range(x.lo, full.hi))
            case _ => Some(full)
      case None if isEnum(norm.stripPrefix("enum ").trim) =>
          r.filter(x => x.lo >= EnumSpan.lo && x.hi <= EnumSpan.hi)
      case None => None

  private def operand(c: Call, i: Int): Option[Expression] =
      c.argumentOption(i).collect { case x: Expression => x }

  private def compute(e: Expression, depth: Int): Option[Range] =
      literal(e).map(v => Range(v, v)).orElse(e match
        case c: Call if returnRangeOf(c).isDefined => returnRangeOf(c)
        case c: Call if c.name == "<operator>.and" =>
            // a non-negative mask bounds the result whatever the other operand holds
            c.argument.l.flatMap(literal).filter(_ >= 0).minOption.map(m => Range(0, m))
        case c: Call if c.name == "<operator>.modulo" =>
            (operand(c, 1).flatMap(of(_, depth)), operand(c, 2).flatMap(literal)) match
              case (Some(r), Some(m)) if r.nonNegative && m > 0 => Some(Range(0, (m - 1).min(r.hi)))
              case _                                            => None
        case c: Call
            if c.name == "<operator>.arithmeticShiftRight" ||
                c.name == "<operator>.logicalShiftRight" =>
            (operand(c, 1).flatMap(of(_, depth)), operand(c, 2).flatMap(literal)) match
              case (Some(r), Some(k)) if r.nonNegative && k >= 0 && k < 64 =>
                  Some(Range(r.lo >> k.toInt, r.hi >> k.toInt))
              case _ => None
        case c: Call if Arithmetic.contains(c.name) =>
            (operand(c, 1).flatMap(of(_, depth)), operand(c, 2).flatMap(of(_, depth))) match
              case (Some(a), Some(b)) =>
                  val exact = c.name match
                    case "<operator>.addition"    => Some(Range(a.lo + b.lo, a.hi + b.hi))
                    case "<operator>.subtraction" => Some(Range(a.lo - b.hi, a.hi - b.lo))
                    case "<operator>.multiplication" =>
                        val corners = Seq(a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi)
                        Some(Range(corners.min, corners.max))
                    case _ if b.lo == b.hi && b.lo > 0 && a.nonNegative => // division
                        Some(Range(a.lo / b.lo, a.hi / b.lo))
                    case _ => None
                  exact.flatMap(inArithmeticType(_, typeOf(c)))
              case _ => None
        case c: Call if c.name == "<operator>.conditional" =>
            val branches = Seq(2, 3).flatMap(i => operand(c, i).map(of(_, depth)))
            if branches.size == 2 && branches.forall(_.isDefined) then
              Some(branches.flatten.reduce(_.union(_)))
            else None
        case c: Call if c.name == "<operator>.cast" =>
            convert(operand(c, 2).orElse(operand(c, 1)).flatMap(of(_, depth)), c.typeFullName)
        case i: Identifier =>
            val fromDefinitions =
                if persistsAcrossCalls(i) then None
                else ofIdentifier(i, depth).flatMap(r => convert(Some(r), typeOf(i)))
            fromDefinitions.orElse(ofType(typeOf(i)))
        // an element read: the element type of the array (`unsigned int buffer_num[4]`), which
        // the frontend leaves off the access itself
        case c: Call
            if c.name == "<operator>.indexAccess" || c.name == "<operator>.indirectIndexAccess" =>
            ofType(typeOf(c)).orElse(
              operand(c, 1)
                  .map(b => typeOf(b).trim.replaceAll("""\[[^\]]*\]$""", "").trim)
                  .flatMap(ofType)
            )
        case other => ofType(typeOf(other))
      )

  /** An arithmetic result in its expression's type. With the type unknown, a result inside [0,
    * INT_MAX] is exact in whatever type the operands promote to; anything else is not known.
    */
  private def inArithmeticType(exact: Range, t: String): Option[Range] =
      convert(Some(exact), t).orElse(Option.when(exact.nonNegative && exact.hi <= IntMax)(exact))

  /** A global, or a function-local `static`: another function, or an earlier call of this one, can
    * have stored anything in it, and the reaching definitions of one invocation do not see that.
    */
  private def persistsAcrossCalls(i: Identifier): Boolean =
      i._refOut.collectFirst { case l: Local => l }.exists { l =>
          l.code.trim.startsWith("static ") ||
          l.inAst.collectFirst { case m: Method => m }.exists(_.name == "<global>")
      }

  /** An identifier's range: the union over the assignments that reach it, or - when it is a
    * parameter no assignment redefines - the union over what every intra-tree caller passes. Any
    * definition this class cannot bound makes the whole answer None.
    */
  private def ofIdentifier(i: Identifier, depth: Int): Option[Range] =
    val method = i.method
    // The reaching-def graph also counts a by-value call argument as a definition (`use(i)`
    // "defines" i); that changes nothing and is skipped. What DOES move the value - an increment,
    // a compound assignment, an address taken for a callee to write through - makes the range
    // unknown: `i = 0; ... i++` is not the range {0}.
    val defs: List[Option[Range]] = OverlayFacts.reachingDefsIn(i).flatMap {
        case p: MethodParameterIn if p.name == i.name => List(ofParameter(p, depth))
        case d: Identifier if d.name == i.name =>
            d._astIn.collectFirst { case a: Call => a }.toList.flatMap { a =>
              val isTarget = a.argumentOption(1).exists(_.id == d.id)
              a.name match
                case "<operator>.assignment" if isTarget =>
                    List(operand(a, 2).flatMap(of(_, depth - 1)))
                // a counter that only ever grows keeps its lower end: `i = 0; ... i++` is
                // [0, unbounded], and the loop condition is what bounds it above
                case n if isTarget && n.matches("<operator>\\.(pre|post)Increment") =>
                    List(Some(Range(Unbounded, Unbounded)))
                case "<operator>.assignmentPlus" if isTarget =>
                    a.argumentOption(2).flatMap(literal).filter(_ >= 0)
                        .map(_ => Range(Unbounded, Unbounded)) match
                      case some @ Some(_) => List(some)
                      case None           => List(None)
                case n
                    if isTarget && (n.startsWith("<operator>.assignment") ||
                        n.matches("<operator>\\.(pre|post)Decrement")) =>
                      List(None)
                case "<operator>.addressOf" => List(None)
                case _                      => Nil
            }
        case _ => Nil
    }
    if defs.isEmpty then
      // a parameter no reaching-def edge reaches is still the parameter
      method.parameter.nameExact(i.name).headOption.flatMap(ofParameter(_, depth))
    else if defs.forall(_.isDefined) then
      // a growth marker (lo = Unbounded) contributes no lower end of its own: the counter
      // starts at the other definitions and only rises from there, without an upper end
      val (growth, values) = defs.flatten.partition(_.lo == Unbounded)
      if values.isEmpty then None
      else
        val base = values.reduce(_.union(_))
        Some(if growth.nonEmpty then Range(base.lo, Unbounded) else base)
    else None
  end ofIdentifier

  /** A parameter's range: what every call site passes, each converted into the parameter's type,
    * when every call site can be seen; otherwise its declared type's range.
    */
  private def ofParameter(p: MethodParameterIn, depth: Int): Option[Range] =
    val fromCallers = callersOf(p.method) match
      case Some(sites) if sites.nonEmpty && depth > 0 =>
          val ranges = sites.map(site =>
              convert(
                site.argumentOption(p.index).collect { case x: Expression => x }
                    .flatMap(of(_, depth - 1)),
                p.typeFullName
              ).filter(_ => site.argumentOption(p.index).isDefined)
          )
          if ranges.forall(_.isDefined) then Some(ranges.flatten.reduce(_.union(_))) else None
      case _ => None
    fromCallers.orElse(ofType(p.typeFullName))
end IndexRange

private[taggers] object IndexRange:

  /** the upper end of a range nothing bounds from above: no capacity is ever this large */
  val Unbounded: BigInt = BigInt(1) << 64

  final case class Range(lo: BigInt, hi: BigInt):
    def union(o: Range): Range = Range(lo.min(o.lo), hi.max(o.hi))
    def nonNegative: Boolean   = lo >= 0

  private def unsigned(bits: Int): Range = Range(0, (BigInt(1) << bits) - 1)
  private def signed(bits: Int): Range =
      Range(-(BigInt(1) << (bits - 1)), (BigInt(1) << (bits - 1)) - 1)

  private val IntMax: BigInt = (BigInt(1) << 31) - 1

  /** What an enum can hold without the conversion changing the value: its underlying type is an int
    * or an unsigned int on every ABI chen analyses.
    */
  private val EnumSpan = Range(-(BigInt(1) << 31), (BigInt(1) << 32) - 1)

  private val Arithmetic = Set(
    "<operator>.addition",
    "<operator>.subtraction",
    "<operator>.multiplication",
    "<operator>.division"
  )

  /** Per type: the range a value must lie in to be preserved by a conversion into it, and the range
    * a value of the type can hold. They differ where the width is platform-dependent: `long` is 32
    * bits on LLP64 and 64 on LP64, so only a 32-bit value survives the conversion everywhere, and a
    * `long` can hold anything 64 bits wide. A plain `char` may be signed or unsigned.
    */
  private val TypeRanges: Map[String, (Range, Range)] =
    def same(r: Range): (Range, Range) = (r, r)
    Map(
      "bool"                   -> same(Range(0, 1)),
      "_Bool"                  -> same(Range(0, 1)),
      "char"                   -> (Range(0, 127), Range(-128, 255)),
      "unsigned char"          -> same(unsigned(8)),
      "uint8_t"                -> same(unsigned(8)),
      "signed char"            -> same(signed(8)),
      "int8_t"                 -> same(signed(8)),
      "unsigned short"         -> same(unsigned(16)),
      "unsigned short int"     -> same(unsigned(16)),
      "uint16_t"               -> same(unsigned(16)),
      "short"                  -> same(signed(16)),
      "short int"              -> same(signed(16)),
      "signed short"           -> same(signed(16)),
      "int16_t"                -> same(signed(16)),
      "int"                    -> same(signed(32)),
      "signed int"             -> same(signed(32)),
      "int32_t"                -> same(signed(32)),
      "unsigned int"           -> same(unsigned(32)),
      "uint32_t"               -> same(unsigned(32)),
      "long"                   -> (signed(32), signed(64)),
      "long int"               -> (signed(32), signed(64)),
      "signed long"            -> (signed(32), signed(64)),
      "unsigned long"          -> (unsigned(32), unsigned(64)),
      "unsigned long int"      -> (unsigned(32), unsigned(64)),
      "long long"              -> same(signed(64)),
      "long long int"          -> same(signed(64)),
      "signed long long"       -> same(signed(64)),
      "int64_t"                -> same(signed(64)),
      "ssize_t"                -> same(signed(64)),
      "ptrdiff_t"              -> same(signed(64)),
      "intptr_t"               -> same(signed(64)),
      "unsigned long long"     -> same(unsigned(64)),
      "unsigned long long int" -> same(unsigned(64)),
      "uint64_t"               -> same(unsigned(64)),
      "size_t"                 -> same(unsigned(64)),
      "uintptr_t"              -> same(unsigned(64))
    )
  end TypeRanges

  /** The range a declared type admits, when it is one of the fixed-width integral types. */
  def ofType(t: String): Option[Range] =
      TypeRanges.get(OverlayFacts.normalizeTypeName(Option(t).getOrElse("").trim)).map(_._2)

  /** The vocabulary's range for a call's result ([[MemoryApiPass.TagReturnRange]], `lo:hi`). */
  private def returnRangeOf(c: Call): Option[Range] =
      c.tag.name(MemoryApiPass.TagReturnRange).value.headOption.flatMap { v =>
          v.split(":") match
            case Array(lo, hi) =>
                (scala.util.Try(BigInt(lo)).toOption, scala.util.Try(BigInt(hi)).toOption) match
                  case (Some(l), Some(h)) => Some(Range(l, h))
                  case _                  => None
            case _ => None
      }

  /** An integer literal's value: decimal, hex, octal (a leading 0: `010` is 8), an ASCII character,
    * and a negated literal.
    */
  def literal(e: AstNode): Option[BigInt] = e match
    case l: Literal                              => literalValue(l.code)
    case c: Call if c.name == "<operator>.minus" => c.argumentOption(1).flatMap(literal).map(-_)
    case _                                       => None

  def literalValue(code: String): Option[BigInt] =
    val c = code.trim.toLowerCase.replaceAll("[ul]+$", "")
    if c.startsWith("0x") then scala.util.Try(BigInt(c.drop(2), 16)).toOption
    else if c.matches("0[0-7]+") then scala.util.Try(BigInt(c.drop(1), 8)).toOption
    else if c.matches("'[\\x20-\\x7e]'") && c != "'\\'" then Some(BigInt(code.trim.charAt(1).toInt))
    else if c.matches("-?[0-9]+") then scala.util.Try(BigInt(c)).toOption
    else None
end IndexRange
