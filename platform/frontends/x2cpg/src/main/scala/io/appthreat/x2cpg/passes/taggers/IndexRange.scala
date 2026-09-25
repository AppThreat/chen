package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** The closed range an integer expression can take, from facts that bound it by CONSTRUCTION
  * rather than by a guard: the width of the read that produced it (`avio_r8` is 0..255), a
  * mask (`x & 0x1fff`), a modulus, a shift, the declared width of its type (`uint8_t`), and -
  * for a parameter - the ranges every caller passes. MS-BOUND-003/004 ask it whether an index
  * can reach a constant capacity at all: a byte read into `frame_code[256]` cannot, into
  * `new_extradata[4]` it can.
  *
  * Every answer is sound or absent. An expression this object cannot bound returns None, never
  * a guess, and a range built from several definitions is their union.
  */
private[taggers] object IndexRange:

  /** the upper end of a range nothing bounds from above: no capacity is ever this large */
  val Unbounded: BigInt = BigInt(1) << 64

  final case class Range(lo: BigInt, hi: BigInt):
    def union(o: Range): Range = Range(lo.min(o.lo), hi.max(o.hi))
    def nonNegative: Boolean   = lo >= 0

  private def unsigned(bits: Int): Range = Range(0, (BigInt(1) << bits) - 1)
  private def signed(bits: Int): Range =
      Range(-(BigInt(1) << (bits - 1)), (BigInt(1) << (bits - 1)) - 1)

  /** Reads whose result is exactly this wide: the byte/word readers of the media I/O layer and
    * the bytestream readers. Helpers that return a negative error (mpegts' `get8`) are not here.
    */
  private val ReadWidths: Map[String, Range] = Map(
    "avio_r8"                   -> unsigned(8),
    "avio_rb16"                 -> unsigned(16),
    "avio_rl16"                 -> unsigned(16),
    "avio_rb24"                 -> unsigned(24),
    "avio_rl24"                 -> unsigned(24),
    "bytestream_get_byte"       -> unsigned(8),
    "bytestream2_get_byte"      -> unsigned(8),
    "bytestream2_get_byteu"     -> unsigned(8),
    "bytestream_get_be16"       -> unsigned(16),
    "bytestream_get_le16"       -> unsigned(16),
    "bytestream2_get_be16"      -> unsigned(16),
    "bytestream2_get_le16"      -> unsigned(16),
    "bytestream2_get_be16u"     -> unsigned(16),
    "bytestream2_get_le16u"     -> unsigned(16),
    "get_bits1"                 -> unsigned(1),
    "av_log2"                   -> Range(0, 31),
    "av_log2_16bit"             -> Range(0, 15),
    "ff_log2"                   -> Range(0, 31)
  )

  /** Readers whose width is their literal second argument: `get_bits(gb, 4)` is 0..15. */
  private val BitReaders = Set("get_bits", "get_bitsz", "get_bits_long", "show_bits")

  private val TypeRanges: Map[String, Range] = Map(
    "bool"               -> Range(0, 1),
    "_Bool"              -> Range(0, 1),
    "unsigned char"      -> unsigned(8),
    "uint8_t"            -> unsigned(8),
    "signed char"        -> signed(8),
    "int8_t"             -> signed(8),
    "unsigned short"     -> unsigned(16),
    "unsigned short int" -> unsigned(16),
    "uint16_t"           -> unsigned(16),
    "short"              -> signed(16),
    "short int"          -> signed(16),
    "int16_t"            -> signed(16),
    "unsigned int"       -> unsigned(32),
    "uint32_t"           -> unsigned(32),
    "unsigned long"      -> unsigned(64),
    "unsigned long long" -> unsigned(64),
    "uint64_t"           -> unsigned(64),
    "size_t"             -> unsigned(64)
  )

  /** The range a declared type admits, when it is one of the fixed-width integral types. */
  def ofType(t: String): Option[Range] =
      TypeRanges.get(OverlayFacts.normalizeTypeName(Option(t).getOrElse("").trim))

  private def literal(e: AstNode): Option[BigInt] = e match
    case l: Literal =>
        val c = l.code.trim.toLowerCase.replaceAll("[ul]+$", "")
        if c.startsWith("0x") then scala.util.Try(BigInt(c.drop(2), 16)).toOption
        else scala.util.Try(BigInt(c)).toOption
    case c: Call if c.name == "<operator>.minus" => c.argumentOption(1).flatMap(literal).map(-_)
    case _                                        => None

  /** @param typeOf
    *   the declared type of an expression (the rule's resolver, which reads a field access's
    *   member type)
    * @param depth
    *   how many definition or call-site hops the answer may cross
    */
  def of(e: Expression, typeOf: Expression => String, depth: Int = 3): Option[Range] =
    if depth < 0 then None
    else
      literal(e).map(v => Range(v, v)).orElse(e match
        case c: Call if ReadWidths.contains(c.name) => ReadWidths.get(c.name)
        case c: Call if BitReaders.contains(c.name) =>
            c.argumentOption(2).flatMap(literal).filter(n => n > 0 && n <= 32)
                .map(n => unsigned(n.toInt))
        case c: Call if c.name == "<operator>.and" =>
            // a non-negative mask bounds the result whatever the other operand holds
            c.argument.l.flatMap(literal).filter(_ >= 0).minOption.map(m => Range(0, m))
        case c: Call if c.name == "<operator>.modulo" =>
            (c.argumentOption(1).collect { case x: Expression => x }.flatMap(of(_, typeOf, depth)),
                c.argumentOption(2).flatMap(literal)) match
              case (Some(r), Some(m)) if r.nonNegative && m > 0 => Some(Range(0, m - 1))
              case _                                            => None
        case c: Call
            if c.name == "<operator>.arithmeticShiftRight" ||
                c.name == "<operator>.logicalShiftRight" =>
            (c.argumentOption(1).collect { case x: Expression => x }.flatMap(of(_, typeOf, depth)),
                c.argumentOption(2).flatMap(literal)) match
              case (Some(r), Some(k)) if r.nonNegative && k >= 0 && k < 64 =>
                  Some(Range(r.lo >> k.toInt, r.hi >> k.toInt))
              case _ => None
        case c: Call if c.name == "<operator>.conditional" =>
            val branches = Seq(2, 3).flatMap(i =>
                c.argumentOption(i).collect { case x: Expression => x }.map(of(_, typeOf, depth))
            )
            if branches.size == 2 && branches.forall(_.isDefined) then
              Some(branches.flatten.reduce(_ union _))
            else None
        case c: Call if c.name == "<operator>.cast" =>
            // the operand's own range when it fits the target, else the target type's range
            val target  = ofType(c.typeFullName)
            val operand = c.argumentOption(2).orElse(c.argumentOption(1))
                .collect { case x: Expression => x }.flatMap(of(_, typeOf, depth))
            (operand, target) match
              case (Some(r), Some(t)) if r.lo >= t.lo && r.hi <= t.hi => Some(r)
              case (_, Some(t))                                        => Some(t)
              case (Some(r), None)                                     => Some(r)
              case _                                                   => None
        case i: Identifier => ofIdentifier(i, typeOf, depth).orElse(ofType(typeOf(i)))
        // an element read: the element type of the array (`unsigned int buffer_num[4]`), which
        // the frontend leaves off the access itself
        case c: Call
            if c.name == "<operator>.indexAccess" || c.name == "<operator>.indirectIndexAccess" =>
            ofType(typeOf(c)).orElse(
              c.argumentOption(1).collect { case b: Expression => b }
                  .map(b => typeOf(b).trim.replaceAll("""\[[^\]]*\]$""", "").trim)
                  .flatMap(ofType)
            )
        case other => ofType(typeOf(other))
      )

  /** An identifier's range: the union over the assignments that reach it, or - when it is a
    * parameter no assignment redefines - the union over what every intra-tree caller passes.
    * Any definition this object cannot bound makes the whole answer None.
    */
  private def ofIdentifier(i: Identifier, typeOf: Expression => String, depth: Int): Option[Range] =
    val method = i.method
    // The reaching-def graph also counts a by-value call argument as a definition (`use(i)`
    // "defines" i); that changes nothing and is skipped. What DOES move the value - an increment,
    // a compound assignment, an address taken for a callee to write through - makes the range
    // unknown: `i = 0; ... i++` is not the range {0}.
    val defs: List[Option[Range]] = OverlayFacts.reachingDefsIn(i).flatMap {
        case p: MethodParameterIn if p.name == i.name => List(ofParameter(p, typeOf, depth))
        case d: Identifier if d.name == i.name =>
            d._astIn.collectFirst { case a: Call => a }.toList.flatMap { a =>
                val isTarget = a.argumentOption(1).exists(_.id == d.id)
                a.name match
                  case "<operator>.assignment" if isTarget =>
                      List(a.argumentOption(2).collect { case x: Expression => x }
                          .flatMap(of(_, typeOf, depth - 1)))
                  // a counter that only ever grows keeps its lower end: `i = 0; ... i++` is
                  // [0, unbounded], and the loop condition is what bounds it above
                  case n if isTarget && n.matches("<operator>\\.(pre|post)Increment") =>
                      List(Some(Range(Unbounded, Unbounded)))
                  case "<operator>.assignmentPlus" if isTarget =>
                      a.argumentOption(2).flatMap(literal).filter(_ >= 0)
                          .map(_ => Range(Unbounded, Unbounded)) match
                        case some @ Some(_) => List(some)
                        case None           => List(None)
                  case n if isTarget && (n.startsWith("<operator>.assignment") ||
                        n.matches("<operator>\\.(pre|post)Decrement")) =>
                      List(None)
                  case "<operator>.addressOf" => List(None)
                  case _                      => Nil
            }
        case _ => Nil
    }
    if defs.isEmpty then
      // a parameter no reaching-def edge reaches is still the parameter
      method.parameter.nameExact(i.name).headOption.flatMap(ofParameter(_, typeOf, depth))
    else if defs.forall(_.isDefined) then
      // a growth marker (lo = Unbounded) contributes no lower end of its own: the counter
      // starts at the other definitions and only rises from there, without an upper end
      val (growth, values) = defs.flatten.partition(_.lo == Unbounded)
      if values.isEmpty then None
      else
        val base = values.reduce(_ union _)
        Some(if growth.nonEmpty then Range(base.lo, Unbounded) else base)
    else None

  private def ofParameter(p: MethodParameterIn, typeOf: Expression => String, depth: Int): Option[Range] =
    val sites = p.method._callIn.collectAll[Call].l.distinct
    val fromCallers =
        if sites.isEmpty || depth <= 0 then None
        else
          val ranges = sites.map(_.argumentOption(p.index).collect { case x: Expression => x }
              .flatMap(of(_, typeOf, depth - 1)))
          if ranges.forall(_.isDefined) then Some(ranges.flatten.reduce(_ union _)) else None
    fromCallers.orElse(ofType(p.typeFullName))
end IndexRange
