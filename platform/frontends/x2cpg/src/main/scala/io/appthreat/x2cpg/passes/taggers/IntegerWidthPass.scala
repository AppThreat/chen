package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Integer width facts - how wide is this number, and where can a narrow one overflow. The two
  * shapes no other overlay fact can express are CWE-190 (an integer overflow that becomes a buffer
  * overflow, hevc.c's uint16_t NAL counter) and CWE-197 (narrowing, rtpenc_av1's `(long) obu_size`
  * guard). This pass emits FACTS ONLY; the integer rules in [[MemorySafetyFindingPass]] read them,
  * so fact quality stays separable from rule policy.
  *
  * Facts (each alongside the `memory-safety` umbrella, fine-grained tag valued with the evidence,
  * the overlay's layered convention):
  *
  *   - `int-narrow` - a (compound) assignment, increment, cast, return or argument whose
  *     DESTINATION is narrower than the width the value is computed in. `array->numNalus =
  *     array->numNalus + 1` on a uint16_t member computes in int and wraps back into 16 bits; a
  *     constant narrows when the destination cannot hold its value. An argument's fact is on the
  *     argument, valued `arg:<index>:...`; a return's on the return.
  *   - `int-resign` - a cast that changes signedness, at any width: the `(long) obu_size` guard
  *     test reinterprets an unsigned int as a signed long, which on LLP64 (long = 32) discards the
  *     values it claims to reject. The width table is LP64, so this fact is what makes the LLP64
  *     hazard visible under a model where the narrowing does not happen. Also a negative decimal
  *     constant stored unsigned, and a comparison that converts a signed operand to unsigned
  *     (`compare:...`).
  *   - `int-arith-len` - a multiplication or addition with an attacker-influenced operand (origin
  *     `caller-param` / `untrusted-read` / `struct-field` / `mixed`) whose result reaches a
  *     `mem-len` argument or an allocation size - the multiply that computes the copy length or the
  *     malloc size.
  *
  * Widths come from `typeFullName` through [[OverlayFacts.integralWidth]]; C arithmetic promotes
  * every operand narrower than int, so an arithmetic result is the widest operand, floored at 32.
  * Nothing here reads source text. Runs after [[ValueOriginPass]] (it reads origin tags); C/C++
  * graphs only.
  */
class IntegerWidthPass(atom: Cpg) extends CpgPass(atom):

  import IntegerWidthPass.*
  import OverlayFacts.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return

    val facts = mutable.LinkedHashMap.empty[StoredNode, mutable.LinkedHashSet[(String, String)]]
    def record(node: StoredNode, tag: String, value: String): Unit =
        facts.getOrElseUpdate(node, mutable.LinkedHashSet.empty) += ((tag, value))

    narrowingFacts(record)
    arithLengthFacts(record)

    OverlayFacts.emitTags(
      dstGraph,
      facts.toList.flatMap { case (node, tags) =>
          tags.toList.map { case (tag, value) => (node, tag, value) }
      }
    )

  /** `int-narrow` and `int-resign` on assignments, increments and casts. Dispatch is a string
    * switch over one streamed call enumeration and the arguments are read ONCE per node (a regex
    * name filter plus an argument sub-traversal per `argumentOption` costs gigabytes of allocation
    * on a large tree).
    */
  private def narrowingFacts(record: (StoredNode, String, String) => Unit): Unit =
    atom.call.foreach { c =>
        c.name match
          case "<operator>.cast" =>
              // c2cpg lays a cast out as (type placeholder, operand) and types the call with
              // the target type; when that type is unresolved the written type name stands in
              val args       = argumentsOf(c)
              val operandOpt = argAt(args, 2).orElse(argAt(args, 1))
              val targetName =
                  if c.typeFullName.nonEmpty && c.typeFullName != "ANY" &&
                    c.typeFullName != "<empty>"
                  then c.typeFullName
                  else
                    argAt(args, 1).filter(_ => argAt(args, 2).isDefined).map(_.code)
                        .getOrElse(c.typeFullName)
              operandOpt.filterNot(fitsAsConstant(_, targetName)).foreach { operand =>
                val (from, fromW) = declaredWidthOf(operand)
                integralWidth(targetName).foreach { tw =>
                    if fromW > tw then
                      record(c, TagNarrow, s"from:$from:$fromW->to:$targetName:$tw")
                    else if fromW > 0 && signednessOf(from) != signednessOf(targetName) then
                      record(c, TagResign, s"from:$from:$fromW->to:$targetName:$tw")
                }
              }
          case "<operator>.assignment" | "<operator>.assignmentPlus" |
              "<operator>.assignmentMinus" | "<operator>.postIncrement" |
              "<operator>.preIncrement" =>
              val args = argumentsOf(c)
              argAt(args, 1).foreach { lhs =>
                  argAt(args, 2).orElse(argAt(args, 1)).foreach { rhs =>
                      // a compound assignment computes in the wider type whatever it adds
                      storeFacts(
                        record,
                        c,
                        declaredTypeOf(lhs),
                        rhs,
                        plainStore = c.name == "<operator>.assignment"
                      )
                  }
              }
          case name if comparisonOps.contains(name)  => comparisonFacts(record, c)
          case name if !name.startsWith("<operator") => argumentFacts(record, c)
          case _                                     => ()
    }
    // a returned value converts to the function's return type
    atom.ret.foreach { r =>
        r.astChildren.collectFirst { case e: Expression => e }.foreach { value =>
            storeFacts(record, r, r.method.methodReturn.typeFullName, value, plainStore = true)
        }
    }
  end narrowingFacts

  /** The facts of storing `value` into a destination of type `to` at `site`: an assignment, a
    * return, an argument passed to a parameter. A constant is judged by its value, the way a
    * compiler warns: it narrows when the destination cannot hold it, and a negative one stored into
    * an unsigned type changes sign. A constant written as a bit pattern (a hexadecimal or octal
    * literal, or bitwise operators over constants) changes sign on purpose: only lost bits count.
    */
  private def storeFacts(
    record: (StoredNode, String, String) => Unit,
    site: StoredNode,
    to: String,
    value: Expression,
    plainStore: Boolean,
    label: String = ""
  ): Unit =
      integralWidth(to).foreach { tw =>
        val constant = if plainStore then IndexRange.literal(value) else None
        constant match
          case Some(v) if isBitPattern(value) =>
              if v > (BigInt(1) << tw) - 1 || v < -(BigInt(1) << (tw - 1)) then
                record(site, TagNarrow, s"${label}from:constant:$v->to:$to:$tw")
          case Some(v) =>
              if overflowsType(v, to) then
                record(site, TagNarrow, s"${label}from:constant:$v->to:$to:$tw")
              else if v < 0 && isUnsignedIntegral(to) then
                record(site, TagResign, s"${label}from:constant:$v->to:$to:$tw")
          case None =>
              val (from, fromW) = computedWidthOf(value)
              if fromW > tw && !fitsAsConstant(value, to) then
                record(site, TagNarrow, s"${label}from:$from:$fromW->to:$to:$tw")
      }

  /** A constant written as bits: a hexadecimal, octal or binary literal (also behind a macro), or a
    * bitwise operator over constants.
    */
  private def isBitPattern(e: Expression): Boolean = e match
    case l: Literal =>
        val c = l.code.trim.toLowerCase
        c.startsWith("0x") || c.startsWith("0b") || c.matches("0[0-7]+[ul]*")
    case c: Call if bitwiseOps.contains(c.name) => true
    case c: Call if c.name == "<operator>.cast" || c.dispatchType == "INLINED" =>
        c.ast.isLiteral.l.lastOption.exists(isBitPattern)
    case _ => false

  /** Arguments passed to parameters of a narrower integral type, by the call's signature. */
  private def argumentFacts(record: (StoredNode, String, String) => Unit, c: Call): Unit =
    val params = parameterTypes(c.signature)
    if params.nonEmpty then
      argumentsOf(c).filter(_.argumentIndex >= 1).foreach { arg =>
          params.lift(arg.argumentIndex - 1).filterNot(_ == "...").foreach { to =>
              storeFacts(
                record,
                arg,
                to,
                arg,
                plainStore = true,
                label = s"arg:${arg.argumentIndex}:"
              )
          }
      }

  /** A comparison of a signed operand with an unsigned one at least as wide: the usual arithmetic
    * conversions turn the signed value unsigned, so a negative one compares as a large one.
    */
  private def comparisonFacts(record: (StoredNode, String, String) => Unit, c: Call): Unit =
      argumentsOf(c) match
        case List(a, b) =>
            val (ta, wa)         = declaredWidthOf(a)
            val (tb, wb)         = declaredWidthOf(b)
            def promoted(w: Int) = w.max(32)
            (signednessOf(ta), signednessOf(tb)) match
              case (Some(true), Some(false))
                  if wa > 0 && promoted(wb) >= promoted(wa) && wb >= 32 =>
                  record(c, TagResign, s"compare:from:$ta:$wa->to:$tb:$wb")
              case (Some(false), Some(true))
                  if wb > 0 && promoted(wa) >= promoted(wb) && wa >= 32 =>
                  record(c, TagResign, s"compare:from:$tb:$wb->to:$ta:$wa")
              case _ => ()
        case _ => ()

  /** The parameter types of a signature `ret(a,b<c,d>,e)`, split at top-level commas. */
  private def parameterTypes(signature: String): List[String] =
    val open = signature.indexOf('(')
    if open < 0 || !signature.endsWith(")") then Nil
    else
      val inner   = signature.substring(open + 1, signature.length - 1)
      val parts   = mutable.ListBuffer.empty[String]
      var depth   = 0
      val current = new StringBuilder
      inner.foreach {
          case ',' if depth == 0 =>
              parts += current.toString
              current.clear()
          case ch =>
              if ch == '<' || ch == '(' then depth += 1
              if ch == '>' || ch == ')' then depth -= 1
              current += ch
      }
      if current.nonEmpty then parts += current.toString
      parts.toList.map(_.trim).filter(_.nonEmpty)

  /** A constant the destination type holds: storing it changes nothing, whatever type the constant
    * is computed in (`uint8_t c = 5`, `(uint16_t) sizeof(hdr)`).
    */
  private def fitsAsConstant(value: Expression, destination: String): Boolean =
      IndexRange.literal(value).exists(IndexRange.fitsType(_, destination))

  /** A constant the destination cannot hold under either signedness: past the top of its range, or
    * below the bottom of a signed one. `-1` into an unsigned type is the all-bits-set idiom, not a
    * loss.
    */
  private def overflowsType(v: BigInt, destination: String): Boolean =
      IndexRange.ofType(destination).exists(r =>
          v > r.hi || (v < r.lo && !isUnsignedIntegral(destination))
      )

  /** The arguments of a call, fetched with one traversal and ordered locally. */
  private def argumentsOf(c: Call): List[Expression] =
      c.argument.l.sortBy(_.argumentIndex)

  private def argAt(args: List[Expression], index: Int): Option[Expression] =
      args.find(_.argumentIndex == index)

  /** `int-arith-len`: attacker-influenced arithmetic reaching a copy length or allocation size. */
  private def arithLengthFacts(record: (StoredNode, String, String) => Unit): Unit =
    val lenArgs = OverlayFacts
        .memoryArgumentSites(atom)
        .collect { case (_, e, MemoryApiPass.TagLen) => e }
        .distinct
    // ONE multi-source bounded BFS from every length argument, instead of one walk per
    // argument: per-argument walks re-visit the same dense def-neighbourhoods hundreds of
    // times over. A node enters the walk once, at its
    // minimum hop distance from any length argument - the union of the per-argument
    // hop-bounded reachable sets, which is exactly the set of facts, collected once.
    val visited     = mutable.LongMap.empty[Int]
    var frontier    = List.empty[(StoredNode, Int)]
    val originCache = mutable.HashMap.empty[Long, Set[String]]
    lenArgs.foreach { len =>
      visited.update(len.id(), 0)
      frontier = (len, 0) :: frontier
      // the length argument may BE the arithmetic (`malloc(n * 4)`): the seed is a candidate
      collectArithFact(len, 0, originCache, mutable.ListBuffer.empty, record)
    }
    while frontier.nonEmpty do
      val next = mutable.ListBuffer.empty[(StoredNode, Int)]
      frontier.foreach { case (node, dist) =>
          val successors = expandDefs(node)
          successors.foreach { candidate =>
            val fresh = !visited.contains(candidate.id())
            if fresh then
              visited.update(candidate.id(), dist + 1)
              collectArithFact(candidate, dist + 1, originCache, next, record)
          }
      }
      frontier = next.toList
  end arithLengthFacts

  private def collectArithFact(
    candidate: StoredNode,
    dist: Int,
    originCache: mutable.HashMap[Long, Set[String]],
    next: mutable.ListBuffer[(StoredNode, Int)],
    record: (StoredNode, String, String) => Unit
  ): Unit =
    candidate match
      case c: Call
          if c.name == "<operator>.multiplication" || c.name == "<operator>.addition" =>
          val origins = c.argument.l.collect { case e: Expression => e }.flatMap { e =>
              originCache.getOrElseUpdate(
                e.id,
                ValueOriginPass
                    .originNamesOf(e)
                    .filterNot(_ == ValueOriginPass.OriginUnknown)
              )
          }
          if origins.exists(attackerOrigins.contains) then
            record(c, TagArithLen, origins.mkString("+"))
      case _ =>
    if dist < MaxWalkHops then next += ((candidate, dist))
  end collectArithFact

  /** The def-neighbours of a node: the same expansion OverlayFacts.reachingDefsIn performs. */
  private def expandDefs(node: StoredNode): List[StoredNode] = node match
    case i: Identifier =>
        val exclude = OverlayFacts.expansionExclusionOf(i)
        i._reachingDefIn.iterator.filterNot(d => exclude.contains(d.id())).toList
    case other =>
        other._reachingDefIn.iterator.toList

  private val attackerOrigins = Set(
    ValueOriginPass.OriginCallerParam,
    ValueOriginPass.OriginUntrustedRead,
    ValueOriginPass.OriginStructField,
    ValueOriginPass.OriginMixed
  )

  /** The declared type of an assignment destination or an operand: the type the frontend records on
    * it (a field access carries the type of the member it reads, an element access its element
    * type).
    */
  private def declaredTypeOf(e: Expression): String = e match
    case i: Identifier => i.typeFullName
    case c: Call       => c.typeFullName
    case _             => ""

  /** (declared type, width) of an expression; width 0 when the type is not a known integral. */
  private def declaredWidthOf(e: Expression): (String, Int) =
    val t = declaredTypeOf(e)
    (t, integralWidth(t).getOrElse(0))

  /** The width the VALUE is computed in: arithmetic promotes every operand narrower than int, so
    * `uint16 + uint16` computes in 32 bits. A bare operand computes at its own declared width -
    * assigning one to the same-width variable loses nothing, and is not a narrowing.
    */
  private def computedWidthOf(e: Expression): (String, Int) =
      e match
        case c: Call
            if c.name == "<operator>.addition" || c.name == "<operator>.subtraction" ||
                c.name == "<operator>.multiplication" =>
            val parts = argumentsOf(c).map(declaredWidthOf)
            val width = (parts.map(_._2) :+ 32).max
            val label = parts.find(_._2 == width).map(_._1).getOrElse("promoted")
            (label, width)
        case other => declaredWidthOf(other)

  private def signednessOf(t: String): Option[Boolean] =
      if isSignedIntegral(t) then Some(true)
      else if isUnsignedIntegral(t) then Some(false)
      else None
end IntegerWidthPass

object IntegerWidthPass:

  private val comparisonOps = Set(
    "<operator>.lessThan",
    "<operator>.greaterThan",
    "<operator>.lessEqualsThan",
    "<operator>.greaterEqualsThan",
    "<operator>.equals",
    "<operator>.notEquals"
  )

  private val bitwiseOps = Set(
    "<operator>.and",
    "<operator>.or",
    "<operator>.xor",
    "<operator>.not",
    "<operator>.shiftLeft",
    "<operator>.arithmeticShiftRight",
    "<operator>.logicalShiftRight"
  )

  final val TagNarrow   = "int-narrow"
  final val TagResign   = "int-resign"
  final val TagArithLen = "int-arith-len"

  /** the walk budget OverlayFacts.reachingDefsIn uses by default */
  private val MaxWalkHops = 8

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end IntegerWidthPass
