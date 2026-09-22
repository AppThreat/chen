package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS7: integer width facts - how wide is this number, and where can a narrow one overflow. The two
  * litmus shapes no current fact can express are CWE-190 (an integer overflow that becomes a buffer
  * overflow, hevc.c's uint16_t NAL counter) and CWE-197 (narrowing, rtpenc_av1's `(long) obu_size`
  * guard). This pass emits FACTS ONLY - no rule reads them yet; the counts and the litmus sites are
  * the deliverable, so fact quality is visible before anything reports.
  *
  * Facts (each alongside the `memory-safety` umbrella, fine-grained tag valued with the evidence,
  * the overlay's layered convention):
  *
  *   - `int-narrow` - a (compound) assignment, increment or cast whose DESTINATION is narrower than
  *     the width the value is computed in. `array->numNalus = array->numNalus + 1` on a uint16_t
  *     member computes in int and wraps back into 16 bits.
  *   - `int-resign` - a cast that changes signedness, at any width: the `(long) obu_size` guard
  *     test reinterprets an unsigned int as a signed long, which on LLP64 (long = 32) discards the
  *     values it claims to reject. The width table is LP64, so this fact is what makes the LLP64
  *     hazard visible under a model where the narrowing does not happen.
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

  /** `int-narrow` and `int-resign` on assignments, increments and casts. */
  private def narrowingFacts(record: (StoredNode, String, String) => Unit): Unit =
      atom.call
          .name(
            "<operator>.assignment|<operator>.assignmentPlus|<operator>.assignmentMinus|<operator>.postIncrement|<operator>.preIncrement|<operator>.cast"
          )
          .l
          .foreach { c =>
              c.name match
                case "<operator>.cast" =>
                    // c2cpg lays a cast out as (type placeholder, operand): the target type is
                    // the FIRST argument's rendered name, the operand the second
                    val operandOpt = c.argumentOption(2).orElse(c.argumentOption(1))
                    val targetName =
                        if c.argumentOption(2).isDefined then
                          c.argumentOption(1).map(_.code).getOrElse(c.typeFullName)
                        else c.typeFullName
                    operandOpt.foreach { operand =>
                      val (from, fromW) = declaredWidthOf(operand)
                      integralWidth(targetName).foreach { tw =>
                          if fromW > tw then
                            record(c, TagNarrow, s"from:$from:$fromW->to:$targetName:$tw")
                          else if fromW > 0 && signednessOf(from) != signednessOf(targetName) then
                            record(c, TagResign, s"from:$from:$fromW->to:$targetName:$tw")
                      }
                    }
                case _ =>
                    c.argumentOption(1).foreach { lhs =>
                      val to = declaredTypeOf(lhs)
                      integralWidth(to).foreach { tw =>
                          c.argumentOption(2).orElse(c.argumentOption(1)).foreach { rhs =>
                            val (from, fromW) = computedWidthOf(rhs)
                            if fromW > tw then
                              record(c, TagNarrow, s"from:$from:$fromW->to:$to:$tw")
                          }
                      }
                    }
          }
  end narrowingFacts

  /** `int-arith-len`: attacker-influenced arithmetic reaching a copy length or allocation size. */
  private def arithLengthFacts(record: (StoredNode, String, String) => Unit): Unit =
    val lenArgs = OverlayFacts
        .memoryArgumentSites(atom)
        .collect { case (_, e, MemoryApiPass.TagLen) => e }
        .distinct
    lenArgs.foreach { len =>
      // the length argument may BE the arithmetic (`malloc(n * 4)`), so it joins the walk -
      // reachingDefsIn deliberately excludes its own start node
      val candidates = len +: OverlayFacts.reachingDefsIn(len)
      candidates.foreach {
          case c: Call
              if c.name == "<operator>.multiplication" ||
                  c.name == "<operator>.addition" =>
              val origins = c.argument.l.collect { case e: Expression => e }
                  .flatMap(ValueOriginPass.originNamesOf)
                  .filterNot(_ == ValueOriginPass.OriginUnknown)
              if origins.exists(attackerOrigins.contains) then
                record(c, TagArithLen, origins.mkString("+"))
          case _ => ()
      }
    }
  end arithLengthFacts

  private val attackerOrigins = Set(
    ValueOriginPass.OriginCallerParam,
    ValueOriginPass.OriginUntrustedRead,
    ValueOriginPass.OriginStructField,
    ValueOriginPass.OriginMixed
  )

  /** The declared type of an assignment destination: an identifier's type, or - for the field
    * accesses the frontend often leaves typeless - the member it writes.
    */
  private def declaredTypeOf(lhs: Expression): String =
    val direct = lhs match
      case i: Identifier => i.typeFullName
      case c: Call       => c.typeFullName
      case _             => ""
    if direct.nonEmpty && direct != "<empty>" then direct
    else
      lhs match
        case c: Call => OverlayFacts.memberRefOf(atom, c).map(_.typeFullName).getOrElse("")
        case _       => ""

  /** The type an operand expression carries, through the typeless-field fallback. */
  private def operandType(c: Call): Option[String] =
      c.argumentOption(1).map(declaredTypeOf).filter(_.nonEmpty)

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
            val parts = c.argument.l.collect { case x: Expression => x }.map(declaredWidthOf)
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

  final val TagNarrow   = "int-narrow"
  final val TagResign   = "int-resign"
  final val TagArithLen = "int-arith-len"

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
