package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS3: what does this comparison establish.
  *
  * For every comparison that control-dominates a memory operation, decide which value it bounds, on
  * which side, and against what - and tag the bounded value's argument node at that operation:
  *
  *   - `bounded-above`, valued `<bounding node id>:<rendered code>` - `size > max_payload_size`
  *     (early-exit), `cap < len`, `len >= cap`, `!(len <= cap)`;
  *   - `bounded-below`, same - `size >= 0`, `size > 0`;
  *   - `bounded-by-extent`, valued with the extent fact the bound came from - `if (n >
  *     sizeof(dst))`.
  *
  * Normalising the comparison is the whole job. `len > cap`, `cap < len`, `len >= cap`, `!(len <=
  * cap)` and an `FFMIN` clamp are the same fact, and only this pass says so. Nothing here reads
  * source text: operands come from the comparison's argument expressions, and "the same variable"
  * is OverlayFacts' structural key (identifier name, or base+member for field accesses) - the thing
  * the deleted `.code` regex could only approximate.
  *
  * Which side holds is decided structurally, not by textual shape: a guard's condition HOLDS at a
  * memory operation inside the guard's then-subtree or loop body, and does NOT hold at one that
  * merely follows an early-exit `if` - which is exactly the difference between `if (len < cap)
  * memcpy(...)` (bounded above) and `if (len > cap) memcpy(...)` (not bounded). Negation through
  * `!(...)`, `||` and `&&` follows the boolean algebra; where only a disjunction could be concluded
  * (`if (a || b) memcpy(...)`), no fact is emitted rather than a wrong one.
  *
  * Clamps are found as assignments whose right side is a conditional whose branches are the
  * comparison's own operands (`x = a < b ? a : b`, the shape every min/max macro expands to,
  * including inside an INLINED macro expansion), or a vocabulary clamp call (`FFMIN`) when the
  * frontend left the macro unexpanded. The bound propagates from the assignment's definition along
  * REACHING_DEF to the memory-operation arguments that use the clamped value.
  *
  * Runs after [[ExtentPass]] (a bound compared against a buffer's extent is `bounded-by-extent`)
  * and [[MemoryApiPass]]. C/C++ graphs only.
  */
class GuardPass(atom: Cpg, externalConfig: Option[String] = None) extends CpgPass(atom):

  import GuardPass.*
  import OverlayFacts.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return

    // argument node -> (tag, value) pairs, emitted in one batch at the end
    val bounds = mutable.LinkedHashMap.empty[StoredNode, mutable.LinkedHashSet[(String, String)]]
    def add(node: StoredNode, tag: String, value: String): Unit =
        bounds.getOrElseUpdate(node, mutable.LinkedHashSet.empty) += ((tag, value))

    val sites = OverlayFacts.memoryArgumentSites(atom)
    val argsByCall = sites.groupBy { case (call, _, _) => call }
        .map { case (call, rows) => call -> rows.map { case (_, arg, _) => arg }.distinct }
    val argNodeIds = sites.map { case (_, arg, _) => arg.id }.toSet

    guardBounds(argsByCall, add)
    clampBounds(argNodeIds, add)

    bounds.foreach { case (node, tags) =>
        tags.foreach { case (tag, value) =>
            Iterator.single(node).newTagNodePair(tag, value).store()(using dstGraph)
        }
    }
    bounds.keys.iterator.newTagNode(MemoryApiPass.UmbrellaTag).store()(using dstGraph)
  end run

  /** Facts from comparisons that control memory operations. */
  private def guardBounds(
    argsByCall: Map[Call, List[Expression]],
    add: (StoredNode, String, String) => Unit
  ): Unit =
      argsByCall.foreach { case (call, args) =>
          val argKeys = args.flatMap(a => variableKey(a).map(k => k -> a)).toMap
          call.controlledBy.collect { case c: Call => c }.foreach { controller =>
              conjuncts(controller, holdsAt(controller, call)).getOrElse(Nil).foreach {
                  case (cmp, cmpHolds) =>
                      directionalFacts(cmp, cmpHolds).foreach { case (bounded, above, bound) =>
                          variableKey(bounded).flatMap(argKeys.get).foreach { arg =>
                            add(
                              arg,
                              if above then TagAbove else TagBelow,
                              s"${bound.id}:${bound.code}"
                            )
                            extentValueOf(bound).foreach(ev => add(arg, TagByExtent, ev))
                          }
                      }
              }
          }
      }

  /** Facts from clamping assignments: `x = a < b ? a : b`, an INLINED macro expansion of it, or a
    * vocabulary clamp call. Tagged at the definition and at the memory-operation arguments that use
    * the clamped value.
    */
  private def clampBounds(
    argNodeIds: Set[Long],
    add: (StoredNode, String, String) => Unit
  ): Unit =
    val inventory = MemApiVocab.inventory(externalConfig)
    atom.call.name("<operator>.assignment").l.foreach { assignment =>
      val lhs = assignment.argumentOption(1).collect { case i: Identifier => i }
      val rhs = assignment.argumentOption(2).collect { case c: Call => c }
      (lhs, rhs) match
        case (Some(target), Some(clampCall)) =>
            clampOf(clampCall, inventory).foreach { clamp =>
              def emit(tag: String): Unit =
                val value = s"${clamp.node.id}:${clamp.node.code}"
                add(target, tag, value)
                // tags land where the rules read them: the argument nodes using the
                // clamped value
                reachingUsesOut(target)
                    .filter(u => argNodeIds.contains(u.id))
                    .foreach(u => add(u, tag, value))
              clamp.above.foreach(_ => emit(TagAbove))
              clamp.below.foreach(_ => emit(TagBelow))
            }
        case _ => ()
    }
  end clampBounds

  private final case class Clamp(node: Call, above: List[Expression], below: List[Expression])

  /** Recognise `cmp ? a : b` where {a, b} are cmp's own operands (the min/max shape), including
    * when it sits inside an INLINED macro expansion; or a vocabulary clamp (`FFMIN`). The tag names
    * `node`: the conditional itself, or the macro invocation for the unexpanded form.
    */
  private def clampOf(
    rhs: Call,
    inventory: Map[String, MemApiVocab.MemApiEntry]
  ): Option[Clamp] =
      rhs.name match
        case "<operator>.conditional" =>
            conditionalClamp(rhs, evidence = rhs)
        case _ =>
            // an unexpanded macro invocation: the expansion (if wired in) is a copy under the
            // call; either way the tag names the macro call, which is "the FFMIN clamp"
            rhs.astChildren.isBlock.ast
                .isCall
                .name("<operator>.conditional")
                .l
                .headOption
                .flatMap(cond => conditionalClamp(cond, evidence = rhs))
                .orElse(vocabularyClamp(rhs, inventory))

  private def vocabularyClamp(
    call: Call,
    inventory: Map[String, MemApiVocab.MemApiEntry]
  ): Option[Clamp] =
    def arg(i: Int): Option[Expression] = call.argumentOption(i)
    inventory.get(call.name).flatMap(_.clamp).flatMap {
        case "min" if arg(1).isDefined && arg(2).isDefined =>
            Some(Clamp(call, List(arg(1).get, arg(2).get), Nil))
        case "max" if arg(1).isDefined && arg(2).isDefined =>
            Some(Clamp(call, Nil, List(arg(1).get, arg(2).get)))
        case "clip" if arg(2).isDefined && arg(3).isDefined =>
            Some(Clamp(call, List(arg(3).get), List(arg(2).get)))
        case _ => None
    }

  /** `cond ? x : y` where cond compares x and y: the result is one of the operands, so it is
    * bounded above by both (min) or below by both (max).
    */
  private def conditionalClamp(conditional: Call, evidence: Call): Option[Clamp] =
      for
        cond <- conditional.argumentOption(1).collect { case c: Call => c }
        t    <- conditional.argumentOption(2)
        f    <- conditional.argumentOption(3)
        kL   <- cond.argumentOption(1).flatMap(variableKey)
        kR   <- cond.argumentOption(2).flatMap(variableKey)
        kT   <- variableKey(t)
        kF   <- variableKey(f)
        if Set(kL, kR) == Set(kT, kF)
        lOp <- cond.argumentOption(1)
        rOp <- cond.argumentOption(2)
      yield
        // a < b ? a : b is min; a < b ? b : a is max (and the > mirror)
        val lessThan = cond.name match
          case "<operator>.lessThan" | "<operator>.lessEqualsThan" => true
          case _                                                   => false
        val isMin = if lessThan then kT == kL else kT == kR
        if isMin then Clamp(evidence, List(lOp, rOp), Nil)
        else Clamp(evidence, Nil, List(lOp, rOp))

  /** The comparison facts implied by a boolean expression that holds (or does not hold) at a point:
    * a list of (comparison, holds) conjuncts, or None when only a disjunction follows and no
    * per-comparison fact can be honestly emitted.
    */
  private def conjuncts(expr: Call, holds: Boolean): Option[List[(Call, Boolean)]] =
      expr.name match
        case n if comparisonOps.contains(n) => Some(List((expr, holds)))
        case "<operator>.logicalNot" =>
            expr.argumentOption(1).collect { case c: Call => c }.flatMap(conjuncts(_, !holds))
        case "<operator>.logicalAnd" if holds => andThen(expr, holds)
        case "<operator>.logicalOr" if !holds => andThen(expr, holds)
        case _                                => None

  private def andThen(expr: Call, holds: Boolean): Option[List[(Call, Boolean)]] =
    val l = expr.argumentOption(1).collect { case c: Call => c }.flatMap(conjuncts(_, holds))
    val r = expr.argumentOption(2).collect { case c: Call => c }.flatMap(conjuncts(_, holds))
    (l, r) match
      case (Some(ls), Some(rs)) => Some(ls ++ rs)
      case _                    => None

  /** Which value a comparison bounds and against what, given that it holds (or does not hold)
    * there: `len > cap` NOT holding at a point means `len <= cap` there. Returns (bounded operand,
    * isAbove, bounding operand). Directional operators only; equality establishes nothing
    * directional.
    */
  private def directionalFacts(
    cmp: Call,
    holds: Boolean
  ): List[(Expression, Boolean, Expression)] =
      (cmp.argumentOption(1), cmp.argumentOption(2)) match
        case (Some(l), Some(r)) =>
            cmp.name match
              case "<operator>.greaterThan" | "<operator>.greaterEqualsThan" =>
                  if holds then List((r, true, l), (l, false, r))
                  else List((l, true, r), (r, false, l))
              case "<operator>.lessThan" | "<operator>.lessEqualsThan" =>
                  if holds then List((l, true, r), (r, false, l))
                  else List((r, true, l), (l, false, r))
              case _ => Nil
        case _ => Nil

  /** Does `condition` (as written) hold at `target`? Decided by control-structure nesting: the
    * condition holds inside its own then-subtree or loop body, does not hold inside its else, and
    * does not hold after an early-exit if (the only way a following node stays control-dependent on
    * the condition).
    */
  private def holdsAt(condition: Call, target: Call): Boolean =
      ownerOf(condition) match
        case Some(owner) =>
            var cursor: Option[StoredNode] = Some(target)
            var result                     = false
            var resolved                   = false
            while cursor.isDefined && !resolved do
              cursor match
                case Some(cs: ControlStructure) =>
                    if cs == owner then
                      result = true
                      resolved = true
                    else if isElse(cs) && cs._astIn
                          .collectFirst { case p: ControlStructure => p }
                          .exists(_ == owner)
                    then
                      result = false
                      resolved = true
                    else cursor = cs._astIn.nextOption()
                case Some(_: Method) =>
                    resolved = true
                case Some(other) =>
                    cursor = other._astIn.nextOption()
                case None => resolved = true
            result
        case None => false

  private def ownerOf(condition: Call): Option[ControlStructure] =
    var cursor = condition._astIn.nextOption()
    while cursor.isDefined do
      cursor match
        case Some(cs: ControlStructure) => return Some(cs)
        case Some(_: Method)            => return None
        case Some(other)                => cursor = other._astIn.nextOption()
    None

  private def isElse(cs: ControlStructure): Boolean =
      cs.parserTypeName.equalsIgnoreCase("else")

  /** The extent fact a bounding expression carries, when it is a buffer's capacity: a sizeof call,
    * or a variable whose declaration ExtentPass tagged.
    */
  private def extentValueOf(bound: Expression): Option[String] = bound match
    case c: Call if c.name.startsWith("<operator>.sizeOf") =>
        c.argumentOption(1).map(operand => s"${ExtentPass.ValueSizeof}:${operand.code}")
    case i: Identifier =>
        declExtent(i.method.local.name(i.name).headOption)
            .orElse(declExtent(i.method.parameter.name(i.name).headOption))
    case c: Call
        if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
        OverlayFacts.memberRefOf(atom, c).flatMap(m => declExtent(Some(m)))
    case _ => None

  private def declExtent(decl: Option[StoredNode]): Option[String] =
      decl.flatMap: d =>
        d.tag.name(ExtentPass.TagExtent).value.l.headOption.filterNot(_ == ExtentPass.ValueUnknown)
end GuardPass

object GuardPass:
  final val TagAbove    = "bounded-above"
  final val TagBelow    = "bounded-below"
  final val TagByExtent = "bounded-by-extent"

  private val comparisonOps = Set(
    "<operator>.greaterThan",
    "<operator>.greaterEqualsThan",
    "<operator>.lessThan",
    "<operator>.lessEqualsThan",
    "<operator>.equals",
    "<operator>.notEquals"
  )

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
