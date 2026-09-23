package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS4 (part 4, D3): per allocation, the state at each program point - `allocated`, `freed`,
  * `maybe-freed` (freed on SOME path reaching the point), `null` (reset to NULL, the `free(p); p =
  * NULL` idiom) and `escaped` - stored into a struct, returned, or passed to a non-inventoried
  * call. `escaped` is this pass's `unknown`: once a pointer escapes, an intraprocedural pass knows
  * nothing more and must say so rather than assuming it stays live.
  *
  * Nothing here reads source text. Allocation, free and realloc sites come from the tags
  * [[MemoryApiPass]] left, families included; the wrapper inference already tagged the project's
  * own `cleanup`/`my_free` helpers, so an interprocedural free THROUGH a wrapper is visible
  * intraprocedurally.
  *
  * Flow-sensitive, intraprocedural, per method: a worklist over the CFG edges the ControlFlow layer
  * built, one state per tracked variable at each node. A variable is tracked from its inventoried
  * allocation; assignment copies the state (`q = p`), assignment of a NULL literal resets it,
  * guards narrow it (`if (p == NULL) return;` makes p null inside the then-branch - the idiom every
  * error path in C is written with), a free marks it freed, and a realloc frees its input and
  * yields a fresh allocation (D1's decision - getting that wrong would turn every realloc into a
  * double-free report).
  *
  * Facts (tags, each alongside the `memory-safety` umbrella) for the rules to read:
  *   - `alloc-state` valued with the state, on the freed argument of a free call and on a tracked
  *     pointer's use - a memory call's dst/src argument, an argument of any other call, an index or
  *     field-access base - whenever the state there is freed or maybe-freed;
  *   - `alloc-leak` valued `leak:<name>`, on the exit node where an allocation is live, un-freed
  *     and un-escaped: the returned expression, the RETURN node for a bare `return;`, or the
  *     METHOD_RETURN for the implicit end. Once per allocation, at the earliest such exit - every
  *     early return looks like a leak, and only the first one carries the fact the later ones
  *     restate.
  */
class AllocationStatePass(atom: Cpg) extends CpgPass(atom):

  import AllocationStatePass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return

    val tags = mutable.LinkedHashMap.empty[StoredNode, mutable.LinkedHashSet[(String, String)]]
    def record(node: StoredNode, tag: String, value: String): Unit =
        tags.getOrElseUpdate(node, mutable.LinkedHashSet.empty) += ((tag, value))

    // one scan of the tag nodes builds the role table for every call in the graph; reading
    // tags per call inside the per-method precompute was millions of traversals on libavformat
    val roles = mutable.LongMap.empty[RoleInfo]
    atom.tag.foreach { t =>
      val name = t.name
      if MemoryRoles.contains(name) then
        t._taggedByIn.iterator.foreach {
            case c: Call =>
                val cur = roles.getOrElse(c.id(), RoleInfoNone)
                roles.update(
                  c.id(),
                  name match
                    case MemoryApiPass.TagAlloc   => cur.copy(alloc = cur.alloc + t.value)
                    case MemoryApiPass.TagFree    => cur.copy(free = cur.free + t.value)
                    case MemoryApiPass.TagRealloc => cur.copy(realloc = cur.realloc + t.value)
                    case _                        => cur.copy(isMemoryCall = true)
                )
            case _ => ()
        }
    }

    atom.method.filterNot(_.isExternal).foreach(m => analyseMethod(m, roles, record))

    OverlayFacts.emitTags(
      dstGraph,
      tags.toList.flatMap { case (node, ts) => ts.toList.map { case (t, v) => (node, t, v) } }
    )
  end run

  private def analyseMethod(
    method: Method,
    roles: mutable.LongMap[RoleInfo],
    record: (StoredNode, String, String) => Unit
  ): Unit =
    val leakFacts = mutable.ListBuffer.empty[(Long, StoredNode, String)] // (site, exit, name)

    // every graph/tag read the worklist needs, extracted ONCE per method: the transfer runs
    // per CFG node per worklist visit, and per-visit tag traversals were what made this pass
    // crawl on a 253 KLOC tree (D3 measurement round)
    val callFacts = mutable.LongMap.empty[CallFacts]
    val callNodes = mutable.LongMap.empty[Call]
    val guards    = mutable.LongMap.empty[ControlStructure]
    method.ast.collectAll[Call].foreach { c =>
      val r = roles.getOrElse(c.id(), RoleInfoNone)
      callNodes.update(c.id(), c)
      callFacts.update(
        c.id(),
        CallFacts(
          c.name,
          c.argument.l,
          r.alloc,
          r.free,
          r.realloc,
          r.isMemoryCall,
          r.alloc.nonEmpty || r.realloc.nonEmpty
        )
      )
    }
    method.ast.collectAll[ControlStructure].foreach { cs =>
        cs.condition.foreach(c => guards.update(c.id(), cs))
    }
    // a method that never allocates, frees, reallocs or touches an inventoried memory call
    // has no tracked pointer and no facts: skip the worklist entirely
    if !callFacts.values.exists(cf =>
          cf.allocFamilies.nonEmpty || cf.freeFamilies.nonEmpty ||
              cf.reallocFamilies.nonEmpty
      )
    then return
    val inStates = mutable.HashMap.empty[Long, Map[String, Tracked]]
    val queued   = mutable.LinkedHashSet.empty[CfgNode]
    val visits   = mutable.LongMap.empty[Int]

    def enqueue(node: CfgNode, in: Map[String, Tracked]): Unit =
      // guard narrowing is not monotone through loop back-edges (a revived pointer can be
      // re-nulled on the next iteration), so the worklist is capped: states settle within a
      // few rounds on real code, and the cap guarantees termination on the rest
      val seen = visits.getOrElse(node.id(), 0)
      if seen >= VisitCap then return
      val merged = inStates.get(node.id()) match
        case Some(prev) => joinPoints(prev, in)
        case None       => in
      if inStates.get(node.id()).forall(_ != merged) then
        inStates(node.id()) = merged
        visits.update(node.id(), seen + 1)
        queued += node

    enqueue(method, Map.empty)
    while queued.nonEmpty do
      val node = queued.head
      queued.remove(node)
      val in  = inStates.getOrElse(node.id(), Map.empty)
      val out = transfer(node, in, callFacts, leakFacts, record)

      node._cfgOut.iterator.foreach {
          case succ: CfgNode =>
              // branch edges leave from the CONDITION CALL of a guard, not from the control
              // structure node, so the narrowing rides on the condition's out-edges
              val succState = guards.get(node.id()) match
                case Some(cs) => branchNarrowing(node, cs, succ, out)
                case None     => out
              enqueue(succ, succState)
          case _ => ()
      }
    // one leak fact per allocation: the earliest exit where it is still live
    leakFacts.groupBy(_._1).foreach { case (site, exits) =>
        // the EARLIEST exit, as the scaladoc says: the first `return` that walks out on a live
        // allocation is where a reader fixes the leak, and every later exit restates it.
        // `minBy(-line)` picked the LAST one instead.
        //
        // A real `return` always wins over the implicit end, and that is not a line comparison:
        // METHOD_RETURN carries the line of the function's DECLARATION, so it is "earliest" by
        // line in every function that has one and would swallow every explicit exit.
        val (_, exit, name) = exits.minBy { case (_, node, _) =>
            (node.isInstanceOf[MethodReturn], lineOf(node))
        }
        // ... and when the implicit end IS the exit, it is not a location at all: its line is
        // the function's declaration, several lines from anything a reader would look at. The
        // allocation is the honest anchor there - it is the statement that leaks.
        val anchor = exit match
          case _: MethodReturn => callNodes.get(site).getOrElse(exit)
          case other           => other
        record(anchor, TagLeak, s"leak:$name")
    }
  end analyseMethod

  private def lineOf(node: StoredNode): Int = node match
    case r: Return       => r.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
    case m: MethodReturn => m.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
    case e: Expression   => e.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
    case _               => Int.MaxValue

  /** The transfer function of one CFG node: reads the in-state, records the state facts the node's
    * own operation produces, returns the out-state for the successors.
    */
  private def transfer(
    node: CfgNode,
    in: Map[String, Tracked],
    callFacts: mutable.LongMap[CallFacts],
    leakFacts: mutable.ListBuffer[(Long, StoredNode, String)],
    record: (StoredNode, String, String) => Unit
  ): Map[String, Tracked] =
      node match
        case c: Call =>
            callFacts.get(c.id()) match
              case Some(cf) => transferCall(c, cf, callFacts, in, record)
              case None     => in
        case r: Return =>
            var out = in
            // a returned tracked pointer transfers ownership: it escapes, it does not leak
            r.astChildren.collect { case e: Expression => e }.foreach { e =>
                trackedNameOf(e).foreach { name =>
                    out.get(name).foreach(t => out = out.updated(name, t.copy(state = StEscaped)))
                }
            }
            out.foreach { case (name, t) =>
                if t.state == StAllocated then leakFacts += ((t.site, r, name))
            }
            out
        case mr: MethodReturn =>
            in.foreach { case (name, t) =>
                if t.state == StAllocated then leakFacts += ((t.site, mr, name))
            }
            in
        case _ => in
  end transfer

  private def transferCall(
    c: Call,
    cf: CallFacts,
    callFacts: mutable.LongMap[CallFacts],
    in: Map[String, Tracked],
    record: (StoredNode, String, String) => Unit
  ): Map[String, Tracked] =
    var out = in
    // uses read the state AS OF THIS NODE's entry - a free must not see its own effect
    val useState = in

    // 1. free: the freed pointer's state becomes the fact. A freep-style free takes the ADDRESS
    //    and nulls the slot; a plain free leaves the pointer dangling.
    if cf.freeFamilies.nonEmpty then
      argAt(cf.args, 1).foreach { freed =>
        val viaAddress = addressOfOperand(freed)
        (viaAddress.orElse(Some(freed))).flatMap(trackedNameOf).flatMap(useState.get).foreach { t =>
          if t.state == StFreed || t.state == StMaybeFreed then
            record(viaAddress.getOrElse(freed), TagState, stateName(t.state))
          out = out.updated(
            trackedNameOf(viaAddress.getOrElse(freed)).get,
            if viaAddress.isDefined then t.copy(state = StNullReset)
            else t.copy(state = StFreed)
          )
        }
      }

    // 2. realloc frees its input and yields a fresh allocation. Runs BEFORE the assignment so
    //    `p = realloc(p, n)` stores the fresh pointer over the freed input.
    if cf.reallocFamilies.nonEmpty then
      argAt(cf.args, 1).foreach { arg =>
        val viaAddress = addressOfOperand(arg)
        (viaAddress.orElse(Some(arg))).flatMap(trackedNameOf).foreach { name =>
          useState.get(name).foreach { t =>
              if t.state == StFreed || t.state == StMaybeFreed then
                record(viaAddress.getOrElse(arg), TagState, stateName(t.state))
          }
          if viaAddress.isDefined then out = out.updated(name, Tracked(StAllocated, c.id))
          else out = out.updated(name, Tracked(StFreed, 0L))
        }
      }

    // 3. assignment: fresh allocation, copy-in, NULL reset, or loss of provenance
    if cf.name == "<operator>.assignment" then
      (argAt(cf.args, 1).flatMap(trackedNameOf), argAt(cf.args, 2)) match
        case (Some(lhs), Some(rhs)) =>
            val rhsIsAlloc = rhs match
              case rc: Call => callFacts.get(rc.id()).exists(_.isAllocCall)
              case _        => false
            out.get(lhs).foreach { t =>
                // overwriting a live allocation loses the only handle: the overwrite IS the leak
                // (a realloc is not an overwrite - it consumed the old block and produced this)
                if t.state == StAllocated && !rhsIsAlloc then
                  record(c, TagLeak, s"leak:$lhs")
            }
            rhs match
              case rhsCall: Call if callFacts.get(rhsCall.id()).exists(_.isAllocCall) =>
                  out = out.updated(lhs, Tracked(StAllocated, rhsCall.id))
              case rhsCall: Call if rhsCall.name == "<operator>.cast" =>
                  // `p = (char *)malloc(n)` - the allocation hides under the cast
                  castOperand(rhsCall).flatMap { inner =>
                      inner match
                        case ic: Call if callFacts.get(ic.id()).exists(_.isAllocCall) =>
                            Some(Tracked(StAllocated, ic.id))
                        case other if trackedNameOf(other).isDefined =>
                            trackedNameOf(other).flatMap(n => out.get(n))
                        case _ => None
                  }.foreach(t => out = out.updated(lhs, t))
              case lit: Literal if isNullLiteral(lit) =>
                  out = out.updated(lhs, Tracked(StNullReset, 0L))
              case other if isNullLiteral(other) =>
                  // NULL macro-expanded into an identifier
                  out = out.updated(lhs, Tracked(StNullReset, 0L))
              case other =>
                  trackedNameOf(other).flatMap(useState.get).foreach { t =>
                      out = out.updated(lhs, t)
                  }
            end match
        case (None, Some(rhs)) =>
            // stored into a struct member or through another non-trackable destination: the
            // pointer escapes - ownership left this method's variable space
            val rhsTracked = rhs match
              case rc: Call if rc.name == "<operator>.cast" =>
                  castOperand(rc).flatMap(trackedNameOf)
              case _ => trackedNameOf(rhs)
            rhsTracked.foreach { name =>
                out.get(name).foreach(t => out = out.updated(name, t.copy(state = StEscaped)))
            }
        case _ => ()
    end if

    if isOperatorCall(cf.name) then
      // 4. index and field accesses through a tracked base are uses
      cf.args.foreach { arg =>
          arg match
            case access: Call if isAccessThroughPointer(access) =>
                access.argumentOption(1).foreach { base =>
                    trackedNameOf(base).flatMap(useState.get).foreach { t =>
                        if t.state == StFreed || t.state == StMaybeFreed then
                          record(base, TagState, stateName(t.state))
                    }
                }
            case _ => ()
      }
    else if cf.isMemoryCall then
      // 5. an inventoried memory call USES its pointer arguments; ownership unchanged
      Seq(1, 2, 3).flatMap(i => argAt(cf.args, i)).foreach { arg =>
        val viaAddress = addressOfOperand(arg)
        trackedNameOf(viaAddress.getOrElse(arg)).flatMap(useState.get).foreach { t =>
            if t.state == StFreed || t.state == StMaybeFreed then
              record(viaAddress.getOrElse(arg), TagState, stateName(t.state))
        }
      }
    else
      // 6. any other call uses AND escapes its tracked pointer arguments: an addressOf argument
      //    escapes the ADDRESS - the callee may free or store through it
      cf.args.foreach { arg =>
        val viaAddress = addressOfOperand(arg)
        val operand    = viaAddress.getOrElse(arg)
        trackedNameOf(operand).flatMap(useState.get).foreach { t =>
          if t.state == StFreed || t.state == StMaybeFreed then
            record(operand, TagState, stateName(t.state))
          out = out.updated(trackedNameOf(operand).get, t.copy(state = StEscaped))
        }
      }
    end if
    out
  end transferCall

  /** Guard narrowing at an `==`/`!=` NULL comparison: on paths where `p == NULL` holds, p is null;
    * where `p != NULL` (or the negation) holds, a nulled p is live again. Which side a successor
    * sits on is decided by [[branchOf]].
    */
  private def branchNarrowing(
    cond: CfgNode,
    cs: ControlStructure,
    succ: CfgNode,
    out: Map[String, Tracked]
  ): Map[String, Tracked] =
    val facts: List[(String, Option[Boolean])] = cond match
      case cmp: Call
          if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
          val equals = cmp.name == "<operator>.equals"
          val pairs =
              for
                l <- cmp.argumentOption(1).toList
                r <- cmp.argumentOption(2).toList
              yield (l, r)
          pairs.flatMap { case (l, r) =>
              val trackedName = if isNullLiteral(l) then trackedNameOf(r) else trackedNameOf(l)
              val nullSide    = if isNullLiteral(l) then l else r
              if isNullLiteral(nullSide) then
                trackedName.map { name =>
                    // branchOf is Some(true) exactly where the comparison AS WRITTEN holds:
                    // `p == NULL` holds -> p is null, `p != NULL` holds -> it is not. Part 4
                    // computed `!branchOf` for notEquals, which is the then/else INVERSION -
                    // `if (p != NULL) return;` marked the pointer NULL on the path that
                    // abandons the allocation and silenced the leak.
                    (name, branchOf(succ, cs).map(_ == equals))
                }
              else None
          }
      // `if (!p)` - truthiness of a tracked pointer is its null-ness
      case not: Call if not.name == "<operator>.logicalNot" =>
          not.argumentOption(1).flatMap(trackedNameOf).map { name =>
              // Some(true) = p is null here, Some(false) = non-null, None = unknown
              (name, branchOf(succ, cs))
          }.toList
      // `if (p)` - the pointer is non-null where the condition holds; the condition node is
      // then the identifier itself
      case tracked if trackedNameOf(tracked).isDefined =>
          trackedNameOf(tracked).map { name =>
              // holds => non-null; else-branch => null
              (name, branchOf(succ, cs).map(h => !h))
          }.toList
      case _ => Nil
    facts.foldLeft(out) { case (acc, (name, nullHereOpt)) =>
        nullHereOpt match
          case Some(nullHere) =>
              acc.get(name) match
                case Some(t) =>
                    val newState =
                        if nullHere then StNull
                        else if t.state == StNull then StAllocated
                        else t.state
                    acc.updated(name, t.copy(state = newState))
                case None =>
                    // an untracked pointer that is provably null becomes tracked-as-null;
                    // nothing downstream reports on it either way
                    if nullHere then acc.updated(name, Tracked(StNull, 0L)) else acc
          case None => acc
    }
  end branchNarrowing

  /** Is `succ` inside the then-subtree of `cs`? Some(true) then, Some(false) on the else side or
    * wherever the condition does not hold.
    *
    * The successor sits inside one of the control structure's branch subtrees by AST nesting (child
    * 1 the then, child 2 the else - and an UNBRACED body hangs inside the then-block child whatever
    * its statement kind: an expression statement, a `return x;`, even a `goto`, all park under that
    * block). A successor the climb cannot place is OUTSIDE the control structure entirely, and the
    * only CFG edge reaching it from the condition is the FALSE edge - the join point, the next
    * statement, the method's implicit end. Part 4 answered None there (with a `return`-shaped
    * special case on top), so the state flowed into the join UN-narrowed: `if (p) free(p);`
    * reported a leak at the implicit end on the path where the free never ran - `good_capped` in
    * c/cwe789_uncontrolled_alloc.c, the negative control that kept MS-ALLOC-003 at `low`.
    *
    * The one control structure whose successors carry no condition semantics is a switch: its cases
    * are not "condition false", so it still answers None.
    */
  private def branchOf(succ: CfgNode, cs: ControlStructure): Option[Boolean] =
    val children                   = cs.astChildren.l
    var cursor: Option[StoredNode] = Some(succ)
    var res: Option[Boolean]       = None
    while res.isEmpty && cursor.isDefined do
      val cur = cursor.get
      if cur.id() == cs.id() then cursor = None
      else
        cur._astIn.collectFirst { case p: StoredNode => p } match
          case Some(parent) if parent.id() == cs.id() =>
              // the condition itself (child 0) is on this climb when the successor sits inside
              // the condition's own subtree: it belongs to neither branch, so stop
              res = children.lift(1).filter(_.id() == cur.id()).map(_ => true)
                  .orElse(children.lift(2).filter(_.id() == cur.id()).map(_ => false))
              if res.isEmpty then cursor = None
          case Some(parent) if parent.isInstanceOf[Method] => cursor = None
          case Some(parent)                                => cursor = Some(parent)
          case None                                        => cursor = None
    res.orElse(Option.unless(isSwitch(cs))(false))
  end branchOf

  private def isSwitch(cs: ControlStructure): Boolean =
      cs.parserTypeName.toLowerCase.contains("switch")

  private def joinPoints(
    a: Map[String, Tracked],
    b: Map[String, Tracked]
  ): Map[String, Tracked] =
      (a.keySet ++ b.keySet).iterator
          .map { name =>
              (a.get(name), b.get(name)) match
                case (Some(ta), Some(tb)) =>
                    // the site is the SMALLER id, whatever the fold order: an order-dependent
                    // merge let the worklist oscillate between (Allocated, s1) and
                    // (Allocated, s2) around allocation loops and never terminate
                    name -> Tracked(joinStates(ta.state, tb.state), math.min(ta.site, tb.site))
                case (Some(t), None) => name -> t
                case (None, Some(t)) => name -> t
                case _               => name -> Tracked(StEscaped, 0L)
          }
          .toMap

  private def joinStates(s1: AllocState, s2: AllocState): AllocState =
      if s1 == s2 then s1
      else if s1 == StEscaped || s2 == StEscaped then StEscaped
      else if s1 == StFreed || s2 == StFreed || s1 == StMaybeFreed || s2 == StMaybeFreed then
        StMaybeFreed
      else if isNullState(s1) && isNullState(s2) then StNullReset
      else StAllocated // Allocated and Null: owned on the path that matters

  /** Both null states hold no memory; only the narrowing one is conditional on the path. */
  private def isNullState(s: AllocState): Boolean = s == StNull || s == StNullReset

  private def trackedNameOf(e: AstNode): Option[String] = e match
    case i: Identifier => Some(i.name)
    case _             => None

  private def addressOfOperand(e: AstNode): Option[Expression] = e match
    case c: Call if c.name == "<operator>.addressOf" => c.argumentOption(1)
    case _                                           => None

  private def castOperand(c: Call): Option[Expression] =
      c.argumentOption(2).orElse(c.argumentOption(1))

  private def isOperatorCall(name: String): Boolean = name.startsWith("<operator>")

  private def isAccessThroughPointer(access: Call): Boolean =
      access.name == "<operator>.indexAccess" || access.name == "<operator>.indirectIndexAccess" ||
          access.name == "<operator>.fieldAccess" ||
          access.name == "<operator>.indirectFieldAccess"

  /** An inventoried memory call (memcpy, read, av_reallocp, free, ...) - the umbrella tag is the
    * inventory's own marker.
    */
  private def isNullLiteral(e: AstNode): Boolean = e match
    case l: Literal =>
        // the preprocessor may have expanded NULL to ((void*)0) - normalise parens/spaces away
        Set("0", "0L", "0UL", "NULL", "nullptr", "void*0").contains(l.code.replaceAll(
          "[\\s()]",
          ""
        ))
    case c: Call if c.name == "<operator>.cast" =>
        // ... or kept it as a cast around the 0 literal
        castOperand(c).exists(isNullLiteral)
    case c: Call =>
        // ... or left it as an unexpanded macro invocation node named NULL
        Set("NULL", "nullptr").contains(c.name.trim)
    case i: Identifier => i.name == "NULL" || i.name == "nullptr"
    case _             => false

  private def argAt(args: List[Expression], index: Int): Option[Expression] =
      args.find(_.argumentIndex == index)

  private def stateName(s: AllocState): String = s match
    case StAllocated  => "allocated"
    case StFreed      => "freed"
    case StMaybeFreed => "maybe-freed"
    case StNull       => "null"
    case StNullReset  => "null-reset"
    case StEscaped    => "escaped"
end AllocationStatePass

object AllocationStatePass:

  sealed trait AllocState
  case object StAllocated  extends AllocState
  case object StFreed      extends AllocState
  case object StMaybeFreed extends AllocState

  /** path-conditioned null: the guard proved the pointer null on THIS path - a non-null guard on a
    * later path revives it (the `if (p == NULL) return;` idiom's else side).
    */
  case object StNull extends AllocState

  /** the pointer was ASSIGNED the NULL literal (`free(p); p = NULL;`): null on every path, and no
    * guard can revive what an assignment killed. Part 5 (E2): reviving this state under a `p !=
    * NULL` guard turned the free-and-reset idiom's dead branch into a phantom live allocation and
    * reported a leak at the implicit end.
    */
  case object StNullReset extends AllocState
  case object StEscaped   extends AllocState

  final case class Tracked(state: AllocState, site: Long)

  /** everything the transfer needs about one call, read once per method */
  final case class CallFacts(
    name: String,
    args: List[Expression],
    allocFamilies: Set[String],
    freeFamilies: Set[String],
    reallocFamilies: Set[String],
    isMemoryCall: Boolean,
    isAllocCall: Boolean
  )

  /** the families a call carries per role, from the inventory tags */
  final case class RoleInfo(
    alloc: Set[String],
    free: Set[String],
    realloc: Set[String],
    isMemoryCall: Boolean
  )
  val RoleInfoNone: RoleInfo = RoleInfo(Set.empty, Set.empty, Set.empty, isMemoryCall = false)

  final val TagState = "alloc-state"
  final val TagLeak  = "alloc-leak"

  /** worklist visit cap per CFG node */
  private val VisitCap = 8

  private val MemoryRoles = Set(
    MemoryApiPass.TagAlloc,
    MemoryApiPass.TagFree,
    MemoryApiPass.TagRealloc,
    MemoryApiPass.UmbrellaTag
  )

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end AllocationStatePass
