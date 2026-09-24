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
                    case MemoryApiPass.TagNullableReturn =>
                        cur.copy(nullable = true, isMemoryCall = true)
                    case _ => cur.copy(isMemoryCall = true)
                )
            case _ => ()
        }
      // F1: the dst/src roles are ON THE ARGUMENT, and what the pass needs is the POSITION the
      // call reads through - that is the fact that decides whether handing a possibly-null
      // pointer to this call is a dereference. The call node itself carries no tag of its own
      // for the copy family (only allocators/frees/readers get one), so the same scan marks it
      // a memory call: case 5 governs every inventoried call, and case 6 stays for the ones
      // nobody inventoried
      else if name == MemoryApiPass.TagDst || name == MemoryApiPass.TagSrc then
        t._taggedByIn.iterator.collectFirst { case e: Expression => e }.foreach { arg =>
            arg._astIn.collectFirst { case c: Call => c }.foreach { call =>
              val cur = roles.getOrElse(call.id(), RoleInfoNone)
              val updated = name match
                case MemoryApiPass.TagDst =>
                    cur.copy(
                      isMemoryCall = true,
                      dstPositions = cur.dstPositions + arg.argumentIndex
                    )
                case _ =>
                    cur.copy(
                      isMemoryCall = true,
                      srcPositions = cur.srcPositions + arg.argumentIndex
                    )
              roles.update(call.id(), updated)
            }
        }
      end if
    }

    // E5 + F1: per-method effect summaries, computed intraprocedurally from the same role table
    // before any method is analysed, so every call site can read them. `frees-param:<i>` - the
    // method releases parameter i (unconditionally: a free under a guard frees on SOME path, and
    // a summary that says "always" would turn every conditional-free wrapper into a false double
    // free). `allocates-return` - every value it returns is a fresh allocation. `escapes-param:
    // <i>` - parameter i is stored into storage that outlives the call. `derefs-param:<i>` (F1) -
    // parameter i is read through (a field/index/indirection dereference, or handed to a call at
    // a position that reads through it) on every path, with no null guard on it in the method.
    val effectRows     = mutable.ListBuffer.empty[(StoredNode, String, String)]
    val effectsByName  = mutable.HashMap.empty[String, Set[String]]
    val definedMethods = atom.method.filterNot(_.isExternal).l
    val derefsByMethod = derefsParamsOf(definedMethods, roles)
    definedMethods.foreach { m =>
      val effects = methodEffects(m, roles) ++ derefsByMethod
          .getOrElse(m.name, Set.empty)
          .map(i => s"effect:derefs-param:$i")
      if effects.nonEmpty then
        effects.foreach(e => effectRows += ((m, TagEffect, e)))
        // a name shared by several defined methods must not carry either one's effects: a
        // wrong frees-param summary is a false double free at every call site
        effectsByName.updateWith(m.name) {
            case Some(existing) => Some(if existing == effects then existing else Set.empty)
            case None           => Some(effects)
        }
    }

    definedMethods.foreach(m => analyseMethod(m, roles, effectsByName, record))

    OverlayFacts.emitTags(
      dstGraph,
      tags.toList.flatMap { case (node, ts) => ts.toList.map { case (t, v) => (node, t, v) } } ++
          effectRows
    )
  end run

  /** The `derefs-param:<i>` conclusions, per METHOD NAME (collapsed across same-named methods the
    * way every effect summary is): a method reads through parameter i on every path. Two phases,
    * because a wrapper's conclusion is one hop away from its callee's:
    *
    *   - direct: a dereference of the parameter (the base of a field/index access, the operand of
    *     an indirection) at a statement with no incoming CDG edge, with no null guard on the
    *     parameter anywhere in the method - the guard clause is what keeps `if (!p) return; p->x`
    *     (dominated, not control-dependent) from concluding "always dereferences";
    *   - one hop, iterated to a bounded fixpoint: the parameter is passed, at a statement with no
    *     incoming CDG edge and under no guard, at a position that READS THROUGH the callee - a
    *     `derefs-param` summary of its own, or a `mem-dst`/`mem-src` role position of an
    *     inventoried memory call. This is how `imf_uri_is_url` inherits the conclusion from
    *     `strstr` (imfdec.c:258's shape) without the inventory naming either.
    *
    * Only pointer-typed parameters are considered; an external callee with no inventory entry and
    * no summary is NOT a dereference - evidence, not silence.
    */
  private def derefsParamsOf(
    methods: List[Method],
    roles: mutable.LongMap[RoleInfo]
  ): Map[String, Set[Int]] =
    def roleOf(c: Call): RoleInfo = roles.getOrElse(c.id(), RoleInfoNone)

    // per method: the pointer-parameter indices, the ones a null guard protects, the directly
    // dereferenced ones, and the (param, callee, position) passings no condition controls
    val facts = methods.map { m =>
      val paramIdx = m.parameter.l.map(p => p.name -> p.index).toMap
      val pointerIdx = m.parameter.l
          .filter(p => OverlayFacts.isPointer(p.typeFullName))
          .map(_.index)
          .toSet
      val guardedIdx = OverlayFacts.nullGuardsOf(m).keySet
          .map(_.stripPrefix("v:"))
          .flatMap(paramIdx.get)
          .toSet
      val direct = m.ast.collectAll[Call].l.flatMap { c =>
        val base: Option[String] = c.name match
          case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" |
              "<operator>.indexAccess" | "<operator>.indirectIndexAccess" |
              "<operator>.indirection" =>
              c.argumentOption(1).collect { case i: Identifier => i.name }
          case _ => None
        // the CDG edge lands on the statement the access lives in, not the nested access
        base.filter(_ => GuardPass.statementRootOf(c)._cdgIn.isEmpty).flatMap(paramIdx.get)
      }.toSet
      val passings = m.ast.collectAll[Call].l
          .filterNot(_.name.startsWith("<operator>"))
          .filter(c => GuardPass.statementRootOf(c)._cdgIn.isEmpty)
          .flatMap { c =>
            val r = roleOf(c)
            c.argument.l.collect { case i: Identifier => i }.flatMap { arg =>
                paramIdx.get(arg.name).map(idx =>
                    (
                      idx,
                      c.name,
                      arg.argumentIndex,
                      r.dstPositions.contains(arg.argumentIndex) ||
                          r.srcPositions.contains(arg.argumentIndex)
                    )
                )
            }
          }
      (m, pointerIdx, guardedIdx, direct.toSet, passings)
    }.toIndexedSeq

    val perMethod = mutable.LinkedHashMap.empty[Method, Set[Int]]
    facts.foreach { case (m, pointerIdx, guardedIdx, direct, _) =>
        perMethod(m) = direct.intersect(pointerIdx -- guardedIdx)
    }

    // collapse by name as every effect summary is: same-named methods that disagree carry nothing
    val byName = mutable.HashMap.empty[String, Set[Int]]
    def collapse(): Unit = facts.foreach { case (m, _, _, _, _) =>
        val own = perMethod(m)
        byName.updateWith(m.name) {
            case Some(existing) => Some(if existing == own then existing else Set.empty)
            case None           => Some(own)
        }
    }
    collapse()

    // the hop rounds: a passing at a position the callee reads through - its own summary, or an
    // inventoried memory call's dst/src role - turns into a conclusion for the passing method
    var changed = true
    var round   = 0
    while changed && round < MaxDerefsRounds do
      changed = false
      round += 1
      facts.foreach { case (m, pointerIdx, guardedIdx, _, passings) =>
          val inherited = passings.flatMap { case (idx, callee, pos, readsThrough) =>
              if readsThrough then Set(idx)
              else if byName.getOrElse(callee, Set.empty).contains(pos) then Set(idx)
              else Set.empty
          }
          val next = (perMethod(m) ++ inherited).intersect(pointerIdx -- guardedIdx)
          if next != perMethod(m) then
            perMethod(m) = next
            changed = true
      }
      collapse()
    perMethod.toMap.map { case (m, idxs) => m.name -> idxs }
  end derefsParamsOf

  /** The effect summary of one method body (E5), from the role table - no tag reads per node.
    *
    * Every summary is a claim about what EVERY call does, and a wrong one is a high-confidence
    * finding at every call site, so each is concluded only on evidence that holds on all paths:
    *
    *   - `frees-param:<i>` - a free of parameter i (or of `*p` for a pointer-to-pointer parameter)
    *     that no condition controls (no incoming CDG edge). A free under an `if`, in a loop, or
    *     behind an FFmpeg-style `goto fail` label frees on SOME path only. A wrapper that also
    *     resets the caller's pointer (`free(*pp); *pp = NULL;`) is a freep: it leaves the caller
    *     null, not dangling, so it carries no summary rather than a false double free.
    *   - `allocates-return` - EVERY value return is, through casts or a local's definition, an
    *     allocation (a NULL literal return is allowed: it is the failure path). A function that
    *     returns a cached pointer on one path and a fresh one on another does not own its result.
    *   - `escapes-param:<i>` - parameter i stored into a member or a global.
    */
  private def methodEffects(method: Method, roles: mutable.LongMap[RoleInfo]): Set[String] =
    val paramIndex                = method.parameter.l.map(p => p.name -> p.index).toMap
    val effects                   = mutable.LinkedHashSet.empty[String]
    def roleOf(c: Call): RoleInfo = roles.getOrElse(c.id(), RoleInfoNone)
    def unwrapCasts(e: Expression): Expression = e match
      case c: Call if c.name == "<operator>.cast" => castOperand(c).map(unwrapCasts).getOrElse(c)
      case other                                  => other
    // the parameter a freed/stored expression names: `p`, or `*pp` for a caller's `&x`
    def paramOf(e: Expression): Option[Int] = unwrapCasts(e) match
      case i: Identifier => paramIndex.get(i.name)
      case c: Call if c.name == "<operator>.indirection" =>
          c.argumentOption(1).collect { case i: Identifier => i }.flatMap(i =>
              paramIndex.get(i.name)
          )
      case _ => None
    val calls = method.ast.collectAll[Call].l
    // `*pp = NULL` - the parameters whose pointee the method resets
    val nulledThrough = calls.collect {
        case a if a.name == "<operator>.assignment" && a.argumentOption(2).exists(isNullLiteral) =>
            a.argumentOption(1).collect {
                case d: Call if d.name == "<operator>.indirection" => d
            }.flatMap(_.argumentOption(1)).collect { case i: Identifier => i.name }
    }.flatten.toSet
    calls.foreach {
        case c if roleOf(c).free.nonEmpty && c._cdgIn.isEmpty =>
            argAt(c.argument.l, 1).map(unwrapCasts).foreach { freed =>
              val viaPointee = freed match
                case d: Call if d.name == "<operator>.indirection" =>
                    d.argumentOption(1).collect { case i: Identifier => i.name }
                case _ => None
              if !viaPointee.exists(nulledThrough.contains) then
                paramOf(freed).foreach(idx => effects += s"effect:frees-param:$idx")
            }
        case c if c.name == "<operator>.assignment" =>
            val dstEternal = argAt(c.argument.l, 1).map(unwrapCasts).exists {
                case d: Call =>
                    d.name == "<operator>.fieldAccess" || d.name == "<operator>.indirectFieldAccess"
                case i: Identifier =>
                    // equality, never `.name(data)`: semanticcpg compiles a name argument as a
                    // REGEX, and a macro-mangled local name is a pattern syntax error
                    method.local.l.forall(_.name != i.name) &&
                    method.parameter.l.forall(_.name != i.name)
                case _ => false
            }
            if dstEternal then
              argAt(c.argument.l, 2).map(unwrapCasts).foreach {
                  case i: Identifier =>
                      paramIndex.get(i.name).foreach(idx => effects += s"effect:escapes-param:$idx")
                  case _ => ()
              }
        case _ => ()
    }
    def isAllocation(e: Expression): Boolean = unwrapCasts(e) match
      case c: Call => roleOf(c).alloc.nonEmpty || roleOf(c).realloc.nonEmpty
      case _       => false
    def flowsFromAllocation(e: Expression): Boolean = unwrapCasts(e) match
      case c: Call => isAllocation(c)
      case i: Identifier =>
          val defs = OverlayFacts
              .reachingDefsIn(i)
              .collect { case d: Identifier => d }
              .flatMap(_._astIn.collectFirst {
                  case a: Call if a.name == "<operator>.assignment" => a
              })
              .flatMap(_.argumentOption(2))
          defs.nonEmpty && defs.forall(d => isAllocation(d) || isNullLiteral(d))
      case _ => false
    val valueReturns = method.ast.collectAll[Return].l
        .flatMap(_.astChildren.collectFirst { case e: Expression => e })
        .filterNot(isNullLiteral)
    // F2: the ANCHOR. `flowsFromAllocation` accepts the NULL-literal fallback, which is right
    // for the failure path - but on its own it concludes "allocates" for `return i` where i is
    // an int counter whose only def is the literal 0 (ff_get_line's shape: every caller's
    // counter became a phantom tracked allocation and "leaked" at every exit, 500+ findings
    // per libavformat tree). At least one return must flow from a REAL allocation call.
    val anchored = valueReturns.exists(e =>
        unwrapCasts(e) match
          case c: Call => isAllocation(c)
          case i: Identifier =>
              OverlayFacts
                  .reachingDefsIn(i)
                  .collect { case d: Identifier => d }
                  .flatMap(_._astIn.collectFirst {
                      case a: Call if a.name == "<operator>.assignment" => a
                  })
                  .flatMap(_.argumentOption(2))
                  .exists(isAllocation)
          case _ => false
    )
    // F2: an allocation is a POINTER - a method whose declared return is an int can hand out
    // an error code while allocating into an out-param (ff_get_extradata's shape: returns 0 on
    // success), and concluding allocates-return for it tracked every caller's `ret` error
    // variable as a live allocation that "leaked" at every exit
    val returnsPointer = Option(method.methodReturn.typeFullName)
        .exists(t => OverlayFacts.isPointer(t))
    if returnsPointer && anchored && valueReturns.nonEmpty &&
      valueReturns.forall(flowsFromAllocation)
    then
      effects += "effect:allocates-return"
    effects.toSet
  end methodEffects

  private def analyseMethod(
    method: Method,
    roles: mutable.LongMap[RoleInfo],
    effectsByName: mutable.HashMap[String, Set[String]],
    record: (StoredNode, String, String) => Unit
  ): Unit =
    val leakFacts = mutable.ListBuffer.empty[(Long, StoredNode, String)] // (site, exit, name)
    val nullUseFacts =
        mutable.ListBuffer.empty[(Long, StoredNode, String, String)] // (site, use, name, kind)

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
          r.nullable,
          r.isMemoryCall,
          r.alloc.nonEmpty || r.realloc.nonEmpty,
          r.dstPositions ++ r.srcPositions
        )
      )
    }
    method.ast.collectAll[ControlStructure].foreach { cs =>
        cs.condition.foreach(c => guards.update(c.id(), cs))
    }
    // E4: the stack-address question is asked of the same worklist. A method that never
    // allocates, frees, reallocs or touches an inventoried memory call AND never takes a local's
    // address has no tracked pointer and no facts: skip the worklist entirely
    // `<global>`'s "locals" are the file-scope declarations, and file scope in C is STATIC
    // storage duration - `static const AVOption options[]` outlives every frame. Treating its
    // initialisers as escapes of stack storage was 464 findings per libavformat tree of pure
    // static-initialiser noise (E4's first FFmpeg measurement), so an empty context turns the
    // whole stack-escape question off for it.
    val isFileScope = method.name == "<global>"
    // a `static` local has static storage duration exactly like file scope: its address outliving
    // the frame is the idiom (`static char buf[32]; ... return buf;`), not an escape. The
    // frontend records the storage class as a STATIC modifier on the local
    val frameLocals =
        Option.unless(isFileScope)(method.local.l.filterNot(isStaticLocal)).getOrElse(Nil)
    val arrayLocals = frameLocals.filter(l =>
        OverlayFacts.arrayExtent(l.typeFullName).isDefined || l.typeFullName.trim.endsWith("[]")
    )
    val ctx = MethodContext(
      locals = frameLocals.map(_.name).toSet,
      arrayLocals = arrayLocals.map(_.name).toSet,
      // the locals whose storage IS the frame's: arrays and by-value aggregates. A member or an
      // element of one is frame storage too, so `c.p = &x` on a local struct escapes nothing
      valueLocals =
          (arrayLocals ++ frameLocals.filterNot(l => OverlayFacts.isPointer(l.typeFullName)))
              .map(_.name)
              .toSet,
      params = method.parameter.l.map(_.name).toSet,
      refReturn = !isFileScope && Option(method.methodReturn.typeFullName).exists(t =>
          t.endsWith("&") || t.endsWith("&&")
      )
    )
    val hasAddressOfLocal = callFacts.values.exists(cf =>
        cf.name == "<operator>.addressOf" && argAt(cf.args, 1)
            .exists { case i: Identifier => ctx.locals.contains(i.name); case _ => false }
    )
    val callsASummarisedCallee = callFacts.values.exists(cf => effectsByName.contains(cf.name))
    if !callFacts.values.exists(cf =>
          cf.allocFamilies.nonEmpty || cf.freeFamilies.nonEmpty ||
              cf.reallocFamilies.nonEmpty || cf.nullable
      ) && !ctx.arrayLocals.nonEmpty && !hasAddressOfLocal && !callsASummarisedCallee &&
      !(ctx.refReturn && ctx.locals.nonEmpty)
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
      val out = transfer(node, in, callFacts, effectsByName, leakFacts, nullUseFacts, ctx, record)

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
    // one null-use fact per nullable producer: the FIRST use the pointer reaches without a
    // narrowing guard in between - the site a reader adds the missing check to. A use under a
    // guard that proved the pointer NULL is the strongest form and wins over an earlier
    // unchecked use of the same producer.
    nullUseFacts.groupBy(_._1).foreach { case (site, uses) =>
        val (_, use, name, kind) = uses.minBy { case (_, node, _, k) =>
            (if k == NullDefinite then 0 else 1, lineOf(node))
        }
        record(use, TagNullUse, s"$kind:$name")
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
    effectsByName: mutable.HashMap[String, Set[String]],
    leakFacts: mutable.ListBuffer[(Long, StoredNode, String)],
    nullUseFacts: mutable.ListBuffer[(Long, StoredNode, String, String)],
    ctx: MethodContext,
    record: (StoredNode, String, String) => Unit
  ): Map[String, Tracked] =
      node match
        case c: Call =>
            callFacts.get(c.id()) match
              case Some(cf) =>
                  transferCall(c, cf, callFacts, effectsByName, in, nullUseFacts, ctx, record)
              case None => in
        case r: Return =>
            var out = in
            // a returned tracked pointer transfers ownership: it escapes, it does not leak
            r.astChildren.collect { case e: Expression => e }.foreach { e =>
              // E4: a stack address that leaves the frame - returned directly (&x, a decayed
              // array), through a local that holds one, or a C++ reference return binding the
              // local itself. Read the incoming state: the escape-marking below would erase it.
              val viaTracked = trackedNameOf(e).flatMap(in.get).exists(_.state == StStackAddr)
              trackedNameOf(e).foreach { name =>
                  out.get(name).foreach(t => out = out.updated(name, t.copy(state = StEscaped)))
              }
              val refToLocale = ctx.refReturn && (e match
                case i: Identifier =>
                    ctx.locals.contains(i.name) && !ctx.arrayLocals.contains(i.name)
                case _ => false
              )
              if holdsStackAddress(e, ctx) || viaTracked || refToLocale then
                record(r, TagStackEscape, "escape:return")
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

  /** Record the null-use fact a use of a nullable-produced pointer produces: `unchecked` when no
    * guard has narrowed it since the producing call, `null` when the use sits under a guard that
    * proved the pointer NULL. A checked or escaped pointer is silent - evidence, not silence,
    * either way.
    */
  private def noteNullUse(
    nullUseFacts: mutable.ListBuffer[(Long, StoredNode, String, String)],
    use: StoredNode,
    name: String,
    t: Tracked
  ): Unit =
      if t.nullable && !t.checked && t.state != StEscaped && t.state != StNullReset then
        nullUseFacts += ((
          t.site,
          use,
          name,
          if t.state == StNull then NullDefinite else NullUnchecked
        ))

  private def transferCall(
    c: Call,
    cf: CallFacts,
    callFacts: mutable.LongMap[CallFacts],
    effectsByName: mutable.HashMap[String, Set[String]],
    in: Map[String, Tracked],
    nullUseFacts: mutable.ListBuffer[(Long, StoredNode, String, String)],
    ctx: MethodContext,
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
            // a nullable NON-allocation (a strchr result) is not ownership: freeing it says
            // nothing this pass tracks
            if t.state != StNullable then
              if t.state == StFreed || t.state == StMaybeFreed then
                record(viaAddress.getOrElse(freed), TagState, stateName(t.state))
              // F5 (CWE-590): the freed pointer holds this frame's storage - the fact the
              // non-heap-free rule reads; ownership language never applies to it
              if t.state == StStackAddr then
                record(viaAddress.getOrElse(freed), TagState, stateName(t.state))
              out = out.updated(
                trackedNameOf(viaAddress.getOrElse(freed)).get,
                if viaAddress.isDefined then t.copy(state = StNullReset)
                else t.copy(state = StFreed)
              )
        }
      }
    end if

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
                  // nullable is the CALL's own declared fact (E3): pointer-returning
                  // allocators carry it, the fd-returning family does not. F5: an allocation
                  // of the STACK family (alloca) is frame storage, not owned heap - tracked
                  // as stack-addr, so it neither leaks at exit nor is freeable
                  val cf           = callFacts.get(rhsCall.id())
                  val isStackAlloc = cf.exists(_.allocFamilies.contains("stack"))
                  out = out.updated(
                    lhs,
                    if isStackAlloc then Tracked(StStackAddr, rhsCall.id)
                    else
                      Tracked(
                        StAllocated,
                        rhsCall.id,
                        nullable = cf.exists(_.nullable)
                      )
                  )
              case rhsCall: Call
                  if effectsByName.get(rhsCall.name)
                      .exists(_.contains("effect:allocates-return")) &&
                      !callFacts.get(rhsCall.id()).exists(_.isAllocCall) =>
                  // E5: the callee's own summary says every value it returns is a fresh
                  // allocation - a wrapper the body-shape inference could not conclude.
                  // An allocating wrapper's nullability is not stated by the summary, so the
                  // pointer is tracked as allocation-live only
                  out = out.updated(lhs, Tracked(StAllocated, rhsCall.id))
              case rhsCall: Call if callFacts.get(rhsCall.id()).exists(_.nullable) =>
                  // a non-allocation nullable return (strchr, av_dict_get): not ownership,
                  // only nullness - leak/free rules never fire on it
                  out = out.updated(lhs, Tracked(StNullable, rhsCall.id, nullable = true))
              case rhsCall: Call if rhsCall.name == "<operator>.cast" =>
                  // `p = (char *)malloc(n)` - the allocation hides under the cast; so does the
                  // `(char **)&buf` a global stash takes (E4)
                  castOperand(rhsCall).flatMap { inner =>
                      inner match
                        case ic: Call if callFacts.get(ic.id()).exists(_.isAllocCall) =>
                            val icf  = callFacts.get(ic.id())
                            val stck = icf.exists(_.allocFamilies.contains("stack"))
                            Some(
                              // the stack family through its cast: frame storage (F5)
                              if stck then Tracked(StStackAddr, ic.id)
                              else
                                Tracked(
                                  StAllocated,
                                  ic.id,
                                  nullable = icf.exists(_.nullable)
                                )
                            )
                        case ic: Call if callFacts.get(ic.id()).exists(_.nullable) =>
                            Some(Tracked(StNullable, ic.id, nullable = true))
                        case ic if holdsStackAddress(ic, ctx) =>
                            Some(Tracked(StStackAddr, ic.id))
                        case other if trackedNameOf(other).isDefined =>
                            trackedNameOf(other).flatMap(n => out.get(n))
                        case _ => None
                  }.foreach(t => out = out.updated(lhs, t))
              case lit: Literal if isNullLiteral(lit) =>
                  out = out.updated(lhs, Tracked(StNullReset, 0L))
              case other if isNullLiteral(other) =>
                  // NULL macro-expanded into an identifier
                  out = out.updated(lhs, Tracked(StNullReset, 0L))
              // E4: the rhs IS a stack address - a local's address taken, or an array local
              // decaying to a pointer - so the variable now carries frame storage
              case other if holdsStackAddress(other, ctx) =>
                  out = out.updated(lhs, Tracked(StStackAddr, other.id))
              case other =>
                  trackedNameOf(other).flatMap(useState.get).foreach { t =>
                      out = out.updated(lhs, t)
                  }
            end match
            // a stack address stored into a GLOBAL variable outlives the frame (E4): a plain
            // local or parameter destination rebinds only this frame's copy and escapes nothing
            argAt(cf.args, 1).foreach { dst =>
                dst match
                  case i: Identifier
                      if !ctx.locals.contains(i.name) && !ctx.params.contains(i.name) =>
                      if rhsHoldsStackAddress(rhs, useState, ctx) then
                        record(c, TagStackEscape, "escape:global")
                  case _ => ()
            }
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
            // ... and a stack address stored there escapes the frame with it (E4) - unless
            // "there" is itself frame storage: a member or element of a by-value local
            if !argAt(cf.args, 1).exists(isFrameStorage(_, ctx)) &&
              rhsHoldsStackAddress(rhs, useState, ctx)
            then
              record(c, TagStackEscape, "escape:store")
        case _ => ()
    end if

    if isOperatorCall(cf.name) then
      // 4. index and field accesses through a tracked base are uses
      cf.args.foreach { arg =>
          arg match
            case access: Call if isAccessThroughPointer(access) =>
                access.argumentOption(1).foreach { base =>
                    trackedNameOf(base).foreach { name =>
                        useState.get(name).foreach { t =>
                          if t.state == StFreed || t.state == StMaybeFreed then
                            record(base, TagState, stateName(t.state))
                          noteNullUse(nullUseFacts, base, name, t)
                        }
                    }
                }
            case _ => ()
      }
    else if cf.isMemoryCall then
      // 5. an inventoried memory call USES its pointer arguments; ownership unchanged. F1: only
      //    the positions the inventory says the call READS THROUGH (dst/src) are uses for the
      //    null question - the freed argument of a free-family call never is (free(NULL) is a
      //    no-op, which part 5 already had), and a length is an integer, not a pointer
      cf.args.filter(a => cf.readsThrough.contains(a.argumentIndex)).foreach { arg =>
        val use             = arg
        val nullSafeUseSite = cf.freeFamilies.nonEmpty && arg.argumentIndex == 1
        trackedNameOf(use).foreach { name =>
            useState.get(name).foreach { t =>
              if t.state == StFreed || t.state == StMaybeFreed then
                record(use, TagState, stateName(t.state))
              if !nullSafeUseSite then noteNullUse(nullUseFacts, use, name, t)
            }
        }
      }
    else
      // 6. any other call escapes its tracked pointer arguments: an addressOf argument escapes
      //    the ADDRESS - the callee may free or store through it. An argument the callee's
      //    summary FREES is recorded by the summary below, as the free site itself - not twice,
      //    once as a generic use. F1: a plain argument is a null-USE only when the callee is
      //    evidence-backed as reading through that position - a `derefs-param` summary of its
      //    own. An external callee with no inventory entry is not a dereference, and neither is
      //    `&p`: handing the slot is not reading through the pointer.
      val summaryFreedArgs: Set[Int] =
          effectsByName
              .getOrElse(cf.name, Set.empty)
              .flatMap {
                  case e if e.startsWith("effect:frees-param:") =>
                      Set(e.stripPrefix("effect:frees-param:").toInt)
                  case _ => Set.empty
              }
      val summaryDerefsArgs: Set[Int] =
          effectsByName
              .getOrElse(cf.name, Set.empty)
              .flatMap {
                  case e if e.startsWith("effect:derefs-param:") =>
                      Set(e.stripPrefix("effect:derefs-param:").toInt)
                  case _ => Set.empty
              }
      cf.args.foreach { arg =>
        val viaAddress       = addressOfOperand(arg)
        val operand          = viaAddress.getOrElse(arg)
        val summaryFreesThis = summaryFreedArgs.contains(arg.argumentIndex)
        trackedNameOf(operand).foreach { name =>
            useState.get(name).foreach { t =>
              if (t.state == StFreed || t.state == StMaybeFreed) && !summaryFreesThis then
                record(operand, TagState, stateName(t.state))
              if viaAddress.isEmpty && summaryDerefsArgs.contains(arg.argumentIndex) then
                noteNullUse(nullUseFacts, operand, name, t)
              out = out.updated(name, t.copy(state = StEscaped))
            }
        }
      }
      // ... and the callee's effect summary (E5), AFTER the generic escape: a call to a method
      // that unconditionally frees one of its parameters frees the matching argument HERE - an
      // interprocedural free as a tag lookup, the existing double-free fact carrying the report.
      // It runs last because the summary is MORE SPECIFIC than "escaped": the callee did not
      // merely take the pointer, it released it.
      effectsByName.get(cf.name).foreach { effects =>
          effects.foreach {
              case e if e.startsWith("effect:frees-param:") =>
                  val idx = e.stripPrefix("effect:frees-param:").toInt
                  argAt(cf.args, idx).foreach { arg =>
                    val operand = addressOfOperand(arg).getOrElse(arg)
                    trackedNameOf(operand).foreach { name =>
                        useState.get(name).foreach { t =>
                          if t.state == StFreed || t.state == StMaybeFreed then
                            // THIS call is the second free: the value names it as the
                            // free site, which is how the rule tells a double free from a
                            // use-after-free
                            record(operand, TagState, ValueSummaryFreed)
                          if t.state != StNullable then
                            out = out.updated(name, t.copy(state = StFreed))
                        }
                    }
                  }
              case _ => ()
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
      // F2: `if (!(p = malloc(n)))` - the assignment hands the condition the assigned
      // variable's truthiness. Where the negation holds the value is null; where it does not,
      // the guard itself is the check. The FFmpeg error path is written exactly this way, and
      // the leak rule used to report the taken branch: the allocation had just FAILED.
      case not: Call
          if not.name == "<operator>.logicalNot" &&
              not.argumentOption(1).exists(a =>
                  a.isInstanceOf[Call] && a.asInstanceOf[Call].name == "<operator>.assignment"
              ) =>
          // the negation holds exactly where the assigned value is null: nullHere IS branchOf
          assignmentTargetOf(not.argumentOption(1).get.asInstanceOf[Call]).toList.flatMap { name =>
              List((name, branchOf(succ, cs)))
          }
      // F2: `if ((p = malloc(n)))` - the same idiom without the negation: holds where the
      // value is non-null, null on the else side
      case asg: Call if asg.name == "<operator>.assignment" =>
          assignmentTargetOf(asg).toList.flatMap { name =>
              List((name, branchOf(succ, cs).map(h => !h)))
          }
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
                    // the non-null side of a guard on a nullable-produced pointer is the
                    // check itself: downstream uses of it are not unchecked (E3)
                    acc.updated(
                      name,
                      t.copy(state = newState, checked = t.checked || !nullHere)
                    )
                case None =>
                    // an untracked pointer that is provably null becomes tracked-as-null;
                    // nothing downstream reports on it either way
                    if nullHere then acc.updated(name, Tracked(StNull, 0L)) else acc
          case None => acc
    }
  end branchNarrowing

  /** Which way the condition of `cs` went on the edge to `succ`: Some(true) where it holds,
    * Some(false) where it does not, None when the structure's successors carry no condition
    * semantics (a switch) or the successor is inside the condition itself.
    *
    * The successor is placed by AST nesting, at the DIRECT CHILD of `cs` that contains it. An if's
    * else child (child 2) is the false side. Any other non-condition child is where the condition
    * HOLDS: an if's then child, and a loop's body wherever the frontend orders it - child 1 of a
    * while, the last child of a for (after init/condition/update, whose update is the true edge of
    * a body-less for), child 0 of a do-while, whose true edge loops back to the body. An UNBRACED
    * body hangs inside its branch child whatever its statement kind, so it needs no special case.
    *
    * A successor OUTSIDE the structure is reached on the false edge - the join point, the next
    * statement, the implicit end. Part 4 answered None there, so `if (p) free(p);` flowed into the
    * join un-narrowed and reported a leak at the implicit end on the path where the free never ran
    * (`good_capped` in c/cwe789_uncontrolled_alloc.c). The first part 5 version answered by child
    * index alone - 1 then, 2 else, everything else false - which put a for loop's body (child 3)
    * and a do-while's (child 0) on the FALSE edge: `for (e = strchr(..); e != NULL; ..) e[1]`
    * marked `e` definitely NULL inside its own loop.
    */
  private def branchOf(succ: CfgNode, cs: ControlStructure): Option[Boolean] =
    if isSwitch(cs) then return None
    val conditionId                  = cs.condition.headOption.map(_.id())
    val isIf                         = cs.controlStructureType == "IF"
    var cursor: Option[StoredNode]   = Some(succ)
    var res: Option[Option[Boolean]] = None
    while res.isEmpty && cursor.isDefined do
      val cur = cursor.get
      cur._astIn.collectFirst { case p: StoredNode => p } match
        case Some(parent) if parent.id() == cs.id() =>
            res = Some(
              if conditionId.contains(cur.id()) then None
              else if isIf && cs.astChildren.l.lift(2).exists(_.id() == cur.id()) then Some(false)
              else Some(true)
            )
        case Some(_: Method) => cursor = None
        case Some(parent)    => cursor = Some(parent)
        case None            => cursor = None
    res.getOrElse(Some(false))
  end branchOf

  /** The variable an assignment-in-condition names: `if (!(p = malloc(n)))` narrows `p`, not the
    * assignment expression.
    */
  private def assignmentTargetOf(assignment: Call): Option[String] =
      argAt(assignment.argument.l, 1).collect { case i: Identifier => i.name }

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
                    name -> Tracked(
                      joinStates(ta.state, tb.state),
                      math.min(ta.site, tb.site),
                      nullable = ta.nullable || tb.nullable,
                      checked = ta.checked && tb.checked
                    )
                case (Some(t), None) => name -> t
                case (None, Some(t)) => name -> t
                case _               => name -> Tracked(StEscaped, 0L)
          }
          .toMap

  private def joinStates(s1: AllocState, s2: AllocState): AllocState =
      if s1 == s2 then s1
      else if s1 == StEscaped || s2 == StEscaped then StEscaped
      else if s1 == StStackAddr || s2 == StStackAddr then StStackAddr
      else if s1 == StNullable || s2 == StNullable then StNullable
      else if s1 == StFreed || s2 == StFreed || s1 == StMaybeFreed || s2 == StMaybeFreed then
        StMaybeFreed
      else if isNullState(s1) && isNullState(s2) then StNullReset
      else StAllocated // Allocated and Null: owned on the path that matters

  /** Both null states hold no memory; only the narrowing one is conditional on the path. */
  private def isNullState(s: AllocState): Boolean = s == StNull || s == StNullReset

  private def trackedNameOf(e: AstNode): Option[String] = e match
    case i: Identifier => Some(i.name)
    case _             => None

  /** Does this expression DENOTE a stack address (E4): `&local` (through casts), or an array local
    * decaying to its own first element? A local's address is the frame's; an array local used as a
    * pointer is the same storage.
    */
  private def holdsStackAddress(e: Expression, ctx: MethodContext): Boolean = e match
    case c: Call =>
        c.name match
          case "<operator>.addressOf" =>
              c.argumentOption(1).exists {
                  case i: Identifier => ctx.locals.contains(i.name)
                  case _             => false
              }
          case "<operator>.cast" =>
              c.argument.l.collect { case x: Expression => x }.exists(holdsStackAddress(_, ctx))
          case _ => false
    case i: Identifier => ctx.arrayLocals.contains(i.name)
    case _             => false

  /** Is this destination part of the frame (E4): a member or element, through `.` and `[]` only, of
    * an array or by-value aggregate local? `->` leaves the frame's storage for wherever the pointer
    * points, so it is never frame storage.
    */
  @scala.annotation.tailrec
  private def isFrameStorage(dst: Expression, ctx: MethodContext): Boolean = dst match
    case c: Call
        if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indexAccess" ||
            c.name == "<operator>.indirectIndexAccess" =>
        c.argumentOption(1) match
          case Some(i: Identifier) => ctx.valueLocals.contains(i.name) &&
              (c.name == "<operator>.fieldAccess" || ctx.arrayLocals.contains(i.name))
          case Some(inner: Expression) => isFrameStorage(inner, ctx)
          case _                       => false
    case _ => false

  private def isStaticLocal(l: Local): Boolean =
      l.tag.name(io.appthreat.x2cpg.Defines.StorageClassTag)
          .value(io.appthreat.x2cpg.Defines.StorageClassStatic)
          .nonEmpty

  /** Does this rhs put a stack address into the destination it feeds (E4): directly, or through a
    * local that currently holds one?
    */
  private def rhsHoldsStackAddress(
    rhs: Expression,
    state: Map[String, Tracked],
    ctx: MethodContext
  ): Boolean =
      holdsStackAddress(rhs, ctx) ||
          trackedNameOf(rhs).flatMap(state.get).exists(_.state == StStackAddr) || {
              rhs match
                case rc: Call if rc.name == "<operator>.cast" =>
                    castOperand(rc).exists(inner =>
                        trackedNameOf(inner).flatMap(state.get).exists(_.state == StStackAddr)
                    )
                case _ => false
          }

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
  private def isNullLiteral(e: AstNode): Boolean = AllocationStatePass.isNullLiteral(e, castOperand)

  private def argAt(args: List[Expression], index: Int): Option[Expression] =
      args.find(_.argumentIndex == index)

  private def stateName(s: AllocState): String = s match
    case StAllocated  => "allocated"
    case StFreed      => "freed"
    case StMaybeFreed => "maybe-freed"
    case StNull       => "null"
    case StNullReset  => "null-reset"
    case StNullable   => "nullable"
    case StStackAddr  => "stack-addr"
    case StEscaped    => "escaped"
end AllocationStatePass

object AllocationStatePass:

  /** The derefs-param positions readable from the graph after the pass ran: method `mem-effect`
    * tags, collapsed across same-named methods exactly as the pass itself collapses them. The
    * null-deref rule reads this so its call-argument arm and the state pass's agree on what a
    * dereference is.
    */
  def derefsParamsByName(cpg: Cpg): Map[String, Set[Int]] =
      cpg.method
          .filterNot(_.isExternal)
          .l
          .flatMap { m =>
              m.tag.name(TagEffect).value.l.collect {
                  case v if v.startsWith("effect:derefs-param:") =>
                      v.stripPrefix("effect:derefs-param:").toInt
              } match
                case idxs if idxs.nonEmpty => List(m.name -> idxs.toSet)
                case _                     => Nil
          }
          .groupMapReduce(_._1)(_._2)((a, b) => if a == b then a else Set.empty)

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

  /** the value of a NON-allocation nullable return (strchr, av_dict_get): may be null, but it is
    * not ownership - the leak/free rules never fire on it. Part 5 (E3).
    */
  case object StNullable extends AllocState

  /** the variable holds the ADDRESS of a stack local of this frame (E4): `q = &x`, or an array
    * local that decayed. Leaving the frame with it - returned, stored into a member or a global -
    * is the CWE-562 escape the state pass and the heap escape share one worklist to ask about.
    */
  case object StStackAddr extends AllocState
  case object StEscaped   extends AllocState

  /** `nullable` - the tracked value came from a call whose result may be NULL (every allocation, or
    * the inventory's `nullable-return` role); `checked` - a guard has since narrowed it non-null on
    * every path that reaches here.
    */
  final case class Tracked(
    state: AllocState,
    site: Long,
    nullable: Boolean = false,
    checked: Boolean = false
  )

  /** everything the transfer needs about one call, read once per method */
  final case class CallFacts(
    name: String,
    args: List[Expression],
    allocFamilies: Set[String],
    freeFamilies: Set[String],
    reallocFamilies: Set[String],
    nullable: Boolean,
    isMemoryCall: Boolean,
    isAllocCall: Boolean,
    readsThrough: Set[Int]
  )

  /** the families a call carries per role, from the inventory tags */
  final case class RoleInfo(
    alloc: Set[String],
    free: Set[String],
    realloc: Set[String],
    nullable: Boolean,
    isMemoryCall: Boolean,
    dstPositions: Set[Int] = Set.empty,
    srcPositions: Set[Int] = Set.empty
  )
  val RoleInfoNone: RoleInfo =
      RoleInfo(Set.empty, Set.empty, Set.empty, nullable = false, isMemoryCall = false)

  final val TagState       = "alloc-state"
  final val TagLeak        = "alloc-leak"
  final val TagNullUse     = "null-use"
  final val TagStackEscape = "stack-escape"

  /** E5: a per-method effect summary, ON the method node - `effect:frees-param:<i>`,
    * `effect:allocates-return`, `effect:escapes-param:<i>` - so an interprocedural effect is a tag
    * lookup at the call site.
    */
  final val TagEffect = "mem-effect"

  /** the method's own locals, the array-typed ones, its parameters - the frame's storage and the
    * names that rebind locally - and whether it returns by reference (a C++ `T&` return binds the
    * returned local itself, no addressOf anywhere) (E4)
    */
  final case class MethodContext(
    locals: Set[String],
    arrayLocals: Set[String],
    valueLocals: Set[String],
    params: Set[String],
    refReturn: Boolean
  )

  /** the `alloc-state` value a summary-free records (E5): the ENCLOSING call is the free - a
    * wrapper whose body-shape the inventory never saw, named by its effect summary
    */
  val ValueSummaryFreed = "freed-by-summary"

  /** the two `null-use` kinds: an unchecked use of a may-be-null value, and a use under a guard
    * that proved the pointer null
    */
  val NullUnchecked = "unchecked"
  val NullDefinite  = "null"

  /** A NULL as the frontend may have left it: a literal (possibly macro-expanded with parens and
    * casts), an unexpanded macro invocation, or an identifier. Shared with the null-deref rule.
    */
  private[taggers] def isNullLiteral(
    e: AstNode,
    castOperand: Call => Option[Expression]
  ): Boolean = e match
    case l: Literal =>
        // the preprocessor may have expanded NULL to ((void*)0) - normalise parens/spaces away
        Set("0", "0L", "0UL", "NULL", "nullptr", "void*0").contains(l.code.replaceAll(
          "[\\s()]",
          ""
        ))
    case c: Call if c.name == "<operator>.cast" =>
        // ... or kept it as a cast around the 0 literal
        castOperand(c).exists(isNullLiteral(_, castOperand))
    case c: Call =>
        // ... or left it as an unexpanded macro invocation node named NULL
        Set("NULL", "nullptr").contains(c.name.trim)
    case i: Identifier => i.name == "NULL" || i.name == "nullptr"
    case _             => false

  /** worklist visit cap per CFG node */
  private val VisitCap = 8

  /** hop rounds for the `derefs-param` fixpoint: each round lets a wrapper inherit the conclusion
    * of a wrapper concluded in the round before. Three is already deeper than any wrapper layer
    * seen in practice, matching the wrapper-inference cap in [[MemoryApiPass]].
    */
  private val MaxDerefsRounds = 3

  private val MemoryRoles = Set(
    MemoryApiPass.TagAlloc,
    MemoryApiPass.TagFree,
    MemoryApiPass.TagRealloc,
    MemoryApiPass.TagNullableReturn,
    MemoryApiPass.UmbrellaTag
  )

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end AllocationStatePass
