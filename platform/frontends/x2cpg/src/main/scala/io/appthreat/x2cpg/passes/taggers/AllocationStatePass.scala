package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Per allocation, the state at each program point - `allocated`, `freed`, `maybe-freed` (freed on
  * SOME path reaching the point), `null` (reset to NULL, the `free(p); p = NULL` idiom) and
  * `escaped` - stored into a struct, returned, or passed to a non-inventoried call. `escaped` is
  * this pass's `unknown`: once a pointer escapes, an intraprocedural pass knows nothing more and
  * must say so rather than assuming it stays live.
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
  * yields a fresh allocation (getting that wrong would turn every realloc into a double-free
  * report).
  *
  * Facts (tags, each alongside the `memory-safety` umbrella) for the rules to read:
  *   - `alloc-state` valued with the state, on the freed argument of a free call and on a tracked
  *     pointer's use - a memory call's dst/src argument, an argument of any other call, an index or
  *     field-access base - whenever the state there is freed or maybe-freed;
  *   - `alloc-leak` valued `leak:<name>`, on the exit node where an allocation is live, un-freed
  *     and un-escaped: the returned expression, the RETURN node for a bare `return;`, or the
  *     METHOD_RETURN for the implicit end. Once per allocation, at the earliest such exit - every
  *     early return looks like a leak, and only the first one carries the fact the later ones
  *     restate. A block a REGION owns never carries one: the region's destroy is its release,
  *     wherever the region's handle is held.
  *   - `alloc-reset-use` valued `1`, beside the `alloc-state` fact of a use whose block's freedom
  *     came from a region reset (or from a destroy that may not have reached it): the mark that
  *     reports the use-after-free below the rule's own confidence.
  *   - `alloc-release-use` valued `medium` or `low`, beside the `alloc-state` fact of a use whose
  *     block's freedom came from a reference release - the count reached zero (`medium`), or the
  *     release dropped a borrowed reference (`low`). A second release of an already spent reference
  *     carries `medium` on its own `alloc-state` fact the same way.
  *
  * The reference roles travel as [[MemoryApiPass]]'s `mem-release` / `mem-acquire` tags: a release
  * drops the object's owned-reference count by one, an acquire raises it. A new allocation owns one
  * reference, so only a release that reaches zero frees; a release of a reference whose ownership
  * this method does not know - a parameter, a field read, an unsummarised call's result
  *   - leaves the object maybe freed, marked borrowed.
  */
class AllocationStatePass(atom: Cpg) extends CpgPass(atom):

  import AllocationStatePass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return

    val tags = mutable.LinkedHashMap.empty[StoredNode, mutable.LinkedHashSet[(String, String)]]
    def record(node: StoredNode, tag: String, value: String): Unit =
        tags.getOrElseUpdate(node, mutable.LinkedHashSet.empty) += ((tag, value))

    // one scan of the tag nodes builds the role table for every call in the graph; reading
    // tags per call inside the per-method precompute costs millions of traversals on a large tree
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
                    case MemoryApiPass.TagRegion =>
                        cur.copy(region = regionInfoOf(t.value).orElse(cur.region))
                    case MemoryApiPass.TagRelease =>
                        rolePosition(t.value).map(i =>
                            cur.copy(release = cur.release + i, isMemoryCall = true)
                        ).getOrElse(cur.copy(isMemoryCall = true))
                    case MemoryApiPass.TagAcquire =>
                        rolePosition(t.value).map(i =>
                            cur.copy(acquire = cur.acquire + i, isMemoryCall = true)
                        ).getOrElse(cur.copy(isMemoryCall = true))
                    case MemoryApiPass.TagRetains =>
                        rolePosition(t.value).map(i =>
                            cur.copy(retains = cur.retains + i, isMemoryCall = true)
                        ).getOrElse(cur.copy(isMemoryCall = true))
                    case MemoryApiPass.TagCleanup =>
                        cur.copy(cleanup = true, isMemoryCall = true)
                    case MemoryApiPass.TagSteal =>
                        rolePosition(t.value).map(i =>
                            cur.copy(steal = cur.steal + i, isMemoryCall = true)
                        ).getOrElse(cur.copy(isMemoryCall = true))
                    case MemoryApiPass.TagNullableReturn =>
                        cur.copy(nullable = true, isMemoryCall = true)
                    case _ => cur.copy(isMemoryCall = true)
                )
            case _ => ()
        }
      // The dst/src roles are ON THE ARGUMENT, and what the pass needs is the POSITION the
      // call reads through - that is the fact that decides whether handing a possibly-null
      // pointer to this call is a dereference. The call node itself carries no tag of its own
      // for the copy family (only allocators/frees/readers get one), so the same scan marks it
      // a memory call: case 5 governs every inventoried call, and case 6 stays for the ones
      // nobody inventoried
      else if name == MemoryApiPass.TagDst || name == MemoryApiPass.TagSrc ||
        name == MemoryApiPass.TagReadsArg
      then
        t._taggedByIn.iterator.collectFirst { case e: Expression => e }.foreach { arg =>
            arg._astIn.collectFirst { case c: Call => c }.foreach { call =>
              val cur = roles.getOrElse(call.id(), RoleInfoNone)
              val updated = name match
                case MemoryApiPass.TagDst =>
                    cur.copy(
                      isMemoryCall = true,
                      dstPositions = cur.dstPositions + arg.argumentIndex
                    )
                case MemoryApiPass.TagSrc =>
                    cur.copy(
                      isMemoryCall = true,
                      srcPositions = cur.srcPositions + arg.argumentIndex
                    )
                case _ =>
                    cur.copy(
                      isMemoryCall = true,
                      readPositions = cur.readPositions + arg.argumentIndex
                    )
              roles.update(call.id(), updated)
            }
        }
      end if
    }

    // Per-method effect summaries, computed intraprocedurally from the same role table
    // before any method is analysed, so every call site can read them. `frees-param:<i>` - the
    // method releases parameter i (unconditionally: a free under a guard frees on SOME path, and
    // a summary that says "always" would turn every conditional-free wrapper into a false double
    // free - a guard of NULL tests of the freed parameter itself is the one exception, because
    // it releases the block exactly when there is one). `allocates-return` - every value it
    // returns is a fresh allocation. `escapes-param:
    // <i>` - parameter i is stored into storage that outlives the call, or handed to a callee
    // nothing concludes about. `derefs-param:<i>` - parameter i is read through (a field/index/
    // indirection dereference, or handed to a call at a position that reads through it) on every
    // path, with no null guard on it in the method.
    val effectRows      = mutable.ListBuffer.empty[(StoredNode, String, String)]
    val effectsByName   = mutable.HashMap.empty[String, Set[String]]
    val effectsByMethod = mutable.LongMap.empty[Set[String]]
    val definedMethods  = atom.method.filterNot(_.isExternal).l
    val derefsByMethod  = derefsParamsOf(definedMethods, roles)
    val readsByMethod   = readsParamsByName(definedMethods)
    definedMethods.foreach { m =>
        effectsByMethod.update(
          m.id(),
          methodEffects(m, roles) ++ derefsByMethod
              .getOrElse(m.name, Set.empty)
              .map(i => s"effect:derefs-param:$i")
        )
    }
    // the conclusions that read another method's settled effects, after every body's own are
    // in the tables: what a scope-cleanup hand-off does to the value a return carries out
    definedMethods.foreach { m =>
      val own = effectsByMethod.getOrElse(m.id(), Set.empty)
      val adjusted = cleanupHandoffEffects(m, roles, effectsByName, effectsByMethod) match
        case extra if extra.nonEmpty =>
            // the released variable's value must not be described as a fresh allocation:
            // the caller receives the dangling block, not an owned one
            own ++ extra - "effect:allocates-return" - "effect:allocates-null-return"
        case _ => own
      effectsByMethod.update(m.id(), adjusted)
    }
    definedMethods.foreach { m =>
      readsByMethod.getOrElse(m.name, Set.empty).foreach { i =>
          effectRows += ((m, TagReadsEffect, s"reads-param:$i"))
      }
      val effects = effectsByMethod.getOrElse(m.id(), Set.empty)
      if effects.nonEmpty then
        effects.foreach(e => effectRows += ((m, TagEffect, e)))
        // a name shared by several defined methods must not carry either one's effects: a
        // wrong frees-param summary is a false double free at every call site. Juliet's C++
        // variants name every file's sink `goodG2BSink`, and the call site's own CALL edge
        // names the one body that matters - the method-level map above is what a resolved
        // call reads, this name-level table only what no edge resolves
        effectsByName.updateWith(m.name) {
            case Some(existing) => Some(if existing == effects then existing else Set.empty)
            case None           => Some(effects)
        }
    }
    // the escape conclusions iterate to the same bounded fixpoint the derefs conclusions do:
    // a parameter handed unconditionally to a callee position that itself escapes (or frees)
    // propagates the conclusion one hop up, so a wrapper of a storing helper is not mistaken
    // for a borrower
    var escapeRound    = 0
    var escapesChanged = true
    val escapesPassings = definedMethods.map { m =>
      val paramIdx = m.parameter.l.map(p => p.name -> p.index).toMap
      val passings = m.ast.collectAll[Call].l
          .filterNot(_.name.startsWith("<operator>"))
          .filter(c => GuardPass.statementRootOf(c)._cdgIn.isEmpty)
          .flatMap { c =>
            val r = roles.getOrElse(c.id(), RoleInfoNone)
            c.argument.l.collect { case i: Identifier => i }.flatMap { arg =>
                paramIdx.get(arg.name).map(idx => (idx, c, arg.argumentIndex, r))
            }
          }
      (m, passings)
    }.toIndexedSeq
    def storesOrFreesAt(effects: Set[String], pos: Int): Boolean =
        effects.exists(e =>
            e.startsWith(s"effect:escapes-param:$pos") ||
                e.startsWith(s"effect:frees-param:$pos") ||
                e.startsWith(s"effect:freep-param:$pos")
        )
    while escapesChanged && escapeRound < MaxDerefsRounds do
      escapesChanged = false
      escapeRound += 1
      escapesPassings.foreach { case (m, passings) =>
          val own = effectsByMethod.getOrElse(m.id(), Set.empty)
          val inherited = passings.collect { case (idx, c, pos, r) =>
              // an inventoried memory call writes bytes through its roles and retains nothing;
              // anything else hands the VALUE on, and what it does with it is its effects
              if !r.isMemoryCall then
                val resolved = c._callOut.collectAll[Method].l.distinct match
                  case List(only) => effectsByMethod.get(only.id())
                  case _          => None
                val escapesThere = resolved.exists(storesOrFreesAt(_, pos)) ||
                    effectsByName.get(c.name).exists(storesOrFreesAt(_, pos))
                // no conclusion at all about the callee: unknown means retained
                val unknown = resolved.isEmpty && !effectsByName.contains(c.name)
                if escapesThere || unknown then s"effect:escapes-param:$idx" else ""
              else ""
          }.filter(_.nonEmpty).toSet
          if !inherited.subsetOf(own) then
            effectsByMethod.update(m.id(), own ++ inherited)
            if effectsByMethod.getOrElse(m.id(), Set.empty).nonEmpty then
              effectsByMethod(m.id()).foreach(e => effectRows += ((m, TagEffect, e)))
            escapesChanged = true
      }
    end while
    // declared `nonnull` parameters of callees with no body in the graph: the call site's
    // null-use evidence (case 6 reads derefs-param summaries)
    MemorySemanticsPass.nonnullParamsByName(atom).foreach { case (name, idxs) =>
        if !definedMethods.exists(m => m.name == name && m.block.astChildren.nonEmpty) then
          effectsByName.updateWith(name) { existing =>
              Some(existing.getOrElse(Set.empty) ++ idxs.map(i => s"effect:derefs-param:$i"))
          }
    }

    // a method whose body contains a throw may unwind at any of its call sites: the unwind path
    // is an exit the frame's live allocations never get freed on (the CWE-401 exception-path
    // leak: a `mayThrow(n)` call between new and delete)
    definedMethods
        .filter(m => m.ast.collectAll[Call].exists(_.name == "<operator>.throw"))
        .foreach { m =>
            effectsByName.updateWith(m.name) {
                case Some(effects) => Some(effects + EffectMayThrow)
                case None          => Some(Set(EffectMayThrow))
            }
        }

    definedMethods.foreach(m => analyseMethod(m, roles, effectsByName, effectsByMethod, record))
    failurePathFieldDoubleFrees(definedMethods, roles, record)
    owningClassFacts(record)

    OverlayFacts.emitTags(
      dstGraph,
      tags.toList.flatMap { case (node, ts) => ts.toList.map { case (t, v) => (node, t, v) } } ++
          effectRows
    )
  end run

  /** CVE-2026-64832's shape, neither function wrong on its own: a callee frees a field of the
    * struct it was handed and returns failure without resetting the field, and a caller, on that
    * failure, releases the same field again - directly or through a callee that frees it.
    *
    * The callee's half: `free(p->f); return <failure>;` (the free is the statement before a
    * negative or non-zero literal return, or an `AVERROR(...)`), with no `p->f = NULL` anywhere in
    * the method. The caller's half: the call sits in an `if` condition (or its result in a variable
    * the condition tests), and the release is inside that `if`'s THEN branch - the failure branch
    * of `if (f(&s) < 0)`. The report is the callee's free: the one the fix removes.
    */
  private def failurePathFieldDoubleFrees(
    methods: List[Method],
    roles: mutable.LongMap[RoleInfo],
    record: (StoredNode, String, String) => Unit
  ): Unit =
    def isFree(c: Call): Boolean = roles.getOrElse(c.id(), RoleInfoNone).free.nonEmpty
    // (param index, field) a free in `m` releases, with the freed argument
    def paramFieldFrees(m: Method): List[(Int, String, Expression)] =
      val params = m.parameter.l.map(p => p.name -> p.index).toMap
      m.ast.collectAll[Call].filter(isFree).l.flatMap { c =>
          c.argumentOption(1).collect { case e: Expression => e }.flatMap { arg =>
              trackedNameOf(addressOfOperand(arg).getOrElse(arg)).flatMap { n =>
                val (base, field) = n.split("->|\\.", 2) match
                  case Array(b, f) => (b, f)
                  case _           => ("", "")
                params.get(base).filter(_ => field.nonEmpty).map(i => (i, field, arg))
              }
          }
      }
    def isFailureReturn(r: Return): Boolean =
        r.astChildren.collectFirst { case e: Expression => e }.exists {
            case l: Literal => l.code.trim.startsWith("-") || l.code.trim.toIntOption.exists(_ != 0)
            case c: Call =>
                c.name == "<operator>.minus" || c.code.startsWith("AVERROR") ||
                c.code.trim.startsWith("-")
            case _ => false
        }
    def nextStatement(e: Expression): Option[AstNode] =
      val stmt = GuardPass.statementRootOf(e)
      stmt._astIn.collectFirst { case a: AstNode => a }
          .flatMap(_.astChildren.l.sortBy(_.order).find(_.order > stmt.order))
    val byName = methods.filter(_.block.astChildren.nonEmpty).groupBy(_.name)
    // a failure-path free no reset follows, per unique callee name
    val failureFrees = byName.collect { case (name, List(m)) =>
        val params = m.parameter.l.map(p => p.name -> p.index).toMap
        val reset = m.ast.collectAll[Call].filter(a =>
            a.name == "<operator>.assignment" && a.argumentOption(2).exists(isNullLiteral)
        ).l.flatMap(a => a.argumentOption(1).flatMap(trackedNameOf)).toSet
        name -> paramFieldFrees(m).filter { case (i, f, arg) =>
            val pname = params.collectFirst { case (n, idx) if idx == i => n }.getOrElse("")
            !reset.contains(s"$pname->$f") && !reset.contains(s"$pname.$f") &&
            nextStatement(arg).exists {
                case r: Return => isFailureReturn(r)
                case _         => false
            }
        }
    }.filter(_._2.nonEmpty)
    if failureFrees.isEmpty then return
    // every field (param index, field) a callee frees at all, for the caller's release
    val releases = byName.collect { case (name, List(m)) =>
        name -> paramFieldFrees(m).map { case (i, f, _) => (i, f) }.toSet
    }
    def baseOf(e: Expression): Option[String] = addressOfOperand(e).getOrElse(e) match
      case i: Identifier => Some(i.name)
      case _             => None
    failureFrees.foreach { case (calleeName, frees) =>
        methods.flatMap(_.ast.collectAll[Call].nameExact(calleeName).l).foreach { site =>
          val caller = site.method
          // the `if` whose condition holds the call or the variable it was stored into
          val stored = assignedTarget(site).toSet
          val guard = caller.ast.collectAll[ControlStructure].l.find { cs =>
              cs.condition.exists(cond =>
                  cond.ast.exists(_.id == site.id) || cond.ast.collectAll[Identifier].exists(i =>
                      stored.contains(i.name)
                  )
              )
          }
          val failureBranch = guard.toList.flatMap(_.whenTrue.ast.collectAll[Call].l)
          frees.foreach { case (idx, field, freedArg) =>
              site.argumentOption(idx).collect { case e: Expression => e }.flatMap(baseOf).foreach {
                  base =>
                    val releasedAgain = failureBranch.exists { c =>
                      val direct = isFree(c) &&
                          c.argumentOption(1).flatMap(trackedNameOf).exists(n =>
                              n == s"$base.$field" || n == s"$base->$field"
                          )
                      direct || releases.getOrElse(c.name, Set.empty).exists { case (j, f) =>
                          f == field && c.argumentOption(j).collect { case e: Expression => e }
                              .flatMap(baseOf).contains(base)
                      }
                    }
                    if releasedAgain then record(freedArg, TagState, stateName(StFreed))
              }
          }
        }
    }
  end failurePathFieldDoubleFrees

  /** The class-ownership facts no single method can see, across the constructor, the destructor and
    * the copy that shares a member's storage:
    *   - a constructor's ARRAY new into a member that the destructor releases with a SCALAR delete:
    *     the forms do not match ([expr.new], [expr.delete]) - every object of the class is released
    *     wrongly, and the report is the destructor's delete.
    *   - a copy-initialised pair of a class whose destructor frees a member: the copy shared the
    *     member's storage, so the two scope-exit destructor calls free it twice. The report is the
    *     copy.
    */
  private def owningClassFacts(record: (StoredNode, String, String) => Unit): Unit =
    def memberOfLhs(lhs: AstNode): Option[Member] = lhs match
      case c: Call       => OverlayFacts.memberRefOf(atom, c)
      case i: Identifier => OverlayFacts.implicitMemberOf(atom, i)
      case _             => None
    // the member a delete or new's enclosing assignment writes, by the delete/new call. A
    // field the resolver will not carry (`this->p`) names the member of the constructor's own
    // class by its field identifier
    def memberThrough(call: Call, owner: Option[TypeDecl] = None): Option[Member] =
        call._astIn.collectFirst { case a: Call if a.name == "<operator>.assignment" => a }
            .flatMap(_.argumentOption(1)).flatMap { lhs =>
                memberOfLhs(lhs).orElse(owner.flatMap(td =>
                    fieldNamed(lhs).flatMap(n => td.member.nameExact(n).headOption)
                ))
            }

    def fieldNamed(lhs: AstNode): Option[String] = lhs match
      case c: Call
          if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
          c.argument.l.collectFirst {
              case f: io.shiftleft.codepropertygraph.generated.nodes.FieldIdentifier =>
                  f.canonicalName
          }
      case _ => None
    def isArrayForm(c: Call): Boolean =
        c.tag.name(io.appthreat.x2cpg.Defines.AllocFormTag).value.l
            .contains(io.appthreat.x2cpg.Defines.AllocFormArray)
    def isScalarDelete(c: Call): Boolean =
        c.name == "<operator>.delete" && !isArrayForm(c)

    val classDecls = atom.typeDecl.l.filter(td => td.method.l.exists(_.block.astChildren.nonEmpty))
    // the classes whose destructor frees one of their own members
    val freeingClasses: Map[TypeDecl, List[Call]] = classDecls.flatMap { td =>
      val dtor = td.method.l.find(m => m.name.startsWith("~") && m.block.astChildren.nonEmpty)
      dtor.toList.flatMap { d =>
        val deletes = d.ast.isCall.name("<operator>.delete").l
            .filter(c => c.argumentOption(1).isDefined)
        Option.when(deletes.exists(c =>
            c.argumentOption(1).flatMap(memberOfLhs).isDefined ||
                memberThrough(c).isDefined
        ))(td -> deletes)
      }
    }.toMap

    // 1. the form mismatch: the constructor's array new into a member the destructor's scalar
    //    delete releases
    freeingClasses.foreach { case (td, deletes) =>
        val ctor = td.method.l.find(m => m.name == td.name && m.block.astChildren.nonEmpty)
        val arrayNewMembers = ctor.toList.flatMap { c =>
            c.ast.isCall.name("<operator>.new").l.filter(isArrayForm).flatMap(memberThrough(
              _,
              Some(td)
            ))
        }.toSet
        if arrayNewMembers.nonEmpty then
          deletes.foreach { del =>
              if isScalarDelete(del) then
                val released =
                    del.argumentOption(1).flatMap(memberOfLhs).orElse(memberThrough(del, Some(td)))
                released.filter(arrayNewMembers.contains).foreach { _ =>
                    del.argumentOption(1).collect { case e: Expression => e }
                        .foreach(e => record(e, TagClassFormMismatch, "new-array-delete"))
                }
          }
    }

    // 2. the copy that shares a freeing member: both objects' scope-exit destructors free it
    // a class that declares its own copy constructor or copy assignment decides what a copy
    // shares (a deep copy shares nothing); only the implicit member-wise copy shares the member
    def declaresCopy(td: TypeDecl): Boolean =
        td.method.l.exists { m =>
            (m.name == td.name || m.name == "operator=") &&
            m.parameter.l.filterNot(_.name == "this").exists(p =>
                p.typeFullName.contains(td.name) && p.typeFullName.trim.endsWith("&")
            )
        }
    val classNames = freeingClasses.keys.filterNot(declaresCopy).map(_.name).toSet
    if classNames.nonEmpty then
      val byMethod = mutable.HashMap.empty[Method, List[Call]]
      def dtorCallNames(m: Method): List[Call] =
          byMethod.getOrElseUpdate(
            m,
            m.ast.isCall.l.filter(c =>
                c.name.startsWith("~") && c.argument.l.exists(_.isInstanceOf[Identifier])
            )
          )
      atom.method.filterNot(_.isExternal).l.foreach { m =>
          m.ast.isCall.nameExact("<operator>.assignment").l.foreach { copy =>
            val sides =
                for
                  lhs <- copy.argumentOption(1).collect { case i: Identifier => i }
                  rhs <- copy.argumentOption(2).collect { case i: Identifier => i }
                  lhsType = String
                      .valueOf(lhs.property("TYPE_FULL_NAME"))
                      .trim
                  rhsType = String
                      .valueOf(rhs.property("TYPE_FULL_NAME"))
                      .trim
                  if classNames.contains(lhsType) && lhsType == rhsType
                yield (lhs, rhs)
            sides.foreach { case (lhs, rhs) =>
                val destroyed = dtorCallNames(m).flatMap(_.argument.l)
                    .collect { case i: Identifier => i.name }.toSet
                if destroyed.contains(lhs.name) && destroyed.contains(rhs.name) then
                  record(copy, TagState, ValueSummaryFreed)
            }
          }
      }
    end if
  end owningClassFacts

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
      // every parameter the body READS THROUGH at all - a guarded dereference still reads,
      // which is the reads question a caller's wider-type conversion asks; `direct` below is
      // the UNGUARDED-always question the null rule asks
      val accessed = m.ast.collectAll[Call].l.flatMap { c =>
        val base: Option[String] = c.name match
          case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" |
              "<operator>.indexAccess" | "<operator>.indirectIndexAccess" |
              "<operator>.indirection" =>
              c.argumentOption(1).collect { case i: Identifier => i.name }
          case _ => None
        base.flatMap(paramIdx.get)
      }.toSet
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
      (m, pointerIdx, guardedIdx, direct, accessed, passings)
    }.toIndexedSeq

    val perMethod = mutable.LinkedHashMap.empty[Method, Set[Int]]
    val readsOf   = mutable.LinkedHashMap.empty[Method, Set[Int]]
    facts.foreach { case (m, pointerIdx, guardedIdx, direct, accessed, _) =>
        perMethod(m) = direct.intersect(pointerIdx -- guardedIdx)
        readsOf(m) = accessed.intersect(pointerIdx)
    }

    // collapse by name as every effect summary is: same-named methods that disagree carry nothing
    val byName = mutable.HashMap.empty[String, Set[Int]]
    // a callee with no body here whose declaration says `nonnull(i)` reads through argument i by
    // contract (MemorySemanticsPass): the same evidence a derefs-param summary is, from a header
    val definedNames = methods.filter(_.block.astChildren.nonEmpty).map(_.name).toSet
    MemorySemanticsPass.nonnullParamsByName(atom).foreach { case (name, idxs) =>
        if !definedNames.contains(name) then byName(name) = idxs
    }
    def collapse(): Unit = facts.foreach { case (m, _, _, _, _, _) =>
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
      facts.foreach { case (m, pointerIdx, guardedIdx, _, _, passings) =>
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
    // by name, as the rounds read them: the last of several same-named methods must not speak
    // for the others, whose conclusions may differ
    perMethod.toList.groupMap(_._1.name)(_._2).map { case (name, idxs) =>
        name -> (if idxs.distinct.size == 1 then idxs.head else Set.empty[Int])
    }
  end derefsParamsOf

  /** The parameter indices each method NAME's bodies READ THROUGH, guards and conditions included -
    * the reads-question a caller's wider-type conversion asks, distinct from the unguarded-always
    * question `derefs-param` answers. Name-collapsed the same way.
    */
  def readsParamsByName(methods: List[Method]): Map[String, Set[Int]] =
    val per = mutable.LinkedHashMap.empty[Method, Set[Int]]
    methods.foreach { m =>
      val paramIdx = m.parameter.l.map(p => p.name -> p.index).toMap
      val pointerIdx = m.parameter.l
          .filter(p => OverlayFacts.isPointer(p.typeFullName))
          .map(_.index)
          .toSet
      val accessed = m.ast.collectAll[Call].l.flatMap { c =>
        val base: Option[String] = c.name match
          case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" |
              "<operator>.indexAccess" | "<operator>.indirectIndexAccess" |
              "<operator>.indirection" =>
              c.argumentOption(1).collect { case i: Identifier => i.name }
          case _ => None
        base.flatMap(paramIdx.get)
      }.toSet
      per(m) = accessed.intersect(pointerIdx)
    }
    per.toList.groupMap(_._1.name)(_._2).map { case (name, idxs) =>
        name -> (if idxs.distinct.size == 1 then idxs.head else Set.empty[Int])
    }
  end readsParamsByName

  /** The effect summary of one method body, from the role table - no tag reads per node.
    *
    * Every summary is a claim about what EVERY call does, and a wrong one is a high-confidence
    * finding at every call site, so each is concluded only on evidence that holds on all paths:
    *
    *   - `frees-param:<i>` - a free of parameter i (or of `*p` for a pointer-to-pointer parameter)
    *     that no condition controls (no incoming CDG edge), or whose only controlling conditions
    *     are NULL tests of the freed parameter itself (for a freep, of its pointee): whenever the
    *     argument names a block, the free runs, so the guard reads as unconditional. A free under
    *     any other condition frees on SOME path only. A wrapper that also resets the caller's
    *     pointer (`free(*pp); *pp = NULL;`) is a freep: it leaves the caller null, not dangling, so
    *     it carries no summary rather than a false double free.
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
    // the parameter a freed/stored expression names: `p`, or `*pp` for a caller's `&x`. The
    // cast a typed spelling needs (`free(*(void **)p)`) is read through
    def paramOf(e: Expression): Option[Int] = unwrapCasts(e) match
      case i: Identifier => paramIndex.get(i.name)
      case c: Call if c.name == "<operator>.indirection" =>
          c.argumentOption(1).map(unwrapCasts).collect { case i: Identifier => i }.flatMap(i =>
              paramIndex.get(i.name)
          )
      case _ => None
    // the expression's root identifier still holds the value the parameter received
    def holdsArgumentOf(e: Expression): Boolean = unwrapCasts(e) match
      case i: Identifier => OverlayFacts.holdsParameterValue(i)
      case c: Call if c.name == "<operator>.indirection" =>
          c.argumentOption(1).map(unwrapCasts).collect { case i: Identifier => i }
              .forall(OverlayFacts.holdsParameterValue)
      case _ => true
    val calls = method.ast.collectAll[Call].l
    // `*pp = NULL` - the parameters whose pointee the method resets
    val nulledThrough = calls.collect {
        case a if a.name == "<operator>.assignment" && a.argumentOption(2).exists(isNullLiteral) =>
            a.argumentOption(1).map(unwrapCasts).collect {
                case d: Call if d.name == "<operator>.indirection" => d
            }.flatMap(_.argumentOption(1).map(unwrapCasts)).collect { case i: Identifier => i.name }
    }.flatten.toSet
    // the pointee a freed expression reads through (`free(*pp)`, casts included): its parameter
    def viaPointeeOf(freed: Expression): Option[String] = unwrapCasts(freed) match
      case d: Call if d.name == "<operator>.indirection" =>
          d.argumentOption(1).map(unwrapCasts).collect { case i: Identifier => i.name }
      case _ => None
    calls.foreach {
        case c
            if roleOf(c).free.nonEmpty && (c._cdgIn.isEmpty || onlyNullChecksOf(c)) =>
            // the freed identifier must still hold the argument: `p = p->next; free(p)`
            // releases another block under the parameter's name
            argAt(c.argument.l, 1).map(unwrapCasts).filter(holdsArgumentOf).foreach { freed =>
              val via = viaPointeeOf(freed)
              if !via.exists(nulledThrough.contains) then
                paramOf(freed).foreach(idx => effects += s"effect:frees-param:$idx")
              // a free THROUGH the pointee the method then nulls (free(*p); *p = NULL)
              // still freed the caller's object: the caller is left null, not dangling,
              // but a SECOND release of it before this call is a double free all the same
              else
                paramOf(freed).foreach(idx => effects += s"effect:freep-param:$idx")
            }
        case c if roleOf(c).free.nonEmpty =>
            // a free a condition other than the freed parameter's own NULL tests controls
            // (an error path, a flag, a goto-fail label) releases the block on SOME path:
            // no frees-param summary (a false double free at every caller), but the
            // ownership MAY leave - a caller that treats the hand-off as a borrow would
            // report the error-path return as a leak of a block the callee already released
            // the one condition is a file-static flag (`if (badStatic) free(data)`): the free
            // happens whenever a caller has stored a nonzero constant into the flag before the
            // call - a summary the call site settles
            val staticFlag = c._cdgIn.l match
              case List(i: Identifier)
                  if method.local.l.forall(_.name != i.name) &&
                      method.parameter.l.forall(_.name != i.name) => Some(i.name)
              case _ => None
            argAt(c.argument.l, 1).map(unwrapCasts).foreach { freed =>
                paramOf(freed).foreach { idx =>
                  effects += s"effect:maybe-frees-param:$idx"
                  staticFlag.foreach(flag => effects += s"effect:frees-param-if-static:$idx:$flag")
                }
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
        .flatMap(seeThroughReturnValue)
        .filterNot(isNullLiteral)
    // The ANCHOR. `flowsFromAllocation` accepts the NULL-literal fallback, which is right
    // for the failure path - but on its own it concludes "allocates" for `return i` where i is
    // an int counter whose only def is the literal 0 (ff_get_line's shape: every caller's
    // counter would become a phantom tracked allocation that "leaked" at every exit). At least
    // one return must flow from a REAL allocation call.
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
    // An allocation is a POINTER - a method whose declared return is an int can hand out
    // an error code while allocating into an out-param (ff_get_extradata's shape: returns 0 on
    // success), and concluding allocates-return for it would track every caller's `ret` error
    // variable as a live allocation that "leaked" at every exit
    val returnsPointer = Option(method.methodReturn.typeFullName)
        .exists(t => OverlayFacts.isPointer(t))
    // a parameter with an UNCONDITIONAL free keeps only that conclusion: the conditional
    // release of the same parameter adds nothing a consumer reads
    val freedUnconditionally = effects.collect {
        case e if e.startsWith("effect:frees-param:") =>
            e.stripPrefix("effect:frees-param:")
    }
    freedUnconditionally.foreach { i => effects -= s"effect:maybe-frees-param:$i" }
    // every value returned is a pointer the method itself released unconditionally and did not
    // rebind afterwards: `data = new T; delete data; return data;` hands the caller a dangling one
    val returnsFreed = valueReturns.nonEmpty && valueReturns.forall { e =>
        unwrapCasts(e) match
          case i: Identifier =>
              val retLine = i.lineNumber.map(_.toInt).getOrElse(0)
              val frees = method.ast.isCall.l.filter(fc =>
                  roles.getOrElse(fc.id(), RoleInfoNone).free.nonEmpty &&
                      (fc._cdgIn.isEmpty || onlyNullChecksOf(fc)) &&
                      fc.lineNumber.exists(_.toInt < retLine) &&
                      argAt(fc.argument.l, 1).map(unwrapCasts).exists {
                          case a: Identifier => a.name == i.name
                          case _             => false
                      }
              )
              frees.nonEmpty && {
                  val freeLine = frees.flatMap(_.lineNumber).map(_.toInt).max
                  !method.ast.isCall.nameExact("<operator>.assignment").l.exists(a =>
                      a.lineNumber.exists(l => l.toInt > freeLine && l.toInt < retLine) &&
                          argAt(a.argument.l, 1).exists {
                              case t: Identifier => t.name == i.name
                              case _             => false
                          }
                  )
              }
          case _ => false
    }
    if returnsFreed then effects += "effect:returns-freed"
    // A steal: a pointer-to-pointer parameter whose pointee the body reads, whose slot the body
    // then empties, and whose read value every value return hands back - `void *steal(void **pp)
    // { void *p = *pp; *pp = NULL; return p; }`. The caller's own block moves to the call's
    // result and the slot is left empty: nothing is released, so no free summary describes it.
    // The returned identifier's definition walk is bounded: a real tree's definition chains run
    // hundreds of locals deep, and an unbounded walk over them overflows the stack - past the
    // bound the walk says nothing and the method concludes no steal. A steal cannot exist
    // without the slot's NULL store, so a method that never stores NULL through a parameter's
    // pointee skips the walk entirely: its per-hop definition reads are graph-scale, and
    // pointer-returning methods without the store are the overwhelming majority
    val stealDefs = mutable.LongMap.empty[List[Expression]]
    def stolenParamOf(e: Expression, depth: Int): Option[Int] = unwrapCasts(e) match
      case d: Call if d.name == "<operator>.indirection" =>
          d.argumentOption(1).map(unwrapCasts).collect { case i: Identifier => i }
              .flatMap(i => paramIndex.get(i.name))
      case i: Identifier if depth > 0 =>
          val defs = stealDefs.getOrElseUpdate(
            i.id(),
            OverlayFacts
                .reachingDefsIn(i)
                .collect { case d: Identifier => d }
                .flatMap(_._astIn.collectFirst {
                    case a: Call if a.name == "<operator>.assignment" => a
                })
                .flatMap(_.argumentOption(2).toList)
          )
          val idxs = defs.flatMap(d => stolenParamOf(d, depth - 1).toList)
          Option.when(defs.nonEmpty && idxs.size == defs.size && idxs.distinct.size == 1)(
            idxs.head
          )
      case _ => None
    val stealParams: Set[Int] =
        if nulledThrough.isEmpty then Set.empty
        else
          val idxs = valueReturns.flatMap(e => stolenParamOf(e, MaxStealChainDepth).toList)
          if valueReturns.nonEmpty && idxs.size == valueReturns.size then
            idxs.distinct.filter(i =>
                method.parameter.l.find(_.index == i).exists(p =>
                    OverlayFacts.isPointer(p.typeFullName) && nulledThrough.contains(p.name)
                )
            ).toSet
          else Set.empty
    stealParams.foreach(i => effects += s"effect:steals-param:$i")
    // the stolen block is the caller's own: a steal never allocates its result, whatever its
    // returns flow from
    if stealParams.isEmpty && returnsPointer && anchored && valueReturns.nonEmpty &&
      valueReturns.forall(flowsFromAllocation)
    then
      effects += "effect:allocates-return"
      // every allocation the anchored returns flow from may hand back NULL: the caller's
      // null-question is the callee's own (a `malloc` wrapper is nullable exactly as malloc is)
      val allocationCalls = valueReturns.flatMap { e =>
          unwrapCasts(e) match
            case c: Call => List(c)
            case i: Identifier =>
                OverlayFacts
                    .reachingDefsIn(i)
                    .collect { case d: Identifier => d }
                    .flatMap(_._astIn.collectFirst {
                        case a: Call if a.name == "<operator>.assignment" => a
                    })
                    .flatMap(_.argumentOption(2).toList)
            case _ => Nil
      }.collect { case c: Call => c }.filter(isAllocation)
      if allocationCalls.nonEmpty &&
        allocationCalls.forall(c => roles.getOrElse(c.id(), RoleInfoNone).nullable)
      then effects += "effect:allocates-null-return"
    end if
    effects.toSet
  end methodEffects

  /** The effect summary in force at a call site: the ONE body the call's own CALL edge resolves
    * (its own conclusion, even an empty one), or the name-level agreement when no edge resolves.
    */
  private def callEffects(
    call: Call,
    effectsByName: mutable.HashMap[String, Set[String]],
    effectsByMethod: mutable.LongMap[Set[String]]
  ): Set[String] =
    // a declared steal (a profile's `steal` role) is the same effect a body concludes
    val declared = call.tag.nameExact(MemoryApiPass.TagSteal).value.l
        .flatMap(_.toIntOption).map(i => s"effect:steals-param:$i").toSet ++
        // and a declared cleanup function releases through the address it is handed
        Option.when(call.tag.nameExact(MemoryApiPass.TagCleanup).nonEmpty)("effect:freep-param:1")
    declared ++ (call._callOut.collectAll[Method].l.distinct match
      case List(only) => effectsByMethod.getOrElse(only.id(), Set.empty)
      case _          => effectsByName.getOrElse(call.name, Set.empty)
    )

  /** The compiler-placed scope-cleanup calls of `method` that release the variable they are handed:
    * the call carries the lifetime-end tag, and the release it makes is its own inventory role or
    * its callee's effect summary - frees-param or freep-param at the position the variable's
    * address occupies. Returns the call and the variable it releases.
    */
  private def releasingCleanupCalls(
    method: Method,
    roles: mutable.LongMap[RoleInfo],
    effectsByName: mutable.HashMap[String, Set[String]],
    effectsByMethod: mutable.LongMap[Set[String]]
  ): List[(Call, String)] =
      method.ast.collectAll[Call].l.flatMap { call =>
          if call.tag.name(io.appthreat.x2cpg.Defines.LifetimeEndTag).l.isEmpty then Nil
          else
            call.argument.l.collect { case a: Call if a.name == "<operator>.addressOf" => a }
                .flatMap { addr =>
                    addr.argumentOption(1).map(unwrapCast).collect { case i: Identifier => i }
                        .flatMap { v =>
                          val pos = addr.argumentIndex
                          val releases = roles.getOrElse(call.id(), RoleInfoNone).free.nonEmpty ||
                              callEffects(call, effectsByName, effectsByMethod).exists(e =>
                                  e == s"effect:frees-param:$pos" ||
                                      e == s"effect:freep-param:$pos"
                              )
                          Option.when(releases)(call -> v.name)
                        }
                }
      }

  /** What a scope-cleanup hand-off adds to a method's own effect conclusions: a value return of a
    * local the compiler-placed cleanup releases hands the caller a dangling pointer, so the method
    * carries returns-freed. The variable must still hold its block where the return reads it - a
    * NULL reset or a steal moved the block out before the cleanup, which then releases nothing -
    * and every non-NULL return must be that variable.
    */
  private def cleanupHandoffEffects(
    method: Method,
    roles: mutable.LongMap[RoleInfo],
    effectsByName: mutable.HashMap[String, Set[String]],
    effectsByMethod: mutable.LongMap[Set[String]]
  ): Set[String] =
    val releases = releasingCleanupCalls(method, roles, effectsByName, effectsByMethod)
    if releases.isEmpty then return Set.empty
    // the compiler places the cleanup call between the value's store and the return, on the
    // return's own line, so the order that decides is the AST's, not the line's
    val orderOf = method.ast.l.zipWithIndex.map((n, i) => n.id() -> i).toMap
    def orderIsBefore(a: AstNode, b: AstNode): Boolean =
        (orderOf.get(a.id()), orderOf.get(b.id())) match
          case (Some(i), Some(j)) => i < j
          case _                  => false
    def everyDefIsNull(i: Identifier): Boolean =
      val defs = OverlayFacts
          .reachingDefsIn(i)
          .collect { case d: Identifier => d }
          .flatMap(_._astIn.collectFirst {
              case a: Call if a.name == "<operator>.assignment" => a
          })
          .flatMap(_.argumentOption(2).toList)
      defs.nonEmpty && defs.forall(isNullLiteral)
    def stolenBefore(name: String, ret: Return): Boolean =
        method.ast.collectAll[Call].l.exists { call =>
            orderIsBefore(call, ret) && call.argument.l.exists { arg =>
              val pointee = addressOfOperand(unwrapCast(arg))
              pointee.exists(p => trackedNameOf(p).contains(name)) &&
              callEffects(call, effectsByName, effectsByMethod).contains(
                s"effect:steals-param:${arg.argumentIndex}"
              )
            }
        }
    val returns = method.ast.collectAll[Return].l
        .flatMap(r => seeThroughReturnValue(r).map(e => (r, e)))
        .filterNot((_, e) => isNullLiteral(e))
    val concluded = returns.nonEmpty && returns.forall { (ret, e) =>
        unwrapCast(e) match
          case i: Identifier =>
              method.local.nameExact(i.name).nonEmpty &&
              releases.exists((call, name) => name == i.name && orderIsBefore(call, ret)) &&
              !everyDefIsNull(i) && !stolenBefore(i.name, ret)
          case _ => false
    }
    Option.when(concluded)("effect:returns-freed").toSet
  end cleanupHandoffEffects

  /** The stores of a cleanup variable into storage that outlives its scope, pending the state at
    * the release of that variable: the claim settles the way the leak facts do, joined over every
    * worklist visit of the release and read after the drain. Each path carries the stores it made
    * ([[Tracked.pendingStores]]), so a release settles only the stores that reached it.
    */
  private final class StoreClaims:
    val stores = mutable.LinkedHashMap.empty[(String, Long), Call]
    val states = mutable.LinkedHashMap.empty[(String, Long), AllocState]

    def register(name: String, store: Call): Unit =
        stores.getOrElseUpdate((name, store.id()), store)

    def settle(name: String, t: Tracked): Unit =
        stores.keysIterator.filter(k => k._1 == name && t.pendingStores.contains(k._2)).foreach {
            key =>
                states.updateWith(key) {
                    case Some(prev) => Some(joinStates(prev, t.state))
                    case None       => Some(t.state)
                }
        }

    def settledFacts: List[(Call, AllocState)] =
        stores.toList.flatMap { (key, store) => states.get(key).map(state => (store, state)) }

  private def analyseMethod(
    method: Method,
    roles: mutable.LongMap[RoleInfo],
    effectsByName: mutable.HashMap[String, Set[String]],
    effectsByMethod: mutable.LongMap[Set[String]],
    record: (StoredNode, String, String) => Unit
  ): Unit =
    // (site, exit, name) -> the state at the exit's LATEST visit. A leak is a claim that NO
    // path frees the allocation ("still live, un-freed and un-escaped"), and the worklist
    // delivers an exit's predecessors at different rounds: the false edge of `if (fd >= 0)
    // close(fd);` reaches the implicit end while the state still says `allocated`, rounds
    // before the freed path joins it into `maybe-freed`. Recording on every visit would restate
    // the pre-join state as a fact the join had already retracted; the fact is read
    // only after the worklist drains, from the state each exit settled on.
    val leakFacts =
        mutable.LinkedHashMap.empty[(Long, Long, String), (StoredNode, AllocState)]
    // the (name, line) pairs the OVERWRITE arm already reported a leak at: in a loop whose body
    // re-allocates, the overwrite of iteration n and the exit-settled fact of iteration n+1's
    // block are one leak at one line, and reporting both would render a loop-carried leak
    // twice. The first report stands; a settled fact at the same (name, line) restates it.
    // the escape CLAIMS settle exactly like the leak facts: the state at an anchor is the JOIN
    // over every visit (commutative, so order-independent), and the claim is read after the
    // worklist drains. Recording on whichever visit saw it first would be run-to-run
    // nondeterministic - the VisitCap can hide or reveal a visit depending on enqueue order,
    // which the frontend's parallel parse reorders (MS-ESC-001 sites would flip per file
    // between identical runs).
    val escFacts = mutable.LinkedHashMap.empty[(Long, String), (StoredNode, Map[String, Tracked])]
    // the stores of a released-by-cleanup variable into storage that outlives the scope, settled
    // from the state at the release and read after the drain like the escapes
    val storeClaims        = new StoreClaims
    val overwriteLeakLines = mutable.HashMap.empty[String, Set[Int]]
    def recordAndNote(node: StoredNode, tag: String, value: String): Unit =
      node match
        case c: Call if tag == TagLeak && value.startsWith("leak:") =>
            val line = c.lineNumber.map(_.toInt).getOrElse(-1)
            overwriteLeakLines.updateWith(value.stripPrefix("leak:")) { prev =>
                Some(prev.getOrElse(Set.empty) + line)
            }
        case _ => ()
      record(node, tag, value)
    val nullUseFacts =
        mutable.ListBuffer.empty[(Long, StoredNode, String, String)] // (site, use, name, kind)

    // every graph/tag read the worklist needs, extracted ONCE per method: the transfer runs
    // per CFG node per worklist visit, and per-visit tag traversals would make this pass
    // crawl on a large tree
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
          r.dstPositions ++ r.srcPositions ++ r.readPositions,
          r.region,
          r.release,
          r.acquire,
          r.retains,
          r.steal,
          r.cleanup
        )
      )
    }
    method.ast.collectAll[ControlStructure].foreach { cs =>
        cs.condition.foreach(c => guards.update(c.id(), cs))
    }
    // a local function pointer every assignment of which names ONE method defined in THIS file
    // resolves to it: `funcPtr = badSink; funcPtr(data)` calls badSink, as the graph's own
    // assignment says - never a name-match across files, where the variants all share names
    val fpTargets: Map[String, Long] =
        method.ast.isCall.nameExact("<operator>.assignment").l
            .flatMap { a =>
                (
                  a.argumentOption(1).collect { case i: Identifier => i.name },
                  a.argumentOption(2).collect {
                      case i: Identifier => i.name
                      case m: MethodRef  => m.code.stripPrefix("&")
                      case ad: Call if ad.name == "<operator>.addressOf" =>
                          ad.argumentOption(1).map(_.code).getOrElse("")
                  }
                ) match
                  case (Some(lhs), Some(rhs)) =>
                      atom.method.nameExact(rhs).l
                          .filter(m =>
                              !m.isExternal && m.block.astChildren.nonEmpty &&
                                  m.filename == method.filename
                          ) match
                        case List(only) => List(lhs -> only.id())
                        case _          => Nil
                  case _ => Nil
            }
            .groupMap(_._1)(_._2)
            .collect { case (local, ids) if ids.distinct.size == 1 => local -> ids.head }
            .toMap
    // the branch edges a constant condition closes: a use, free or narrowing there is on no
    // path, and the worklist must not walk it
    val closedBranches = OverlayFacts.constantBranchExits(method)
    // The stack-address question is asked of the same worklist. A method that never
    // allocates, frees, reallocs or touches an inventoried memory call AND never takes a local's
    // address has no tracked pointer and no facts: skip the worklist entirely
    // `<global>`'s "locals" are the file-scope declarations, and file scope in C is STATIC
    // storage duration - `static const AVOption options[]` outlives every frame. Treating its
    // initialisers as escapes of stack storage would be pure static-initialiser noise (every
    // AVOption table in FFmpeg), so an empty context turns the whole stack-escape question off
    // for it.
    val isFileScope = method.name == "<global>"
    // a `static` local has static storage duration exactly like file scope: its address outliving
    // the frame is the idiom (`static char buf[32]; ... return buf;`), not an escape. The
    // frontend records the storage class as a STATIC modifier on the local
    val frameLocals =
        Option.unless(isFileScope)(method.local.l.filterNot(isStaticLocal)).getOrElse(Nil)
    val arrayLocals = frameLocals.filter(l =>
        OverlayFacts.arrayExtent(l.typeFullName).isDefined || l.typeFullName.trim.endsWith("[]")
    )
    // the base variables one of whose count fields this method stores into: `o->refs = 2` (or a
    // store of a value the transfer cannot read) says the object carries more references than the
    // method's own count - one release of it reaches no zero the method can vouch for. A count
    // is an INTEGER the frame stores into its own field: a store into a pointer-typed field (the
    // object's name, its buffer) says nothing about the reference count
    val countStores: Set[String] =
        method.ast.isCall.nameExact("<operator>.assignment").flatMap { a =>
            for
              lhsNode <- a.argumentOption(1)
              lhs     <- trackedNameOf(lhsNode)
              if isFieldName(lhs)
              if !isPointerNode(lhsNode)
              rhs = a.argumentOption(2)
              blocked = rhs.flatMap(IndexRange.literal) match
                case Some(one) => one != 1
                case None      => true
              if blocked
            yield countBaseOf(lhs)
        }.toSet
    // the count fields the frame's own arithmetic counts in: the fields the release callees
    // drop, mapped through each call's release position (the callee's decrement names its
    // parameter's field, the caller's argument at that position names the object), and the
    // fields this frame itself decrements under a zero test - the release spelled inline.
    // An increment or decrement of any other field of the object counts nothing
    val countFields: Set[(String, String)] =
      val mapped = method.ast.collectAll[Call].l
          .filter(c => roles.getOrElse(c.id(), RoleInfoNone).release.nonEmpty)
          .flatMap { c =>
              c._callOut.collectAll[Method].l.distinct match
                case List(only) =>
                    val paramAt = only.parameter.l.map(p => p.name -> p.index).toMap
                    decrementedCountFields(only).flatMap { (paramName, field) =>
                        paramAt.get(paramName).flatMap { pos =>
                            argAt(c.argument.l, pos).flatMap(releasedObjectName)
                                .map(base => (base, field))
                        }
                    }
                case _ => Nil
          }
      val inline = method.ast.collectAll[Call].l.flatMap { c =>
          c.name match
            case "<operator>.postDecrement" | "<operator>.preDecrement" =>
                c.argumentOption(1).flatMap(countedPairOf)
                    .filter(pair => zeroGatedOn(c, pair))
            case _ => None
      }
      (mapped ++ inline).toSet
    end countFields
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
      // a static pointer local keeps its allocation past the frame by design (the cache idiom):
      // it is not a leak at exit
      staticLocals = method.local.l.filter(isStaticLocal).map(_.name).toSet,
      refReturn = !isFileScope && Option(method.methodReturn.typeFullName).exists(t =>
          t.endsWith("&") || t.endsWith("&&")
      ),
      // a reference return is the pointer itself escaping; only the BY-VALUE string return
      // copies. An unknown or empty return type stays an escape - silence needs evidence
      stringReturn = !isFileScope &&
          Option(method.methodReturn.typeFullName).exists { t =>
              !t.trim.endsWith("&") && !t.trim.endsWith("*") && isCppStringType(t)
          },
      cleanupReleased = releasingCleanupCalls(method, roles, effectsByName, effectsByMethod)
          .map(_._2).toSet,
      countStores = countStores,
      countFields = countFields
    )
    val hasAddressOfLocal = callFacts.values.exists(cf =>
        cf.name == "<operator>.addressOf" && argAt(cf.args, 1)
            .exists { case e: Expression => namesFrameObject(e, ctx); case null => false }
    )
    // a compound literal's address in a return is the frame question with no allocation, no
    // array local and no addressOf anywhere: the literal is an unnamed automatic object
    val returnsLiteralAddress = method.ast.collectAll[Return].exists(r =>
        r.astChildren.collectFirst { case e: Expression => e }.exists(holdsBlockLiteralAddress)
    )
    val callsASummarisedCallee = callFacts.values.exists(cf =>
        effectsByName.contains(cf.name) || returnsStackNames.contains(cf.name)
    )
    // a method that assigns NULL to a pointer local carries the definite-null question even
    // with no allocation anywhere in it (`p = NULL; use p`)
    val assignsNullToPointer = callFacts.values.exists(cf =>
        cf.name == "<operator>.assignment" &&
            cf.args.find(_.argumentIndex == 1).exists {
                case i: Identifier =>
                    OverlayFacts.isPointer(String.valueOf(i.property("TYPE_FULL_NAME")))
                case _ => false
            } && cf.args.exists(isNullLiteral)
    )
    if !callFacts.values.exists(cf =>
          cf.allocFamilies.nonEmpty || cf.freeFamilies.nonEmpty ||
              cf.reallocFamilies.nonEmpty || cf.nullable || cf.region.isDefined ||
              cf.releasePositions.nonEmpty || cf.acquirePositions.nonEmpty ||
              cf.retainPositions.nonEmpty || cf.stealPositions.nonEmpty || cf.cleanup
      ) && !ctx.arrayLocals.nonEmpty && !hasAddressOfLocal && !callsASummarisedCallee &&
      !returnsLiteralAddress && !assignsNullToPointer &&
      !(ctx.refReturn && ctx.locals.nonEmpty)
    then
      return
    val inStates = mutable.HashMap.empty[Long, Map[String, Tracked]]
    val visits   = mutable.LongMap.empty[Int]
    // the worklist runs in reverse postorder: a node where paths meet is taken only after every
    // forward path into it delivered its state, so no fact is recorded from a visit that saw one
    // branch of an `if` and not yet the other. The depth-first walk takes successors in the same
    // content order the worklist enqueues them in, so the order is stable run to run
    val rpoIndex = mutable.LongMap.empty[Int]
    locally {
        def contentKey(n: CfgNode): (Int, Int, String, String) =
            (
              n.propertiesMap.get("LINE_NUMBER") match
                case i: Integer => i.intValue
                case _          => Int.MaxValue
              ,
              n.propertiesMap.get("COLUMN_NUMBER") match
                case i: Integer => i.intValue
                case _          => Int.MaxValue
              ,
              String.valueOf(n.propertiesMap.get("CODE")),
              n.label
            )
        val post    = mutable.ArrayBuffer.empty[CfgNode]
        val entered = mutable.HashSet.empty[Long]
        val stack   = mutable.Stack.empty[(CfgNode, Iterator[CfgNode])]
        def succs(n: CfgNode): Iterator[CfgNode] =
            n._cfgOut.iterator.collect { case s: CfgNode => s }.toList.sortBy(contentKey).iterator
        entered += method.id()
        stack.push((method, succs(method)))
        while stack.nonEmpty do
          val (n, it) = stack.top
          if it.hasNext then
            val next = it.next()
            if entered.add(next.id()) then stack.push((next, succs(next)))
          else
            stack.pop()
            post += n
        post.reverseIterator.zipWithIndex.foreach((n, i) => rpoIndex.update(n.id(), i))
    }
    val queuedNodes = mutable.LongMap.empty[CfgNode]
    val queued      = mutable.TreeSet.empty[(Int, Long)]
    def queueKey(node: CfgNode): (Int, Long) =
        (rpoIndex.getOrElse(node.id(), Int.MaxValue), node.id())

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
        queuedNodes.update(node.id(), node)
        queued += queueKey(node)

    // a tracked site that hands out OWNERSHIP: an allocator (or realloc), or a call whose
    // summary says it allocates its return. Only these may come back as `allocated`
    def isOwningSite(site: Long): Boolean =
        callFacts.get(site).exists(cf =>
            cf.isAllocCall ||
                effectsByName.get(cf.name).exists(_.contains("effect:allocates-return"))
        )

    // the call sites whose summary names a region: the blocks they hand out live inside the
    // named container and die with it, so no frame exit reports them as leaks, however the
    // pointer travels inside the frame. The per-path region key can be joined away when one
    // branch drew from the container and another left the variable at its NULL init; the
    // site's own summary is the stable fact
    val regionAllocSites: Set[Long] =
        callFacts.iterator.collect { case (id, cf) if cf.region.isDefined => id }.toSet

    // a realloc site's input variable: the block a successful realloc consumed
    def reallocInputOf(site: Long): Option[String] =
        callFacts.get(site).filter(_.reallocFamilies.nonEmpty).flatMap(cf =>
            argAt(cf.args, 1).flatMap(trackedNameOf)
        )

    // a tracked site whose handle IS an integer (the fd-returning families): its failure
    // sentinel is -1 rather than NULL, and the guard that checks it is a `< 0` comparison
    def isHandleSite(site: Long): Boolean =
        callFacts.get(site).exists(cf =>
            cf.allocFamilies.nonEmpty && cf.allocFamilies.subsetOf(IntHandleFamilies)
        )

    enqueue(method, Map.empty)
    while queued.nonEmpty do
      val key = queued.head
      queued -= key
      val node = queuedNodes(key._2)
      val in   = inStates.getOrElse(node.id(), Map.empty)
      val out = transfer(
        node,
        in,
        callFacts,
        regionAllocSites,
        effectsByName,
        effectsByMethod,
        fpTargets,
        leakFacts,
        escFacts,
        nullUseFacts,
        storeClaims,
        ctx,
        recordAndNote
      )

      // successors enqueue in a CONTENT-stable order: line, then code, then which side of the
      // controlling condition the edge leaves by (then before else). overflowdb iterates a
      // node's edges in insertion order, which the parallel frontend reorders run-to-run, and
      // the worklist's VisitCap turns that order into different settled states - run-to-run
      // nondeterminism visible as MS-ESC-001 sites flipping per file. The
      // branch side is the tiebreaker two structurally identical branches need: same line, same
      // code, different narrowing.
      val cs = guards.get(node.id())
      // a call that never returns (abort, exit, a `noreturn` function) ends its path: nothing
      // after it runs, so no use, leak or escape there is reachable from this state
      val successors =
          if isNoReturnCall(node) then Nil
          else
            val closed = closedBranches.getOrElse(node.id(), Set.empty)
            node._cfgOut.iterator.collect { case succ: CfgNode => succ }.toList
                .filterNot(succ => closed.contains(succ.id()))
                .sortBy { succ =>
                    (
                      succ.lineNumber.map(_.toInt).getOrElse(Int.MaxValue),
                      succ.code,
                      cs.flatMap(branchOf(succ, _)).map(b => if b then 0 else 1).getOrElse(2)
                    )
                }
      successors.foreach { succ =>
        // branch edges leave from the CONDITION CALL of a guard, not from the control
        // structure node, so the narrowing rides on the condition's out-edges
        val succState = guards.get(node.id()) match
          case Some(cs) =>
              branchNarrowing(node, cs, succ, out, isOwningSite, isHandleSite, reallocInputOf)
          case None => out
        enqueue(succ, succState)
      }
    end while
    // the settled escape claims, read the way the leak facts are read: the predicates are the
    // ones the transfer used, evaluated against the state the exit JOINED over every visit
    escFacts.foreach { case (_, (node, settled)) =>
        node match
          case r: Return =>
              val refToLocale = ctx.refReturn && r.astChildren.exists {
                  case i: Identifier => boundToFrameLocal(r, i, ctx)
                  case _             => false
              }
              r.astChildren.collect { case e: Expression => e }.foreach { e =>
                val viaTracked =
                    trackedNameOf(e).flatMap(settled.get).exists(_.state == StStackAddr)
                // a by-value string return copies the characters out of the frame; a
                // char[] flowing to it is not an escape (std::string owns its
                // buffer)
                if !ctx.stringReturn &&
                  (holdsStackAddress(e, ctx) || viaTracked || refToLocale ||
                      holdsBlockLiteralAddress(e) || callReturnsStackAddress(e))
                then record(r, TagStackEscape, "escape:return")
              }
          // main's automatic objects live until the program ends: only exit handlers run
          // after its frame, so a global or a member keeping one of its addresses outlives
          // nothing that could read it (CBMC asserts only at a dereference of a dead object)
          case c: Call
              if c.name == "<operator>.assignment" && !initializesTemporary(c) && c.method.name != "main" =>
              (argAt(c.argument.l, 1), argAt(c.argument.l, 2)) match
                case (Some(dst), Some(rhs)) =>
                    val stackRhs = rhsHoldsStackAddress(rhs, settled, ctx)
                    dst match
                      case i: Identifier =>
                          if !ctx.locals.contains(i.name) && !ctx.params.contains(i.name) &&
                            stackRhs && !isStringDestination(dst)
                          then record(c, TagStackEscape, "escape:global")
                      case _ =>
                          if !isFrameStorage(dst, ctx) && stackRhs &&
                            !isStringDestination(dst)
                          then record(c, TagStackEscape, "escape:store")
                case _ => ()
          case _ => ()
    }

    // the stores whose kept block the scope's cleanup released: the fact the rule reads at the
    // store, once the release's settled state says the variable still held the block there (a
    // NULL reset or a steal means the release freed nothing the store keeps)
    storeClaims.settledFacts.foreach { case (store, settled) =>
        if settled == StAllocated || settled == StEscaped then
          record(store, TagState, ValueStoredThenReleased)
    }

    // one leak fact per allocation: the earliest exit where it settled as still live
    val settledLeaks = leakFacts.toList.collect { case ((site, _, name), (exit, StAllocated)) =>
        (site, exit, name)
    }
    settledLeaks.groupBy(_._1).foreach { case (site, exits) =>
        // the EARLIEST exit, as the scaladoc says: the first `return` that walks out on a live
        // allocation is where a reader fixes the leak, and every later exit restates it
        // (`minBy(-line)` would pick the LAST one).
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
        // the overwrite arm's report at the same (name, line) already carries this leak
        val restatedByOverwrite =
            overwriteLeakLines.getOrElse(name, Set.empty).contains(lineOf(anchor))
        if !restatedByOverwrite then record(anchor, TagLeak, s"leak:$name")
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
    regionAllocSites: Set[Long],
    effectsByName: mutable.HashMap[String, Set[String]],
    effectsByMethod: mutable.LongMap[Set[String]],
    fpTargets: Map[String, Long],
    leakFacts: mutable.LinkedHashMap[(Long, Long, String), (StoredNode, AllocState)],
    escFacts: mutable.LinkedHashMap[(Long, String), (StoredNode, Map[String, Tracked])],
    nullUseFacts: mutable.ListBuffer[(Long, StoredNode, String, String)],
    storeClaims: StoreClaims,
    ctx: MethodContext,
    record: (StoredNode, String, String) => Unit
  ): Map[String, Tracked] =
      node match
        case c: Call =>
            // a call into a method that may throw is an UNWIND exit of this frame: an allocation
            // still live here is lost on that path however dutifully the normal path frees it. It
            // is an exit like a return, so its fact settles the same way (joined over every
            // visit, read after the drain). A call inside the frame's own try block unwinds into
            // this frame's handler, not out of it.
            if effectsByName.get(c.name).exists(_.contains(EffectMayThrow)) && !insideTry(c) then
              in.foreach { case (name, t) =>
                  if !isFieldName(name) && !ctx.staticLocals.contains(name) &&
                    t.region.isEmpty && !regionAllocSites.contains(t.site)
                  then
                    noteLeak(leakFacts, (t.site, c.id(), name), (c, t.state))
              }
            callFacts.get(c.id()) match
              case Some(cf) =>
                  transferCall(
                    c,
                    cf,
                    callFacts,
                    regionAllocSites,
                    effectsByName,
                    effectsByMethod,
                    fpTargets,
                    in,
                    escFacts,
                    nullUseFacts,
                    storeClaims,
                    ctx,
                    record
                  )
              case None => in
        case r: Return =>
            var out = in
            // a returned tracked pointer transfers ownership: it escapes, it does not leak
            r.astChildren.collect { case e: Expression => e }.foreach { e =>
              // reading the block out of the frame is a use of it, however the return spells
              // the expression: no statement-level call sits under a bare `return b[0];`, so
              // the use facts the call sites record are walked here instead
              useFactsIn(e, 3, in, None, record)
              // A stack address that leaves the frame - returned directly (&x, a decayed
              // array), through a local that holds one, or a C++ reference return binding the
              // local itself. Read the incoming state: the escape-marking below would erase it.
              val viaTracked = trackedNameOf(e).flatMap(in.get).exists(_.state == StStackAddr)
              // a pointer into the block returned past its start (`return h + 1;`, the
              // header-prefixed allocator's hand-out) hands the block over all the same
              def returnedBase(x: Expression): Option[String] = unwrapCast(x) match
                case arith: Call
                    if arith.name == "<operator>.addition" || arith.name == "<operator>.subtraction" =>
                    OverlayFacts.pointerOperandOf(arith).orElse(
                      arith.argument.l.collect { case o: Expression => o }
                          .filterNot(o => IndexRange.literal(o).isDefined) match
                        case List(only) => Some(only)
                        case _          => None
                    ).flatMap(returnedBase)
                case other => trackedNameOf(other)
              returnedBase(e).foreach { name =>
                  out.get(name).foreach { t =>
                    out = withGroup(out, name, t.aliases, StEscaped)
                    out = out.updated(name, t.copy(state = StEscaped))
                  }
              }
              // the escape CLAIM settles: recorded after the drain from the joined state, not
              // on whichever visit happened to see it. The INCOMING state is
              // what the claim reads - the escape-marking below would erase it.
              escFacts.updateWith((r.id, "escape:return")) {
                  case Some((_, prev)) => Some((r, joinPoints(prev, in)))
                  case None            => Some((r, in))
              }
            }
            out.foreach { case (name, t) =>
                if !ctx.staticLocals.contains(name) && !isFieldName(name) && t.region.isEmpty &&
                  !regionAllocSites.contains(t.site)
                then noteLeak(leakFacts, (t.site, r.id, name), (r, t.state))
            }
            out
        case mr: MethodReturn =>
            in.foreach { case (name, t) =>
                if !ctx.staticLocals.contains(name) && !isFieldName(name) && t.region.isEmpty &&
                  !regionAllocSites.contains(t.site)
                then noteLeak(leakFacts, (t.site, mr.id, name), (mr, t.state))
            }
            in
        case _ => in
  end transfer

  /** Record the null-use fact a use of a nullable-produced pointer produces: `unchecked` when no
    * guard has narrowed it since the producing call, `null` when the use sits under a guard that
    * proved the pointer NULL. A checked or escaped pointer is silent - evidence, not silence,
    * either way.
    */
  // the null-ness each tracked variable has where `e` evaluates to `holds`. Reading one atom
  // per condition, `if (!entry || !node) goto fail;` - FFmpeg's paired-allocation check -
  // would narrow nothing, and every use after it would be an "unchecked" null dereference. A
  // disjunction that FAILS makes every disjunct fail; a conjunction that HOLDS makes every
  // conjunct hold; the other polarity says nothing about any single operand.
  private def nullFacts(e: AstNode, holds: Boolean): List[(String, Boolean)] = e match
    case c: Call if c.name == "<operator>.logicalNot" =>
        c.argumentOption(1).toList.flatMap(nullFacts(_, !holds))
    case c: Call if c.name == "<operator>.logicalOr" =>
        if holds then Nil else c.argument.l.flatMap(nullFacts(_, holds = false))
    case c: Call if c.name == "<operator>.logicalAnd" =>
        if holds then c.argument.l.flatMap(nullFacts(_, holds = true)) else Nil
    // `if (!(p = malloc(n)))` / `if ((p = malloc(n)))` - the assignment hands the
    // condition the assigned variable's truthiness
    case asg: Call if asg.name == "<operator>.assignment" =>
        assignmentTargetOf(asg).toList.map(name => (name, !holds))
    case cmp: Call
        if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
        val equals = cmp.name == "<operator>.equals"
        (cmp.argumentOption(1), cmp.argumentOption(2)) match
          case (Some(l), Some(r)) =>
              val trackedName = if isNullLiteral(l) then trackedNameOf(r) else trackedNameOf(l)
              val nullSide    = if isNullLiteral(l) then l else r
              // `p == NULL` holds -> p is null, `p != NULL` holds -> it is not (inverting
              // notEquals would silence `if (p != NULL) return;` leaks)
              if isNullLiteral(nullSide) then trackedName.map(n => (n, holds == equals)).toList
              else Nil
          case _ => Nil
    // `if (p)` - truthiness of a tracked pointer is its null-ness
    case tracked if trackedNameOf(tracked).isDefined =>
        trackedNameOf(tracked).map(name => (name, !holds)).toList
    case _ => Nil

  /** The int-handle failure check: a comparison of a tracked fd-returning allocation against the
    * failure boundary, naming the side on which the acquisition FAILED. With the handle on the
    * left, `fd < 0`, `fd <= -1` and `fd == -1` fail where they hold; `fd >= 0`, `fd > -1` and `fd
    * != -1` fail where they do not; a handle on the right mirrors the operator. Any other threshold
    * (`fd >= 5`, `fd > 0`) puts a legal descriptor on the "failed" side and narrows nothing. `-1`
    * reaches here as a unary minus over the literal `1`.
    */
  private def handleFailureSides(
    cond: AstNode,
    out: Map[String, Tracked],
    isHandleSite: Long => Boolean
  ): List[(String, Boolean)] =
    def lit(e: AstNode): Option[Long] = e match
      case l: Literal                              => l.code.trim.toLongOption
      case c: Call if c.name == "<operator>.minus" => c.argumentOption(1).flatMap(lit).map(-_)
      case _                                       => None
    def trackedHandle(e: AstNode): Option[String] = e match
      case i: Identifier => out.get(i.name).filter(t => isHandleSite(t.site)).map(_ => i.name)
      case _             => None
    val mirrored = Map(
      "<operator>.lessThan"          -> "<operator>.greaterThan",
      "<operator>.greaterThan"       -> "<operator>.lessThan",
      "<operator>.lessEqualsThan"    -> "<operator>.greaterEqualsThan",
      "<operator>.greaterEqualsThan" -> "<operator>.lessEqualsThan",
      "<operator>.equals"            -> "<operator>.equals",
      "<operator>.notEquals"         -> "<operator>.notEquals"
    )
    cond match
      case c: Call if mirrored.contains(c.name) =>
          val oriented = (c.argumentOption(1), c.argumentOption(2)) match
            case (Some(l), Some(r)) =>
                trackedHandle(l).zip(lit(r)).map((c.name, _))
                    .orElse(trackedHandle(r).zip(lit(l)).map((mirrored(c.name), _)))
            case _ => None
          oriented.toList.flatMap {
              case ("<operator>.lessThan", (n, 0L))          => List((n, true))
              case ("<operator>.lessEqualsThan", (n, -1L))   => List((n, true))
              case ("<operator>.equals", (n, -1L))           => List((n, true))
              case ("<operator>.greaterEqualsThan", (n, 0L)) => List((n, false))
              case ("<operator>.greaterThan", (n, -1L))      => List((n, false))
              case ("<operator>.notEquals", (n, -1L))        => List((n, false))
              case _                                         => Nil
          }
      case _ => Nil
  end handleFailureSides

  /** Is this use protected by a null test of `name` in its OWN expression - `p && p->x`, `!p ||
    * p->x`, `p ? p->x : d`? Short-circuit guards are not control structures, so the worklist never
    * narrows through them, and without this check they are a large share of MS-NULL-001 noise.
    */
  private def guardedInExpression(use: StoredNode, name: String): Boolean =
    var child: StoredNode          = use
    var cursor: Option[StoredNode] = use._astIn.nextOption()
    var found                      = false
    while !found && cursor.exists(_.isInstanceOf[Expression]) do
      val parent = cursor.get
      parent match
        case c: Call =>
            val args  = c.argument.l
            val index = args.indexWhere(_.id == child.id)
            def nonNullWhen(op: AstNode, holds: Boolean): Boolean =
                nullFacts(op, holds).contains((name, false))
            found = c.name match
              case "<operator>.logicalAnd" if index > 0 =>
                  args.take(index).exists(nonNullWhen(_, holds = true))
              case "<operator>.logicalOr" if index > 0 =>
                  args.take(index).exists(nonNullWhen(_, holds = false))
              case "<operator>.conditional" if index == 1 =>
                  nonNullWhen(args.head, holds = true)
              case "<operator>.conditional" if index == 2 =>
                  nonNullWhen(args.head, holds = false)
              case _ => false
        case _ => ()
      child = parent
      cursor = parent._astIn.nextOption()
    end while
    found
  end guardedInExpression

  /** The line spans of the loops around `node`, walked cycle-safely (an expansion can give a node
    * two AST parents).
    */
  private def enclosingLoopSpans(node: AstNode): List[(Int, Int)] =
    val seen                       = mutable.HashSet.empty[Long]
    val spans                      = mutable.ListBuffer.empty[(Int, Int)]
    var cursor: Option[StoredNode] = node._astIn.nextOption()
    while cursor.isDefined do
      val current = cursor.get
      if !seen.add(current.id()) then cursor = None
      else
        current match
          case cs: ControlStructure =>
              val t = cs.controlStructureType.toUpperCase
              if t == "WHILE" || t == "FOR" || t == "DO" then
                val lines = cs.ast.lineNumber.l.map(_.toInt)
                if lines.nonEmpty then spans += ((lines.min, lines.max))
              cursor = cs._astIn.nextOption()
          case _: Method => cursor = None
          case other     => cursor = other._astIn.nextOption()
    spans.toList

  /** Each method's calls, listed once: the null arm asks them per use */
  private val callsByMethod = new java.util.concurrent.ConcurrentHashMap[Long, List[Call]]()
  private def callsOf(m: Method): List[Call] =
      callsByMethod.computeIfAbsent(m.id(), _ => m.ast.isCall.l)

  /** Per method, per variable name, the lines of the stores and increments that redefine it beyond
    * NULL: neither the NULL literal nor a plain copy of another name. Built once per method.
    */
  private val redefinitionsByMethod =
      new java.util.concurrent.ConcurrentHashMap[Long, Map[String, List[Int]]]()
  private def redefinitionLinesOf(m: Method): Map[String, List[Int]] =
      redefinitionsByMethod.computeIfAbsent(
        m.id(),
        _ =>
            callsOf(m).filter(c => RedefiningOps.contains(c.name)).flatMap { a =>
                a.argumentOption(1).collect { case i: Identifier => i.name }.filter(_ =>
                    !a.argumentOption(2).exists {
                        case _: Identifier => true
                        case _             => false
                    } && !a.argumentOption(2).forall(isNullLiteral)
                ).map(_ -> a.lineNumber.map(_.toInt).getOrElse(Int.MaxValue))
            }.groupMap(_._1)(_._2)
      )

  private val RedefiningOps = Set(
    "<operator>.assignment",
    "<operator>.assignmentPlus",
    "<operator>.assignmentMinus",
    "<operator>.assignmentMult",
    "<operator>.postIncrement",
    "<operator>.preIncrement",
    "<operator>.postDecrement",
    "<operator>.preDecrement"
  )

  /** The states a reassignment from something the transfer cannot name makes stale: the variable
    * now holds another value, so neither its NULL, its frame provenance nor the release of the
    * object it used to hold says anything about it (`free(p); p = wrapper_alloc(n); use(p)`)
    */
  private def staleOnRebind(state: AllocState, rhs: AstNode, lhs: String): Boolean =
      state == StNull || state == StNullReset || state == StStackAddr ||
          ((state == StFreed || state == StMaybeFreed) && !handsBackItself(rhs, lhs))

  /** Is the variable itself an argument of the producer it is rebound to? `data = badSource(data)`
    * may return the very object the callee released, so its freed state is not stale.
    */
  private def handsBackItself(rhs: AstNode, lhs: String): Boolean =
      rhs.ast.isIdentifier.l.exists(_.name == lhs)

  /** The freed/maybe-freed facts a use of a tracked block produces, through a bounded walk of the
    * expression: an index or field access over the tracked base, and the operator expressions
    * around it. The CFG does not always deliver nested expressions as their own nodes, so the walk
    * recurses through operator arguments; a return's expressions are walked the same way, since
    * reading a block out of the frame is a use of it however the statement spells it. The null-use
    * facts are recorded where `nullUseFacts` says so - a return's null question stays where it was.
    */
  private def useFactsIn(
    arg: AstNode,
    depth: Int,
    useState: Map[String, Tracked],
    nullUseFacts: Option[mutable.ListBuffer[(Long, StoredNode, String, String)]],
    record: (StoredNode, String, String) => Unit
  ): Unit = arg match
    case query: Call
        if query.name.startsWith("<operator>.sizeOf") ||
            query.name.startsWith("<operator>.alignOf") => ()
    case access: Call if isAccessThroughPointer(access) =>
        access.argumentOption(1).foreach { base =>
          trackedNameOf(base).foreach { name =>
              useState.get(name).foreach { t =>
                if t.state == StFreed || t.state == StMaybeFreed then
                  record(base, TagState, stateName(t.state))
                  recordFreedomMarks(base, t, record)
                nullUseFacts.foreach(nf => noteNullUse(nf, base, name, t))
              }
          }
          // a read through a NESTED path (`o->ref.refcount`) whose first hop is itself
          // untracked is still a use of the container the hop hangs from
          base match
            case bc: Call
                if depth > 0 && isAccessThroughPointer(bc) &&
                    trackedNameOf(bc).exists(n => useState.get(n).isEmpty) =>
                useFactsIn(bc, depth - 1, useState, nullUseFacts, record)
            case _ => ()
        }
    case inner: Call if depth > 0 && isOperatorCall(inner.name) =>
        inner.argument.l.foreach(a => useFactsIn(a, depth - 1, useState, nullUseFacts, record))
    case _ => ()

  /** The freedom marks a use of a freed or maybe-freed block carries beside its `alloc-state`
    * value: the confidence the use-after-free finding reports at when the block's freedom came from
    * a reference release - the borrowed kind (`low`), a region reset (`medium`, the region mark),
    * or a release that reached zero (`medium`). One mark per use, the weakest claim first.
    */
  private def recordFreedomMarks(
    use: StoredNode,
    t: Tracked,
    record: (StoredNode, String, String) => Unit
  ): Unit =
      if t.borrowed then record(use, TagReleaseUse, "low")
      else if t.resetByRegion then record(use, TagResetUse, "1")
      else if t.freedByRelease then record(use, TagReleaseUse, "medium")

  private def noteNullUse(
    nullUseFacts: mutable.ListBuffer[(Long, StoredNode, String, String)],
    use: StoredNode,
    name: String,
    t: Tracked
  ): Unit =
    // a DEFINITE NULL: the pointer's every definition on this path is the NULL literal or a
    // guard that proved it null (`data = NULL; data->intOne`, `(p != NULL) & p->intOne` - the
    // bitwise `&` does not short-circuit, so the second operand runs whatever p is). No
    // nullability is asked: the value IS null, which is exact evidence, not a hypothesis.
    // A guard that since proved it NON-NULL (`p = NULL; if (p != NULL) p->x`) still
    // silences it - the author checked, whatever the initialiser said
    // an assignment this transfer never interpreted - one inside a condition's
    // expression (`if ((v = strchr(s, ':')) == NULL || ...) goto err;`), or a macro
    // expansion - replaced the value after the null the state remembers. The definite
    // arm speaks only for a value whose EVERY definition before the use it saw as the
    // null literal; any non-null redefinition it did not interpret ends the claim
    def redefinedBeyondNullBefore(use: StoredNode, name: String): Boolean = use match
      case n: io.shiftleft.codepropertygraph.generated.nodes.Expression =>
          val useLine = n.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
          // a plain-identifier rhs is NEUTRAL: the transfer's own alias copy carries the
          // source's state - the copies variant's `dataCopy = data` of a NULL is null, and the
          // copy is not a redefinition beyond it
          redefinitionLinesOf(n.method).getOrElse(name, Nil).exists(_ < useLine)
      case _ => false
    // the DEFINITE claim carries the arithmetic arm's own discipline: every assignment to
    // the variable before this use must be the NULL literal (at least one is) or a plain
    // copy of another name (neutral - the alias copy carries its state), no call may have
    // received the variable's address (the callee writes through it), and no increment may
    // have rewritten it. A declaration's `= NULL` initialiser alone is not enough: the
    // projects' false families lived exactly on values a later unmodelled producer replaced
    // (`&cpid` handed to a table-walk helper, strchr behind a checked guard)
    def definiteNullDefined(use: StoredNode, name: String): Boolean = use match
      case n: io.shiftleft.codepropertygraph.generated.nodes.Expression =>
          val useLine = n.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
          // a loop around the use carries the back edge: a write later in its body reaches the
          // use on the next iteration (`prev = NULL; while (...) { prev->next = ...; prev = curr; }`)
          val loopSpans = enclosingLoopSpans(n)
          def reaches(a: Call): Boolean =
            val line = a.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
            line <= useLine || loopSpans.exists((lo, hi) => line >= lo && line <= hi)
          def assignmentsTo(v: String): List[Call] =
              callsOf(n.method).filter(a =>
                  a.name == "<operator>.assignment" &&
                      a.argumentOption(1).exists {
                          case i: Identifier => i.name == v
                          case _             => false
                      }
              )
          // a copy is neutral only when its source is itself null on every write: `dataCopy =
          // data` of `data = NULL` is null, `prev = curr` of a list cursor is not
          def nullOnly(v: String, depth: Int): Boolean =
            val sources = assignmentsTo(v).flatMap(_.argumentOption(2).toList)
            sources.nonEmpty && sources.forall {
                case s if isNullLiteral(s) => true
                case i: Identifier =>
                    depth > 0 && i.name != v && nullOnly(i.name, depth - 1)
                case _ => false
            }
          val writes     = assignmentsTo(name).filter(reaches)
          val stores     = writes.flatMap(a => a.argumentOption(2).toList)
          val nullStores = stores.count(s => isNullLiteral(s))
          val copiesOnly = stores.filterNot(s => isNullLiteral(s)).forall {
              case i: Identifier => nullOnly(i.name, 2)
              case _             => false
          }
          // the address may sit behind a cast or inside a nested argument expression
          def namesAddressedUnder(e: AstNode, depth: Int): Set[String] = e match
            case a: Call if a.name == "<operator>.addressOf" =>
                a.argument.l.collect { case x: Identifier => x.name }.toSet
            case c: Call if depth > 0 && c.name.startsWith("<operator>") =>
                c.argument.l.collect { case x: AstNode => x }.flatMap(namesAddressedUnder(
                  _,
                  depth - 1
                )).toSet
            case _ => Set.empty
          // a call through a function pointer (`meth->compute_key(&sec, ...)`) writes as well
          val addressHanded = callsOf(n.method).exists { c =>
              (!c.name.startsWith("<operator>") || c.name == "<operator>.pointerCall") &&
              c.lineNumber.map(_.toInt).getOrElse(Int.MaxValue) <= useLine &&
              c.argument.l.exists(namesAddressedUnder(_, 3).contains(name))
          }
          val incremented = callsOf(n.method)
              .filter(c =>
                  Set(
                    "<operator>.postIncrement",
                    "<operator>.preIncrement",
                    "<operator>.postDecrement",
                    "<operator>.preDecrement"
                  ).contains(c.name)
              )
              .exists(a =>
                  a.argumentOption(1).exists {
                      case i: Identifier => i.name == name
                      case _             => false
                  } && reaches(a)
              )
          writes.nonEmpty && nullStores > 0 && copiesOnly && !addressHanded && !incremented
      case _ => false
    if (t.state == StNull || t.state == StNullReset) && !t.checked &&
      !guardedInExpression(use, name) && !redefinedBeyondNullBefore(use, name) &&
      definiteNullDefined(use, name)
    then
      nullUseFacts += ((t.site, use, name, NullDefinite))
    else if t.nullable && !t.checked && t.state != StEscaped && t.state != StNullReset &&
      !guardedInExpression(use, name)
    then
      // an allocation's own result (malloc, calloc, realloc - the CWE-690 shape) is
      // distinguished from a nullable non-owner (strchr): the value's kind carries it, and
      // the rule reads the difference as a confidence question
      val allocProduced = t.site != 0L && {
          val site = Option(atom.graph.node(t.site)).collect { case c: Call => c }
          site.exists(c =>
              c.tag.name(MemoryApiPass.TagAlloc).nonEmpty ||
                  c.tag.name(MemoryApiPass.TagRealloc).nonEmpty
          )
      }
      // a null state the definite discipline above did not confirm (a guard's failing side on
      // a value some call produced) is a path the author may have correlated away, so it stays
      // with the hypotheses rather than the exact evidence
      val kind =
          if allocProduced then NullUncheckedAlloc
          else NullUnchecked
      nullUseFacts += ((t.site, use, name, kind))
    end if
  end noteNullUse

  private def transferCall(
    c: Call,
    cf: CallFacts,
    callFacts: mutable.LongMap[CallFacts],
    regionAllocSites: Set[Long],
    effectsByName: mutable.HashMap[String, Set[String]],
    effectsByMethod: mutable.LongMap[Set[String]],
    fpTargets: Map[String, Long],
    in: Map[String, Tracked],
    escFacts: mutable.LinkedHashMap[(Long, String), (StoredNode, Map[String, Tracked])],
    nullUseFacts: mutable.ListBuffer[(Long, StoredNode, String, String)],
    storeClaims: StoreClaims,
    ctx: MethodContext,
    record: (StoredNode, String, String) => Unit
  ): Map[String, Tracked] =
    var out = in
    // uses read the state AS OF THIS NODE's entry - a free must not see its own effect
    val useState = in

    // a pointer moved in place (`node++`, `p += n`) points at another object: the fields
    // tracked through it (`node->name`) are that object's, not the ones this frame freed
    c match
      case step: Call
          if PointerStepOps.contains(step.name) ||
              (step.name.startsWith("<operator>.assignment") && step.name != "<operator>.assignment") =>
          step.argumentOption(1).collect { case i: Identifier => i.name }.foreach(base =>
              out = dropFieldsOf(out, base)
          )
      case _ => ()
    // a call handed a struct's address (`kfifo_get(&fifo, &attn_data)`, a macro that copies a
    // new element into it) may rewrite every member: the fields tracked through it are no
    // longer the blocks this frame saw there
    c.argument.l.foreach { arg =>
        addressOfOperand(unwrapCastOperand(arg)).map(unwrapCast).collect { case i: Identifier =>
            i.name
        }.foreach(base => out = dropFieldsOf(out, base))
    }

    // The region handle an argument names, as that expression's own variable key: the
    // identifier past the casts, the address-of an out-pointer, and a field path's own key
    // (`&s->directory` names the directory array's region, never the fat array's). A copy of
    // the handle is a different key that matches nothing, and regions match by the same
    // expression's key only. A plain variable's key also carries the writes that gave it its
    // value, so a handle rebound between the allocation and the destroy (`pool = b`) names
    // another region.
    def regionNameOf(e: Expression): Option[String] =
      val handle = unwrapCast(e)
      OverlayFacts.variableKey(handle).map { key =>
          handle match
            // a local or a parameter; a global's writes sit in other methods
            case i: Identifier if i._refOut.exists {
                    case l: Local             => !l.method.name.l.contains("<global>")
                    case _: MethodParameterIn => true
                    case _                    => false
                } =>
                OverlayFacts.writesReaching(i).toList.sorted.mkString(s"$key@", ",", "")
            case _ => key
      }

    // The region a call draws from: the argument its entry names, or the named global context.
    def regionKeyOf(site: Call): Option[String] =
        callFacts.get(site.id()).flatMap(_.region).flatMap {
            case RegionInfo("allocate", Some(idx), _) =>
                argAt(site.argument.l, idx).flatMap(regionNameOf)
            case RegionInfo("allocate", None, Some(global)) => Some(s"v:$global")
            case _                                          => None
        }

    // The region lifecycle's effect on the blocks: a destroy releases every block the method
    // took from the same region handle (a block the call ALSO took from the heap - the
    // region-full fallback - is only maybe released, its other arm outliving the region), and a
    // reset leaves every one of them maybe released. The blocks carry their region's name from
    // the allocation, so the move finds them wherever they sit.
    def moveRegionBlocks(
      state: Map[String, Tracked],
      key: String,
      freed: Boolean
    ): Map[String, Tracked] =
        state.view.mapValues { t =>
            if t.region.contains(key) then
              // a block the SAME call also took from the plain heap - the region-full
              // fallback's malloc arm - is only maybe released here: its other arm outlives
              // the region. A family label a pool allocator's own entry gave it (aprpool,
              // pgmem) names the region's memory, not the heap's
              val alsoHeap = callFacts.get(t.site).exists(f => f.allocFamilies.contains("heap"))
              if freed && !alsoHeap then t.copy(state = StFreed)
              else t.copy(state = StMaybeFreed, resetByRegion = true)
            else t
        }.toMap

    // 1. free: the freed pointer's state becomes the fact. A freep-style free takes the ADDRESS
    //    and nulls the slot; a plain free leaves the pointer dangling. A macro invocation that
    //    spells the free (`ngx_free(p)` over `free(p)`) and its expansion's own free-tagged call
    //    are ONE free event: the invocation stands down and the expansion's call runs the free,
    //    so a project's own free macro is not read as two releases of the same block
    val freeSpelledByMacro =
        c.dispatchType == io.shiftleft.codepropertygraph.generated.DispatchTypes.INLINED &&
            c.ast.isCall.l.exists(fc => fc.tag.name(MemoryApiPass.TagFree).nonEmpty)
    if cf.freeFamilies.nonEmpty && !freeSpelledByMacro then
      argAt(cf.args, 1).foreach { freed =>
        // a release of the region handle itself - the destroy whose summary or body frees it -
        // takes every block the method took from that region with it
        regionNameOf(freed).foreach(key => out = moveRegionBlocks(out, key, freed = true))
        val viaAddress = addressOfOperand(freed)
        // a field nothing here assigned is still a block the struct owns: its first free is the
        // fact a second one is checked against (`free(b->p); free(b->p);`)
        val freedName = viaAddress.orElse(Some(freed)).flatMap(trackedNameOf)
        val known = freedName.flatMap(useState.get).orElse(
          freedName.filter(isFieldName).map(_ => Tracked(StAllocated, 0L, refs = 1))
        )
        known.foreach { t =>
            // a nullable NON-allocation (a strchr result) is not ownership: freeing it says
            // nothing this pass tracks
            if t.state != StNullable then
              if t.state == StFreed || t.state == StMaybeFreed then
                record(viaAddress.getOrElse(freed), TagState, stateName(t.state))
                // a free after a borrowed release or a region reset claims what that left
                // behind: only maybe gone, at the same lowered confidence as a use
                recordFreedomMarks(viaAddress.getOrElse(freed), t, record)
              // CWE-590: the freed pointer holds this frame's storage - the fact the
              // non-heap-free rule reads; ownership language never applies to it
              if t.state == StStackAddr then
                record(viaAddress.getOrElse(freed), TagState, stateName(t.state))
              val name = freedName.get
              if viaAddress.isDefined then storeClaims.settle(name, t)
              out = out.updated(
                name,
                if viaAddress.isDefined then t.copy(state = StNullReset)
                else t.copy(state = StFreed)
              )
              if viaAddress.isEmpty then out = withGroup(out, name, t.aliases, StFreed)
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
          if viaAddress.isDefined then
            out = out.updated(name, Tracked(StAllocated, c.id, refs = 1))
          // `tmp = realloc(p, n); if (!tmp) { free(p); ... } p = tmp;` - a failed realloc leaves
          // its input untouched, so p stays live until the result is stored back over it. Only
          // `p = realloc(p, n)` consumes p here (the assignment below stores the fresh block)
          else if assignedTarget(c).exists(_ != name) then ()
          else
            // `p = realloc(p, n)`: when realloc fails it returns NULL and leaves the block -
            // whose only handle the assignment has just overwritten with that NULL (C11
            // 7.22.3.5p4). The block is lost on the failure path
            if assignedTarget(c).contains(name) && useState.get(name).exists(t =>
                  t.state == StAllocated && t.region.isEmpty &&
                      !t.aliases.exists(useState.contains)
              )
            then record(c, TagLeak, s"leak:$name")
            out = withGroup(out, name, out.get(name).map(_.aliases).getOrElse(Set.empty), StFreed)
            out = out.updated(name, Tracked(StFreed, 0L))
        }
      }
    end if

    // 2b. the declared region lifecycle: a destroy tears every block the method took from the
    //     same region handle down, a reset leaves them maybe torn down - the same move a
    //     release of the handle makes, keyed by the argument the role names
    cf.region.foreach {
        case RegionInfo("destroy", Some(idx), _) =>
            argAt(cf.args, idx).flatMap(regionNameOf).foreach(key =>
                out = moveRegionBlocks(out, key, freed = true)
            )
        case RegionInfo("reset", Some(idx), _) =>
            argAt(cf.args, idx).flatMap(regionNameOf).foreach(key =>
                out = moveRegionBlocks(out, key, freed = false)
            )
        case _ => ()
    }

    // 2c. the reference roles: a release drops the object's owned-reference count by one, an
    //     acquire raises it. A new allocation carries one reference from its own site, so only a
    //     release that reaches zero frees - marked, so a use after it reports below the rule's own
    //     confidence. A release of a reference whose ownership this method does not know - a
    //     parameter, a field read, an unsummarised call's result - leaves the object maybe freed,
    //     and the release was the borrowed kind.
    def dropReference(
      name: String,
      factNode: StoredNode,
      borrowUnknown: Boolean = true,
      freeAtZero: Boolean = true
    ): Unit =
      val base = countBaseOf(name)
      useState.get(name) match
        // a slot that holds nothing releases nothing
        case Some(t) if isNullState(t.state) => ()
        case Some(t) if t.state == StFreed || t.state == StMaybeFreed =>
            if t.refs > 0 then out = out.updated(name, t.copy(refs = t.refs - 1))
            else if t.state == StFreed && !t.borrowed then
              // a release below zero: on every path the reference was already spent. The
              // fact sits on the release's own argument, which is how the rule tells the
              // double release from a use of the freed object. A borrowed release, or one
              // only some paths spent, counts references this frame never knew
              record(factNode, TagState, stateName(t.state))
              record(factNode, TagReleaseUse, "medium")
        case Some(t) if t.state == StAllocated =>
            // the references the method owns: the allocation itself carried one from
            // its own site, every acquire added one more
            if t.refs > 1 then out = out.updated(name, t.copy(refs = t.refs - 1))
            else if ctx.countStores.contains(base) then
              // a store into the object's count field (`o->refs = 2`) is a number this
              // frame wrote: one release cannot know the field reached zero. The method's
              // own reference is spent and the block survives under the count the store
              // left - no longer a block this frame can free or leak
              out = withGroup(out, name, t.aliases, StEscaped)
              out = out.updated(name, t.copy(state = StEscaped, refs = 0))
            else if freeAtZero then
              // the count reaches zero: the block is gone the way a free leaves it
              out = withGroup(out, name, t.aliases, StFreed)
              out = out.updated(
                name,
                t.copy(state = StFreed, refs = 0, freedByRelease = true)
              )
            else
              // the zero-gated decrement spelled inline: its zero arm's own release or
              // free models the release's effect, so the arithmetic only spends the count
              out = out.updated(name, t.copy(refs = 0))
        case Some(t) if t.refs > 0 =>
            // a reference the method acquired on an object whose base ownership it does
            // not know: dropping it nets the method back out, the base's own doubt stays
            val left = t.refs - 1
            out =
                if left <= 0 && t.state == StNullable then out - name
                else out.updated(name, t.copy(refs = math.max(left, 0)))
        // a block whose count the paths disagreed on: this frame no longer claims to know it
        case Some(t) if t.countUnknown                         => ()
        case Some(t) if t.state == StNullable && borrowUnknown =>
            // a value that is not ownership: the release dropped a borrowed reference
            out = out.updated(name, Tracked(StMaybeFreed, c.id, borrowed = true))
        // StEscaped and StStackAddr release nothing this frame can vouch for; the frame's
        // own arithmetic on an object it does not track counts nothing either
        case _ if borrowUnknown =>
            // unknown ownership: the method dropped a reference it cannot account for,
            // so the object is maybe freed and the release was the borrowed kind
            out = out.updated(name, Tracked(StMaybeFreed, c.id, borrowed = true))
        case _ => ()
      end match
    end dropReference

    def takeReference(name: String, factNode: StoredNode): Unit =
      out.get(name) match
        case Some(t) =>
            // acquiring a reference of a block the state says is gone is itself a use
            // of it; the fact reads the state as any call's argument would
            if t.state == StFreed || t.state == StMaybeFreed then
              record(factNode, TagState, stateName(t.state))
              if t.borrowed then record(factNode, TagReleaseUse, "low")
              else if t.freedByRelease then record(factNode, TagReleaseUse, "medium")
            out = out.updated(name, t.copy(refs = t.refs + 1))
        case None =>
            // the method now owns one reference of an object whose base ownership it does
            // not know. Tracked so the matching release nets out - never as an allocation:
            // a reference taken and never dropped is the caller's business, and no exit
            // reports it as a leak
            out = out.updated(name, Tracked(StNullable, c.id, refs = 1))
      end match

    cf.releasePositions.foreach { idx =>
        argAt(cf.args, idx).foreach { arg =>
            releasedObjectName(arg).foreach(name => dropReference(name, arg))
        }
    }

    cf.acquirePositions.foreach { idx =>
        argAt(cf.args, idx).foreach { arg =>
            releasedObjectName(arg).foreach(name => takeReference(name, arg))
        }
    }

    // 2d. the frame's own count arithmetic: an increment of a tracked count field is an
    //     acquire (+1), a decrement is a release (-1), at the statement itself - the same
    //     statement shapes the release inference reads. The decrement under a zero test is
    //     the release spelled inline: its zero-reach frees, which the zero arm's own release
    //     or free models, so the arithmetic here only moves the count.
    def countArithmeticOf(c: Call): Option[((String, String), Boolean, Expression)] =
      val op = c.name match
        case "<operator>.postIncrement" | "<operator>.preIncrement" =>
            Some((c.argumentOption(1), false))
        case "<operator>.postDecrement" | "<operator>.preDecrement" =>
            Some((c.argumentOption(1), true))
        case "<operator>.assignmentPlus" | "<operator>.assignmentMinus" =>
            c.argumentOption(2).flatMap(IndexRange.literal)
                .filter(_ == 1).map(_ => c.argumentOption(1))
                .map(opt => (opt, c.name == "<operator>.assignmentMinus"))
        case _ => None
      op.flatMap { (operand, drop) =>
          for
            node <- operand
            pair <- countedPairOf(node)
            if ctx.countFields.contains(pair)
          yield (pair, drop, node)
      }

    countArithmeticOf(c).foreach { case (pair, drop, operand) =>
        if drop then
          dropReference(
            pair._1,
            operand,
            borrowUnknown = false,
            freeAtZero = !zeroGatedOn(c, pair)
          )
        else takeReference(pair._1, operand)
    }

    // 3. assignment: fresh allocation, copy-in, NULL reset, or loss of provenance
    if cf.name == "<operator>.assignment" then
      // a REBOUND null-tracked variable is no longer the null a move or a guard left: whatever
      // the rhs produces, the old null-ness is gone. The movesHandle rhs keeps the block, and
      // a tracked rhs hands its own state over below
      (argAt(cf.args, 1).flatMap(trackedNameOf), argAt(cf.args, 2)) match
        case (Some(lhs), Some(rhs))
            if out.get(lhs).exists(_.state == StNull) && !isNullLiteral(rhs) &&
                !movesHandle(rhs, lhs) =>
            out = out - lhs
        case _ => ()
      val fieldLhs = argAt(cf.args, 1).flatMap(trackedNameOf).filter(isFieldName)
      (argAt(cf.args, 1).flatMap(trackedNameOf).filterNot(isFieldName), argAt(cf.args, 2)) match
        case (Some(lhs), Some(rhs)) =>
            // `p = tmp` where tmp is realloc(p, n)'s result: the block moved, not leaked.
            // Resolved through casts: `p = (T *)realloc(p, n)` consumed p just the same.
            val rhsIsReallocOfLhs =
              val reallocCallOf: Expression => Option[Call] =
                case rc: Call if callFacts.get(rc.id()).exists(_.reallocFamilies.nonEmpty) =>
                    Some(rc)
                case _ => None
              trackedNameOf(rhs).flatMap(out.get).exists { r =>
                  callFacts.get(r.site).exists(f =>
                      f.reallocFamilies.nonEmpty && argAt(f.args, 1).flatMap(trackedNameOf)
                          .contains(lhs)
                  )
              } || unwrapCast(rhs).flatMap(reallocCallOf).exists(rc =>
                  argAt(rc.argument.l, 1).flatMap(trackedNameOf).contains(lhs)
              )
            // the rhs still names the handle itself (`p = p + 4`): pointer arithmetic MOVES the
            // handle inside the block, it does not lose the block - the overwrite-leak claim
            // would be false (the CWE-761 shape: `p = p + 4` before `free(p)`)
            val rhsReadsLhs = movesHandle(rhs, lhs)
            out.get(lhs).foreach { t =>
                // overwriting a live allocation loses the only handle: the overwrite IS the leak
                // (a fresh allocation on the rhs loses the old block exactly as any other
                // rebinding does; a realloc consumed the old block and produced this; and an
                // aliased block still has its other handles). A block the region owns is not
                // lost - the region keeps it however the handle is rebound
                if t.state == StAllocated && t.region.isEmpty &&
                  !regionAllocSites.contains(t.site) && !rhsIsReallocOfLhs &&
                  !t.aliases.exists(out.contains) && !rhsReadsLhs
                then record(c, TagLeak, s"leak:$lhs")
            }
            // lhs is rebound: it leaves its alias group, and its fields are someone else's now
            out = dropFieldsOf(unalias(out, lhs), lhs)
            // an int-typed destination of a HEAP-family call holds its error code, not the
            // block: `ret = av_reallocp(&p, n)` allocates into p and returns 0/AVERROR. Tracking
            // ret as the allocation would report a phantom leak at every exit. The handle
            // family (fd) does return an int that IS the resource, and stays tracked
            val lhsIsErrorCode = argAt(cf.args, 1).exists { l =>
              val t = l.property("TYPE_FULL_NAME") match
                case s: String => s.trim
                case _         => ""
              t.nonEmpty && t != "ANY" && !OverlayFacts.isPointer(t)
            } && (rhs match
              case rc: Call =>
                  callFacts.get(rc.id()).exists(f =>
                      (f.allocFamilies ++ f.reallocFamilies).nonEmpty &&
                          (f.allocFamilies ++ f.reallocFamilies).forall(fam =>
                              !IntHandleFamilies.contains(fam)
                          )
                  )
              case _ => false
            )
            // a macro invocation that spells an allocator (`tmp = curlx_realloc(p, n)`) produces
            // what its expansion's one allocating call produces
            val producer = rhs match
              case m: Call
                  if m.dispatchType == io.shiftleft.codepropertygraph.generated.DispatchTypes.INLINED =>
                  m.ast.isCall.l.filter(inner =>
                      callFacts.get(inner.id()).exists(_.isAllocCall)
                  ) match
                    case List(only) => only
                    case _          => m
              case other => other
            producer match
              case _: Call if lhsIsErrorCode => out = out - lhs
              case rhsCall: Call if callFacts.get(rhsCall.id()).exists(_.isAllocCall) =>
                  // nullable is the CALL's own declared fact: pointer-returning
                  // allocators carry it, the fd-returning family does not. An allocation
                  // of the STACK family (alloca) is frame storage, not owned heap - tracked
                  // as stack-addr, so it neither leaks at exit nor is freeable. A PLACEMENT
                  // new constructs inside storage someone else owns: it acquires nothing,
                  // frees nothing and leaks nothing - the buffer's own questions stand
                  val isPlacementNew = rhsCall.name == "<operator>.new" &&
                      rhsCall.tag.name(io.appthreat.x2cpg.Defines.AllocFormTag).value.l
                          .contains(io.appthreat.x2cpg.Defines.AllocFormPlacement)
                  val cf           = callFacts.get(rhsCall.id())
                  val isStackAlloc = cf.exists(_.allocFamilies.contains("stack"))
                  if isPlacementNew then ()
                  else
                    out = out.updated(
                      lhs,
                      if isStackAlloc then Tracked(StStackAddr, rhsCall.id)
                      else
                        Tracked(
                          StAllocated,
                          rhsCall.id,
                          nullable = cf.exists(_.nullable),
                          region = regionKeyOf(rhsCall),
                          refs = 1
                        )
                    )
              case rhsCall: Call
                  if callFacts.get(rhsCall.id()).exists(_.region.exists(_.role == "allocate")) =>
                  // a REGION allocation the heap's families do not cover: owned memory whose
                  // region is the argument the entry named (or the named global), so the
                  // region's destroy and reset decide its fate and no exit reports it as a leak
                  out = out.updated(
                    lhs,
                    Tracked(
                      StAllocated,
                      rhsCall.id,
                      nullable = callFacts.get(rhsCall.id()).exists(_.nullable),
                      region = regionKeyOf(rhsCall),
                      refs = 1
                    )
                  )
              case rhsCall: Call
                  if (rhsCall._callOut.collectAll[Method].l.distinct match
                    case List(only) => effectsByMethod.get(only.id())
                    case _          => effectsByName.get(rhsCall.name)
                  ).exists(_.contains("effect:returns-freed")) =>
                  // the callee's summary says every value it returns is a pointer it released
                  out = out.updated(lhs, Tracked(StFreed, rhsCall.id))
              case rhsCall: Call
                  if effectsByName.get(rhsCall.name)
                      .exists(_.contains("effect:allocates-return")) &&
                      !callFacts.get(rhsCall.id()).exists(_.isAllocCall) =>
                  // The callee's own summary says every value it returns is a fresh
                  // allocation - a wrapper the body-shape inference could not conclude.
                  // An allocating wrapper's nullability is not stated by the summary, so the
                  // pointer is tracked as allocation-live only
                  out = out.updated(lhs, Tracked(StAllocated, rhsCall.id, refs = 1))
              case rhsCall: Call
                  if callFacts.get(rhsCall.id()).exists(_.nullable) =>
                  // a non-allocation nullable return (strchr, av_dict_get): not ownership,
                  // only nullness - leak/free rules never fire on it
                  out = out.updated(lhs, Tracked(StNullable, rhsCall.id, nullable = true))
              case rhsCall: Call if rhsCall.name == "<operator>.cast" =>
                  // `p = (char *)malloc(n)` - the allocation hides under the cast; so does the
                  // `(char **)&buf` a global stash takes
                  castOperand(rhsCall).flatMap { inner =>
                      inner match
                        case ic: Call if callFacts.get(ic.id()).exists(_.isAllocCall) =>
                            val icf  = callFacts.get(ic.id())
                            val stck = icf.exists(_.allocFamilies.contains("stack"))
                            Some(
                              // the stack family through its cast: frame storage
                              if stck then Tracked(StStackAddr, ic.id)
                              else
                                Tracked(
                                  StAllocated,
                                  ic.id,
                                  nullable = icf.exists(_.nullable),
                                  region = regionKeyOf(ic),
                                  refs = 1
                                )
                            )
                        case ic: Call
                            if callFacts.get(ic.id())
                                .exists(_.region.exists(_.role == "allocate")) =>
                            // the region allocation through its cast
                            Some(
                              Tracked(
                                StAllocated,
                                ic.id,
                                nullable = callFacts.get(ic.id()).exists(_.nullable),
                                region = regionKeyOf(ic),
                                refs = 1
                              )
                            )
                        case ic: Call if callFacts.get(ic.id()).exists(_.nullable) =>
                            Some(Tracked(StNullable, ic.id, nullable = true))
                        case ic if holdsStackAddress(ic, ctx) =>
                            Some(Tracked(StStackAddr, ic.id))
                        case other if trackedNameOf(other).isDefined =>
                            trackedNameOf(other).flatMap(n => out.get(n))
                        case _ => None
                  } match
                    case Some(t) => out = out.updated(lhs, t)
                    case None    =>
                        // the cast wraps a producer this transfer does not model (abseil's
                        // `Allocate` behind a reinterpret_cast): the old state must not
                        // survive it for the questions that read provenance exactly
                        if out.get(lhs).exists(t =>
                              staleOnRebind(t.state, rhs, lhs)
                          )
                        then out = out - lhs
              // a null store makes a NULL state only for a POINTER destination: the literal
              // 0 is the null literal only where it initialises a pointer, and an integer
              // counter born `= 0` is not a null pointer awaiting a check (bytes_read)
              case lit: Literal if isNullLiteral(lit) && argAt(cf.args, 1).exists(isPointerNode) =>
                  out = out.updated(lhs, Tracked(StNullReset, 0L))
              case other if isNullLiteral(other) && argAt(cf.args, 1).exists(isPointerNode) =>
                  // NULL macro-expanded into an identifier
                  out = out.updated(lhs, Tracked(StNullReset, 0L))
              // The rhs IS a stack address - a local's address taken, or an array local
              // decaying to a pointer - so the variable now carries frame storage
              case other if holdsStackAddress(other, ctx) =>
                  out = out.updated(lhs, Tracked(StStackAddr, other.id))
              case other =>
                  trackedNameOf(other) match
                    case Some(n) =>
                        useState.get(n) match
                          case Some(t) =>
                              out = out.updated(lhs, t.copy(aliases = Set.empty))
                              out = linkAlias(out, lhs, n)
                          case None =>
                              // the source is a name this frame does not track - a caller's
                              // parameter, a member nobody stored through here - so the value
                              // became whatever that carries, and the definite questions
                              // (every definition NULL, frame provenance) must not speak
                              if out.get(lhs).exists(t =>
                                    staleOnRebind(t.state, rhs, lhs)
                                )
                              then out = out - lhs
                        // `p = tmp` after `tmp = realloc(p, n)`: the block moved back into p,
                        // and tmp no longer owns it - else tmp leaks when p is returned
                        if rhsIsReallocOfLhs then out = out - n
                    case None =>
                        // a producer this transfer does not model - an unsummarised wrapper's
                        // call, a member read - must not leave a NULL state in place: the
                        // definite-null arm reads that state as "every definition reaching here
                        // is NULL or a guard's proof of it", and this assignment replaced the
                        // value with something the transfer cannot name (`irow = NULL; ...;
                        // irow = app_malloc_array(...)`, the NULL long stale). Ownership facts
                        // for LIVE blocks are untouched: those arms ask may-questions of the
                        // best fact available, as they always have
                        // the same holds for a frame-storage state: `stack = stack_buf; ...;
                        // stack = Allocate(n)` (a custom allocator the transfer does not
                        // know) must not keep the declared-array provenance alive to a
                        // later release of the reassigned pointer
                        if out.get(lhs).exists(t =>
                              staleOnRebind(t.state, rhs, lhs)
                          )
                        then out = out - lhs
            end match
            // a stack address stored into a GLOBAL variable outlives the frame: a plain
            // local or parameter destination rebinds only this frame's copy and escapes nothing
            argAt(cf.args, 1).foreach { dst =>
                dst match
                  case i: Identifier
                      if !ctx.locals.contains(i.name) && !ctx.params.contains(i.name) =>
                      escFacts.updateWith((c.id(), "escape:global")) {
                          case Some((_, prev)) => Some((c, joinPoints(prev, in)))
                          case None            => Some((c, in))
                      }
                      // the destination outlives this frame and the stored variable's
                      // scope-cleanup release is still to come: whether the store keeps a block
                      // the release then frees is what the release's state settles
                      val storedName = rhs match
                        case rc: Call if rc.name == "<operator>.cast" =>
                            castOperand(rc).flatMap(trackedNameOf)
                        case _ => trackedNameOf(rhs)
                      storedName.filter(ctx.cleanupReleased.contains).foreach { name =>
                        storeClaims.register(name, c)
                        out.get(name).foreach(t =>
                            out = out.updated(name, t.copy(pendingStores = t.pendingStores + c.id))
                        )
                      }
                  case _ => ()
            }
        case (None, Some(rhs)) =>
            // stored into a struct member or through another non-trackable destination: the
            // pointer escapes - ownership left this method's variable space. A string
            // destination is the exception: std::string's operator= copies the characters,
            // so a heap block assigned through it is still exactly where it was
            val stringDst = argAt(cf.args, 1).exists(isStringDestination)
            val rhsTracked = rhs match
              case rc: Call if rc.name == "<operator>.cast" =>
                  castOperand(rc).flatMap(trackedNameOf)
              case _ => trackedNameOf(rhs)
            if !stringDst then
              rhsTracked.foreach { name =>
                out.get(name).foreach { t =>
                  out = withGroup(out, name, t.aliases, StEscaped)
                  out = out.updated(name, t.copy(state = StEscaped))
                }
                // the destination outlives this frame and the variable's scope-cleanup
                // release is still to come: whether the store keeps a block the release then
                // frees is what the release's state settles
                if ctx.cleanupReleased.contains(name) then
                  storeClaims.register(name, c)
                  out.get(name).foreach(t =>
                      out = out.updated(name, t.copy(pendingStores = t.pendingStores + c.id))
                  )
              }
            // ... and the field itself is tracked from here: a fresh block, a reset, or unknown
            fieldLhs.foreach { f =>
              val alloc = rhs match
                case rc: Call if rc.name == "<operator>.cast" =>
                    castOperand(rc).collect { case ic: Call => ic }
                case rc: Call => Some(rc)
                case _        => None
              val regionOnly = alloc.find(a =>
                  callFacts.get(a.id()).exists(_.region.exists(_.role == "allocate"))
              )
              if alloc.exists(a => callFacts.get(a.id()).exists(_.isAllocCall)) then
                out = out.updated(
                  f,
                  Tracked(StAllocated, alloc.get.id, region = regionKeyOf(alloc.get), refs = 1)
                )
              else if regionOnly.isDefined then
                out = out.updated(
                  f,
                  Tracked(
                    StAllocated,
                    regionOnly.get.id,
                    nullable = callFacts.get(regionOnly.get.id()).exists(_.nullable),
                    region = regionKeyOf(regionOnly.get),
                    refs = 1
                  )
                )
              else if isNullLiteral(rhs) then out = out.updated(f, Tracked(StNullReset, 0L))
              else out = out - f
            }
            // ... and a stack address stored there escapes the frame with it - unless
            // "there" is itself frame storage: a member or element of a by-value local
            if !argAt(cf.args, 1).exists(isFrameStorage(_, ctx)) then
              escFacts.updateWith((c.id(), "escape:store")) {
                  case Some((_, prev)) => Some((c, joinPoints(prev, in)))
                  case None            => Some((c, in))
              }
        case _ => ()
      end match
    end if

    // 4. index and field accesses through a tracked base are uses - as an operator's operand,
    //    and as any call's argument: `printf("%c", p[0])` reads through p as surely as `p[0] = 1`
    //    writes through it (else a loop that frees p after that printf goes unreported). The
    //    CFG does not always deliver nested expressions as their own nodes (`v = *p + seed`
    //    visits the assignment only), so the scan recurses through operator arguments.
    //    A compile-time query is not a use any way it is reached - as the statement's own
    //    call (`sizeof(*p)` visits the sizeOf) or as a nested argument: sizeof never
    //    evaluates its operand, and reading `p = app_malloc(sizeof(*p), ...)`'s sizing
    //    argument as a dereference would judge p by the NULL it was initialised to, one
    //    statement before the assignment gives it a value
    val compileTimeQuery = c.name.startsWith("<operator>.sizeOf") ||
        c.name.startsWith("<operator>.alignOf")
    if !compileTimeQuery then
      cf.args.foreach(arg => useFactsIn(arg, 3, useState, Some(nullUseFacts), record))
    // a C++ construction (`new T(args)`) is an operator call whose arguments are handed to
    // the constructor: a tracked fd or pointer argument is owned by the new object from here
    // on. It falls through to the generic argument escape below - leaving it tracked-live
    // would report every later exit as a leak of a resource the object now owns (leveldb's
    // env-wrapper shape)
    if isOperatorCall(cf.name) && cf.name != "<operator>.new" &&
      !(cf.name == "<operator>.pointerCall" && c._callOut.collectAll[Method].l.size == 1)
    then ()
    // a compile-time query keeps nothing it is handed (`__builtin_object_size(p, 0)` in a
    // fortified call's expansion), and inside a macro that stands for an inventoried API
    // (`memset` defined as `__builtin___memset_chk(...)`) the expansion's call IS the macro's
    // call, already read as that API's use
    else if NonRetainingBuiltins.contains(cf.name) || expandsInventoriedMacro(c) then ()
    else if cf.isMemoryCall && cf.name != "<operator>.new" then
      // 5. an inventoried memory call USES its pointer arguments; ownership unchanged. Only
      //    the positions the inventory says the call READS THROUGH (dst/src) are uses for the
      //    null question - the freed argument of a free-family call never is (free(NULL) is a
      //    no-op), and a length is an integer, not a pointer
      cf.args.filter(a => cf.readsThrough.contains(a.argumentIndex)).foreach { arg =>
        val use             = arg
        val nullSafeUseSite = cf.freeFamilies.nonEmpty && arg.argumentIndex == 1
        trackedNameOf(use).foreach { name =>
            useState.get(name).foreach { t =>
              if t.state == StFreed || t.state == StMaybeFreed then
                record(use, TagState, stateName(t.state))
                recordFreedomMarks(use, t, record)
              if !nullSafeUseSite then noteNullUse(nullUseFacts, use, name, t)
            }
        }
      }
      // a declared cleanup function frees the block its argument's slot holds: a second
      // release of a block already freed there is the double free at the cleanup call
      if cf.cleanup then
        argAt(cf.args, 1).foreach { arg =>
            addressOfOperand(unwrapCastOperand(arg)).foreach { operand =>
                trackedNameOf(operand).foreach { name =>
                    useState.get(name).foreach { t =>
                      if t.state == StFreed || t.state == StMaybeFreed then
                        record(operand, TagState, ValueSummaryFreed)
                      out = out.updated(name, t.copy(state = StNullReset))
                      storeClaims.settle(name, t)
                    }
                }
            }
        }
      // a declared steal empties the slot it is handed the address of and moves the block to
      // its result, as the body-inferred steal does
      cf.args.filter(a => cf.stealPositions.contains(a.argumentIndex)).foreach { arg =>
          addressOfOperand(unwrapCastOperand(arg)).foreach { operand =>
              trackedNameOf(operand).foreach { name =>
                  useState.get(name).foreach(t =>
                      out = out.updated(name, t.copy(state = StNullReset))
                  )
              }
          }
      }
      // a call that takes over an argument's resource (`fdopen`'s descriptor) hands it to
      // what it returns: the variable no longer owns it, so its exits leak nothing
      cf.args.filter(a => cf.retainPositions.contains(a.argumentIndex)).foreach { arg =>
          trackedNameOf(arg).foreach { name =>
              out.get(name).foreach { t =>
                  if t.state == StAllocated then
                    out = withGroup(out, name, t.aliases, StEscaped)
                    out = out.updated(name, t.copy(state = StEscaped))
              }
          }
      }
    else
      // 6. any other call escapes its tracked pointer arguments: an addressOf argument escapes
      //    the ADDRESS - the callee may free or store through it. An argument the callee's
      //    summary FREES is recorded by the summary below, as the free site itself - not twice,
      //    once as a generic use. A plain argument is a null-USE only when the callee is
      //    evidence-backed as reading through that position - a `derefs-param` summary of its
      //    own. An external callee with no inventory entry is not a dereference, and neither is
      //    `&p`: handing the slot is not reading through the pointer.
      // the callee's effects: the ONE body the call's own CALL edge resolves (Juliet's C++
      // variants name every file's sink alike, and a name shared by disagreeing bodies carries
      // nothing), falling back to the name-level table when no edge resolves
      val resolvedEffects: Option[Set[String]] =
          c._callOut.collectAll[Method].l.distinct match
            case List(only) => effectsByMethod.get(only.id())
            case _          => fpTargets.get(cf.name).flatMap(id => effectsByMethod.get(id))
      val nameEffects: Option[Set[String]] = effectsByName.get(cf.name)
      val effectsInForce: Set[String] =
          resolvedEffects.getOrElse(nameEffects.getOrElse(Set.empty))
      def positionsOf(prefix: String): Set[Int] =
          effectsInForce
              .filter(_.startsWith(prefix))
              .map(_.stripPrefix(prefix).toInt)
      val summaryFreedArgs: Set[Int] =
          positionsOf("effect:frees-param:") ++ positionsOf("effect:freep-param:")
      // the READS question accumulates every conclusion: the resolved body's own, the
      // name-level agreement, and a DECLARED nonnull contract - a body the graph resolves
      // must not silence what its declaration promises. The frees/escapes questions stay
      // with the conclusions in force
      val summaryDerefsArgs: Set[Int] =
          (effectsInForce ++ nameEffects.getOrElse(Set.empty) ++ resolvedEffects.getOrElse(
            Set.empty
          )).filter(_.startsWith("effect:derefs-param:"))
              .map(_.stripPrefix("effect:derefs-param:").toInt)
      // a BORROW: the callee's own body is in the graph and its effects say it neither frees
      // nor stores nor passes the pointer on to anything unknown - handing it the block moves
      // no ownership, so the allocation stays this frame's to free or leak. A callee nothing
      // concludes about keeps the conservative escape
      val retainedArgs: Set[Int] =
          positionsOf("effect:escapes-param:") ++ summaryFreedArgs ++
              positionsOf("effect:maybe-frees-param:")
      cf.args.foreach { arg =>
        val viaAddress       = addressOfOperand(arg)
        val operand          = unwrapCastOperand(viaAddress.getOrElse(arg))
        val summaryFreesThis = summaryFreedArgs.contains(arg.argumentIndex)
        // an AGREEMENT-COLLAPSED empty name summary is a disagreement (some same-named method
        // retains, some do not): it concludes nothing. A resolved body's own empty effect set
        // IS a conclusion - the body frees, stores and passes on nothing - UNLESS the callee
        // is a constructor: its parameters become the new object's state through initialiser
        // lists the effect reader does not see, and a constructor retains by construction
        val intoConstructor = c._callOut.collectAll[Method].l.exists(m =>
            m.astParent.isInstanceOf[TypeDecl]
        )
        val concluded = !intoConstructor &&
            (resolvedEffects.isDefined || nameEffects.exists(_.nonEmpty))
        val borrowed = viaAddress.isEmpty && !retainedArgs.contains(arg.argumentIndex) &&
            concluded
        trackedNameOf(operand).foreach { name =>
            useState.get(name).foreach { t =>
              // handing a dangling pointer to a callee whose body never mentions that parameter is
              // not a use of the freed block; a call through a function pointer takes only the callee's
              // release effects, as before
              val calleeIgnores = cf.name == "<operator>.pointerCall" || viaAddress.isEmpty &&
                  (c._callOut.collectAll[Method].l.distinct match
                    case List(only) =>
                        !only.isExternal && only.block.astChildren.nonEmpty &&
                        only.parameter.l.find(_.index == arg.argumentIndex).exists(p =>
                            !only.block.ast.isIdentifier.l.exists(_.name == p.name)
                        )
                    case _ => false
                  )
              // handing the variable's ADDRESS is not a use of the block it held: the callee is
              // given the slot, and may well fill it (`getSafeInfoString(s, n, &tmp)` stores a
              // fresh string into the slot whose previous block the last iteration freed)
              if (t.state == StFreed || t.state == StMaybeFreed) && !summaryFreesThis &&
                !calleeIgnores && viaAddress.isEmpty
              then
                record(operand, TagState, stateName(t.state))
                recordFreedomMarks(operand, t, record)
              if viaAddress.isEmpty && summaryDerefsArgs.contains(arg.argumentIndex) then
                noteNullUse(nullUseFacts, operand, name, t)
              if !borrowed then
                out = withGroup(out, name, t.aliases, StEscaped)
                out = out.updated(name, t.copy(state = StEscaped))
            }
        }
        // the callee may rewrite the members of what it was handed
        operand match
          case i: Identifier => out = dropFieldsOf(out, i.name)
          case _             => ()
      }
      // a callee whose body assigns a global this frame tracks (`server.aof_manifest =
      // ...` in the loader the caller runs after freeing the old manifest) leaves that global
      // holding whatever the callee stored: no longer a block this frame knows
      c._callOut.collectAll[Method].l.distinct match
        case List(only) if !only.isExternal && only.block.astChildren.nonEmpty =>
            val frameNames =
                (c.method.local.name.l ++ c.method.parameter.name.l).toSet
            val assigned = only.ast.isCall.l.filter(a =>
                OverlayFacts.isAssignmentOperator(a.name)
            ).flatMap(_.argumentOption(1).map(_.code.replaceAll("\\s+", ""))).toSet
            out.keys.filter(n => isFieldName(n) || !frameNames.contains(n))
                .filterNot(n => frameNames.contains(countBaseOf(n)))
                .filter(assigned.contains)
                .foreach { n =>
                    out.get(n).foreach(t => out = out.updated(n, t.copy(state = StEscaped)))
                }
        case _ => ()
      // ... and the callee's effect summary, AFTER the generic escape: a call to a method
      // that unconditionally frees one of its parameters frees the matching argument HERE - an
      // interprocedural free as a tag lookup, the existing double-free fact carrying the report.
      // It runs last because the summary is MORE SPECIFIC than "escaped": the callee did not
      // merely take the pointer, it released it.
      // a conditional free the callee guards with a file-static flag happens when the caller has
      // set the flag to a nonzero constant before this call
      def flagSetBefore(flag: String): Boolean =
        val line = c.lineNumber.map(_.toInt).getOrElse(0)
        val stores = c.method.ast.isCall.nameExact("<operator>.assignment").l
            .filter(a =>
                a.lineNumber.exists(_.toInt < line) && a.argumentOption(1).exists {
                    case i: Identifier => i.name == flag
                    case _             => false
                }
            )
            .sortBy(_.lineNumber.map(_.toInt).getOrElse(0))
        // every store before the call is a nonzero constant, and the last one runs whenever the
        // call does: `if (x) badStatic = 1;` leaves the flag unknown on the other path
        val callControllers = c._cdgIn.l.map(_.id()).toSet
        stores.nonEmpty && stores.forall(
          _.argumentOption(2).flatMap(IndexRange.literal).exists(_ != 0)
        ) && stores.last._cdgIn.l.forall(n => callControllers.contains(n.id()))
      val summaryFreeFacts: Set[String] = effectsInForce.collect {
          case e if e.startsWith("effect:frees-param-if-static:") =>
              val Array(idx, flag) = e.stripPrefix("effect:frees-param-if-static:").split(":", 2)
              if flagSetBefore(flag) then s"effect:frees-param:$idx" else ""
      }.filter(_.nonEmpty)
      (effectsInForce ++ summaryFreeFacts).foreach {
          case e if e.startsWith("effect:frees-param:") =>
              val idx = e.stripPrefix("effect:frees-param:").toInt
              argAt(cf.args, idx).foreach { arg =>
                val operand = addressOfOperand(arg).getOrElse(arg)
                // an inferred destroy called with a REGION handle tears the blocks the method
                // took from that region down, the same way a declared destroy does
                regionNameOf(arg).foreach(key => out = moveRegionBlocks(out, key, freed = true))
                trackedNameOf(operand).foreach { name =>
                    useState.get(name).foreach { t =>
                      if t.state == StFreed || t.state == StMaybeFreed then
                        // THIS call is the second free: the value names it as the
                        // free site, which is how the rule tells a double free from a
                        // use-after-free
                        record(operand, TagState, ValueSummaryFreed)
                        // the callee's own release of that parameter is a site of the same
                        // finding: the suites mark the flaw where the second release is written
                        (c._callOut.collectAll[Method].l.distinct match
                          case Nil =>
                              val viaPointer: List[Method] = fpTargets.get(cf.name)
                                  .flatMap(id => Option(atom.graph.node(id)))
                                  .collect { case m: Method => m }.toList
                              if viaPointer.nonEmpty then viaPointer
                              else atom.method.nameExact(cf.name).filterNot(_.isExternal).l
                          case linked => linked
                        ) match
                          case List(callee) =>
                              callee.parameter.l.find(_.index == idx).foreach { param =>
                                  callee.ast.isCall.l.filter(fc =>
                                      fc.tag.name(MemoryApiPass.TagFree).nonEmpty
                                  )
                                      .flatMap(fc =>
                                          fc.argumentOption(1).collect { case e: Expression =>
                                              unwrapCast(e)
                                          }
                                      )
                                      .collect { case i: Identifier if i.name == param.name => i }
                                      .foreach(i => record(i, TagState, ValueSummaryFreed))
                              }
                          case _ => ()
                        end match
                      end if
                      // a slot that holds no block (NULL, or reset to it) frees nothing when the
                      // callee releases through it: the slot stays empty rather than dangling
                      if t.state != StNullable && !isNullState(t.state) then
                        out = withGroup(out, name, t.aliases, StFreed)
                        out = out.updated(name, t.copy(state = StFreed))
                      storeClaims.settle(name, t)
                    }
                }
              }
          case e if e.startsWith("effect:freep-param:") =>
              val idx = e.stripPrefix("effect:freep-param:").toInt
              argAt(cf.args, idx).foreach { arg =>
                val operand = addressOfOperand(arg).getOrElse(arg)
                trackedNameOf(operand).foreach { name =>
                    useState.get(name).foreach { t =>
                      if t.state == StFreed || t.state == StMaybeFreed then
                        record(operand, TagState, ValueSummaryFreed)
                      // the callee nulls the slot through the address it was given:
                      // the caller's variable holds NULL from here, not a dangling
                      // pointer
                      out = out.updated(name, t.copy(state = StNullReset))
                      storeClaims.settle(name, t)
                    }
                }
              }
          case e if e.startsWith("effect:steals-param:") =>
              val idx = e.stripPrefix("effect:steals-param:").toInt
              argAt(cf.args, idx).foreach { arg =>
                  // the argument's address, through the cast a typed spelling wraps it in
                  addressOfOperand(unwrapCastOperand(arg)).foreach { operand =>
                      trackedNameOf(operand).foreach { name =>
                          useState.get(name).foreach { t =>
                              // the block moves to the call's result and the slot is left empty:
                              // nothing is released here, so no double-free fact, and the caller's
                              // variable is spent exactly as a resetting freep leaves it
                              out = out.updated(name, t.copy(state = StNullReset))
                          }
                      }
                  }
              }
          case _ => ()
      }
      // ... and a move into a by-value or rvalue-reference parameter of an owning type spends
      // the source: a unique_ptr's move construction takes the pointer and leaves the source
      // null, so from here the source variable is tracked AS null - a later read through it is
      // the null rule's question. The parameter's type is the resolved callee's own fact; the
      // name `move` is never consulted
      val callees = c._callOut.collectAll[Method].l
      cf.args.foreach {
          case i: Identifier
              if callees.exists(m => movesOwningParameter(m, i.argumentIndex)) ||
                  movesOwningSignature(c.methodFullName, i.argumentIndex) =>
              out = out.updated(i.name, Tracked(StNull, c.id, nullable = true))
          case _ => ()
      }
    end if
    out
  end transferCall

  /** Guard narrowing at an `==`/`!=` NULL comparison: on paths where `p == NULL` holds, p is null;
    * where `p != NULL` (or the negation) holds, a nulled p is live again. Which side a successor
    * sits on is decided by [[branchOf]].
    *
    * The int-handle failure check shares the same fold: an fd-returning family's sentinel is -1,
    * not NULL, and the exit under `fd < 0` holds no descriptor - narrowing it the way a NULL check
    * narrows a pointer keeps the failure path from reporting a leak.
    */
  private def branchNarrowing(
    cond: CfgNode,
    cs: ControlStructure,
    succ: CfgNode,
    out: Map[String, Tracked],
    isOwningSite: Long => Boolean,
    isHandleSite: Long => Boolean,
    reallocInputOf: Long => Option[String]
  ): Map[String, Tracked] =
    // branchOf: Some(true) where the condition holds on this successor, None when unknown
    val facts: List[(String, Option[Boolean])] = branchOf(succ, cs) match
      case Some(holds) =>
          val nulls = nullFacts(cond, holds)
          nulls.map { case (n, nullHere) => (n, Some(nullHere)) } ++
              handleFailureSides(cond, out, isHandleSite)
                  .map { case (n, failureHolds) => (n, Some(holds == failureHolds)) } ++
              errorChannelFacts(nulls, out)
      case None => Nil
    facts.foldLeft(out) { case (acc, (name, nullHereOpt)) =>
        nullHereOpt match
          case Some(nullHere) =>
              acc.get(name) match
                case Some(t) if !nullHere && t.state == StNull && !isOwningSite(t.site) =>
                    // the non-null side of a pointer known only to be NULL - one a guard
                    // created (`if (!ret)` tracks ret as null) or a strchr result a guard
                    // nulled: nothing on this side owns memory, so the variable is untracked
                    // again. Reviving it as `allocated` would create a phantom allocation
                    // that leaks at every later exit.
                    acc - name
                case Some(t) =>
                    val newState =
                        if nullHere then StNull
                        else if t.state == StNull then StAllocated
                        else t.state
                    // the non-null side of a guard on a nullable-produced pointer is the
                    // check itself: downstream uses of it are not unchecked
                    val narrowed = acc.updated(
                      name,
                      t.copy(state = newState, checked = t.checked || !nullHere)
                    )
                    // `tmp = realloc(p, n)` succeeded on this side: realloc consumed p (the
                    // block moved to tmp), so p is released here - a read of it is a use after
                    // free, and it no longer leaks. On the NULL side p is still the block
                    reallocInputOf(t.site).filter(in => !nullHere && in != name).flatMap(in =>
                        narrowed.get(in).map(in -> _)
                    ).map { case (in, it) => narrowed.updated(in, it.copy(state = StFreed)) }
                        .getOrElse(narrowed)
                case None =>
                    // an untracked pointer that is provably null becomes tracked-as-null;
                    // nothing downstream reports on it either way
                    if nullHere then acc.updated(name, Tracked(StNull, 0L)) else acc
          case None => acc
    }
  end branchNarrowing

  /** A call to a function that does not return: declared `noreturn` (on the call, from its
    * declaration, or on the METHOD it links to), one of the C library's terminators when no header
    * said so, or a function whose own body can only end in a terminator (a cleanup helper whose
    * every path reaches `exit` - its callers' paths end at the call, whatever it frees first), when
    * every function the call links to is one.
    */
  private def isNoReturnCall(node: CfgNode): Boolean = node match
    case c: Call if !c.name.startsWith("<operator") =>
        NoReturnFunctions.contains(c.name) ||
        c.tag.nameExact(io.appthreat.x2cpg.Defines.FunctionAttributeTag).value.l.contains(
          "noreturn"
        ) ||
        c._callOut.collectAll[Method].exists(
          _.tag.nameExact(io.appthreat.x2cpg.Defines.FunctionAttributeTag).value.l.contains(
            "noreturn"
          )
        ) || {
            // every function the call can reach ends in a terminator: two static helpers of one
            // name in two files are two answers, and the one that returns decides
            val callees = c._callOut.collectAll[Method].l
            callees.nonEmpty && callees.forall(neverReturnsByBody)
        }
    case _ => false

  /** Whether every path through the method's body reaches its return only through a call that does
    * not return: each of the return's CFG predecessors is itself one. A method still being walked
    * answers no (a cycle of calls each ending in the other says nothing about either).
    */
  private val neverReturnsMemo    = mutable.HashMap.empty[Long, Boolean]
  private val neverReturnsWalking = mutable.HashSet.empty[Long]
  private def neverReturnsByBody(m: Method): Boolean =
      neverReturnsMemo.get(m.id()) match
        case Some(known) => known
        case None =>
            if neverReturnsWalking.add(m.id()) then
              val answer = m.methodReturn._cfgIn.collectAll[CfgNode].l match
                case preds if preds.nonEmpty => preds.forall(isNoReturnCall)
                case _                       => false
              neverReturnsWalking.remove(m.id())
              neverReturnsMemo.update(m.id(), answer)
              answer
            else false

  /** The error channel of a C API: `db = leveldb_open(opts, name, &err)` returns NULL exactly when
    * it sets `err`. Where a guard proves `err` NULL the call succeeded and its result is not NULL;
    * where it proves `err` set, the result is NULL - the same two sides `if (!db)` gives. `nulls`
    * are the condition's null facts on this side: (variable, whether it is NULL here).
    */
  private def errorChannelFacts(
    nulls: List[(String, Boolean)],
    out: Map[String, Tracked]
  ): List[(String, Option[Boolean])] =
      if nulls.isEmpty then Nil
      else
        out.toList.flatMap { (name, t) =>
            if t.site == 0L || !t.nullable then Nil
            else
              val channel = errorOutParams(t.site)
              nulls.collectFirst { case (err, errNull) if channel.contains(err) => errNull }
                  .map(errNull => (name, Some(!errNull)))
                  .toList
        }

  private val errorOutParamCache = mutable.LongMap.empty[Set[String]]

  /** The variables whose address the producing call at `site` (the call, or the assignment of its
    * result) received: where it reports an error.
    */
  private def errorOutParams(site: Long): Set[String] =
      errorOutParamCache.getOrElseUpdate(
        site,
        Option(atom.graph.node(site)).collect { case c: Call => c }.toList
            .flatMap(c => c :: c.ast.isCall.l)
            .filterNot(_.name.startsWith("<operator"))
            .flatMap(_.argument.l)
            .collect { case a: Call if a.name == "<operator>.addressOf" => a }
            .flatMap(_.argument.l.collect { case i: Identifier => i.name })
            .toSet
      )

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
    * statement, the implicit end. Answering None there would let `if (p) free(p);` flow into the
    * join un-narrowed and report a leak at the implicit end on the path where the free never ran.
    * Answering by child index alone - 1 then, 2 else, everything else false - would put a for
    * loop's body (child 3) and a do-while's (child 0) on the FALSE edge: `for (e = strchr(..); e !=
    * NULL; ..) e[1]` would mark `e` definitely NULL inside its loop.
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

  /** The region the joined entry answers to. Equal regions join to themselves. When the sides
    * disagree, the side with no live block (a null init, a freed or spent slot) yields to the
    * region the other side drew from: the only block the join can carry is that one. Two sides that
    * each hold a live block from different regions join to none.
    */
  private def joinRegions(ta: Tracked, tb: Tracked): Option[String] =
      if ta.region == tb.region then ta.region
      else
        def spent(t: Tracked): Boolean =
            t.state == StNull || t.state == StNullReset || t.state == StFreed
        (ta.region, tb.region) match
          case (r, None) if spent(tb) => r
          case (None, r) if spent(ta) => r
          case _                      => None

  private def joinPoints(
    a: Map[String, Tracked],
    b: Map[String, Tracked]
  ): Map[String, Tracked] =
      // most joins meet the same state from both sides: start from one side and merge only the
      // entries the other changes, instead of rebuilding the map
      if (a eq b) || b.isEmpty then a
      else if a.isEmpty then b
      else
        var merged = a
        b.foreach { (name, tb) =>
            a.get(name) match
              case Some(ta) if ta == tb => ()
              case Some(ta)             =>
                  // the owned-reference count: a side that holds no block says nothing about
                  // it, so the other side's count stands. Two live paths that disagree (an
                  // acquire on one branch, a loop's back edge) leave a count this frame cannot
                  // know, and the block becomes the pass's unknown: no use after it, second
                  // release or leak is claimed from a guess at the count
                  val (refs, countUnknown) =
                      if isNullState(ta.state) then (tb.refs, false)
                      else if isNullState(tb.state) then (ta.refs, false)
                      else if ta.refs != tb.refs && ta.state == StAllocated && tb.state == StAllocated
                      then (0, true)
                      else (math.max(ta.refs, tb.refs), false)
                  // the site is the SMALLER id, whatever the fold order: an order-dependent
                  // merge let the worklist oscillate between (Allocated, s1) and
                  // (Allocated, s2) around allocation loops and never terminate. A side that
                  // holds no block (the NULL init, site 0) says nothing about where the block
                  // came from: the live side's site stands, so a region site's block keeps the
                  // exemption its site gives it
                  val site =
                      if isNullState(ta.state) && !isNullState(tb.state) then tb.site
                      else if isNullState(tb.state) && !isNullState(ta.state) then ta.site
                      else math.min(ta.site, tb.site)
                  merged = merged.updated(
                    name,
                    Tracked(
                      if countUnknown then StEscaped else joinStates(ta.state, tb.state),
                      site,
                      nullable = ta.nullable || tb.nullable,
                      checked = ta.checked && tb.checked,
                      aliases = ta.aliases.intersect(tb.aliases),
                      // a block one path drew from region A and another from region B is
                      // under no single region's rule; the reset claim joins like nullable.
                      // A side that holds NO block at all (the null init, an already spent
                      // or freed slot) takes the other side's region: the live block the
                      // join keeps is the drawn one, and dropping its region here is what
                      // leaked the `p = NULL; ... if (c) p = region_get(...)` shape at the
                      // frame exit
                      region = joinRegions(ta, tb),
                      resetByRegion = ta.resetByRegion || tb.resetByRegion,
                      // the borrowed and release marks join like the reset claim
                      refs = refs,
                      borrowed = ta.borrowed || tb.borrowed,
                      freedByRelease = ta.freedByRelease || tb.freedByRelease,
                      pendingStores = ta.pendingStores ++ tb.pendingStores,
                      countUnknown = countUnknown || ta.countUnknown || tb.countUnknown
                    )
                  )
              case None => merged = merged.updated(name, tb)
        }
        merged

  /** The leak fact an exit carries: the JOIN of the state over every visit of that exit, not the
    * latest visit's - the join is commutative, so the claim does not depend on the order the
    * worklist happened to deliver paths in.
    */
  private def noteLeak(
    leakFacts: mutable.LinkedHashMap[(Long, Long, String), (StoredNode, AllocState)],
    key: (Long, Long, String),
    value: (StoredNode, AllocState)
  ): Unit =
      leakFacts.updateWith(key) {
          case Some((prevExit, prevState)) => Some((prevExit, joinStates(prevState, value._2)))
          case None                        => Some(value)
      }

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

  /** The variable a call's result is stored into, through any casts: `tmp = (T *)realloc(p, n)`. */
  private def assignedTarget(c: Call): Option[String] =
    // through casts and through the macro invocation that spells the call: `arr =
    // curlx_realloc(elem, n)` stores the expansion's realloc (a block under the INLINED call)
    // into arr, not into elem
    def isInlined(n: AstNode): Boolean = n match
      case m: Call =>
          m.dispatchType == io.shiftleft.codepropertygraph.generated.DispatchTypes.INLINED
      case _ => false
    def up(n: AstNode): Option[AstNode] = n._astIn.nextOption().collect { case a: AstNode => a }
    var parent                          = up(c)
    while parent.exists {
          case p: Call  => p.name == "<operator>.cast" || isInlined(p)
          case b: Block => up(b).exists(isInlined)
          case _        => false
      }
    do parent = parent.flatMap(up)
    parent
        .collect { case a: Call if a.name == "<operator>.assignment" => a }
        .flatMap(a => a.argument.l.find(_.argumentIndex == 1))
        .flatMap(trackedNameOf)
  end assignedTarget

  /** The node's own declared type is a pointer: the null questions are pointer questions, and an
    * integer counter born `= 0` is not a null pointer awaiting a check.
    */
  private def isPointerNode(d: AstNode): Boolean =
    val t = String.valueOf(d.property("TYPE_FULL_NAME")).trim
    t.nonEmpty && OverlayFacts.isPointer(t)

  private def trackedNameOf(e: AstNode): Option[String] = e match
    case i: Identifier => Some(i.name)
    // `s->p` / `s.p` over an identifier base: a field is tracked as its own variable
    case c: Call
        if c.name == "<operator>.indirectFieldAccess" || c.name == "<operator>.fieldAccess" =>
        (c.argumentOption(1), c.argumentOption(2)) match
          case (Some(b: Identifier), Some(f: FieldIdentifier)) =>
              val sep = if c.name == "<operator>.indirectFieldAccess" then "->" else "."
              Some(s"${b.name}$sep${f.canonicalName}")
          case _ => None
    case _ => None

  /** Is the rhs the handle `name` moved inside its own block - `p + 4`, `p - k`, `&p[i]`, through
    * casts? That keeps the block reachable. Any other rhs that merely mentions p (`p = strdup(p)`,
    * `p = f(p)`) produces a different value and loses the old block.
    */
  private def movesHandle(e: Expression, name: String): Boolean = unwrapCast(e) match
    case i: Identifier => i.name == name
    case c: Call if c.name == "<operator>.addition" || c.name == "<operator>.subtraction" =>
        argAt(c.argument.l, 1).exists(movesHandle(_, name)) ||
        (c.name == "<operator>.addition" && argAt(c.argument.l, 2).exists(movesHandle(_, name)))
    case c: Call if c.name == "<operator>.addressOf" =>
        argAt(c.argument.l, 1).exists {
            case ia: Call if ia.name == "<operator>.indexAccess" =>
                argAt(ia.argument.l, 1).exists(movesHandle(_, name))
            case _ => false
        }
    case _ => false

  private def unwrapCast(e: Expression): Expression = e match
    case c: Call if c.name == "<operator>.cast" => castOperand(c).map(unwrapCast).getOrElse(e)
    case other                                  => other

  /** Is this call nested inside the method's own try block? An unwind there is handled before it
    * leaves the frame, so the frame's live allocations survive it.
    */
  private def insideTry(c: Call): Boolean =
    var cursor: Option[StoredNode] = c._astIn.nextOption()
    var found                      = false
    var walking                    = true
    while walking && cursor.isDefined do
      cursor.get match
        case cs: ControlStructure if cs.controlStructureType.equalsIgnoreCase("TRY") =>
            found = true
            walking = false
        case _: Method => walking = false
        case other     => cursor = other._astIn.nextOption()
    found

  /** The same question off the resolved signature a call carries: a template's parameters are often
    * typed ANY while the signature spells them (`std.unique_ptr<...> &&`). The parameter list is
    * split at the depth-zero commas; the argument's position names its parameter.
    */
  private def movesOwningSignature(callee: String, argIndex: Int): Boolean =
    val open = callee.indexOf('(')
    if open < 0 then return false
    val close = callee.lastIndexOf(')')
    if close <= open then return false
    var depth = 0
    val parts = scala.collection.mutable.ListBuffer.empty[String]
    val cur   = StringBuilder()
    callee.substring(open + 1, close).foreach { ch =>
      ch match
        case '(' | '<' => depth += 1
        case ')' | '>' => depth -= 1
        case _         => ()
      if ch == ',' && depth == 0 then
        parts += cur.result()
        cur.clear()
      else cur += ch
    }
    parts += cur.result()
    // the callee numbers its parameters from 1; a member call's receiver occupies argument 0,
    // so the argument's own index and the one before it both name a parameter
    // a single `&` spells a template-derived rvalue reference too (`std.move:...(T &)`,
    // the instantiated `_Tp&&`): the callee's rvalue-reference RETURN names the move family,
    // while a plain lview borrower returns something else
    val returnsRvalue = callee.substring(0, open).trim.endsWith("&&")
    Seq(argIndex, argIndex - 1).flatMap(i => parts.lift(i - 1)).exists { t =>
      val x = t.trim
      val byMove = x.endsWith("&&") || !x.endsWith("&") ||
          (returnsRvalue && x.endsWith("&"))
      byMove && x.stripSuffix("&&").trim.contains("unique_ptr<")
    }
  end movesOwningSignature

  /** Whether the method's parameter at `index` takes an owning unique pointer BY VALUE or by rvalue
    * reference - the two forms whose argument is spent by the call. An lvalue reference (`&`)
    * borrows; the moved-from question is not asked of it.
    */
  private def movesOwningParameter(method: Method, index: Int): Boolean =
      method.parameter.index(index).headOption.exists { p =>
        val t      = Option(p.typeFullName).map(_.trim).getOrElse("")
        val byMove = t.endsWith("&&") || !t.endsWith("&")
        byMove && t.stripSuffix("&&").trim.contains("unique_ptr<")
      }

  /** A tracked field path: its block is owned by the struct, so it never leaks from the frame. */
  private def isFieldName(name: String): Boolean = name.contains("->") || name.contains(".")

  /** The variable a tracked field path hangs from: `it->refs` and `it.obj` name `it`. */
  private def countBaseOf(name: String): String =
      Seq(name.indexOf("->"), name.indexOf('.')).filter(_ >= 0).minOption match
        case Some(sep) if sep > 0 => name.substring(0, sep)
        case _                    => name

  /** The (object, count field) pair a count-arithmetic operand names: `r->refs` hangs the count
    * field `refs` from `r`, through the casts a typed spelling wraps it in.
    */
  private def countedPairOf(e: AstNode): Option[(String, String)] =
      trackedNameOf(e).flatMap { name =>
          if !isFieldName(name) then None
          else
            val base  = countBaseOf(name)
            val field = name.substring(base.length).stripPrefix("->").stripPrefix(".")
            Option.when(field.nonEmpty)((base, field))
      }

  /** The object a release or acquire argument names: the pointer itself (through casts), or the
    * CONTAINER a count field's address names - `kref_put(&o->ref, release)` drops a reference of
    * the object the field hangs from, not of the field.
    */
  private def releasedObjectName(e: Expression): Option[String] =
      unwrapCast(e) match
        case c: Call if c.name == "<operator>.addressOf" =>
            c.argumentOption(1).map(unwrapCast).flatMap {
                case i: Identifier => Some(i.name)
                case f: Call
                    if f.name == "<operator>.indirectFieldAccess" ||
                        f.name == "<operator>.fieldAccess" =>
                    f.argumentOption(1).collect { case i: Identifier => i.name }
                case _ => None
            }
        case other => trackedNameOf(other)

  /** The fields of its parameter the method itself decrements by one: the count fields the release
    * inference reads - the prefix and postfix decrement, the compound subtract of one, and the
    * assignment of a subtraction by one.
    */
  private def decrementedCountFields(m: Method): Set[(String, String)] =
      m.ast.collectAll[Call].l.flatMap { c =>
          c.name match
            case "<operator>.postDecrement" | "<operator>.preDecrement" =>
                c.argumentOption(1).flatMap(countedPairOf)
            case "<operator>.assignmentMinus" =>
                for
                  k    <- c.argumentOption(2).flatMap(IndexRange.literal) if k == 1
                  pair <- c.argumentOption(1).flatMap(countedPairOf)
                yield pair
            case "<operator>.assignment" =>
                (c.argumentOption(1), c.argumentOption(2)) match
                  case (Some(lhs), Some(rhs: Call)) if rhs.name == "<operator>.subtraction" =>
                      val operands = rhs.argument.l.collect { case e: Expression => e }
                      val one      = operands.exists(x => IndexRange.literal(x).exists(_ == 1))
                      for
                        pair <- countedPairOf(lhs) if one
                        if operands.flatMap(countedPairOf).contains(pair)
                      yield pair
                  case _ => None
            case _ => None
      }.toSet

  /** The count pair an operand of a zero test names: the field read itself, or its own decrement
    * (`if (--r->refs == 0)` tests the field through the decrement).
    */
  private def countOperandOf(e: Expression): Option[(String, String)] =
      countedPairOf(e).orElse {
          e match
            case c: Call
                if Set(
                  "<operator>.postDecrement",
                  "<operator>.preDecrement",
                  "<operator>.postIncrement",
                  "<operator>.preIncrement"
                ).contains(c.name) =>
                c.argumentOption(1).flatMap(countedPairOf)
            case _ => None
      }

  /** Every condition controlling the statement is a zero test of the count pair - directly or
    * through its own decrement - with the zero or the one count: the release spelled inline.
    */
  private def zeroGatedOn(c: Call, pair: (String, String)): Boolean =
    val conds = c._cdgIn.l.collect { case e: Expression => e }
    conds.nonEmpty && conds.forall { cond =>
        (cond +: cond.ast.collectAll[Expression].l).exists {
            case cmp: Call
                if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
                val operands = cmp.argument.l.collect { case e: Expression => e }
                operands.flatMap(countOperandOf).contains(pair) &&
                operands.exists(x => IndexRange.literal(x).exists(v => v == 0 || v == 1))
            case _ => false
        }
    }

  /** Forget every field tracked through `base`: rebinding it, or handing it (or its address) to a
    * callee that may rewrite its members, makes their states stale.
    */
  private def dropFieldsOf(m: Map[String, Tracked], base: String): Map[String, Tracked] =
      m.filterNot { case (n, _) => n.startsWith(s"$base->") || n.startsWith(s"$base.") }

  /** Remove `name` from its alias group, before it is rebound. */
  private def unalias(m: Map[String, Tracked], name: String): Map[String, Tracked] =
      m.get(name) match
        case Some(t) if t.aliases.nonEmpty =>
            t.aliases.foldLeft(m.updated(name, t.copy(aliases = Set.empty))) { (acc, a) =>
                acc.get(a).fold(acc)(ta => acc.updated(a, ta.copy(aliases = ta.aliases - name)))
            }
        case _ => m

  /** `lhs = rhs` of a tracked pointer: lhs joins rhs's alias group. */
  private def linkAlias(m: Map[String, Tracked], lhs: String, rhs: String): Map[String, Tracked] =
      if lhs == rhs || isFieldName(lhs) || isFieldName(rhs) then m
      else
        m.get(rhs) match
          case Some(t) =>
              val group = (t.aliases + rhs) - lhs
              group.foldLeft(m.updated(lhs, t.copy(aliases = group))) { (acc, g) =>
                  acc.get(g).fold(acc)(tg => acc.updated(g, tg.copy(aliases = tg.aliases + lhs)))
              }
          case None => m

  /** The state `name` moves to, applied to its alias group as well: the block's fate is shared. */
  private def withGroup(
    m: Map[String, Tracked],
    name: String,
    aliases: Set[String],
    state: AllocState
  ): Map[String, Tracked] =
      aliases.foldLeft(m) { (acc, a) =>
          acc.get(a) match
            case Some(ta) if ta.state == StAllocated =>
                acc.updated(a, ta.copy(state = state))
            case _ => acc
      }

  /** Does this expression DENOTE a stack address: `&local` (through casts), or an array local
    * decaying to its own first element? A local's address is the frame's; an array local used as a
    * pointer is the same storage.
    */
  /** Does a by-reference return hand out a frame local? The returned name, or the value the
    * frontend's `<return-value>` temporary is bound to: the temporary holds the returned expression
    * while the scope's destructors run, and in a reference return it is a reference to that
    * expression (`return *this;`), not a frame object of its own.
    */
  private def boundToFrameLocal(r: Return, i: Identifier, ctx: MethodContext): Boolean =
    def frameValue(name: String): Boolean =
        ctx.locals.contains(name) && !ctx.arrayLocals.contains(name)
    if i.name != ReturnValueName then frameValue(i.name)
    else
      r.astParent.astChildren.isCall.nameExact("<operator>.assignment").exists { a =>
          a.argumentOption(1).exists {
              case t: Identifier => t.name == ReturnValueName
              case _             => false
          } && a.argumentOption(2).exists {
              case v: Identifier => v.name != ReturnValueName && frameValue(v.name)
              case _             => false
          }
      }

  /** The value a return really hands out, seen through the compiler-generated `<return-value>`
    * local a return whose scope runs cleanups stores its value in before they run: the walk the
    * effect summaries make must judge the variable the return names, not the temporary that carried
    * it past the cleanup calls. The store sits in the same compiler-generated block as the return,
    * before it (the reaching-def layer leaves a return's own expression unwired).
    */
  private def seeThroughReturnValue(ret: Return): Option[Expression] =
      ret.astChildren.collectFirst { case e: Expression => e }.map(unwrapCast) match
        case Some(i: Identifier) if i.name == ReturnValueName =>
            val stores = (ret.astParent match
              case b: Block => b.astChildren.l
              case _        => i.method.ast.isCall.nameExact("<operator>.assignment").l
            ).collect {
                case a: Call
                    if a.name == "<operator>.assignment" && a.argumentOption(1).exists {
                        case t: Identifier => t.name == ReturnValueName
                        case _             => false
                    } =>
                    a
            }
            stores.lastOption.flatMap(_.argumentOption(2)).orElse(Some(i))
        case other => other

  private val ReturnValueName = "<return-value>"

  private def holdsStackAddress(e: Expression, ctx: MethodContext): Boolean = e match
    case c: Call =>
        c.name match
          // the address of a local, of one of its elements or members (`&buf[1]`, `&s.f`): a
          // pointer into this frame's object, at whatever offset
          case "<operator>.addressOf" =>
              c.argumentOption(1).collect { case x: Expression => x }.exists(namesFrameObject(
                _,
                ctx
              ))
          case "<operator>.cast" =>
              c.argument.l.collect { case x: Expression => x }.exists(holdsStackAddress(_, ctx))
          // `buf + k`, `buf - k`: the array local, moved within itself by an integer (the
          // difference of two pointers is an integer, no address)
          case "<operator>.addition" | "<operator>.subtraction" =>
              c.argumentOption(1).collect { case x: Expression => x }.exists {
                  case i: Identifier => ctx.arrayLocals.contains(i.name)
                  case _             => false
              } && c.argumentOption(2).collect { case x: Expression => x }.exists { k =>
                val t = String.valueOf(k.property("TYPE_FULL_NAME")).trim
                !OverlayFacts.isPointer(t) && !t.endsWith("]")
              }
          case _ => false
    case i: Identifier => ctx.arrayLocals.contains(i.name)
    case _             => false

  /** The lvalue names this frame's own object: a local, or an element or member of one. */
  private def namesFrameObject(e: Expression, ctx: MethodContext): Boolean = e match
    case i: Identifier => ctx.locals.contains(i.name)
    case c: Call if c.name == "<operator>.indexAccess" || c.name == "<operator>.fieldAccess" =>
        c.argumentOption(1).collect { case x: Expression => x }.exists(namesFrameObject(_, ctx))
    // an array local indexed as a pointer (`text[1]` on `char text[] = "..."`)
    case c: Call if c.name == "<operator>.indirectIndexAccess" =>
        c.argumentOption(1).exists {
            case i: Identifier => ctx.arrayLocals.contains(i.name)
            case _             => false
        }
    case _ => false

  /** `&(T){...}` - the address of a block-scope compound literal, an unnamed automatic object of
    * this frame (C99 6.5.2.5p5). Returned, it leaves the frame exactly the way a named local's
    * address does. The literal itself assigned to storage is the store arm's question (the
    * destination's duration decides it), and a file-scope literal never reaches a frame's return -
    * `<global>` asks no stack question.
    */
  private def holdsBlockLiteralAddress(e: Expression): Boolean = e match
    case c: Call if c.name == "<operator>.addressOf" =>
        c.argument.l.collectFirst { case x: Expression => x }.exists(isCompoundLiteral)
    case c: Call if c.name == "<operator>.cast" =>
        c.argument.l.collectFirst { case x: Expression => x }.exists(holdsBlockLiteralAddress)
    case _ => false

  private def isCompoundLiteral(e: Expression): Boolean = e match
    case c: Call if c.name == "<operator>.cast" =>
        c.argument.l.collect { case x: Expression => x }.exists {
            case init: Call => init.name == "<operator>.arrayInitializer"
            case _          => false
        }
    case _ => false

  /** A designated initializer of an object with no name - a compound literal, a C++ temporary: the
    * frontend writes it as an assignment to the bare designator inside the initializer list. The
    * object lives in this frame, as a by-value local does; whether it leaves the frame is the
    * enclosing expression's business.
    */
  private def initializesTemporary(c: Call): Boolean =
      c.astParent match
        case b: Block =>
            b.astParent match
              case list: Call => list.name == "<operator>.arrayInitializer"
              case _          => false
        case _ => false

  /** Is this destination part of the frame: a member or element, through `.` and `[]` only, of an
    * array or by-value aggregate local? `->` leaves the frame's storage for wherever the pointer
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

  /** The C++ string types that copy on by-value assignment, construction and return: std::string
    * and its wide/utf specialisations. `std::string_view` is deliberately absent - a view really
    * does borrow the pointer it is built from. Namespace and template spellings are normalised
    * away; the last name component decides.
    */
  private def isCppStringType(t: String): Boolean =
    val last = t.trim
        .stripPrefix("const ")
        .trim
        .takeWhile(_ != '<')
        .trim
        .stripSuffix("&")
        .trim
        .replace("::", ".")
        .split('.')
        .lastOption
        .getOrElse("")
    CppStringTypes.contains(last)

  private val CppStringTypes = Set("string", "basic_string", "wstring", "u16string", "u32string")

  /** Is this assignment destination a C++ string that would COPY the rhs characters rather than
    * store a pointer into it: a global or local `std::string` variable, or the deref of a
    * `std::string*` (`*value = buf` copies). The referent type decides: an `std::string` member
    * read through a pointer is one too. Anything unresolvable stays an escape.
    */
  private def isStringDestination(dst: Expression): Boolean =
    def typeOf(e: Expression): String = e.property("TYPE_FULL_NAME") match
      case s: String => s
      case _         => ""
    val referent = dst match
      case c: Call if c.name == "<operator>.indirection" =>
          // the pointee of the dereferenced pointer: `std::string *` -> `std::string`
          c.argumentOption(1).map(typeOf).getOrElse("").stripSuffix("*").trim
      case _ => typeOf(dst)
    isCppStringType(referent)

  /** Does this rhs put a stack address into the destination it feeds: directly, or through a local
    * that currently holds one?
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
          } || callReturnsStackAddress(rhs)

  /** The names every defined method of which returns its own frame's address: the summary a call
    * site reads (returning such a call's result, or storing it into eternal storage, hands out a
    * dead frame's address). Name-level like every effect summary: same-named methods that disagree
    * carry nothing.
    */
  private lazy val returnsStackNames: Set[String] =
    val per = atom.method.filterNot(_.isExternal).filter(_.block.astChildren.nonEmpty).l
        .map(m => m.name -> returnsFrameAddress(m))
    per.groupMap(_._1)(_._2).collect {
        case (name, answers) if answers.forall(_ == true) =>
            name
    }.toSet

  /** Every return of the method hands out this frame's storage: the address of a non-static local,
    * or an array local decaying to its first element.
    */
  private def returnsFrameAddress(m: Method): Boolean =
    val locals = m.local.l.filterNot(isStaticLocal).map(_.name).toSet
    val arrays = m.local.l
        .filter(l =>
            OverlayFacts.arrayExtent(l.typeFullName).isDefined || l.typeFullName.trim.endsWith(
              "[]"
            )
        )
        .map(_.name)
        .toSet
    val returns = m.ast.collectAll[Return].l
        .flatMap(_.astChildren.collectFirst { case e: Expression => e })
    def holds(e: Expression): Boolean = e match
      case c: Call if c.name == "<operator>.addressOf" =>
          c.argument.l.collectFirst {
              case i: Identifier => locals.contains(i.name)
              case _             => false
          }.getOrElse(false)
      case c: Call if c.name == "<operator>.cast" =>
          c.argument.l.collectFirst { case x: Expression => x }.exists(holds)
      case i: Identifier => arrays.contains(i.name)
      case _             => false
    returns.nonEmpty && returns.forall(holds)
  end returnsFrameAddress

  /** An expression that is (through a cast) a call to a method whose every return is its own
    * frame's address.
    */
  private def callReturnsStackAddress(e: Expression): Boolean = e match
    case c: Call =>
        (c.name.startsWith("<operator>.cast") &&
            c.argument.l.collectFirst { case x: Expression => x }
                .exists(callReturnsStackAddress)) ||
        returnsStackNames.contains(c.name)
    case _ => false

  private def addressOfOperand(e: AstNode): Option[Expression] = e match
    case c: Call if c.name == "<operator>.addressOf" => c.argumentOption(1)
    case _                                           => None

  /** The tracked value an argument names, casts unwrapped: `new X((char *)mmap_base)` hands the
    * mapping to the constructor exactly as a bare argument would.
    */
  private def unwrapCastOperand(e: Expression): Expression = e match
    case c: Call if c.name == "<operator>.cast" =>
        castOperand(c).map(unwrapCastOperand).getOrElse(e)
    case other => other

  private def castOperand(c: Call): Option[Expression] =
      c.argumentOption(2).orElse(c.argumentOption(1))

  private def isOperatorCall(name: String): Boolean = name.startsWith("<operator>")

  private def isAccessThroughPointer(access: Call): Boolean =
      access.name == "<operator>.indexAccess" || access.name == "<operator>.indirectIndexAccess" ||
          access.name == "<operator>.fieldAccess" ||
          access.name == "<operator>.indirectFieldAccess" ||
          // the plain dereference `*p` reads through p exactly as `p[0]` does
          access.name == "<operator>.indirection"

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
          .groupMapReduce(_._1)(_._2)((a, b) => if a == b then a else Set.empty) ++
          MemorySemanticsPass.nonnullParamsByName(cpg).filterNot { case (name, _) =>
              cpg.method.nameExact(name).exists(m => !m.isExternal && m.block.astChildren.nonEmpty)
          }

  sealed trait AllocState
  case object StAllocated  extends AllocState
  case object StFreed      extends AllocState
  case object StMaybeFreed extends AllocState

  /** path-conditioned null: the guard proved the pointer null on THIS path - a non-null guard on a
    * later path revives it (the `if (p == NULL) return;` idiom's else side).
    */
  case object StNull extends AllocState

  /** the pointer was ASSIGNED the NULL literal (`free(p); p = NULL;`): null on every path, and no
    * guard can revive what an assignment killed. Reviving this state under a `p != NULL` guard
    * would turn the free-and-reset idiom's dead branch into a phantom live allocation and report a
    * leak at the implicit end.
    */
  case object StNullReset extends AllocState

  /** the value of a NON-allocation nullable return (strchr, av_dict_get): may be null, but it is
    * not ownership - the leak/free rules never fire on it.
    */
  case object StNullable extends AllocState

  /** the variable holds the ADDRESS of a stack local of this frame: `q = &x`, or an array local
    * that decayed. Leaving the frame with it - returned, stored into a member or a global - is the
    * CWE-562 escape the state pass and the heap escape share one worklist to ask about.
    */
  case object StStackAddr extends AllocState
  case object StEscaped   extends AllocState

  /** `nullable` - the tracked value came from a call whose result may be NULL (every allocation, or
    * the inventory's `nullable-return` role); `checked` - a guard has since narrowed it non-null on
    * every path that reaches here.
    *
    * `region` - the REGION the block belongs to, when the allocation drew from one: the variable
    * key the allocation's region argument spelled - the local or parameter's name, a field path's
    * own key, or the global a context-less allocator reads. The region's destroy releases the block
    * wherever it is, and no exit reports it as a leak. Regions match by that one key only - a copy
    * of the handle is a different key and matches nothing. `resetByRegion` - the block's freedom
    * came from a region reset (or from a destroy that may not have reached it, the region-full
    * fallback's heap arm): the use after it is the weaker claim, marked so it reports below the
    * use-after-free rule's own confidence.
    *
    * `refs` - the references of the object THIS method owns: a new allocation is one, an acquire
    * adds one, a release drops one. Zero says the method owns none - either it never did (the
    * release was the borrowed kind) or its last one just reached zero. `borrowed` - a release of a
    * reference whose ownership the method does not know (a parameter, a field read, an unsummarised
    * call's result) touched the object: the object is maybe freed, and a use after it is the
    * weakest claim. `freedByRelease` - the block's freedom came from a release that reached zero,
    * so the use after it reports below the rule's own confidence, one level above the borrowed
    * kind.
    */
  private val PointerStepOps = Set(
    "<operator>.preIncrement",
    "<operator>.postIncrement",
    "<operator>.preDecrement",
    "<operator>.postDecrement"
  )

  final case class Tracked(
    state: AllocState,
    site: Long,
    nullable: Boolean = false,
    checked: Boolean = false,
    // the other variables holding the SAME block (`q = p`): a free through one frees them all.
    // A must-alias set - the join intersects it
    aliases: Set[String] = Set.empty,
    region: Option[String] = None,
    resetByRegion: Boolean = false,
    refs: Int = 0,
    borrowed: Boolean = false,
    freedByRelease: Boolean = false,
    // the stores into storage that outlives the scope this path made of the variable while a
    // scope cleanup was still to release it: the release settles these and no others
    pendingStores: Set[Long] = Set.empty,
    // the paths into a join disagreed on the owned-reference count: the block is the pass's
    // unknown, and no release of it is read as reaching zero or going below it
    countUnknown: Boolean = false
  )

  /** The encoded `mem-region` value of one call, parsed: the role and where it names the region
    * (the argument index, or the global a context-less allocator reads).
    */
  final case class RegionInfo(role: String, arg: Option[Int], context: Option[String])

  /** Decodes the values [[MemoryApiPass.TagRegion]] carries: `alloc:<i>`, `alloc:ctx:<global>`,
    * `create`, `create:<i>`, `destroy:<i>` and `reset:<i>`.
    */
  private def regionInfoOf(value: String): Option[RegionInfo] =
      value.split(":", 3) match
        case Array("alloc", idx) =>
            idx.toIntOption.filter(_ >= 1).map(i => RegionInfo("allocate", Some(i), None))
        case Array("alloc", "ctx", name) => Some(RegionInfo("allocate", None, Some(name)))
        case Array("create")             => Some(RegionInfo("create", None, None))
        case Array("create", idx) =>
            idx.toIntOption.filter(_ >= 1).map(i => RegionInfo("create", Some(i), None))
        case Array("destroy", idx) =>
            idx.toIntOption.filter(_ >= 1).map(i => RegionInfo("destroy", Some(i), None))
        case Array("reset", idx) =>
            idx.toIntOption.filter(_ >= 1).map(i => RegionInfo("reset", Some(i), None))
        case _ => None

  /** The 1-based argument index a `mem-release` / `mem-acquire` tag value carries. */
  private def rolePosition(value: String): Option[Int] =
      value.toIntOption.filter(_ >= 1)

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
    readsThrough: Set[Int],
    region: Option[RegionInfo] = None,
    releasePositions: Set[Int] = Set.empty,
    acquirePositions: Set[Int] = Set.empty,
    retainPositions: Set[Int] = Set.empty,
    stealPositions: Set[Int] = Set.empty,
    cleanup: Boolean = false
  )

  /** the families a call carries per role, from the inventory tags */
  final case class RoleInfo(
    alloc: Set[String],
    free: Set[String],
    realloc: Set[String],
    nullable: Boolean,
    isMemoryCall: Boolean,
    dstPositions: Set[Int] = Set.empty,
    srcPositions: Set[Int] = Set.empty,
    readPositions: Set[Int] = Set.empty,
    region: Option[RegionInfo] = None,
    release: Set[Int] = Set.empty,
    acquire: Set[Int] = Set.empty,
    retains: Set[Int] = Set.empty,
    steal: Set[Int] = Set.empty,
    cleanup: Boolean = false
  )
  val RoleInfoNone: RoleInfo =
      RoleInfo(Set.empty, Set.empty, Set.empty, nullable = false, isMemoryCall = false)

  final val TagState   = "alloc-state"
  final val TagLeak    = "alloc-leak"
  final val TagNullUse = "null-use"

  /** A use of a block whose freedom came from a region reset (or from a destroy that may not have
    * reached it): the fact that demotes the use-after-free finding below the rule's own confidence,
    * beside the `alloc-state` value the use carries.
    */
  final val TagResetUse = "alloc-reset-use"

  /** A use of a block whose freedom came from a REFERENCE release - the count reached zero
    * (`medium`), or the release dropped a borrowed reference (`low`) - or a second release of an
    * already spent reference (`medium` on the double-free fact): beside the `alloc-state` value,
    * the confidence the finding reports at, one level under what a free's own facts carry.
    */
  final val TagReleaseUse = "alloc-release-use"

  /** Builtins that read nothing through a pointer argument and keep nothing: queries the compiler
    * answers (`__builtin_object_size`, `__builtin_constant_p`) and a cache hint.
    */
  private val NonRetainingBuiltins = Set(
    "__builtin_object_size",
    "__builtin_dynamic_object_size",
    "__builtin_constant_p",
    "__builtin_prefetch"
  )

  /** A call inside the expansion of a macro whose own call the inventory tags with the same API: a
    * fortified `memset(p, 0, n)` expanding to `__builtin___memset_chk(p, 0, n, ...)`.
    */
  private def expandsInventoriedMacro(c: Call): Boolean =
    val api = MemApiVocab.apiOf(c.name)
    c.inAst.collectAll[Call].exists(m =>
        m.dispatchType == io.shiftleft.codepropertygraph.generated.DispatchTypes.INLINED &&
            MemApiVocab.apiOf(m.name) == api &&
            m.argument.l.exists(_.tag.name("mem-.*").nonEmpty)
    )

  /** The C library's functions that do not return, for code whose headers are not available. The
    * assert family's abort calls are deliberately absent: a release build compiles the assert's
    * check out and falls through it, so a path that reaches `__assert_fail` in the sources
    * continues in the binary the analysis is describing.
    */
  private val NoReturnFunctions = Set(
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__builtin_trap",
    "__builtin_unreachable",
    "longjmp",
    "siglongjmp",
    "_longjmp",
    "pthread_exit",
    "err",
    "errx",
    "verr",
    "verrx"
  )
  final val TagStackEscape = "stack-escape"

  /** A release whose form does not match the acquisition the object's own class performed: the
    * constructor array-newed the member, the destructor scalar-deletes it.
    */
  final val TagClassFormMismatch = "class-form-mismatch"

  /** A per-method effect summary, ON the method node - `effect:frees-param:<i>`,
    * `effect:allocates-return`, `effect:escapes-param:<i>` - so an interprocedural effect is a tag
    * lookup at the call site.
    */
  final val TagEffect = "mem-effect"

  /** The READS-THROUGH summary, its own tag beside the effects: a guarded dereference still reads
    * (the question a caller's wider-type conversion asks), where `derefs-param` is the
    * unguarded-always question the null rule asks. Kept out of `mem-effect` so a consumer reading
    * one vocabulary never sees the other's conclusions.
    */
  final val TagReadsEffect = "mem-reads-effect"

  /** the effect tag marking a method whose body contains a throw: calls into it add an unwind exit
    * to the calling frame (the exception-path leak)
    */
  val EffectMayThrow = "effect:may-throw"

  /** the method's own locals, the array-typed ones, its parameters - the frame's storage and the
    * names that rebind locally - and whether it returns by reference (a C++ `T&` return binds the
    * returned local itself, no addressOf anywhere)
    */
  final case class MethodContext(
    locals: Set[String],
    arrayLocals: Set[String],
    valueLocals: Set[String],
    params: Set[String],
    staticLocals: Set[String],
    refReturn: Boolean,
    // a by-value C++ string return copies the characters out of the frame - a
    // char[] or char* that flows to it is a copy, not an escape (std::string owns its buffer)
    stringReturn: Boolean,
    // the variables the compiler-placed cleanup calls of this method release: a store of one of
    // them into storage that outlives the scope keeps a block the release then frees
    cleanupReleased: Set[String] = Set.empty,
    // the variables one of whose INTEGER-typed count fields the method stores into
    // (`o->refs = 2`, or a non-literal store): the block's count is a number this frame wrote,
    // so a release of it cannot know the field reached zero - the method's own reference is
    // spent and the block survives under the count the store left, outside this frame's free
    // and leak questions
    countStores: Set[String] = Set.empty,
    // the (object, count field) pairs the frame's own arithmetic counts in: an increment of
    // one of these is an acquire, a decrement is a release, at the statement itself
    countFields: Set[(String, String)] = Set.empty
  )

  /** the `alloc-state` value a summary-free records: the ENCLOSING call is the free - a wrapper
    * whose body-shape the inventory never saw, named by its effect summary
    */
  val ValueSummaryFreed = "freed-by-summary"

  /** the `alloc-state` value a store into storage that outlives the variable's scope carries when
    * the scope's cleanup release frees the block the store kept: the finding site is the store, at
    * a lower confidence than a use already made
    */
  val ValueStoredThenReleased = "stored-then-released"

  /** the `null-use` kinds: an unchecked use of a may-be-null value, an unchecked use of an
    * ALLOCATION's own result (the CWE-690 shape), and a use under a guard that proved the pointer
    * null
    */
  val NullUnchecked      = "unchecked"
  val NullUncheckedAlloc = "unchecked-alloc"
  val NullDefinite       = "null"

  /** A free whose only controlling conditions are null tests of the freed pointer itself - the `if
    * (data == NULL) exit(-1);` that precedes it, or `if (p) free(p)` - releases the block whenever
    * there is one to release: a summary reads it as unconditional. For a free through the pointee
    * (`free(*pp)`), a null test OF THE POINTEE (`*pp == NULL`, `!*pp`, `if (*pp)`) is the same
    * guarantee: the freed value is the pointee, and the guard releases it exactly when it names a
    * block. The body inference concludes the same about a destroy function's own release of its
    * argument.
    */
  private[taggers] def onlyNullChecksOf(c: Call): Boolean =
    def unwrap(e: Expression): Expression = e match
      case x: Call if x.name == "<operator>.cast" =>
          x.argumentOption(2).orElse(x.argumentOption(1)).map(unwrap).getOrElse(x)
      case other => other
    def nullLiteral(e: AstNode): Boolean =
        isNullLiteral(e, op => op.argumentOption(2).orElse(op.argumentOption(1)))
    // the freed value after casts: its name, marked whether the free reads it through an
    // indirection (the pointee `*pp`, not the slot pp)
    def freedOf(e: Expression): Option[(String, Boolean)] = unwrap(e) match
      case i: Identifier => Some((i.name, false))
      case d: Call if d.name == "<operator>.indirection" =>
          d.argumentOption(1).collect { case i: Identifier => i.name }.map((_, true))
      case _ => None
    // a condition operand names the freed value: the identifier itself, or for a free through
    // the pointee the same indirection of it
    def names(e: Expression, n: String, throughPointee: Boolean): Boolean = unwrap(e) match
      case i: Identifier => !throughPointee && i.name == n
      case d: Call if d.name == "<operator>.indirection" =>
          throughPointee && d.argumentOption(1).exists {
              case i: Identifier => i.name == n
              case _             => false
          }
      case _ => false
    // whether the value is non-NULL when the condition holds (Some(true)) or when it fails
    def nonNullWhen(cond: Expression, n: String, throughPointee: Boolean): Option[Boolean] =
        cond match
          case cmp: Call
              if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
              val args = cmp.argument.l.collect { case e: Expression => unwrap(e) }
              Option.when(args.exists(names(_, n, throughPointee)) && args.exists(nullLiteral))(
                cmp.name == "<operator>.notEquals"
              )
          case cmp: Call if cmp.name == "<operator>.logicalNot" =>
              Option.when(
                cmp.argument.l.collect { case e: Expression => unwrap(e) }
                    .exists(names(_, n, throughPointee))
              )(false)
          case other => Option.when(names(other, n, throughPointee))(true)
    c.argument.l.find(_.argumentIndex == 1).flatMap(freedOf).exists { (n, throughPointee) =>
      val conds = c._cdgIn.l
      // the free runs on the side of each test where the value is not NULL: `if (!p) return;`
      // guards it, `if (p != NULL) return;` makes it a free of NULL only
      conds.nonEmpty && conds.forall {
          case cond: Expression =>
              nonNullWhen(unwrap(cond), n, throughPointee).exists { nonNullWhenTrue =>
                  cond._astIn.collectFirst { case cs: ControlStructure => cs }.exists { cs =>
                      cs.whenTrue.ast.id.toSet.contains(c.id) == nonNullWhenTrue
                  }
              }
          case _ => false
      }
    }
  end onlyNullChecksOf

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

  /** allocation families whose handle IS an integer (a descriptor: the `fd` family), unlike a heap
    * block or a `FILE *` stream
    */
  private val IntHandleFamilies = Set("fd")

  /** worklist visit cap per CFG node. States settle within a handful of revisits on real code; a
    * cap as tight as 8 makes the settle point itself depend on the order the frontend's parallel
    * parse left the CFG edges in - whole MS-ESC-001/MS-ALLOC-003 groups flip per file between
    * identical runs. At 64 methods in real C code bases converge long before the cap, so the
    * settled state is the join over every path and not a function of the visit order.
    */
  private val VisitCap = 64

  /** hop rounds for the `derefs-param` fixpoint: each round lets a wrapper inherit the conclusion
    * of a wrapper concluded in the round before. Three is already deeper than any wrapper layer
    * seen in practice, matching the wrapper-inference cap in [[MemoryApiPass]].
    */
  private val MaxDerefsRounds = 3

  /** definition-walk depth for the steal's returned identifier: the return names the value through
    * the locals it passed through (`p = *pp; q = p; return q;`), and a real tree's chains run
    * hundreds of locals deep, where an unbounded walk overflows the stack. Eight is far deeper than
    * any steal spelled for a reader (`p = *pp; return p;` is one hop); past it the walk says
    * nothing and the method concludes no steal.
    */
  private val MaxStealChainDepth = 8

  private val MemoryRoles = Set(
    MemoryApiPass.TagAlloc,
    MemoryApiPass.TagFree,
    MemoryApiPass.TagRealloc,
    MemoryApiPass.TagRegion,
    MemoryApiPass.TagRelease,
    MemoryApiPass.TagAcquire,
    MemoryApiPass.TagRetains,
    MemoryApiPass.TagSteal,
    MemoryApiPass.TagCleanup,
    MemoryApiPass.TagNullableReturn,
    MemoryApiPass.TagNonRetaining,
    MemoryApiPass.UmbrellaTag
  )

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end AllocationStatePass
