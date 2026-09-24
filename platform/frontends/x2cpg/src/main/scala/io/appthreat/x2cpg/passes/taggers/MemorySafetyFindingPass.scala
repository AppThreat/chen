package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS6: rules as tag algebra. The only overlay pass that emits findings.
  *
  * Each rule is a conjunction over the tags MS1-MS5 left on the graph, and carries a rule id, a
  * CWE, a confidence and the message a renderer shows. A finding is itself a tag - `ms-finding`
  * valued with the rule id, alongside the `memory-safety` umbrella - so `atom reachables --sink-tag
  * memory-safety` and a chennai session see it with no second output path.
  *
  * Two rules in part 2, replacing the prototype queries deleted in the same commit:
  *
  *   - **MS-BOUND-002** - unbounded attacker-controlled copy (CWE-787), replacing
  *     `queries/unbounded-memcpy.sc`: the length argument is caller- or reader-controlled
  *     (`caller-param` / `untrusted-read`) and nothing bounds it from above (`bounded-above` /
  *     `bounded-by-extent`). Three tag lookups - no regex, no argument indices, no API name list.
  *     Part 3 (C3) adds the interprocedural half: a `caller-param`-only length reports only when
  *     the call graph shows no caller establishing the bound - the method has no intra-tree
  *     callers, or some call site passes a non-constant for the feeding parameter. 51 of part 2's
  *     66 libavformat findings were "this function copies as many bytes as its caller asked for",
  *     which is what a correct helper looks like from inside.
  *   - **MS-BOUND-001** - size-parameter contract violation (CWE-787), replacing
  *     `queries/MS-BOUND-PARAM.sc`: the destination is a buffer parameter whose extent is an
  *     adjacent capacity parameter (`extent` `param:<name>`), and that capacity reaches no bound on
  *     the write - neither as the copy's own length (REACHING_DEF path to the length argument) nor
  *     as a guard on it. The shape behind CVE-2026-75143: `size = payload_len` destroys the
  *     caller's capacity before `memcpy(buf, payload, size)`.
  *
  * Part 3 (C4) adds the index family, over the facts that already existed but had no reader:
  *
  *   - **MS-BOUND-003** (CWE-125, read) / **MS-BOUND-004** (CWE-787, write) - the index is
  *     attacker-controlled (`caller-param` / `untrusted-read`) into a base of known capacity with
  *     no upper bound; or it is a signed struct-field read bounded only ABOVE (CVE-2026-75146's
  *     negative-index shape, which the fixed tree's `>= 0` conjunct silences). `bounded-below` is
  *     the fact that separates the bug from the guard that fixes it.
  *
  * `unknown` extents never satisfy a rule that needs an extent: MS-BOUND-001 fires only on an
  * explicit `param:` extent, MS-BOUND-002 needs no extent at all, and the index rules accept only
  * `const:`/`alloc:` capacities. Part 4 (D0) adds the integer family, over the C5 width facts:
  *
  *   - **MS-INT-001** (CWE-190) - an allocation/copy length computed by attacker-influenced
  *     arithmetic (`int-arith-len`), no guard bounding an operand above, no widened operand;
  *   - **MS-INT-002** (CWE-197, `high`) - a sign-changing cast that a guard bounds, with the
  *     guarded uses reading the declared view. A resign that merely exists is not a finding.
  *
  * Runs last in the overlay, after MemoryApi, Extent, Guard, ValueOrigin and IntegerWidth. C/C++
  * graphs only.
  */
class MemorySafetyFindingPass(atom: Cpg) extends CpgPass(atom):

  import MemorySafetyFindingPass.*
  import OverlayFacts.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return

    val findings = mutable.LinkedHashMap.empty[StoredNode, mutable.LinkedHashSet[String]]
    def record(node: StoredNode, ruleId: String): Unit =
        findings.getOrElseUpdate(node, mutable.LinkedHashSet.empty) += ruleId

    val sites = OverlayFacts.memoryArgumentSites(atom)
    val argsByCall = sites.groupBy { case (call, _, _) => call }
        .map { case (call, rows) => call -> rows.map { case (_, arg, _) => arg }.distinct }

    ruleUnboundedCopy(argsByCall, record)
    ruleSizeParameterContract(argsByCall, record)
    ruleIndexBounds(record)
    ruleCapacityOverrun(record)
    ruleWrongDeallocation(record)
    ruleUncontrolledAllocationSize(record)
    ruleIntegerArithmeticLength(record)
    ruleResignAcrossGuard(record)
    ruleAllocationState(record)
    val lowConfidenceNodes = ruleNullDereference(record)

    // MS-ALLOC-009 (CWE-680) and MS-INT-001 (CWE-190) ask one question of an allocation size
    // computed by attacker arithmetic; on libavformat 36 of 52 ALLOC-009 findings sat on an
    // INT-001 line. One report per site, under the CWE the arithmetic names: a PRODUCT sizing an
    // allocation is the overflow-to-undersized-buffer shape (CWE-680, the corpus's
    // `malloc(count * sizeof(int))`), a SUM is the plain wrap (CWE-190, `malloc(len + 1)`)
    def isProduct(node: StoredNode): Boolean = node match
      case c: Call => c.name == "<operator>.multiplication"
      case _       => false
    val sizeSites = findings.collect {
        case (node, rules) if rules.contains(RuleUncontrolledSizeOverflow) =>
            siteOf(node) -> isProduct(node)
    }.toMap
    val intSites = findings.collect {
        case (node, rules) if rules.contains(RuleIntegerOverflow) => siteOf(node)
    }.toSet
    findings.foreach { case (node, rules) =>
        val site = siteOf(node)
        if rules.contains(RuleUncontrolledSizeOverflow) && intSites.contains(site) &&
          !sizeSites.getOrElse(site, false)
        then rules -= RuleUncontrolledSizeOverflow
        if rules.contains(RuleIntegerOverflow) && sizeSites.getOrElse(site, false) then
          rules -= RuleIntegerOverflow
    }

    OverlayFacts.emitTags(
      dstGraph,
      findings.toList.filter(_._2.nonEmpty).flatMap { case (node, ruleIds) =>
          ruleIds.toList.map(ruleId => (node, TagFinding, ruleId))
      } ++ lowConfidenceNodes.map(node => (node, TagConfidence, s"$RuleNullDeref=low")) ++
          heuristicFindings(findings).map { case (node, rule) =>
              (node, TagConfidence, s"$rule=low")
          }
    )
  end run

  /** The rules a free call triggers: the double free and use-after-free the free's state enables,
    * and the wrong-deallocation checks of the free's own argument.
    */
  private val FreeTriggeredRules =
      Set(RuleDoubleFree, RuleUseAfterFree, RuleNonHeapFree, RuleOffsetFree, RuleMismatchedFree)

  /** Findings that rest on a HEURISTIC summary (MemorySemanticsPass: a `void f(void *)` named
    * `free`, an `int f(void *, size_t)` named `realloc`, with no body in scope): a finding on the
    * guessed call or inside one of its arguments, and a free-triggered finding over a pointer a
    * guessed free releases in the same method. The role is a guess, so the finding reports at
    * `low`, whatever its rule's confidence.
    */
  private def heuristicFindings(
    findings: mutable.LinkedHashMap[StoredNode, mutable.LinkedHashSet[String]]
  ): List[(StoredNode, String)] =
    val heuristic = MemorySemanticsPass.heuristicSummaries(atom)
    if heuristic.isEmpty then return Nil
    def insideGuessedCall(e: Expression): Boolean =
        (e +: e.inAst.collectAll[Expression].l).exists {
            case c: Call => heuristic.contains(c.name)
            case _       => false
        }
    def rootName(e: Expression): Option[String] = e match
      case i: Identifier => Some(i.name)
      case c: Call
          if c.name == "<operator>.cast" || c.name == "<operator>.addressOf" ||
              c.name == "<operator>.indirection" =>
          c.argument.l.collect { case x: Expression => x }.lastOption.flatMap(rootName)
      case _ => None
    val freedByMethod = heuristic.toList
        .flatMap(n => atom.call.nameExact(n).l)
        .flatMap(c =>
            c.argumentOption(1).flatMap(rootName)
                .map(n => c.method.id -> (n, c.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)))
        )
        .groupMap(_._1)(_._2)
    findings.toList.flatMap { case (node, rules) =>
        node match
          case e: Expression if insideGuessedCall(e) => rules.toList.map(node -> _)
          case e: Expression =>
              // only a guessed free BEFORE the finding can be what triggered it: a real
              // `free(p); free(p);` keeps its confidence though `av_free(p)` follows
              val line  = e.lineNumber.map(_.toInt).getOrElse(-1)
              val names = (e +: e.ast.collectAll[Expression].l).flatMap(rootName).toSet
              if freedByMethod.get(e.method.id).exists(_.exists { case (n, l) =>
                    l < line && names.contains(n)
                  })
              then
                rules.toList.filter(FreeTriggeredRules.contains).map(node -> _)
              else Nil
          case _ => Nil
    }
  end heuristicFindings

  /** (method id, line) - the granularity a reader sees a finding at */
  private def siteOf(node: StoredNode): (Long, Int) = node match
    case e: Expression => (e.method.id, e.lineNumber.map(_.toInt).getOrElse(-1))
    case other         => (other.id, -1)

  /** MS-ALLOC-001/002/003 (D3): double-free, use-after-free and leak, over the states
    * [[AllocationStatePass]] put on the graph. The rules are pure readers of those facts - the pass
    * decides WHAT the state at a program point is, the rules decide WHAT IT MEANS:
    *
    *   - **MS-ALLOC-001** (CWE-415): a free of a pointer that is `freed` (must-freed, every path)
    *     or `maybe-freed` (freed on some path reaching it - the conditional-double-free shape). A
    *     double CLOSE of a `file`-family handle is CWE-1341 (**MS-ALLOC-004**), the same state fact
    *     over a different family.
    *   - **MS-ALLOC-002** (CWE-416): a use of a `freed`/`maybe-freed` pointer - through a memory
    *     call's arguments, another call's arguments, or an index/field access base.
    *   - **MS-ALLOC-003** (CWE-401): the `alloc-leak` fact on an exit node - an allocation still
    *     live, un-freed and un-escaped there.
    *
    * A pointer that is `null` (the free-and-reset idiom), `escaped`, or untracked is silent: the
    * pass says `escaped` when it genuinely does not know, and a rule must not turn on that silence.
    */
  private def ruleAllocationState(record: (StoredNode, String) => Unit): Unit =
    atom.tag
        .name(AllocationStatePass.TagState)
        .l
        .flatMap(t => t._taggedByIn.collectAll[StoredNode].l.map(n => (n, t.value)))
        .foreach { case (node, state) =>
            state match
              case "freed" | "maybe-freed" | AllocationStatePass.ValueSummaryFreed =>
                  // the SAME fact means two things by site: a free of an already-freed
                  // pointer is a double-free, any other use is a use-after-free
                  val enclosing = node._astIn.collectFirst { case c: Call => c }
                  // a summary-freed value (E5) names the call that freed it: the ENCLOSING
                  // call is the free even though it carries no inventory tag of its own
                  val isFreeSite = state == AllocationStatePass.ValueSummaryFreed ||
                      enclosing.exists(c =>
                          tagValues(c, MemoryApiPass.TagFree).nonEmpty ||
                              tagValues(c, MemoryApiPass.TagRealloc).nonEmpty
                      )
                  if isFreeSite then
                    val family = enclosing.flatMap(c =>
                        tagValues(c, MemoryApiPass.TagFree).headOption
                    )
                    record(
                      node,
                      if family.contains("file") then RuleDoubleClose else RuleDoubleFree
                    )
                  else record(node, RuleUseAfterFree)
              case _ => ()
        }
    atom.tag
        .name(AllocationStatePass.TagLeak)
        .l
        .flatMap(t => t._taggedByIn.collectAll[StoredNode].l)
        .foreach(node => record(node, RuleLeak))
    // MS-ESC-001 (part 5, E4, CWE-562): a stack address that left its frame - returned, or
    // stored into a member, a global, or through a pointer parameter. The state pass tracks the
    // frame's storage through the SAME worklist and escape analysis it tracks the heap's: the
    // rule is the reader, exactly as for the leak.
    atom.tag
        .name(AllocationStatePass.TagStackEscape)
        .l
        .flatMap(t => t._taggedByIn.collectAll[StoredNode].l)
        .foreach(node => record(node, RuleStackEscape))
  end ruleAllocationState

  /** MS-NULL-001 (part 5, E3, CWE-476): a dereference of a value that may be null, three arms over
    * two fact sources. Returns the nodes whose finding is a HYPOTHESIS tier - the renderer lowers
    * those below the rule's own confidence, the same way a whole rule ships at `low` when its
    * evidence does not earn `medium`.
    *
    *   - **unchecked nullable return** (the state pass's `null-use` facts): a use of a pointer
    *     whose producing call may return NULL - every allocation, or the inventory's
    *     `nullable-return` role (the strchr family, av_dict_get) - with no narrowing guard between
    *     the call and the use. The imfdec.c:258 shape: `uri = xmlNodeGetContent(...)`;
    *     `imf_uri_is_url(uri)` dereferences what the library may have handed back NULL.
    *   - **check-after-use** (rule-side): a use of a variable whose null guard appears LATER in the
    *     method - the author knew it could be null, one statement too late. The corpus's
    *     `bad_check_after_use`: `strlen(s); if (s == NULL) return;`. Part 6 (F1) makes the ordering
    *     structural: a use nested inside the structure whose condition is the guard is protected (a
    *     loop body under its own trailer), and a guard that follows a REDEFINITION of the variable
    *     speaks about a different value - neither is a check-after-use.
    *   - **unvalidated parameter** (rule-side, the hypothesis tier): a pointer parameter
    *     dereferenced with no null guard anywhere in the method, through a SELF-REFERENTIAL field
    *     chain (`head->next->v`, where `next` has `head`'s own pointee type - a traversal hop
    *     nothing validated). Part 5's boundary kept the whole field chain; that was 3,176 findings
    *     per libavformat tree, because a cross-type chain (`s->priv_data->x`) is FFmpeg's idiom for
    *     an owned sub-object initialised with its parent. The type relation is the fact that
    *     separates the traversal hop from the owned sub-object; an unresolvable member type says
    *     nothing and stays silent.
    *
    * A use under a guard that proved the pointer NON-NULL is not a finding; an escaped pointer is
    * not one either - the state pass says so, not this rule's silence. A call argument is a use
    * only at a position the callee READS THROUGH - an inventoried dst/src role, or the callee's own
    * `derefs-param` summary - exactly the evidence the state pass's arm 1 turns on, so the two arms
    * cannot disagree about what a dereference is.
    */
  private def ruleNullDereference(
    record: (StoredNode, String) => Unit
  ): Set[StoredNode] =
    // arm 1: the state pass already asked the flow question
    val stateFacts = atom.tag
        .name(AllocationStatePass.TagNullUse)
        .l
        .flatMap(t => t._taggedByIn.collectAll[StoredNode].l)
        .distinct
    stateFacts.foreach(node => record(node, RuleNullDeref))

    // the call positions that read through their argument: inventoried roles, and the callee
    // summaries the state pass concluded - one scan each, not a traversal per use
    val derefsByName  = AllocationStatePass.derefsParamsByName(atom)
    val readPositions = OverlayFacts.memoryReadPositions(atom)

    // arms 2 and 3: per method, the null guards the author wrote and the uses that precede (or
    // never meet) them. `<global>` is skipped: its AST nests every function of the file, so its
    // "uses" and "guards" would be every function's at once - one function's guard reaching
    // another function's use through it is not a check-after-use, it is an aggregation artefact
    val hypothesis = mutable.LinkedHashSet.empty[StoredNode]
    atom.method.filterNot(_.isExternal).filterNot(_.name == "<global>").l.foreach { method =>
      // a bare `if (x)` is a null guard only for POINTER x: FFmpeg truthiness-checks ints
      // everywhere (`if (ret)`, `if (size)`), and counting those made arm 2 fire on every
      // earlier use of the int - the bulk of the rule's first libavformat measurement
      val pointerNames = (method.local.l ++ method.parameter.l)
          .map(d => d.name -> d.property("TYPE_FULL_NAME"))
          .collect { case (n, t: String) if OverlayFacts.isPointer(t) => n }
          .toSet
      // the guard's LINE (the earliest, when the author wrote several) and the structure it
      // belongs to - nesting inside that structure is protection, not lateness
      val guards = mutable.LinkedHashMap.empty[String, (Int, ControlStructure)]
      method.ast.collectAll[ControlStructure].l.foreach { cs =>
          cs.condition.foreach { cond =>
              OverlayFacts.nullGuardKeyOf(cond, pointerNames).foreach { key =>
                val line = cond.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
                guards.update(
                  key,
                  guards.get(key) match
                    case Some((prevLine, prevCs)) if prevLine <= line => (prevLine, prevCs)
                    case _                                            => (line, cs)
                )
              }
          }
      }
      // the redefinitions of each variable, by line: a guard that follows one speaks about a
      // different value than the one the use read
      val redefinitions: Map[String, Seq[Int]] =
          method.ast
              .collectAll[Call]
              .l
              .flatMap(c =>
                  c.name match
                    case "<operator>.assignment" | "<operator>.assignmentPlus" |
                        "<operator>.assignmentMinus" | "<operator>.postIncrement" |
                        "<operator>.preIncrement" =>
                        c.argumentOption(1).collect { case i: Identifier => i }
                    case _ => None
              )
              .groupMap(_.name)(i => i.lineNumber.map(_.toInt).getOrElse(Int.MaxValue))
              .view
              .mapValues(_.toSeq.sorted)
              .toMap
      val paramNames = method.parameter.name.l.toSet
      if guards.nonEmpty || method.parameter.exists(p => OverlayFacts.isPointer(p.typeFullName))
      then
        // the uses a null guard would have protected: a dereference base, or an argument handed
        // to a call at a position that reads through it
        val uses = method.ast.collectAll[Call].l.flatMap { c =>
          val derefBases = c.name match
            case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" |
                "<operator>.indexAccess" | "<operator>.indirectIndexAccess" =>
                c.argumentOption(1).toList
            case _ => Nil
          val callArgs =
              if c.name.startsWith("<operator>") then Nil
              else
                val readsThrough = readPositions.getOrElse(c.id, Set.empty) ++
                    derefsByName.getOrElse(c.name, Set.empty)
                c.argument.l.filter(a => readsThrough.contains(a.argumentIndex))
          (derefBases ++ callArgs).collect { case i: Identifier => i }
        }
        uses.foreach { use =>
            castUnwrappingKey(use).foreach { key =>
              val line = use.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
              guards.get(key) match
                case Some((guardLine, cs)) if guardLine > line =>
                    // the guard exists but comes AFTER the use: check-after-use, unless the
                    // use sits inside the guard's own structure (a loop body under its
                    // trailer is guarded from the second iteration on and the author wrote
                    // the check where the loop could see it), or the variable was
                    // redefined in between (the guard speaks about a different value)
                    val insideGuard = isNestedWithin(use, cs)
                    val redefinedInBetween =
                        redefinitions.get(key.stripPrefix("v:")).exists(lines =>
                            lines.exists(l => l > line && l < guardLine)
                        )
                    if !insideGuard && !redefinedInBetween then
                      record(use, RuleNullDeref)
                case None
                    if paramNames.contains(use.name) && isTraversalChainBase(use) =>
                    // a parameter dereferenced with no guard on it anywhere, through a
                    // self-referential field chain (`head->next->v`): every hop is a fresh,
                    // independently-nullable traversal pointer. The part-5 boundary (any pure
                    // field chain) was the FFmpeg context idiom (`s->priv_data->x`), 3,176
                    // findings per tree of it; the member's type equal to the parameter's own
                    // pointee type is the fact that separates the two.
                    record(use, RuleNullDeref)
                    hypothesis += use
                case _ => ()
              end match
            }
        }
      end if
    }
    hypothesis.toSet
  end ruleNullDereference

  /** Is `node` nested inside `cs`'s subtree? */
  private def isNestedWithin(node: AstNode, cs: ControlStructure): Boolean =
    var cursor: Option[StoredNode] = node._astIn.nextOption()
    var found                      = false
    var walking                    = true
    while walking do
      cursor match
        case Some(n) =>
            if n.id == cs.id then
              found = true
              walking = false
            else
              n match
                case _: Method => walking = false
                case _         => cursor = n._astIn.nextOption()
        case None => walking = false
    found

  /** Is this identifier the base of the inner access of a SELF-REFERENTIAL field chain
    * (`head->next->v`, where `next` is a pointer of `head`'s own pointee type)? The inner member is
    * resolved through the graph's type table; an unresolvable member type concludes nothing. Index
    * accesses in the chain are deliberately excluded, as in part 5: the corpus run put three
    * \@nofinding lines on the field-through-index form while the pure field chain kept the true
    * shape.
    */
  private def isTraversalChainBase(use: Identifier): Boolean =
      use._astIn.collectFirst { case c: Call => c }.exists { access =>
          isFieldAccess(access) && OverlayFacts.memberRefOf(atom, access).exists { member =>
            val paramType = use.method.parameter
                .name(use.name)
                .l
                .headOption
                .map(_.typeFullName)
                .getOrElse("")
            OverlayFacts.isPointer(member.typeFullName) &&
            member.typeFullName.trim == paramType.trim
          } && access._astIn.collectFirst { case outer: Call => outer }
              .exists(outer =>
                  isFieldAccess(outer) && outer.argumentOption(1).exists(_.id == access.id)
              )
      }

  private def isFieldAccess(c: Call): Boolean =
      c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess"

  private def tagValues(node: StoredNode, tag: String): Set[String] =
      node.tag.name(tag).value.l.toSet

  /** MS-BOUND-002: attacker-controlled length, no upper bound, into a buffer the call actually
    * writes (CWE-787 is about a destination; an allocation-size argument creates a buffer, it does
    * not overrun one). A length that flows from the destination's own paired capacity parameter is
    * NOT unbounded - it honours the buffer/capacity contract, and only MS-BOUND-001 (which fires
    * when that contract is broken) has any business reporting at such a site.
    *
    * C3: a caller-param-only length is the signature of a correctly written helper - the bound
    * lives at its callers - so it reports only when the call graph says the callers do NOT
    * establish the bound: the method has no intra-tree callers at all (framework-reachable), or
    * some call site passes a value for the feeding parameter that is not provably a constant or a
    * sizeof. An untrusted-read length always reports: the function read it itself.
    */
  private def ruleUnboundedCopy(
    argsByCall: Map[Call, List[Expression]],
    record: (StoredNode, String) => Unit
  ): Unit =
      argsByCall.foreach { case (call, args) =>
          val capParam     = capacityParamOf(call, args)
          val writesBuffer = args.exists(a => a.tag.name(MemoryApiPass.TagDst).l.nonEmpty)
          lengthArgsOf(args).foreach { lenArg =>
            val tags = lenArg.tag.name.l
            val controlled = tags.contains(ValueOriginPass.OriginUntrustedRead) ||
                (tags.contains(ValueOriginPass.OriginCallerParam) &&
                    unboundedAtCallSites(call.method, lenArg))
            val honoursCapacity = capParam.exists(reaches(lenArg, _))
            if writesBuffer && controlled && !isBounded(tags) && !honoursCapacity then
              record(lenArg, RuleUnboundedCopy)
          }
      }

  /** Does some caller leave this caller-param length unbounded? Report when the method has no
    * intra-tree callers (externally reachable - framework callbacks and exports), when the length
    * cannot be attributed to a parameter, or when any resolved call site passes a value whose
    * origin is not purely constant (literals and sizeofs). Every call site passing a provable
    * constant is the helper whose bound lives at its callers, and stays silent.
    */
  private def unboundedAtCallSites(method: Method, lenArg: Expression): Boolean =
    val callers = method._callIn.collectAll[Call].l.distinct
    if callers.isEmpty then true
    else
      val params = lenArg.tag.name(ValueOriginPass.OriginCallerParam).value.l
          .flatMap(name => method.parameter.name(name).headOption)
      if params.isEmpty then true
      else
        val siteArgs =
            for
              site  <- callers
              param <- params
              arg   <- site.argumentOption(param.index)
            yield arg
        if siteArgs.isEmpty then true
        else
          siteArgs.exists(arg =>
              ValueOriginPass.originNamesOf(arg) != Set(ValueOriginPass.OriginConstant)
          )
  end unboundedAtCallSites

  /** MS-BOUND-003/004 (C4): index out of bounds, over facts that already exist on the graph.
    * `ValueOriginPass` tags array indices with their origin and nobody read them. Two arms:
    *
    *   - **unchecked attacker index**: an index whose origin is `caller-param` or `untrusted-read`,
    *     on a base whose extent is a known capacity (`const:N` / `alloc:`), with no `bounded-above`
    *     \- and no `bounded-below` either, since a signed index that can go negative can also go
    *     above.
    *   - **half-bounded signed index** (the CVE-2026-75146 shape): the author bounded the index
    *     ABOVE (`cur_seq_no < n_fragments`) but not below, and the index is a signed value read out
    *     of a struct - someone else set it, it can be negative, and the comparison that is there
    *     does not stop it. `bounded-below` finally earns its keep: the fixed tree adds the `>= 0`
    *     conjunct and the arm goes quiet.
    *
    * CWE-125 for a read, CWE-787 for a write - the distinction is which side of an assignment the
    * index access sits on.
    */
  private def ruleIndexBounds(record: (StoredNode, String) => Unit): Unit =
    // the half-bounded arm reports once per (method, index variable): the missing `>= 0` is one
    // fix however many accesses the counter indexes - movenc.c wrote `trk->cluster[trk->entry]`
    // five times in one function, five findings of one hypothesis
    val halfBoundedFirst = mutable.LinkedHashMap.empty[(Long, String), Expression]
    atom.call
        .name("<operator>.indexAccess|<operator>.indirectIndexAccess")
        .l
        .foreach { access =>
          for
            idx  <- access.argumentOption(2)
            base <- access.argumentOption(1)
          do
            val tags = idx.tag.name.l
            val extent = base.tag.name(ExtentPass.TagExtent).value.l.headOption
                .getOrElse(ExtentPass.ValueUnknown)
            val knownExtent = extent.startsWith(ExtentPass.ValueConst + ":") ||
                extent.startsWith(ExtentPass.ValueAlloc + ":")
            val boundedAbove = tags.contains(GuardPass.TagAbove) ||
                tags.contains(GuardPass.TagByExtent)
            val boundedBelow = tags.contains(GuardPass.TagBelow)
            val attackerIndex = tags.contains(ValueOriginPass.OriginCallerParam) ||
                tags.contains(ValueOriginPass.OriginUntrustedRead)
            val halfBounded = tags.contains(ValueOriginPass.OriginStructField) &&
                signednessOf(idx).contains(true)
            // The two arms are separate rules because they know different amounts. The attacker
            // arm has a capacity and an origin and no bound: evidence. The half-bounded arm has
            // a HYPOTHESIS - this signed counter could be negative - which is true of most
            // signed counters and wrong about almost all of them (76 of libavformat's index
            // findings, against one CVE shape). It reports at `low`, so a default run at
            // `--min-confidence medium` does not drown in it, and looking for the shape
            // deliberately still works.
            if attackerIndex && knownExtent && !boundedAbove && !boundedBelow then
              record(idx, ruleIdFor(access))
            else if halfBounded && boundedAbove && !boundedBelow then
              val key  = (idx.method.id, OverlayFacts.variableKey(idx).getOrElse(s"n:${idx.id}"))
              val line = idx.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
              halfBoundedFirst.get(key) match
                case Some(prev) if prev.lineNumber.map(_.toInt).getOrElse(Int.MaxValue) <= line =>
                case _ => halfBoundedFirst(key) = idx
          end for
        }
    halfBoundedFirst.values.foreach(idx => record(idx, RuleNegativeIndexHazard))
  end ruleIndexBounds

  /** A read through the index is CWE-125, a write through it CWE-787. */
  private def ruleIdFor(access: Call): String =
    val isWrite = access._astIn.collectFirst { case c: Call => c }.exists(c =>
        c.name.startsWith("<operator>.assignment") &&
            c.argumentOption(1).exists(_.id == access.id)
    )
    if isWrite then RuleIndexWrite else RuleIndexRead

  /** MS-BOUND-006/007 (F4, part 6): a write or copy overruns a buffer whose capacity the graph
    * KNOWS. The CWE is the storage family the extent names - CWE-121 for a declared array
    * (`const:`, stack or struct member alike), CWE-122 for an allocator-sized buffer (`alloc:`).
    * Three arms over facts that already existed when the nine CWE-121/122 corpus rows were all
    * missed:
    *
    *   - **a constant length past the extent**: `memcpy(buf, s, 100)` into `malloc(10)` - the
    *     cwe122 fixture rows. Invisible until ExtentPass learned to see the allocation under its
    *     cast (`(char *)malloc(10)` resolved to `unknown`), and no rule asked the
    *     constant-vs-capacity question - MS-BOUND-002 needs an attacker, and this arm needs only
    *     arithmetic.
    *   - **an unbounded string copy into a fixed buffer** (the cwe121 strcpy/sprintf rows): the
    *     copy family with NO length argument - strcpy/strcat/sprintf - where the content argument's
    *     origin is attacker-controlled and no guard bounds the source's length against anything. A
    *     call is of this family exactly when the inventory gives it a dst and no len - data, not a
    *     name list. Restricted to `const:` extents: `strcpy` into an allocator-sized buffer is
    *     CWE-131's off-by-one question (needs the strlen arithmetic), not this rule's.
    *   - **a loop write bounded by an unvalidated count** (the struct-array row, CVE-2026-64831's
    *     shape): the index is an induction variable a loop comparison bounds above by an
    *     attacker-origin COUNT, the base has a known extent, and nothing bounds the count itself -
    *     `for (i = 0; i < count; i++) vps->hrd[i] = src[i]`. The good pair caps the count (`if
    *     (count > MAX_HRD) return;`) and stands down: the cap is a NOT-holding comparison of an
    *     early-exit guard, which no CDG edge reaches.
    */
  private def ruleCapacityOverrun(record: (StoredNode, String) => Unit): Unit =
    val attackers = Set(ValueOriginPass.OriginCallerParam, ValueOriginPass.OriginUntrustedRead)
    val sitesByCall = OverlayFacts.memoryArgumentSites(atom)
        .groupBy { case (c, _, _) => c }
        .map { case (c, rows) => c -> rows.map { case (_, arg, _) => arg }.distinct }

    def literalNumberOf(e: Expression): Option[Long] = e match
      case l: Literal => l.code.trim.toLongOption
      case _          => None

    def allocCallOf(e: Expression): Option[Call] = e match
      case c: Call
          if tagValues(c, MemoryApiPass.TagAlloc).nonEmpty ||
              tagValues(c, MemoryApiPass.TagRealloc).nonEmpty =>
          Some(c)
      case c: Call if c.name == "<operator>.cast" =>
          c.argument.l.collectFirst { case x: Call => x }.flatMap(allocCallOf)
      case _ => None

    /** The capacity in BYTES the dst's extent names, when it is knowable - a copy length counts
      * bytes. `const:N` counts ELEMENTS, so it converts only for a byte-sized element type (`int
      * a[10]` cleared with `memset(a, 0, 40)` is exact, not an overrun); any other element type
      * concludes nothing. `alloc:<size-arg>` needs every size argument literal - calloc's capacity
      * is count * size.
      */
    def extentCapacity(dst: Expression): Option[Long] =
        dst.tag.name(ExtentPass.TagExtent).value.l.headOption.flatMap {
            case v if v.startsWith(s"${ExtentPass.ValueConst}:") =>
                v.stripPrefix(s"${ExtentPass.ValueConst}:").toLongOption
                    .filter(_ => hasByteElements(dst))
            case v if v.startsWith(s"${ExtentPass.ValueAlloc}:") =>
                OverlayFacts
                    .reachingDefsIn(dst)
                    .collect { case d: Identifier => d }
                    .flatMap(_._astIn.collectFirst {
                        case a: Call if a.name == "<operator>.assignment" => a
                    })
                    .flatMap(_.argumentOption(2))
                    .flatMap(allocCallOf)
                    .flatMap { alloc =>
                      // the count role is tagged `mem-len` too: calloc's two arguments
                      val sizeArgs =
                          alloc.argument.l.filter(_.tag.name(MemoryApiPass.TagLen).l.nonEmpty)
                      val literals = sizeArgs.flatMap(literalNumberOf)
                      Option.when(sizeArgs.nonEmpty && literals.size == sizeArgs.size)(
                        literals.product
                      )
                    }
                    .headOption
            case _ => None
        }

    /** The rule id an extent family selects: declared array -> CWE-121, allocation -> CWE-122. */
    def extentRule(dst: Expression): Option[String] =
        dst.tag.name(ExtentPass.TagExtent).value.l.headOption.flatMap {
            case v if v.startsWith(s"${ExtentPass.ValueConst}:") => Some(RuleFixedExtentOverrun)
            case v if v.startsWith(s"${ExtentPass.ValueAlloc}:") => Some(RuleHeapExtentOverrun)
            case _                                               => None
        }

    // arm 1: a constant length past the extent
    sitesByCall.foreach { case (call, args) =>
        val dstArgs = args.filter(a => a.tag.name(MemoryApiPass.TagDst).l.nonEmpty)
        val lenArgs = args.filter(a => a.tag.name(MemoryApiPass.TagLen).l.nonEmpty)
        for
          dst  <- dstArgs.headOption
          len  <- lenArgs.collectFirst(Function.unlift(literalNumberOfAs))
          cap  <- extentCapacity(dst)
          rule <- extentRule(dst)
          if len._2 > cap
        do record(len._1, rule)
    }

    // arm 2: the implicit-length copy family (dst role, no len role) into a FIXED buffer
    sitesByCall.foreach { case (call, args) =>
        val dstArgs = args.filter(a => a.tag.name(MemoryApiPass.TagDst).l.nonEmpty)
        val srcArgs = args.filter(a => a.tag.name(MemoryApiPass.TagSrc).l.nonEmpty)
        val lenArgs = args.filter(a => a.tag.name(MemoryApiPass.TagLen).l.nonEmpty)
        if dstArgs.nonEmpty && srcArgs.nonEmpty && lenArgs.isEmpty then
          dstArgs.headOption.foreach { dst =>
              extentRule(dst).filter(_ == RuleFixedExtentOverrun).foreach { rule =>
                // the content: a src argument, or (sprintf's variadic %s) an argument the
                // inventory gave no role at all
                val rolePositions = (dstArgs ++ srcArgs).map(_.argumentIndex).toSet
                val extras = call.argument.l
                    .filter(a => !rolePositions.contains(a.argumentIndex))
                    .filterNot(_.isFieldIdentifier)
                // only a STRING grows with the attacker: `sprintf(buf, "%d", n)` formats an
                // integer of bounded width, whatever n's origin
                (srcArgs ++ extras).find(a =>
                    OverlayFacts.isPointer(a.property("TYPE_FULL_NAME") match
                      case t: String => t.trim
                      case _         => ""
                    ) && ValueOriginPass.originNamesOf(a).exists(attackers.contains)
                ).foreach { content =>
                    if !lengthGuardedCopy(call, content) then record(content, rule)
                }
              }
          }
        end if
    }

    // arm 3: a loop write bounded by an unvalidated count
    atom.method.filterNot(m => m.isExternal || m.name == "<global>").l.foreach { method =>
      val conds = method.ast.collectAll[ControlStructure].l
          .flatMap(_.condition.collect { case c: Call => c })
      def factsAt(holds: Boolean) =
          conds.flatMap(c => GuardPass.conjuncts(c, holds).getOrElse(Nil)).flatMap {
              case (cmp, h) => GuardPass.directionalFacts(cmp, h)
          }
      val holdsFacts                           = factsAt(holds = true)
      val rejectsFacts                         = factsAt(holds = false)
      def keyOf(e: Expression): Option[String] = OverlayFacts.variableKey(e)
      def isConstantish(e: Expression): Boolean = e match
        case _: Literal                                        => true
        case c: Call if c.name.startsWith("<operator>.sizeOf") => true
        case c: Call
            if !c.name.startsWith("<operator>") && c.ast.isLiteral.l.nonEmpty &&
                c.ast.isIdentifier.l.isEmpty && c.ast.isCall.l.forall(_.id == c.id) =>
            // an unexpanded macro the frontend left as a call, carrying its expansion as a
            // subtree of literals - a #define'd bound, read from the graph rather than
            // guessed from the name (MAX_HRD is 16 because the expansion says so)
            true
        // a #define constant: an identifier that is neither a local nor a parameter here -
        // or one the frontend gave a local but no definition (macro constants get locals),
        // the same def-less-external-constant reading ValueOriginPass uses for NULL
        case i: Identifier =>
            (method.local.name(i.name).l.isEmpty && method.parameter.name(i.name).l.isEmpty) ||
            OverlayFacts.reachingDefsIn(i).forall(_.isInstanceOf[Method])
        case _ => false
      // a count is capped when some early-exit comparison (read at its NOT-holding polarity -
      // the side an in-block successor runs on, which no CDG edge reaches) bounds it above
      // against a constant
      def cappedAbove(bound: Expression): Boolean =
        val boundKey = keyOf(bound)
        boundKey.exists(k =>
            rejectsFacts.exists { case (bounded, above, cap) =>
                above && keyOf(bounded).contains(k) && isConstantish(cap)
            }
        )
      // a loop bounded by the SAME variable that sizes the allocation writes exactly the
      // buffer's capacity: `malloc(count * sizeof(int)); for (i < count) arr[i]` is bounded
      // by construction, whatever count is - the rule stands down
      def selfSizedLoop(base: Expression, loopBound: Expression): Boolean =
          base.tag.name(ExtentPass.TagExtent).value.l.headOption.exists {
              case v if v.startsWith(s"${ExtentPass.ValueAlloc}:") =>
                  OverlayFacts
                      .reachingDefsIn(base)
                      .collect { case d: Identifier => d }
                      .flatMap(_._astIn.collectFirst {
                          case a: Call if a.name == "<operator>.assignment" => a
                      })
                      .flatMap(_.argumentOption(2))
                      .flatMap(allocCallOf)
                      .exists(alloc =>
                          alloc.argument.l
                              .filter(a => a.tag.name(MemoryApiPass.TagLen).l.nonEmpty)
                              .exists { sz =>
                                // the size may be the count scaled (`count * sizeof(T)`):
                                // the bound's key on the size or one of its factors
                                val szKeys = keyOf(sz).toSet ++ (sz match
                                  case c: Call
                                      if c.name == "<operator>.multiplication" ||
                                          c.name == "<operator>.division" =>
                                      c.argument.l.flatMap(a => keyOf(a)).toSet
                                  case _ => Set.empty
                                )
                                keyOf(loopBound).exists(szKeys.contains)
                              }
                      )
              case _ => false
          }
      method.ast
          .isCall
          .name("<operator>.indexAccess|<operator>.indirectIndexAccess")
          .l
          .foreach { access =>
              for
                idx    <- access.argumentOption(2)
                base   <- access.argumentOption(1)
                rule   <- extentRule(base)
                idxKey <- keyOf(idx)
                if ruleIdFor(access) == RuleIndexWrite
                if idx.tag.name(GuardPass.TagByExtent).l.isEmpty
                attackerCount = holdsFacts.exists { case (bounded, above, bound) =>
                    above && keyOf(bounded).contains(idxKey) &&
                    ValueOriginPass.originNamesOf(bound).exists(attackers.contains) &&
                    !isConstantish(bound) && !cappedAbove(bound) &&
                    !selfSizedLoop(base, bound)
                }
                if attackerCount
              do record(idx, rule)
          }
    }
  end ruleCapacityOverrun

  /** Is the declared element type of this array expression one byte wide? The type is read off the
    * expression (`char[16]`, `uint8_t[4]`); an unresolved type is not assumed to be bytes.
    */
  private def hasByteElements(dst: Expression): Boolean =
    val t = Option(dst.property("TYPE_FULL_NAME")).collect { case s: String => s }.getOrElse("")
    val element = t.replaceAll("""\[[^\]]*\]""", "").replace("const ", "").trim
    MemorySafetyFindingPass.ByteTypes.contains(element)

  /** The (literal, node) pair of an expression when it is a plain literal - Function.unlift keeps
    * the for-comprehension shape of the arm-1 loop.
    */
  private def literalNumberOfAs(e: Expression): Option[(Expression, Long)] =
      e match
        case l: Literal => l.code.trim.toLongOption.map(v => (l, v))
        case _          => None

  /** Is the copy guarded by a comparison bounding some call over the content variable above - `if
    * (strlen(userInput) < sizeof(dest)) strcpy(dest, userInput)`? The guard bounds the source's
    * LENGTH (a call of the variable), not the variable itself, so the structural question is
    * whether a controller's bounded operand is a call reading that variable.
    */
  private def lengthGuardedCopy(call: Call, content: Expression): Boolean =
      OverlayFacts.variableKey(content).exists { contentKey =>
          call.controlledBy.collect { case c: Call => c }.exists { controller =>
              GuardPass
                  .conjuncts(controller, GuardPass.holdsAt(controller, call))
                  .getOrElse(Nil)
                  .exists { case (cmp, holds) =>
                      GuardPass.directionalFacts(cmp, holds).exists { case (bounded, above, _) =>
                          above && (bounded match
                            case bc: Call =>
                                bc.argument.l.exists(a =>
                                    OverlayFacts.variableKey(a).contains(contentKey)
                                )
                            case _ => false
                          )
                      }
                  }
          }
      }

  /** MS-ALLOC-005/006 (F5, part 6): the deallocation of the wrong thing, over the state and
    * inventory facts. One implementation, two CWE families by shape:
    *
    *   - **CWE-590** - a free of storage that is not the heap's: the argument holds this frame's
    *     storage (the state pass's `stack-addr` fact, or an array/static LOCAL directly - the
    *     `storage-class=static` tag c2cpg writes), or is a string literal.
    *   - **CWE-761** - a free of a pointer not at the start of its buffer: the argument is pointer
    *     arithmetic (`p + 4`, `p += n`), or an identifier whose definition is such arithmetic on a
    *     tracked allocation.
    *
    * and **MS-ALLOC-007 (CWE-762)** - the release family does not match the acquisition family. The
    * graph cannot distinguish `new[]`/`delete[]` from `new`/`delete` (frontend probe Q3), so the
    * reachable mismatches are the cross-family ones: `new` released by `free`, `malloc` released by
    * `delete`. The array/scalar confusion inside one family is out of reach and is said so rather
    * than guessed.
    */
  private def ruleWrongDeallocation(record: (StoredNode, String) => Unit): Unit =
    def allocCallOf(e: Expression): Option[Call] = e match
      case c: Call
          if tagValues(c, MemoryApiPass.TagAlloc).nonEmpty ||
              tagValues(c, MemoryApiPass.TagRealloc).nonEmpty =>
          Some(c)
      case c: Call if c.name == "<operator>.cast" =>
          c.argument.l.collectFirst { case x: Call => x }.flatMap(allocCallOf)
      case _ => None

    atom.call.l.foreach { c =>
      val freeFamilies = tagValues(c, MemoryApiPass.TagFree)
      if freeFamilies.nonEmpty then
        c.argumentOption(1).foreach { arg =>
            // CWE-590: non-heap storage
            arg match
              case lit: Literal if lit.code.startsWith("\"") =>
                  record(lit, RuleNonHeapFree)
              case i: Identifier =>
                  // an ARRAY local (automatic or static) is not heap storage. A static POINTER
                  // local is the cache idiom - it holds heap storage and freeing it is correct -
                  // so the storage class alone decides nothing
                  i.method.local.nameExact(i.name).l.headOption.foreach { local =>
                      if OverlayFacts.arrayExtent(local.typeFullName).isDefined ||
                        local.typeFullName.trim.endsWith("[]")
                      then record(i, RuleNonHeapFree)
                  }
                  // the state pass's frame-storage fact (q = &x; free(q)), and a
                  // definition that is a string literal (p = "literal"; free(p))
                  if i.tag.name(AllocationStatePass.TagState).value.l
                        .contains("stack-addr") ||
                    OverlayFacts
                        .reachingDefsIn(i)
                        .collect { case d: Identifier => d }
                        .flatMap(d =>
                            d._astIn.collectFirst {
                                case a: Call if a.name == "<operator>.assignment" => a
                            }
                        )
                        .flatMap(_.argumentOption(2))
                        .exists {
                            case lit: Literal => lit.code.startsWith("\"")
                            case _            => false
                        }
                  then record(i, RuleNonHeapFree)
                  // CWE-761: the identifier's definition is pointer arithmetic over a
                  // tracked allocation
                  val defsAreOffsetArith = OverlayFacts
                      .reachingDefsIn(i)
                      .collect { case d: Identifier => d }
                      .flatMap(d =>
                          d._astIn.collectFirst {
                              case a: Call if a.name == "<operator>.assignment" => a
                          }
                      )
                      .flatMap(_.argumentOption(2))
                      .exists {
                          case arith: Call
                              if arith.name == "<operator>.addition" ||
                                  arith.name == "<operator>.subtraction" =>
                              arith.argument.l.collect { case x: Expression => x }
                                  .exists(op =>
                                      // one operand is the allocation, the other the offset
                                      allocCallOf(op).isDefined ||
                                          OverlayFacts.reachingDefsIn(op)
                                              .collect { case d: Identifier => d }
                                              .flatMap(d =>
                                                  d._astIn.collectFirst {
                                                      case a: Call
                                                          if a.name == "<operator>.assignment" => a
                                                  }
                                              )
                                              .flatMap(_.argumentOption(2))
                                              .exists(x => allocCallOf(x).isDefined)
                                  )
                          case _ => false
                      }
                  if defsAreOffsetArith then record(i, RuleOffsetFree)
                  // CWE-762: family mismatch against the allocation that produced the pointer
                  val allocFamily = OverlayFacts
                      .reachingDefsIn(i)
                      .collect { case d: Identifier => d }
                      .flatMap(d =>
                          d._astIn.collectFirst {
                              case a: Call if a.name == "<operator>.assignment" => a
                          }
                      )
                      .flatMap(_.argumentOption(2))
                      .flatMap(allocCallOf)
                      .flatMap(alloc => tagValues(alloc, MemoryApiPass.TagAlloc).headOption)
                      .headOption
                  allocFamily.foreach { acquired =>
                      if freeFamilies.exists(_ != acquired) then
                        record(i, RuleMismatchedFree)
                  }
              case arith: Call
                  if arith.name == "<operator>.addition" || arith.name == "<operator>.subtraction" =>
                  record(arith, RuleOffsetFree)
              case _ => ()
        }
      end if
    }
  end ruleWrongDeallocation

  /** MS-ALLOC-008/009 (F5, part 6): an allocation whose size is attacker-controlled with no bound
    * above - MS-INT-001's question without requiring the arithmetic. The card's constraint is
    * deliberate: a plain `struct-field` origin is NOT an attacker here (part 5's MS-INT-001
    * diagnosis showed two thirds of that rule's noise turned on struct-field arithmetic - every
    * correctly written FFmpeg counter). CWE-789 for a plain unbounded size; CWE-680 when the size
    * is attacker-influenced ARITHMETIC (the integer-overflow-to-buffer question, which MS-INT-001
    * asks at `low` with CWE-190 - this rule names the CWE the row actually is). The caller-param
    * arm reuses MS-BOUND-002's C3 call-site check: a helper whose every intra-tree caller passes a
    * constant is bounded at its callers.
    */
  private def ruleUncontrolledAllocationSize(record: (StoredNode, String) => Unit): Unit =
    val attackers = Set(ValueOriginPass.OriginUntrustedRead, ValueOriginPass.OriginCallerParam)
    OverlayFacts
        .memoryArgumentSites(atom)
        .collect { case (call, arg, MemoryApiPass.TagLen) => (call, arg) }
        .foreach { case (call, lenArg) =>
            val allocates = tagValues(call, MemoryApiPass.TagAlloc).nonEmpty ||
                tagValues(call, MemoryApiPass.TagRealloc).nonEmpty
            if allocates then
              val tags    = lenArg.tag.name.l
              val origins = ValueOriginPass.originNamesOf(lenArg).filter(attackers.contains)
              val bounded =
                  tags.contains(GuardPass.TagAbove) || tags.contains(GuardPass.TagByExtent)
              def unboundedAtCallers: Boolean = callerParamUnbounded(call.method, lenArg)
              val controlled = origins.contains(ValueOriginPass.OriginUntrustedRead) ||
                  (origins.contains(ValueOriginPass.OriginCallerParam) && unboundedAtCallers)
              if controlled && !bounded then
                val arithmetic = lenArg match
                  case c: Call =>
                      c.name == "<operator>.multiplication" || c.name == "<operator>.addition"
                  case _ => false
                record(
                  lenArg,
                  if arithmetic then RuleUncontrolledSizeOverflow else RuleUncontrolledSize
                )
        }
  end ruleUncontrolledAllocationSize

  /** Is the caller-param origin of `expr` (inside `method`) attacker-controlled one hop up? True
    * when the method has no intra-tree caller (an API or callback entry - nothing bounds it), or
    * when some caller passes, at a parameter `expr` derives from, a value that is itself
    * attacker-origin and unbounded at that site. A caller passing its own struct's field or a
    * length it already checked is the helper's contract being met, not an uncontrolled size.
    */
  private def callerParamUnbounded(method: Method, expr: Expression): Boolean =
    val attackers = Set(ValueOriginPass.OriginUntrustedRead, ValueOriginPass.OriginCallerParam)
    val callers   = method._callIn.collectAll[Call].l.distinct
    callers.isEmpty || {
        val params = (expr +: expr.ast.collectAll[Expression].l)
            .flatMap(_.tag.name(ValueOriginPass.OriginCallerParam).value.l)
            .distinct
            .flatMap(name => method.parameter.nameExact(name).headOption)
        params.isEmpty || {
            val siteArgs =
                for
                  site  <- callers
                  param <- params
                  arg   <- site.argumentOption(param.index)
                yield arg
            siteArgs.isEmpty || siteArgs.exists { arg =>
              val argTags = arg.tag.name.l
              ValueOriginPass.originNamesOf(arg).exists(attackers.contains) &&
              !argTags.contains(GuardPass.TagAbove) && !argTags.contains(GuardPass.TagByExtent)
            }
        }
    }
  end callerParamUnbounded

  /** A length arithmetic whose ONLY attacker origin is a caller parameter the callers bound (see
    * [[callerParamUnbounded]]): `size + AV_INPUT_BUFFER_PADDING_SIZE` in a helper every caller
    * hands a checked size is the padding idiom, not a wrap.
    */
  private def callerBoundedArithmetic(memCall: Call, arith: Call): Boolean =
    val origins = arith.tag.name(IntegerWidthPass.TagArithLen).value.l
        .flatMap(_.split("\\+"))
        .filter(attackerOrigins)
        .toSet
    origins == Set(ValueOriginPass.OriginCallerParam) && !callerParamUnbounded(
      memCall.method,
      arith
    )

  /** MS-INT-001 (D0, CWE-190): an allocation or copy length computed by arithmetic whose operands
    * are attacker-influenced, with no guard bounding an operand from above and no widened operand.
    * The facts were left on the graph by C5 and nobody read them: `int-arith-len` names the
    * arithmetic AND its attacker origins (the evidence the rule turns on - never a type's absence),
    * and D1's count role is what makes the attacker-influenced factor of a count-by-size allocator
    * visible at all (hevc.c:847's `numNalus + 1` carried no length fact before it).
    *
    * The guard conjunct reuses GuardPass's comparison semantics at OPERAND level: a guard bounds
    * `numNalus`, not `numNalus + 1`, so the tag-level bound lookup (which keys on the argument)
    * never sees it. An operand bounded above - `count > UINT_MAX / sizeof(int)` - is exactly the
    * guard that makes the overflow impossible, and the rule stands down; the fixed tree of
    * CVE-2026-75141 adds precisely that guard. A widened operand - `(size_t) a * b` - means the
    * arithmetic already computes at the wider width, so there is nothing to overflow; standing down
    * there is evidence-based (a widening cast exists), not silence-based.
    *
    * Part 5 (E1) adds the capacity conjunct: the arithmetic must bound a buffer that does not
    * already have one. An allocator's size/count argument BECOMES the new buffer's capacity, so it
    * is always in scope (the CVE-2026-75141 shape); a copy into a destination that already carries
    * an extent (`const:`, `param:`, `field:`, `alloc:`, `sizeof:`) is bounded by a fact the
    * MS-BOUND rules own, whatever this arithmetic does to the length. The def walk that finds the
    * arithmetic is [[OverlayFacts.reachingDefsIn]], which no longer crosses argument-to-argument
    * plumbing edges - part 4's rule reported the pointer arithmetic in a copy's DESTINATION as a
    * length computation through exactly those edges.
    */
  private def ruleIntegerArithmeticLength(record: (StoredNode, String) => Unit): Unit =
      OverlayFacts.memoryArgumentSites(atom)
          .collect { case (call, arg, MemoryApiPass.TagLen) => (call, arg) }
          .foreach { case (memCall, lenArg) =>
              // the first length arithmetic along the def chain that satisfies every conjunct: a
              // product nested in another product reports once, at the node nearest the length
              (lenArg +: OverlayFacts.reachingDefsIn(lenArg)).collectFirst {
                  case arith: Call
                      if isLengthArithmetic(arith) && attackerArithmetic(arith)
                          && !widenedOperandOf(arith)
                          && !guardBoundsAnOperand(memCall, arith)
                          && !earlyExitBoundsAnOperand(memCall, arith)
                          && !stringLengthSum(arith)
                          && !wideCounterGrowth(arith)
                          && !pointerArithmetic(arith)
                          && !callerBoundedArithmetic(memCall, arith)
                          && lengthBecomesCapacity(memCall) =>
                      record(arith, RuleIntegerOverflow)
              }
          }

  /** An early-exit bound: `if (n > MAX) return AVERROR(EINVAL);` earlier in the method bounds n
    * above on every path that reaches the allocation, yet the allocation is not control-dependent
    * on it (it post-dominates the check), so [[guardBoundsAnOperand]] never sees it. FFmpeg writes
    * almost every size check this way. A comparison read at either polarity counts - the side that
    * continues is the one the author allowed - as long as it precedes the call in the method and
    * bounds an operand from above.
    */
  private def earlyExitBoundsAnOperand(memCall: Call, arith: Call): Boolean =
    val operandKeys = arith.argument.l
        .collect { case e: Expression => e }
        .flatMap(castUnwrappingKey)
        .toSet
    val callLine = memCall.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
    operandKeys.nonEmpty && memCall.method.ast
        .collectAll[ControlStructure]
        .l
        .filter(_.lineNumber.exists(_.toInt < callLine))
        .flatMap(_.condition.collect { case c: Call => c })
        .exists { cond =>
            Seq(true, false).exists { holds =>
                GuardPass.conjuncts(cond, holds).getOrElse(Nil).exists { case (cmp, h) =>
                    GuardPass.directionalFacts(cmp, h).exists { case (bounded, above, _) =>
                        above && castUnwrappingKey(bounded).exists(operandKeys.contains)
                    }
                }
            }
        }
  end earlyExitBoundsAnOperand

  /** `count + k` (optionally scaled, `(count + 1) * sizeof(T)`) where every operand origin is a
    * struct field and k a small literal: the growth-by-one of an array that already holds `count`
    * elements in memory. It can only wrap when the counter is NARROW - hevc.c's `uint16_t numNalus
    * + 1` (CVE-2026-75141) wraps at 65,535 entries, which a file can ask for - so the arm reports
    * it only when the counter's width is KNOWN to be under 32 bits. An int-width counter, or one
    * whose member type the graph cannot resolve (most FFmpeg members: their structs live in headers
    * outside the analysed tree), stands down: the hypothesis tier turns on evidence of the narrow
    * width, not on its absence.
    */
  private def wideCounterGrowth(arith: Call): Boolean =
    def smallLiteral(e: Expression): Boolean = e match
      case l: Literal => l.code.trim.toLongOption.exists(v => v >= 0 && v <= 64)
      case _          => false
    def wideStructCounter(e: Expression): Boolean =
      val origins = ValueOriginPass.originNamesOf(e)
      origins.nonEmpty &&
      origins.subsetOf(Set(ValueOriginPass.OriginStructField, ValueOriginPass.OriginConstant)) &&
      !OverlayFacts.integralWidth(typeOfExpr(e)).exists(_ < 32)
    def growth(e: Expression): Boolean = e match
      case c: Call if c.name == "<operator>.addition" =>
          c.argument.l match
            case List(a, b) =>
                (smallLiteral(a) && wideStructCounter(b)) || (smallLiteral(b) && wideStructCounter(
                  a
                ))
            case _ => false
      case _ => false
    arith.name match
      case "<operator>.addition" => growth(arith)
      case "<operator>.multiplication" =>
          arith.argument.l match
            case List(a, b) =>
                def scale(e: Expression) = e match
                  case c: Call if c.name.startsWith("<operator>.sizeOf") => true
                  case l: Literal                                        => true
                  case _                                                 => false
                (growth(a) && scale(b)) || (growth(b) && scale(a))
            case _ => false
      case _ => false
  end wideCounterGrowth

  /** `pkt->data + pkt->size`, `buf + 2`: an operand is a POINTER, so the sum is an address, not a
    * length - it reached the rule through a def chain that ends in a destination, and wrapping an
    * address is the bounds rules' question.
    */
  private def pointerArithmetic(arith: Call): Boolean =
      arith.argument.l.exists(a => OverlayFacts.isPointer(typeOfExpr(a).trim))

  /** `strlen(s) + 1` and its kin: every non-constant operand is the length of a string that already
    * exists in memory (or a sizeof), so the sum cannot wrap a size_t on a real address space - the
    * terminator arithmetic correct code writes everywhere.
    */
  private def stringLengthSum(arith: Call): Boolean =
    def smallLiteral(e: Expression) = e match
      case l: Literal => l.code.trim.toLongOption.exists(v => v >= 0 && v <= 16)
      case _          => false
    def stringLength(e: Expression): Boolean = e match
      case _: Literal                                           => true
      case c: Call if c.name == "strlen" || c.name == "strnlen" => true
      case c: Call if c.name.startsWith("<operator>.sizeOf")    => true
      case c: Call if c.name == "<operator>.addition"           => c.argument.l.forall(stringLength)
      // a string's length scaled by a small constant (`strlen(s) * 4`, a wide-char buffer)
      case c: Call if c.name == "<operator>.multiplication" =>
          c.argument.l match
            case List(x, y) =>
                (stringLength(x) && smallLiteral(y)) || (smallLiteral(x) && stringLength(y))
            case _ => false
      case _ => false
    (arith.name == "<operator>.addition" || arith.name == "<operator>.multiplication") &&
    stringLength(arith)

  /** Does the length this call consumes become a buffer's capacity? An allocator produces a fresh
    * buffer whose size IS this argument; a copy into a destination with a recorded extent writes
    * into a capacity that exists independently of the arithmetic, and the wrap question is the
    * BOUND rules' to ask.
    */
  private def lengthBecomesCapacity(memCall: Call): Boolean =
    val allocates = tagValues(memCall, MemoryApiPass.TagAlloc).nonEmpty ||
        tagValues(memCall, MemoryApiPass.TagRealloc).nonEmpty
    if allocates then true
    else
      val dstExtents = memCall.argument.l
          .filter(a => a.tag.name(MemoryApiPass.TagDst).l.nonEmpty)
          .flatMap(_.tag.name(ExtentPass.TagExtent).value.l)
      dstExtents.isEmpty || dstExtents.forall(_ == ExtentPass.ValueUnknown)

  private def isLengthArithmetic(c: Call): Boolean =
      c.name == "<operator>.multiplication" || c.name == "<operator>.addition"

  /** The arithmetic's `int-arith-len` fact names its operand origins (`struct-field+constant`); the
    * rule fires only when at least one of them is a rule-relevant attacker origin.
    */
  private def attackerArithmetic(arith: Call): Boolean =
      arith.tag.name(IntegerWidthPass.TagArithLen).value.l.exists(
        _.split("\\+").exists(attackerOrigins)
      )

  private val attackerOrigins = Set(
    ValueOriginPass.OriginCallerParam,
    ValueOriginPass.OriginUntrustedRead,
    ValueOriginPass.OriginStructField,
    ValueOriginPass.OriginMixed
  )

  /** True when some operand of the arithmetic is cast to a WIDER type than the operand itself: the
    * author already widened before the multiply, and a 64-bit product is a different question.
    */
  private def widenedOperandOf(arith: Call): Boolean =
      arith.argument.l.collect { case e: Expression => e }.exists {
          case c: Call if c.name == "<operator>.cast" =>
              val operand = c.argumentOption(2).orElse(c.argumentOption(1))
              integralWidth(castTargetName(c)).exists { tw =>
                  operand.exists(o => integralWidth(typeOfExpr(o)).exists(_ < tw))
              }
          case _ => false
      }

  /** The target type of a cast, as written: c2cpg lays a cast out as (type placeholder, operand),
    * the target type being the FIRST argument's rendered name - the same convention
    * [[IntegerWidthPass]] reads its width facts with.
    */
  private def castTargetName(c: Call): String =
      if c.argumentOption(2).isDefined then
        c.argumentOption(1).map(_.code).getOrElse(typeOfExpr(c))
      else typeOfExpr(c)

  /** Does some comparison controlling the memory call bound one of the arithmetic's operands (or
    * the arithmetic itself) from ABOVE? Only an upper bound makes the overflow impossible.
    */
  private def guardBoundsAnOperand(memCall: Call, arith: Call): Boolean =
    val operandKeys = arith.argument.l
        .collect { case e: Expression => e }
        .flatMap(castUnwrappingKey)
        .toSet
    memCall.controlledBy.collect { case c: Call => c }.exists { controller =>
        GuardPass
            .conjuncts(controller, GuardPass.holdsAt(controller, memCall))
            .getOrElse(Nil)
            .exists { case (cmp, holds) =>
                GuardPass.directionalFacts(cmp, holds).exists { case (bounded, above, _) =>
                    above && (bounded.id == arith.id ||
                        castUnwrappingKey(bounded).exists(operandKeys.contains))
                }
            }
    }

  /** MS-INT-002 (D0, CWE-197): a value whose guard ran at one signedness and whose use happens at
    * another. The `int-resign` fact on `(long) obu_size` says the cast reinterprets the value; the
    * rule adds the crossing: the cast is a comparison's BOUNDED operand (the guard tested the
    * re-signed view) and the same variable is used elsewhere under that comparison's control (the
    * use reads the declared view). A narrowing that merely exists is not a finding - and a cast on
    * the guard's OTHER operand (`obu_size > (unsigned) frame_size`, both fixed trees of the
    * rtpenc_av1 pair) does not cross anything: the bounded value never changed width.
    */
  private def ruleResignAcrossGuard(record: (StoredNode, String) => Unit): Unit =
      atom.call.name("<operator>.cast").l.foreach { cast =>
          if cast.tag.name(IntegerWidthPass.TagResign).value.l.nonEmpty then
            enclosingComparison(cast).foreach { cmp =>
                castOperand(cast).flatMap(castUnwrappingKey).foreach { key =>
                  val crossed = usesOfKey(cast.method, key).exists { stmt =>
                      stmt.controlledBy.collect { case c: Call => c }.exists(_.id == cmp.id) &&
                      GuardPass
                          .directionalFacts(cmp, GuardPass.holdsAt(cmp, stmt))
                          .exists { case (bounded, above, _) =>
                              // an UPPER bound is the crossing: the guard rejected the too-large
                              // values in the cast's signedness. A bound FROM below - what the
                              // fixed trees' `obu_size > (unsigned) frame_size` produces, where the
                              // cast is the bound and not the bounded value - crosses nothing.
                              above && bounded.id == cast.id
                          }
                  }
                  if crossed then record(cast, RuleResignAcrossGuard)
                }
            }
      }

  /** The comparison the cast sits in, walking up through expression calls only. */
  private def enclosingComparison(node: AstNode): Option[Call] =
    var cursor: Option[StoredNode] = node._astIn.nextOption()
    var found: Option[Call]        = None
    while found.isEmpty && cursor.isDefined do
      cursor.get match
        case c: Call =>
            if GuardPass.comparisonOps.contains(c.name) then found = Some(c)
            else cursor = c._astIn.nextOption()
        case _ => cursor = None
    found

  private def castOperand(cast: Call): Option[Expression] =
      cast.argumentOption(2).orElse(cast.argumentOption(1))

  /** The statements of `method` whose expression tree reads the variable `key`, as statement roots
    * (the nodes CDG edges reach). Collected per method, not per graph.
    */
  private def usesOfKey(method: Method, key: String): Set[Call] =
      method.ast
          .collectAll[Expression]
          .filter(e => castUnwrappingKey(e).contains(key))
          .map(e => GuardPass.statementRootOf(e))
          .collect { case c: Call => c }
          .l
          .toSet

  /** The variable a comparison bounds, through the casts the frontend leaves in the comparison:
    * `(long) x` talks about `x`.
    */
  private def castUnwrappingKey(e: Expression): Option[String] = e match
    case c: Call if c.name == "<operator>.cast" =>
        castOperand(c).flatMap(castUnwrappingKey)
    case other => OverlayFacts.variableKey(other)

  /** The declared type of an index expression, when the frontend recorded one. */
  private def typeOfExpr(e: Expression): String = e match
    case i: Identifier => i.typeFullName
    // c2cpg leaves a field access's own type empty; the member it reads has one
    case c: Call
        if isFieldAccess(c) && Option(c.typeFullName).forall(t => t.isEmpty || t == "ANY") =>
        OverlayFacts.memberRefOf(atom, c).map(_.typeFullName).getOrElse("")
    case c: Call    => c.typeFullName
    case l: Literal => l.typeFullName
    case _          => ""

  /** Can this index go negative, and do we actually know? c2cpg often leaves the TYPE of a
    * field-access expression empty, so a `pls->cur_seq_no` index resolves its type through the
    * member it reads; when neither records a type, the answer is None - we do not know.
    *
    * The distinction is load-bearing. Treating "no type recorded" as signed made the rule fire 120
    * times on libavformat, 105 of them on indices whose type the frontend simply never wrote down:
    * an absent fact quietly satisfying a rule, which is what `unknown` extents are forbidden to do.
    * A negative-index claim needs evidence that the index CAN be negative, and the frontend's
    * silence is not that evidence.
    */
  private def signednessOf(idx: Expression): Option[Boolean] =
    val declared = typeOfExpr(idx) match
      // c2cpg writes the placeholder type "<empty>" rather than an empty string
      case t if t.nonEmpty && t != "<empty>" => Some(t)
      case _ =>
          idx match
            case c: Call => OverlayFacts.memberRefOf(atom, c).map(_.typeFullName)
            case _       => None
    declared.collect {
        case t if OverlayFacts.isSignedIntegral(t)   => true
        case t if OverlayFacts.isUnsignedIntegral(t) => false
    }

  /** MS-BOUND-001: the destination's extent is an adjacent capacity parameter, and that parameter
    * reaches neither the copy's length nor a bound on it.
    */
  private def ruleSizeParameterContract(
    argsByCall: Map[Call, List[Expression]],
    record: (StoredNode, String) => Unit
  ): Unit =
      argsByCall.foreach { case (call, args) =>
          for
            cap    <- capacityParamOf(call, args)
            lenArg <- lengthArgsOf(args).headOption
            if !isBounded(lenArg.tag.name.l) && !reaches(lenArg, cap)
          do record(lenArg, RuleSizeParamContract)
      }

  /** The destination's paired capacity parameter, when [[ExtentPass]] resolved its extent to one.
    * Both rules turn on this: 001 fires when the contract it states is broken, 002 stands down when
    * it is honoured.
    */
  private def capacityParamOf(call: Call, args: List[Expression]): Option[MethodParameterIn] =
      args
          .flatMap(a => a.tag.name(ExtentPass.TagExtent).value.l)
          .collectFirst { case v if v.startsWith(ExtentPass.ValueParam + ":") => v }
          .flatMap { extent =>
              call.method.parameter
                  .name(extent.stripPrefix(ExtentPass.ValueParam + ":"))
                  .headOption
          }

  private def lengthArgsOf(args: List[Expression]): List[Expression] =
      args.filter(a => a.tag.name(MemoryApiPass.TagLen).l.nonEmpty)

  /** An upper bound from either GuardPass family. `bounded-below` is deliberately not one: a length
    * known to be non-negative is still free to be enormous.
    */
  private def isBounded(tags: List[String]): Boolean =
      tags.contains(GuardPass.TagAbove) || tags.contains(GuardPass.TagByExtent)

  private def reaches(value: Expression, param: MethodParameterIn): Boolean =
      OverlayFacts.reachingDefsIn(value).contains(param)
end MemorySafetyFindingPass

object MemorySafetyFindingPass:

  final val TagFinding = "ms-finding"

  /** A finding-level confidence override, emitted when one arm of a rule is a hypothesis tier the
    * rule's own confidence does not describe. Valued `<rule-id>=<confidence>`: the override is
    * SCOPED to its rule, because one node can carry several findings - a null-deref hypothesis on
    * the same identifier as a high-confidence use-after-free must not demote the use-after-free. A
    * renderer reads it INSTEAD of the rule's default, never in addition.
    */
  final val TagConfidence = "ms-confidence"

  /** The confidence a finding of `ruleId` on `node` reports: its scoped override, else the rule's.
    */
  def confidenceOf(node: StoredNode, rule: MemorySafetyRule): String =
      node.tag
          .name(TagConfidence)
          .value
          .l
          .collectFirst { case v if v.startsWith(s"${rule.id}=") => v.stripPrefix(s"${rule.id}=") }
          .getOrElse(rule.confidence)

  final val RuleUnboundedCopy     = "MS-BOUND-002"
  final val RuleSizeParamContract = "MS-BOUND-001"
  final val RuleIndexRead         = "MS-BOUND-003"
  final val RuleIndexWrite        = "MS-BOUND-004"

  /** The half-bounded signed-index arm: a hypothesis, reported at `low`. */
  final val RuleNegativeIndexHazard = "MS-BOUND-005"

  /** F4 (part 6): a write or copy overruns a buffer with a KNOWN capacity - the CWE is the storage
    * family the extent names.
    */
  /** the one-byte element types a declared array's element count converts to bytes through */
  private[taggers] val ByteTypes =
      Set("char", "signed char", "unsigned char", "uint8_t", "int8_t", "u_char", "u_int8_t")

  final val RuleFixedExtentOverrun = "MS-BOUND-006"
  final val RuleHeapExtentOverrun  = "MS-BOUND-007"

  /** F5 (part 6): the deallocation of the wrong thing, and the uncontrolled allocation size.
    */
  final val RuleNonHeapFree              = "MS-ALLOC-005"
  final val RuleOffsetFree               = "MS-ALLOC-006"
  final val RuleMismatchedFree           = "MS-ALLOC-007"
  final val RuleUncontrolledSize         = "MS-ALLOC-008"
  final val RuleUncontrolledSizeOverflow = "MS-ALLOC-009"

  final val RuleIntegerOverflow   = "MS-INT-001"
  final val RuleResignAcrossGuard = "MS-INT-002"

  final val RuleDoubleFree   = "MS-ALLOC-001"
  final val RuleUseAfterFree = "MS-ALLOC-002"
  final val RuleLeak         = "MS-ALLOC-003"

  /** A double CLOSE of a file-family handle: the same state fact as MS-ALLOC-001 over a different
    * family, and a different CWE.
    */
  final val RuleDoubleClose = "MS-ALLOC-004"

  /** A dereference of a value that may be NULL (CWE-476), part 5 E3. */
  final val RuleNullDeref = "MS-NULL-001"

  /** A stack address that left its frame (CWE-562), part 5 E4. */
  final val RuleStackEscape = "MS-ESC-001"

  /** What a renderer needs per rule; the finding's own evidence (origin, extent, guards) is read
    * back from the tags on the offending node at render time.
    */
  final case class MemorySafetyRule(
    id: String,
    cwe: String,
    kind: String,
    severity: String,
    confidence: String,
    message: String
  )

  val rules: Map[String, MemorySafetyRule] = List(
    MemorySafetyRule(
      id = RuleSizeParamContract,
      cwe = "CWE-787",
      kind = "size-param-contract-violation",
      severity = "high",
      confidence = "high",
      message = "the capacity parameter is overwritten or unused while a write into its " +
          "buffer parameter is bounded by another value"
    ),
    MemorySafetyRule(
      id = RuleUnboundedCopy,
      cwe = "CWE-787",
      kind = "unbounded-copy",
      severity = "high",
      confidence = "medium",
      message = "attacker-controlled copy length with no guard bounding it against the " +
          "destination's capacity"
    ),
    MemorySafetyRule(
      id = RuleIndexRead,
      cwe = "CWE-125",
      kind = "oob-index-read",
      severity = "high",
      confidence = "medium",
      message = "array read at an index that can leave the buffer: attacker-controlled and " +
          "unbounded above, or signed and bounded only above - a negative index passes"
    ),
    MemorySafetyRule(
      id = RuleIndexWrite,
      cwe = "CWE-787",
      kind = "oob-index-write",
      severity = "high",
      confidence = "medium",
      message = "array write at an index that can leave the buffer: attacker-controlled and " +
          "unbounded above, or signed and bounded only above - a negative index passes"
    ),
    MemorySafetyRule(
      id = RuleNegativeIndexHazard,
      cwe = "CWE-125",
      kind = "negative-index-hazard",
      severity = "medium",
      confidence = "low",
      message = "signed index bounded above but not below, so a negative value passes the " +
          "check - the CVE-2026-75146 shape, and also what most correct counters look like"
    ),
    MemorySafetyRule(
      id = RuleFixedExtentOverrun,
      cwe = "CWE-121",
      kind = "fixed-extent-overrun",
      severity = "high",
      confidence = "medium",
      message = "a write or copy overruns a fixed buffer's declared capacity - a constant " +
          "length past the extent, an unbounded string copy into it, or a loop bounded by an " +
          "unvalidated count"
    ),
    MemorySafetyRule(
      id = RuleHeapExtentOverrun,
      cwe = "CWE-122",
      kind = "heap-extent-overrun",
      severity = "high",
      confidence = "medium",
      message = "a write or copy overruns an allocated buffer's capacity - a constant length " +
          "past the allocation's size, or a loop bounded by an unvalidated count"
    ),
    MemorySafetyRule(
      id = RuleIntegerOverflow,
      cwe = "CWE-190",
      kind = "integer-overflow-length",
      severity = "high",
      // `low`, on the MS-BOUND-005 / MS-ALLOC-003 precedent, decided BEFORE shipping rather than
      // after (part 5, E1). Part 4 shipped it at medium and it became 76% of the overlay's
      // libavformat output (6,966 of 9,216 findings across the 16 vulnerable trees, ~435 per
      // tree) while firing 5,666 times in the FIXED trees - it was not distinguishing vulnerable
      // code from patched code at all. The E1 diagnosis of the 439 findings in the 75141 tree:
      // 116 were the pointer arithmetic of a copy's DESTINATION read as "the length" through
      // argument-to-argument REACHING_DEF plumbing (now cut in OverlayFacts.reachingDefsIn), and
      // of the rest, two thirds turn on `struct-field` arithmetic - `track->entry + 1`,
      // `os->bufsize + PADDING` - the shape of every correctly written FFmpeg counter, because a
      // struct field that some other function validated looks identical to one nobody did. The
      // one true shape in the bucket (hevc.c:847's uint16_t counter) is NOT separable from that
      // noise by any fact the graph carries: it fires here, at `low`, exactly as the widening and
      // guard conjuncts leave it.
      confidence = "low",
      message = "allocation or copy length computed by attacker-influenced arithmetic with no " +
          "guard bounding an operand from above and no widened accumulator - the product or " +
          "sum can wrap before it bounds the buffer (CVE-2026-75141 shape)"
    ),
    MemorySafetyRule(
      id = RuleResignAcrossGuard,
      cwe = "CWE-197",
      kind = "lossy-cast-in-guard",
      severity = "high",
      confidence = "high",
      message = "a sign-changing cast is the value a comparison bounds, while the guarded uses " +
          "read it at its declared width - the guard checked one signedness, the use happens at " +
          "another (CVE-2026-75145 shape)"
    ),
    MemorySafetyRule(
      id = RuleNonHeapFree,
      cwe = "CWE-590",
      kind = "free-of-non-heap",
      severity = "high",
      confidence = "high",
      message = "storage that is not the heap's is released - a stack buffer, a static, or a " +
          "string literal; the heap's ownership language does not apply to it"
    ),
    MemorySafetyRule(
      id = RuleOffsetFree,
      cwe = "CWE-761",
      kind = "free-of-offset-pointer",
      severity = "high",
      confidence = "high",
      message = "a pointer not at the start of its buffer is released - pointer arithmetic " +
          "moved it into the allocation, and only the original base is freeable"
    ),
    MemorySafetyRule(
      id = RuleMismatchedFree,
      cwe = "CWE-762",
      kind = "mismatched-deallocation",
      severity = "high",
      confidence = "high",
      message = "the release family does not match the acquisition family - a new-ed pointer " +
          "released with free, or a malloc-ed one with delete; the allocator's metadata " +
          "disagrees with the release"
    ),
    MemorySafetyRule(
      id = RuleUncontrolledSize,
      cwe = "CWE-789",
      kind = "uncontrolled-allocation-size",
      severity = "medium",
      // `low` on the MS-INT-001/MS-BOUND-005 precedent: an unguarded param-sized allocation
      // is also how every correctly written FFmpeg helper looks, and the C3 caller-site
      // check cannot separate them at one level - measured before shipping, promoted only
      // if the per-tree count earns it
      confidence = "low",
      message = "an allocation size controlled by the attacker with no guard bounding it - a " +
          "hostile value exhausts memory or hands back a buffer sized by the request"
    ),
    MemorySafetyRule(
      id = RuleUncontrolledSizeOverflow,
      cwe = "CWE-680",
      kind = "overflow-sized-allocation",
      severity = "high",
      confidence = "low",
      message = "an allocation size computed from attacker-influenced arithmetic with no " +
          "guard bounding an operand - the product can wrap before it sizes the buffer"
    ),
    MemorySafetyRule(
      id = RuleDoubleFree,
      cwe = "CWE-415",
      kind = "double-free",
      severity = "high",
      confidence = "high",
      message = "a pointer already freed on some path reaching this point is freed again - " +
          "the free-and-reset idiom (p = NULL) is what makes the second free safe"
    ),
    MemorySafetyRule(
      id = RuleUseAfterFree,
      cwe = "CWE-416",
      kind = "use-after-free",
      severity = "high",
      confidence = "high",
      message = "a pointer that is already freed on some path reaching this point is read or " +
          "written - freed memory must not be used before it is replaced"
    ),
    MemorySafetyRule(
      id = RuleLeak,
      cwe = "CWE-401",
      kind = "memory-leak",
      severity = "medium",
      // `low`, on the MS-BOUND-005 precedent. The rule scores 4 true against 9 false on the
      // corpus (31%), and one of the nine is a `@nofinding` negative control - `good_capped`
      // in c/cwe789_uncontrolled_alloc.c, whose `if (p) free(p);` is an UNBRACED if that the
      // state pass's branch narrowing does not see. None of that was visible while the atom
      // renderer was dropping the exit-anchored findings; the 89% this rule was credited with
      // was measured through that defect. Until the unbraced-if case lands, a leak is a
      // hypothesis, not a finding.
      confidence = "low",
      message = "an allocation is still live, un-freed and un-escaped at this exit - no path " +
          "from it reaches a free or hands ownership on"
    ),
    MemorySafetyRule(
      id = RuleDoubleClose,
      cwe = "CWE-1341",
      kind = "double-close",
      severity = "high",
      confidence = "high",
      message = "a file handle already closed on some path reaching this point is closed again"
    ),
    MemorySafetyRule(
      id = RuleNullDeref,
      cwe = "CWE-476",
      kind = "null-deref",
      severity = "high",
      // `low`, decided by the per-rule gate BEFORE shipping (part 5, E3) rather than after:
      // on libavformat the nullable-producer arms fire 567 times per tree (8,986 across the
      // 16, 76% of the overlay's output) - an av_dict_get result passed to av_log, a
      // stream-pointer read before the error path, the FFmpeg idiom itself. The corpus loves
      // the rule (3/3 true, 0 false at its own arm) and imfdec.c:258 fires; none of that is
      // separable from the style findings by a fact the graph carries, so the whole rule
      // reports at low and the medium run stays quiet. The chained-parameter arm additionally
      // carries a per-finding `low` (ms-confidence).
      confidence = "low",
      message = "a value that may be NULL is dereferenced with no narrowing guard between the " +
          "producing call and the use - or the author's own null check comes one statement " +
          "too late"
    ),
    MemorySafetyRule(
      id = RuleStackEscape,
      cwe = "CWE-562",
      kind = "stack-address-escape",
      severity = "high",
      confidence = "medium",
      message = "the address of a stack local leaves its frame - returned, or stored into " +
          "storage that outlives the function - and any later use of it reads dead storage"
    )
  ).map(r => r.id -> r).toMap

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end MemorySafetyFindingPass
