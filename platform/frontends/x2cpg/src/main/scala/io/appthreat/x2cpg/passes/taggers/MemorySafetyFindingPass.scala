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
    ruleIntegerArithmeticLength(record)
    ruleResignAcrossGuard(record)
    ruleAllocationState(record)
    val lowConfidenceNodes = ruleNullDereference(record)

    OverlayFacts.emitTags(
      dstGraph,
      findings.toList.flatMap { case (node, ruleIds) =>
          ruleIds.toList.map(ruleId => (node, TagFinding, ruleId))
      } ++ lowConfidenceNodes.map(node => (node, TagConfidence, "low"))
    )
  end run

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
    *     `bad_check_after_use`: `strlen(s); if (s == NULL) return;`.
    *   - **unvalidated parameter** (rule-side, the hypothesis tier): a pointer parameter
    *     dereferenced with no null guard anywhere in the method. The common FFmpeg shape (`s` is
    *     never null by contract) makes this arm loud, so it carries its own `low` tier - the
    *     imfdec.c:541 shape fires there, deliberately, and a default run does not drown in it.
    *
    * A use under a guard that proved the pointer NON-NULL is not a finding; an escaped pointer is
    * not one either - the state pass says so, not this rule's silence.
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

    // arms 2 and 3: per method, the null guards the author wrote and the uses that precede (or
    // never meet) them
    val hypothesis = mutable.LinkedHashSet.empty[StoredNode]
    atom.method.filterNot(_.isExternal).l.foreach { method =>
      val guards = mutable.LinkedHashMap.empty[String, Int] // variable key -> guard line
      method.ast.collectAll[ControlStructure].l.foreach { cs =>
          cs.condition.foreach { cond =>
              nullGuardKeyOf(cond).foreach { key =>
                val line = cond.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
                guards.update(key, math.min(guards.getOrElse(key, Int.MaxValue), line))
              }
          }
      }
      if guards.nonEmpty || method.parameter.exists(p => OverlayFacts.isPointer(p.typeFullName))
      then
        // the uses a null guard would have protected: a dereference base, or an argument handed
        // to a call that will read through it
        val uses = method.ast.collectAll[Call].l.flatMap { c =>
          val derefBases = c.name match
            case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" |
                "<operator>.indexAccess" | "<operator>.indirectIndexAccess" =>
                c.argumentOption(1).toList
            case _ => Nil
          val callArgs = Option.unless(c.name.startsWith("<operator>"))(c.argument.l).getOrElse(Nil)
          (derefBases ++ callArgs).collect { case i: Identifier => i }
        }
        val paramNames = method.parameter.name.l.toSet
        uses.foreach { use =>
            castUnwrappingKey(use).foreach { key =>
              val line = use.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
              guards.get(key) match
                case Some(guardLine) if guardLine > line =>
                    // the guard exists but comes AFTER the use: check-after-use
                    record(use, RuleNullDeref)
                case None if paramNames.contains(use.name) && isDerefBase(use) =>
                    // a parameter dereferenced with no guard on it anywhere: hypothesis tier
                    record(use, RuleNullDeref)
                    hypothesis += use
                case _ => ()
            }
        }
      end if
    }
    hypothesis.toSet
  end ruleNullDereference

  /** The variable a null guard's condition tests: `x == NULL` / `NULL != x`, `!x`, or the truth of
    * `x` itself.
    */
  private def nullGuardKeyOf(cond: AstNode): Option[String] = cond match
    case cmp: Call
        if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
        val operands = Seq(1, 2).flatMap(cmp.argumentOption)
        val nullSide = operands.find(isNullLiteralNode)
        nullSide.flatMap { _ =>
            operands.filterNot(_ == nullSide).flatMap(castUnwrappingKey).headOption
        }
    case not: Call if not.name == "<operator>.logicalNot" =>
        not.argumentOption(1).flatMap(castUnwrappingKey)
    case i: Identifier => OverlayFacts.variableKey(i)
    case _             => None

  private def isNullLiteralNode(e: AstNode): Boolean =
      AllocationStatePass.isNullLiteral(e, c => c.argumentOption(2).orElse(c.argumentOption(1)))

  /** Is this identifier the BASE of a field/index access rather than a bare call argument? */
  private def isDerefBase(use: Identifier): Boolean =
      use._astIn.collectFirst { case c: Call => c }.exists(c =>
          c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" ||
              c.name == "<operator>.indexAccess" || c.name == "<operator>.indirectIndexAccess"
      )

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
                record(idx, RuleNegativeIndexHazard)
            end for
          }
  end ruleIndexBounds

  /** A read through the index is CWE-125, a write through it CWE-787. */
  private def ruleIdFor(access: Call): String =
    val isWrite = access._astIn.collectFirst { case c: Call => c }.exists(c =>
        c.name.startsWith("<operator>.assignment") &&
            c.argumentOption(1).exists(_.id == access.id)
    )
    if isWrite then RuleIndexWrite else RuleIndexRead

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
                          && lengthBecomesCapacity(memCall) =>
                      record(arith, RuleIntegerOverflow)
              }
          }

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
    case c: Call       => c.typeFullName
    case l: Literal    => l.typeFullName
    case _             => ""

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
    * rule's own confidence does not describe. Valued `low` today; a renderer reads it INSTEAD of
    * the rule's default, never in addition.
    */
  final val TagConfidence = "ms-confidence"

  final val RuleUnboundedCopy     = "MS-BOUND-002"
  final val RuleSizeParamContract = "MS-BOUND-001"
  final val RuleIndexRead         = "MS-BOUND-003"
  final val RuleIndexWrite        = "MS-BOUND-004"

  /** The half-bounded signed-index arm: a hypothesis, reported at `low`. */
  final val RuleNegativeIndexHazard = "MS-BOUND-005"

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
      // medium for the two evidence arms (a nullable-return producer used unchecked; a use the
      // author's own later null guard admits was nullable). The unvalidated-parameter arm
      // carries a per-finding `low` (ms-confidence): a pointer parameter with no guard anywhere
      // is also the common correctly-coded shape, and that tier is a hypothesis.
      confidence = "medium",
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
