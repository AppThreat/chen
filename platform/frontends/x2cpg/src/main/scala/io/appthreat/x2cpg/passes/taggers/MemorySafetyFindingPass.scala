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
  * `const:`/`alloc:` capacities. Runs last in the overlay, after MemoryApi, Extent, Guard and
  * ValueOrigin. C/C++ graphs only.
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

    OverlayFacts.emitTags(
      dstGraph,
      findings.toList.flatMap { case (node, ruleIds) =>
          ruleIds.toList.map(ruleId => (node, TagFinding, ruleId))
      }
    )
  end run

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
                  isSignedIndex(idx)
              val fires = (attackerIndex && knownExtent && !boundedAbove && !boundedBelow) ||
                  (halfBounded && boundedAbove && !boundedBelow)
              if fires then record(idx, ruleIdFor(access))
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

  /** The declared type of an index expression, when the frontend recorded one. */
  private def typeOfExpr(e: Expression): String = e match
    case i: Identifier => i.typeFullName
    case c: Call       => c.typeFullName
    case l: Literal    => l.typeFullName
    case _             => ""

  /** Can this index go negative? c2cpg often leaves the TYPE of a field-access expression empty, so
    * a `pls->cur_seq_no` index resolves its type through the member it reads; an index whose type
    * is nowhere recorded is treated as signed - the negative-index hazard stands, and the absence
    * of a type is not evidence of unsignedness.
    */
  private def isSignedIndex(idx: Expression): Boolean =
    val declared = typeOfExpr(idx) match
      // c2cpg writes the placeholder type "<empty>" rather than an empty string
      case t if t.nonEmpty && t != "<empty>" => Some(t)
      case _ =>
          idx match
            case c: Call => OverlayFacts.memberRefOf(atom, c).map(_.typeFullName)
            case _       => None
    declared match
      case Some(t) => OverlayFacts.isSignedIntegral(t)
      case None    => true

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

  final val RuleUnboundedCopy     = "MS-BOUND-002"
  final val RuleSizeParamContract = "MS-BOUND-001"
  final val RuleIndexRead         = "MS-BOUND-003"
  final val RuleIndexWrite        = "MS-BOUND-004"

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
    )
  ).map(r => r.id -> r).toMap

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end MemorySafetyFindingPass
