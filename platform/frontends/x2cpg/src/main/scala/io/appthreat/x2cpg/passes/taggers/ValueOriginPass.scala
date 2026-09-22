package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS5: where did this number come from.
  *
  * Tags every value reaching a `mem-len` argument, a `mem-alloc` size (also `mem-len`, by the
  * inventory's roles) or an array index with its origin:
  *
  *   - `caller-param` - the method's own parameter (attacker-controllable to the caller);
  *   - `untrusted-read` - part 1's source inventory (`read`, `recv`, `fgets`, ...);
  *   - `constant` - a literal;
  *   - `struct-field` - read out of a struct (`data_block->payload_len`);
  *   - `mixed` - more than one of the above;
  *   - `unknown` - nothing derivable; stated rather than guessed, for the same reason ExtentPass
  *     says `unknown`.
  *
  * The point is to remove `.df(...)` from the common case. `df` stays for the evidence chain a
  * finding renders and for genuinely interprocedural questions, but a detector must not pay for a
  * reachability solve to answer "is this length attacker-influenced" - at FFmpeg scale it visibly
  * cannot. The origins are computed from the REACHING_DEF edges directly: a bounded breadth-first
  * walk over the definitions of the value, plus the arguments of any call that produced it
  * (`FFMIN(payload_len, size)` is struct-field AND caller-param, hence `mixed`).
  *
  * Emitted as the layered pair the other overlay passes use: the family tag `origin` valued with
  * the origin (histograms read one tag family), and the origin itself as a fine-grained tag name
  * valued with the evidence (rules write `tag.name("caller-param")`), both alongside the
  * `memory-safety` umbrella. `mixed` and `unknown` deliberately do not match the rule-relevant
  * names - a mixed value is not established to be attacker-influenced.
  */
class ValueOriginPass(atom: Cpg) extends CpgPass(atom):

  import ValueOriginPass.*
  import OverlayFacts.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return

    val targets = mutable.LinkedHashMap.empty[StoredNode, (String, String)]
    def record(node: StoredNode, origin: String, evidence: String): Unit =
        targets(node) = (origin, evidence)

    // mem-len arguments: one pass over the tag nodes, not a graph re-traversal per target
    val lenArgs = OverlayFacts
        .memoryArgumentSites(atom)
        .collect { case (_, e, MemoryApiPass.TagLen) => e }
        .distinct

    // array indices: the second argument of an index access, identifiers and calls only -
    // literal indices are their own origin and add nothing
    val indexArgs = atom.call
        .name("<operator>.indexAccess|<operator>.indirectIndexAccess")
        .l
        .flatMap(_.argumentOption(2).collect {
            case e @ (_: Identifier | _: Call) => e: Expression
        })
        .distinct

    (lenArgs ++ indexArgs).foreach { target =>
      val origins = originsOf(target, MaxDepth)
      originTagOf(origins).foreach { case (origin, evidence) =>
          record(target, origin, evidence)
      }
    }

    OverlayFacts.emitTags(
      dstGraph,
      targets.toList.flatMap { case (node, (origin, evidence)) =>
          List((node, TagOrigin, origin), (node, origin, evidence))
      }
    )
  end run

  /** (origin, evidence) for an expression, or nothing when nothing is derivable. */
  private def originsOf(expr: Expression, depth: Int): Set[(String, String)] =
    if depth < 0 then return Set.empty
    expr match
      case lit: Literal => Set((OriginConstant, lit.code))
      case i: Identifier =>
          walkDefs(i, depth)
      case c: Call =>
          callOrigins(c, depth)
      case _ => Set.empty

  /** Walk the definitions of an identifier backwards over REACHING_DEF, classifying each node the
    * walk lands on. A node that already determines an origin (parameter, literal, tagged call,
    * field access) STOPS the walk: expanding through it into its arguments would report the
    * arguments' origins too, and a length defined by `read(fd, tmp, n)` is an untrusted read, not
    * an untrusted read mixed with whatever `fd` is. Each identifier expands with
    * OverlayFacts.expansionExclusionOf, so the argument-to-argument edges of its enclosing call (a
    * guard's other operand, a memory call's sibling arguments) are not read as definitions.
    */
  private def walkDefs(start: Identifier, depth: Int): Set[(String, String)] =
    val out                        = mutable.LinkedHashSet.empty[(String, String)]
    val seen                       = mutable.LinkedHashSet.empty[StoredNode]
    var frontier: List[StoredNode] = List(start)
    var hops                       = MaxHops
    while frontier.nonEmpty && hops >= 0 do
      val next = mutable.ListBuffer.empty[StoredNode]
      frontier.foreach { node =>
          if seen.add(node) then
            node match
              case i: Identifier =>
                  // an intermediate assignment target: keep walking to its definitions
                  val exclude = OverlayFacts.expansionExclusionOf(i)
                  next ++= i._reachingDefIn.collectAll[StoredNode].l
                      .filterNot(seen)
                      .filterNot(d => exclude.contains(d.id))
              case other =>
                  out ++= classifyDef(other, depth)
      }
      frontier = next.toList
      hops -= 1
    out.toSet
  end walkDefs

  /** The origin of a node the REACHING_DEF walk landed on. */
  private def classifyDef(d: StoredNode, depth: Int): Set[(String, String)] = d match
    case p: MethodParameterIn => Set((OriginCallerParam, p.name))
    case lit: Literal         => Set((OriginConstant, lit.code))
    case c: Call              => callOrigins(c, depth - 1)
    case _                    => Set.empty

  private def callOrigins(c: Call, depth: Int): Set[(String, String)] =
    if depth < 0 then return Set.empty
    c.name match
      case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" =>
          Set((OriginStructField, c.code))
      case n if n.startsWith("<operator>.sizeOf") =>
          // sizeof never varies with its operand's provenance: it is a constant, whatever flows
          // into the pointer it measures
          Set((OriginConstant, c.code))
      case _ =>
          if c.tag.name(MemoryApiPass.TagUntrustedRead).l.nonEmpty then
            Set((OriginUntrustedRead, c.name))
          else
            c.argument.l.collect { case e: Expression => e }
                .filterNot(_.isFieldIdentifier)
                .flatMap(originsOf(_, depth))
                .toSet

  /** Collapse a set of origins to the emitted pair: one origin as-is, several to `mixed`, nothing
    * to `unknown`. The mixed evidence names the contributing origins only - origins and their
    * individual evidences are separate sets, and zipping them fabricates pairings
    * (`caller-param:'\0'`) that never existed.
    */
  private def originTagOf(origins: Set[(String, String)]): Option[(String, String)] =
      if origins.isEmpty then Some((OriginUnknown, ""))
      else if origins.size == 1 then origins.headOption
      else Some((OriginMixed, origins.map(_._1).toList.sorted.mkString("+")))
end ValueOriginPass

object ValueOriginPass:
  final val TagOrigin = "origin"

  final val OriginCallerParam   = "caller-param"
  final val OriginUntrustedRead = "untrusted-read"
  final val OriginConstant      = "constant"
  final val OriginStructField   = "struct-field"
  final val OriginMixed         = "mixed"
  final val OriginUnknown       = "unknown"

  final val MaxDepth = 3
  final val MaxHops  = 8

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
