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

  /** The origin names of an expression without their evidence, for consumers inside the overlay -
    * the C3 call-site check asks only "is this passed length provably a constant".
    */
  private[taggers] def originNamesOf(expr: Expression): Set[String] =
      originsOf(expr, MaxDepth).map(_._1)

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
          untrustedFill(c).map(api => Set((OriginUntrustedRead, api)))
              .orElse(storedOrigins(c, depth))
              .getOrElse(Set((OriginStructField, c.code)))
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

  /** The field's base expression: `m` in `m.len`, `hdr` in `hdr->len`. */
  private def baseOf(field: Call): Option[Expression] =
      field.argumentOption(1).collect { case e: Expression => e }

  private def withoutCasts(e: Expression): Expression = e match
    case c: Call if c.name == "<operator>.cast" =>
        c.argumentOption(2).orElse(c.argumentOption(1)).collect { case x: Expression => x }
            .map(withoutCasts).getOrElse(e)
    case other => other

  /** The declarations a pointer or struct expression names: itself, through casts, `&x` and `buf +
    * off`, and through a pointer local's single definition (`hdr = (struct h *)buf`).
    */
  private def bufferDecls(e: Expression, depth: Int = 0): Set[Long] = withoutCasts(e) match
    case c: Call if c.name == "<operator>.addressOf" || c.name == "<operator>.addition" =>
        c.argumentOption(1).collect { case x: Expression => x }
            .map(bufferDecls(_, depth)).getOrElse(Set.empty)
    case i: Identifier =>
        val own = OverlayFacts.declOf(i).map(_.id()).toSet
        val defs = OverlayFacts.reachingDefsIn(i, maxHops = 1).collect {
            case d: Identifier if d.name == i.name =>
                d._astIn.collectFirst {
                    case a: Call
                        if a.name == "<operator>.assignment" &&
                            a.argumentOption(1).exists(_.id == d.id) => a
                }
        }.flatten
        val through =
            if depth >= 3 || defs.size != 1 then Set.empty[Long]
            else
              defs.flatMap(_.argumentOption(2).collect { case x: Expression => x })
                  .flatMap(bufferDecls(_, depth + 1)).toSet
        own ++ through
    case _ => Set.empty

  /** A field read out of bytes an untrusted read filled first: `read(fd, buf, n)` then `((struct
    * hdr *)buf)->len`, or `fread(&h, sizeof h, 1, f)` then `h.len`. The filling call must dominate
    * the read. The API's name is the evidence.
    */
  private def untrustedFill(field: Call): Option[String] =
      baseOf(field).flatMap { base =>
        val wanted = bufferDecls(base)
        if wanted.isEmpty then None
        else
          field.method.ast.isCall.l.iterator
              .filter(_.tag.name(MemoryApiPass.TagUntrustedRead).nonEmpty)
              .filter(fill => field.dominatedBy.exists(_.id == fill.id))
              .find(fill =>
                  fill.argument.l.exists(a =>
                      a.tag.name(MemoryApiPass.TagUntrustedRead).nonEmpty &&
                          bufferDecls(a).intersect(wanted).nonEmpty
                  )
              )
              .map(_.name)
      }

  /** The origins of a field read that the method itself stored to (`m.len = n; ... m.len`): the
    * stored values of every store that reaches the read with its base unchanged. The field's own
    * earlier value (`struct-field`) joins them when some path reaches the read without a store, or
    * a call handed the base could have rewritten it in between. None when no store reaches.
    */
  private def storedOrigins(field: Call, depth: Int): Option[Set[(String, String)]] =
    if depth < 0 then return None
    val fs = OverlayFacts.fieldStoresReaching(field)
    if fs.reaching.isEmpty then None
    else
      val stored = fs.reaching.flatMap { st =>
        val rhs = st.argumentOption(2).collect { case e: Expression => e }.toSet
            .flatMap(originsOf(_, depth - 1))
        // a compound store (`m.len *= 2`) keeps part of the value before it
        if st.name == "<operator>.assignment" then rhs
        else
          rhs ++ st.argumentOption(1).collect { case lhs: Call => lhs }
              .flatMap(storedOrigins(_, depth - 1))
              .getOrElse(Set((OriginStructField, field.code)))
      }.toSet
      Some(
        if fs.dominated && !fs.rewritable then stored
        else stored + ((OriginStructField, field.code))
      )
  end storedOrigins

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
end ValueOriginPass
