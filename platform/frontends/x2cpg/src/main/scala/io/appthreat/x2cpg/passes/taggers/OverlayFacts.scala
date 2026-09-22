package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable

/** Structural facts shared by the phase-2a overlay passes (Extent, Guard, ValueOrigin, Findings):
  * variable identity, reaching-definition walks and the memory-API argument view left by
  * [[MemoryApiPass]].
  *
  * Nothing here reads source text. Variable identity is keyed on the graph's own name properties
  * (an identifier's name, a field access's base and member) because that is what the C frontend
  * gives two occurrences of the same variable in one method; extents are parsed out of
  * `typeFullName`, which is where the frontend records declared array sizes (confirmed by part-1
  * task A5).
  */
private[taggers] object OverlayFacts:

  /** A stable key for "the same variable" across two expressions in one method: identifiers by
    * name, field accesses by base and member, with addressOf/indexAccess/sizeOf unwrapped so
    * `&buf`, `buf[i]` and `sizeof(buf)` still talk about `buf`.
    */
  def variableKey(expr: AstNode): Option[String] = expr match
    case i: Identifier => Some(s"v:${i.name}")
    case c: Call =>
        c.name match
          case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" =>
              for
                baseKey <- c.argumentOption(1).flatMap(variableKey)
                member  <- memberOf(c)
              yield s"$baseKey.$member"
          case "<operator>.addressOf" | "<operator>.indexAccess" |
              "<operator>.indirectIndexAccess" | "<operator>.sizeOf" =>
              c.argumentOption(1).flatMap(variableKey)
          case _ => None
    case _ => None

  /** The member name a field access reads, from its FIELD_IDENTIFIER argument. */
  def memberOf(fieldAccess: Call): Option[String] =
      fieldAccess.argument.isFieldIdentifier.headOption.map(_.canonicalName)

  /** The struct member a field access reads. c2cpg leaves FIELD_IDENTIFIER REF edges empty, so the
    * member is resolved through the base expression's type (`blk*` -> typeDecl `blk`) and the
    * canonical member name; identifiers without a recovered type resolve nothing.
    */
  def memberRefOf(cpg: Cpg, fieldAccess: Call): Option[Member] =
      for
        fi   <- fieldAccess.argument.isFieldIdentifier.headOption
        base <- fieldAccess.argumentOption(1)
        baseType <- base match
          case i: Identifier => Option.when(i.typeFullName.nonEmpty)(i.typeFullName)
          case c: Call =>
              c.name match
                case "<operator>.fieldAccess" | "<operator>.indirectFieldAccess" =>
                    memberRefOf(cpg, c).map(_.typeFullName)
                case _ => None
          case _ => None
        typeName = baseType.stripSuffix("*").trim
        member <- cpg.typeDecl.name(typeName).member.name(fi.canonicalName).headOption
      yield member

  /** Declared array size from a type full name (`char[64]`, `int[16]` through a #define). */
  def arrayExtent(typeFullName: String): Option[Int] =
      """\[(\d+)\]$""".r.findFirstMatchIn(typeFullName).map(_.group(1).toInt)

  /** True when the type is a pointer or a decayed array - the R1 predicate, promoted from the
    * prototype query where it was validated against the real CVE.
    */
  def isPointer(t: String): Boolean = t.endsWith("*") || t.endsWith("[]")

  private val integralTypes = Set(
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "long long",
    "short",
    "size_t",
    "ssize_t",
    "ptrdiff_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t"
  )

  def isIntegral(t: String): Boolean = integralTypes.contains(t.stripPrefix("const ").trim)

  /** Reaching definitions backwards from `node`, breadth-first with a hop budget: the walk the
    * value-origin and finding rules run instead of a `.df(...)` reachability solve. Identifier
    * expansion applies [[expansionExclusionOf]]: the flow semantics and the Flux engine emit
    * argument-to-argument REACHING_DEF edges (a memory call's siblings, a comparison's other
    * operand) that are plumbing, not definitions.
    */
  def reachingDefsIn(node: StoredNode, maxHops: Int = 8): List[StoredNode] =
      bfs(node, maxHops) {
          case i: Identifier =>
              val exclude = expansionExclusionOf(i)
              i._reachingDefIn.collectAll[StoredNode].l.filterNot(d => exclude.contains(d.id))
          case other =>
              other._reachingDefIn.collectAll[StoredNode].l
      }

  /** Identifier uses defined (transitively) by `node`, forwards along REACHING_DEF. */
  def reachingUsesOut(node: StoredNode, maxHops: Int = 8): List[Identifier] =
      bfs(node, maxHops)(n => n._reachingDefOut.collectAll[StoredNode].l)
          .collect { case i: Identifier => i }

  /** The nodes an identifier's definition walk must not cross: the argument subtree of its
    * ENCLOSING call, unless that call is an assignment. A comparison's other operand and a memory
    * call's sibling arguments did not define the value (on graphs built with the memory-API flow
    * semantics, those edges exist and would otherwise turn every guarded length into `mixed`); an
    * assignment's RHS did define it and must stay reachable.
    */
  def expansionExclusionOf(i: Identifier): Set[Long] =
      i._astIn.collectFirst { case c: Call => c } match
        case Some(c) if c.name != "<operator>.assignment" =>
            (Iterator.single[StoredNode](c) ++ c.argument.iterator).map(_.id).toSet
        case _ => Set.empty[Long]

  private def bfs(start: StoredNode, maxHops: Int)(
    expand: StoredNode => List[StoredNode]
  ): List[StoredNode] =
    val seen      = mutable.LinkedHashSet.empty[StoredNode]
    var frontier  = List(start)
    var remaining = maxHops
    while remaining >= 0 && frontier.nonEmpty do
      val next = mutable.ListBuffer.empty[StoredNode]
      frontier.foreach { n =>
          if seen.add(n) then next ++= expand(n).filterNot(seen.contains)
      }
      frontier = next.toList
      remaining -= 1
    seen.filterNot(_ == start).toList

  /** Emit `(node, tag, value)` rows the way [[MemoryApiPass]] does: one batched store per distinct
    * `(tag, value)` pair and a single umbrella store over every node touched. The overlay tags tens
    * of thousands of nodes on a real tree, so a store per node is the difference between one
    * traversal of a grouping and a DiffGraph round per tag.
    */
  def emitTags(
    dstGraph: DiffGraphBuilder,
    rows: Iterable[(StoredNode, String, String)]
  ): Unit =
    rows.groupMap { case (_, tag, value) => (tag, value) } { case (node, _, _) => node }
        .foreach { case ((tag, value), nodes) =>
            nodes.iterator.distinct.newTagNodePair(tag, value).store()(using dstGraph)
        }
    rows.iterator.map(_._1).distinct.newTagNode(MemoryApiPass.UmbrellaTag).store()(using dstGraph)

  /** One `(call, argument, role)` row per memory-API argument tag, collected in a single pass over
    * the tag nodes rather than a re-traversal of the graph per role (the PiiTagsPass convention).
    */
  def memoryArgumentSites(cpg: Cpg): List[(Call, Expression, String)] =
    val roles = Set(MemoryApiPass.TagDst, MemoryApiPass.TagSrc, MemoryApiPass.TagLen)
    cpg.tag
        .filter(t => roles.contains(t.name))
        .l
        .flatMap { t =>
            t._taggedByIn.collectFirst { case e: Expression =>
                e._astIn.collectFirst { case c: Call => (c, e, t.name) }
            }
        }
        .flatten
        .distinct
end OverlayFacts
