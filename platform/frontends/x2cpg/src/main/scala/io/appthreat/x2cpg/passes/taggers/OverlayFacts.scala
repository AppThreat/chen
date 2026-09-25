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
    *
    * Same-named structs in different files are different structs: libavformat defines an
    * ASFContext per asfdec variant, and their `asf_st` members are `ASFStream*` in one and
    * `ASFStream*[128]` in another. C's visibility answers which one a read sees - the struct
    * defined in the file that reads it - and that preference is also what makes the answer
    * deterministic: the typeDecl a traversal returns first is parse order, which run-to-run
    * parallelism reorders (part 10 task 0: whole MS-BOUND-003 groups flipped per file on this).
    * Without a same-file definition the candidates are read in a content-stable order and the
    * first is taken - arbitrary, but the same arbitrary one every run.
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
        member <- membersOfNamedType(cpg, typeName, fi.canonicalName, fieldAccess.method.filename)
            .headOption
      yield member

  /** The member `memberName` of the type declarations named `typeName`, preferring the
    * definition in `inFile`, then a content-stable order. See [[memberRefOf]].
    */
  def membersOfNamedType(
    cpg: Cpg,
    typeName: String,
    memberName: String,
    inFile: String
  ): List[Member] =
      val candidates = cpg.typeDecl.nameExact(typeName).l
          .flatMap(td => membersOfTypeDecl(td).map(m => (td.filename, m)))
          .filter { case (_, m) => m.name == memberName }
      val sameFile = candidates.collect { case (f, m) if f == inFile => m }
      val ordered  = if sameFile.nonEmpty then sameFile
                     else candidates.sortBy { case (f, m) => (f, m.typeFullName) }.map(_._2)
      ordered.distinctBy(_.id)

  /** The members of one type declaration, read through the AST edge.
    *
    * The schema's `TypeDecl.member` step matches members by their `typeDeclFullName` property. A
    * type that exists both as a definition and as a frontend stub carries that property on
    * whichever node's pass finished first - parse order is parallel - so the property-keyed step
    * can return nothing for the very type declaration that owns the members, and whether it does
    * differs between runs of the SAME tree on the same code. The AST edge is the source of truth;
    * the schema step is only the fallback for a declaration whose edge was never built.
    */
  def membersOfTypeDecl(td: TypeDecl): List[Member] =
      val viaAst = td.astChildren.collectAll[Member].l
      if viaAst.nonEmpty then viaAst else td.member.l


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

  def isIntegral(t: String): Boolean = integralTypes.contains(normalizeTypeName(t))

  private val signedIntegralTypes = Set(
    "int",
    "long",
    "long long",
    "short",
    "ssize_t",
    "ptrdiff_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t"
  )

  /** GCC writes compound type names with the sign word last (`short unsigned`); every lookup in
    * this object normalises to the canonical order first. The bare spellings `unsigned` and
    * `signed` are `unsigned int` and `int` in C - libavformat's `unsigned count` parameters
    * carried the bare word, and every integral lookup on them concluded nothing (part 10: the
    * one-sided bounds arm's `param:` extent and the unsigned-index negative both read it).
    */
  def normalizeTypeName(t: String): String =
    val words   = t.stripPrefix("const ").trim.split("\\s+").toList
    val sign    = words.find(w => w == "unsigned" || w == "signed")
    val rest    = words.filterNot(w => sign.contains(w))
    val norm    = (sign.toList ::: rest).mkString(" ")
    norm match
      case "unsigned" => "unsigned int"
      case "signed"   => "int"
      case other      => other

  /** A signed integral type: the only kind an index can go negative in. */
  def isSignedIntegral(t: String): Boolean =
      signedIntegralTypes.contains(normalizeTypeName(t))

  /** An unsigned integral type - its values never go negative, whatever the width. */
  def isUnsignedIntegral(t: String): Boolean =
    val s = normalizeTypeName(t)
    s.startsWith("unsigned ") || s.startsWith("uint") || s == "size_t" || s == "size_type"

  /** Declared width in bits, LP64 (long = 64). The LLP64 choice - long = 32, the Windows model
    * FFmpeg also ships on - is a fact the consumer can apply when the target demands it; the width
    * table states which model it is rather than hiding the choice.
    */
  def integralWidth(t: String): Option[Int] =
      integralWidths.get(normalizeTypeName(t))

  private val integralWidths: Map[String, Int] = Map(
    "char"               -> 8,
    "signed char"        -> 8,
    "unsigned char"      -> 8,
    "short"              -> 16,
    "unsigned short"     -> 16,
    "int"                -> 32,
    "unsigned int"       -> 32,
    "long"               -> 64,
    "unsigned long"      -> 64,
    "long long"          -> 64,
    "unsigned long long" -> 64,
    "size_t"             -> 64,
    "ssize_t"            -> 64,
    "ptrdiff_t"          -> 64,
    "int8_t"             -> 8,
    "uint8_t"            -> 8,
    "int16_t"            -> 16,
    "uint16_t"           -> 16,
    "int32_t"            -> 32,
    "uint32_t"           -> 32,
    "int64_t"            -> 64,
    "uint64_t"           -> 64
  )

  /** Reaching definitions backwards from `node`, breadth-first with a hop budget: the walk the
    * value-origin and finding rules run instead of a `.df(...)` reachability solve. Identifier
    * expansion applies [[expansionExclusionOf]]: the flow semantics and the Flux engine emit
    * argument-to-argument REACHING_DEF edges (a memory call's siblings, a comparison's other
    * operand) that are plumbing, not definitions.
    *
    * Part 5 (E1): the exclusion is not an identifier-only concern. A `mem-len` argument that is
    * itself a call (`memset(dst + off, 0, asf->size_left)`) expands through the SAME
    * argument-to-argument edges into the destination's subtree, which is how MS-INT-001 came to
    * report the pointer arithmetic in a copy's DESTINATION as "the length computation". Every
    * expression node that sits as an argument of a non-assignment call now excludes that call's
    * argument subtree, exactly as identifiers always have.
    */
  def reachingDefsIn(node: StoredNode, maxHops: Int = 8): List[StoredNode] =
      bfs(node, maxHops) { n =>
        val exclude = n match
          case e: Expression => expansionExclusionOf(e)
          case _             => Set.empty[Long]
        neighboursWithout(n._reachingDefIn.iterator, exclude)
      }

  /** The neighbours of `raw` whose ids are not in `exclude`, iterated without building a traversal
    * per node: `reachingDefsIn` walks millions of adjacency lists on a real tree, and the per-node
    * traversal materialisation was the bulk of the overlay's allocation (D2).
    */
  private def neighboursWithout(
    raw: Iterator[StoredNode],
    exclude: Set[Long]
  ): List[StoredNode] =
    val out = mutable.ListBuffer.empty[StoredNode]
    raw.foreach { d =>
        if !exclude.contains(d.id()) then out += d
    }
    out.toList

  /** Identifier uses defined (transitively) by `node`, forwards along REACHING_DEF. */
  def reachingUsesOut(node: StoredNode, maxHops: Int = 8): List[Identifier] =
      bfs(node, maxHops)(n => n._reachingDefOut.collectAll[StoredNode].l)
          .collect { case i: Identifier => i }

  /** The nodes an expression's definition walk must not cross: the argument subtree of its
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

  /** The same exclusion for any expression argument: an argument of a non-assignment call does not
    * read its sibling arguments' REACHING_DEF edges as definitions of itself.
    */
  def expansionExclusionOf(e: Expression): Set[Long] =
      e._astIn.collectFirst { case c: Call => c } match
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

  /** The argument positions of one call that a `mem-dst`/`mem-src` role READS OR WRITES THROUGH,
    * collected in one tag scan: the positions a possibly-null pointer is dereferenced at when
    * handed to an inventoried memory call. The `len` role is deliberately absent - a length is an
    * integer, not something the call reads through.
    */
  def memoryReadPositions(cpg: Cpg): Map[Long, Set[Int]] =
    val out = mutable.HashMap.empty[Long, mutable.LinkedHashSet[Int]]
    cpg.tag
        .filter(t => t.name == MemoryApiPass.TagDst || t.name == MemoryApiPass.TagSrc)
        .l
        .foreach { t =>
            t._taggedByIn.collectFirst { case e: Expression => e } match
              case Some(arg) =>
                  arg._astIn.collectFirst { case c: Call => c }.foreach { call =>
                      out.getOrElseUpdate(call.id, mutable.LinkedHashSet.empty) += arg.argumentIndex
                  }
              case None => ()
        }
    out.view.mapValues(_.toSet).toMap

  /** The POINTER variable a null guard's condition tests: `p == NULL` / `NULL != p`, `!p`, or the
    * truth of `p` itself. Every shape is restricted to pointer-typed locals and parameters: FFmpeg
    * tests ints the same three ways (`size == 0`, `!ret`, `if (n)`), and `0` is also how the
    * frontend spells NULL, so an unrestricted shape reads every earlier use of an int counter as a
    * check-after-use. Shared by the null-deref rule and the derefs-param summary, which must agree
    * on what a guard is or a summary would contradict the rule that consumes it.
    */
  def nullGuardKeyOf(cond: AstNode, pointerNames: Set[String]): Option[String] =
    def pointerKey(e: AstNode): Option[String] = e match
      case i: Identifier if pointerNames.contains(i.name) => variableKey(i)
      case c: Call if c.name == "<operator>.cast" =>
          c.argumentOption(2).orElse(c.argumentOption(1)).flatMap(pointerKey)
      case _ => None
    cond match
      case cmp: Call
          if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
          val operands = Seq(1, 2).flatMap(cmp.argumentOption)
          if operands.exists(isNullLiteralNode) then
            operands.filterNot(isNullLiteralNode).flatMap(pointerKey).headOption
          else None
      case not: Call if not.name == "<operator>.logicalNot" =>
          not.argumentOption(1).flatMap(pointerKey)
      case other => pointerKey(other)

  private def isNullLiteralNode(e: AstNode): Boolean =
      AllocationStatePass.isNullLiteral(e, c => c.argumentOption(2).orElse(c.argumentOption(1)))

  /** The variable keys any null guard in the method tests, with the ControlStructure each guard
    * belongs to: a summary that claims "every path" must stand down where the author wrote a check,
    * and a use nested inside its own guard's structure is protected, not check-after-use.
    */
  def nullGuardsOf(method: Method): Map[String, ControlStructure] =
    val pointerNames = (method.local.l ++ method.parameter.l)
        .map(d => d.name -> d.property("TYPE_FULL_NAME"))
        .collect { case (n, t: String) if isPointer(t) => n }
        .toSet
    method.ast
        .collectAll[ControlStructure]
        .l
        .flatMap { cs =>
            cs.condition.flatMap(cond => nullGuardKeyOf(cond, pointerNames)).map(key => (key, cs))
        }
        .toMap
end OverlayFacts
