package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable

/** Structural facts shared by the memory-safety overlay passes (Extent, Guard, ValueOrigin,
  * Findings): variable identity, reaching-definition walks and the memory-API argument view left by
  * [[MemoryApiPass]].
  *
  * Nothing here reads source text. Variable identity is keyed on the graph's own name properties
  * (an identifier's name, a field access's base and member) because that is what the C frontend
  * gives two occurrences of the same variable in one method; extents are parsed out of
  * `typeFullName`, which is where the frontend records declared array sizes.
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
    * Same-named structs in different files are different structs: libavformat defines an ASFContext
    * per asfdec variant, and their `asf_st` members are `ASFStream*` in one and `ASFStream*[128]`
    * in another. C's visibility answers which one a read sees - the struct defined in the file that
    * reads it - and that preference is also what makes the answer deterministic: the typeDecl a
    * traversal returns first is parse order, which run-to-run parallelism reorders (whole
    * MS-BOUND-003 groups would flip per file on this). Without a same-file definition the
    * candidates are read in a content-stable order and the first is taken - arbitrary, but the same
    * arbitrary one every run.
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

  /** The member `memberName` of the type declarations named `typeName`, preferring the definition
    * in `inFile`, then a content-stable order. See [[memberRefOf]].
    */
  def membersOfNamedType(
    cpg: Cpg,
    typeName: String,
    memberName: String,
    inFile: String
  ): List[Member] = membersAmong(cpg.typeDecl.nameExact(typeName).l, memberName, inFile)

  /** The member `memberName` of `decls`, preferring the definition in `inFile`, then a
    * content-stable order. Only declarations that declare the member count: a same-named
    * `<includes>` stub carries none.
    */
  def membersAmong(decls: List[TypeDecl], memberName: String, inFile: String): List[Member] =
    val candidates = decls
        .flatMap(td => membersOfTypeDecl(td).map(m => (td.filename, m)))
        .filter { case (_, m) => m.name == memberName }
    val sameFile = candidates.collect { case (f, m) if f == inFile => m }
    // the definition a header the file includes gives it, when two headers define the name
    lazy val included = decls.headOption.map(td => includedBy(Cpg(using td.graph), inFile))
        .getOrElse(Set.empty)
    lazy val fromIncludes = candidates.collect { case (f, m) if included.contains(f) => m }
    val ordered =
        if sameFile.nonEmpty then sameFile
        else if candidates.map(_._1).distinct.sizeIs > 1 && fromIncludes.nonEmpty then
          fromIncludes.sortBy(_.typeFullName)
        else candidates.sortBy { case (f, m) => (f, m.typeFullName) }.map(_._2)
    ordered.distinctBy(_.id)

  /** The include graph of each graph, between its FILE names: a file -> the files its includes
    * resolved to. An include records the absolute path it resolved to; it names the graph's file
    * whose (project-relative) name that path ends with.
    */
  private val includeGraphs =
      java.util.Collections.synchronizedMap(new java.util.WeakHashMap[Cpg, Map[
        String,
        Set[String]
      ]]())

  private def includeGraph(cpg: Cpg): Map[String, Set[String]] =
    val known = includeGraphs.get(cpg)
    if known != null then known
    else
      val byBaseName = cpg.file.name.l.groupBy(n => n.replace('\\', '/').split('/').last)
      def fileNamed(path: String): String =
        val p = path.replace('\\', '/')
        byBaseName.getOrElse(p.split('/').last, Nil)
            .filter(f => p == f.replace('\\', '/') || p.endsWith("/" + f.replace('\\', '/')))
            .maxByOption(_.length).getOrElse(path)
      val graph = cpg.imports.l.flatMap { imp =>
          for
            file <- imp.file.name.headOption
            path <- imp.tag.nameExact("include-resolved-path").value.headOption
          yield file -> fileNamed(path)
      }.groupMap(_._1)(_._2).view.mapValues(_.toSet).toMap
      includeGraphs.put(cpg, graph)
      graph

  /** Every file `file` includes, directly or through other includes. */
  def includedBy(cpg: Cpg, file: String): Set[String] =
    val graph = includeGraph(cpg)
    val seen  = mutable.LinkedHashSet.empty[String]
    var next  = graph.getOrElse(file, Set.empty).toList
    while next.nonEmpty do
      val f = next.head
      next = next.tail
      if seen.add(f) then next = graph.getOrElse(f, Set.empty).toList ++ next
    seen.toSet

  /** The member an implicit-this read names (`space_` inside a method). c2cpg types that identifier
    * with the OWNER class (`leveldb.LookupKey`, `leveldb..PosixWritableFile` in an anonymous
    * namespace), so the member is looked up in the owner's declaration by full name, and by its
    * simple name only when no full-name match declares it. A header class is known only as
    * `<includes>` stubs, and a stub of the same simple name with no members (another translation
    * unit's unqualified spelling) must not hide the one that carries the layout.
    */
  def implicitMemberOf(cpg: Cpg, i: Identifier): Option[Member] =
    val owner = i.typeFullName.trim.replace("::", ".")
    if owner.isEmpty || isPointer(owner) then None
    else
      val inFile = i.method.filename
      val exact  = membersAmong(cpg.typeDecl.fullNameExact(owner).l, i.name, inFile)
      val found =
          if exact.nonEmpty then exact
          else membersOfNamedType(cpg, owner.split('.').lastOption.getOrElse(""), i.name, inFile)
      found.headOption

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

  /** True when the type is a pointer or a decayed array - the buffer side of an adjacent (buffer,
    * capacity) parameter pair.
    */
  def isPointer(t: String): Boolean = t.endsWith("*") || t.endsWith("[]")

  /** Any assignment: `=` and every compound form. The schema spells six compound forms
    * `<operators>.assignment...` (`%=`, `<<=`, `>>=`, `&=`, `|=`, `^=`), the rest
    * `<operator>.assignment...`.
    */
  def isAssignmentOperator(name: String): Boolean =
      name.startsWith("<operator>.assignment") || name.startsWith("<operators>.assignment")

  /** Pointer arithmetic, as the frontend tagged it
    * ([[io.appthreat.x2cpg.Defines.PointerArithmeticTag]]): the kind (`add`, `sub`, `diff`) and the
    * argument index of the pointer operand (1 for `diff`).
    */
  def pointerArithmeticOf(c: Call): Option[(String, Int)] =
      c.tag.nameExact(io.appthreat.x2cpg.Defines.PointerArithmeticTag).value.headOption.flatMap {
          v =>
              v.split(':') match
                case Array("diff")      => Some(("diff", 1))
                case Array(kind, index) => index.toIntOption.map(i => (kind, i))
                case _                  => None
      }

  /** The pointer operand of `p + n`, `n + p` or `p - n`: the buffer the arithmetic moves within. */
  def pointerOperandOf(c: Call): Option[Expression] =
      pointerArithmeticOf(c).filter(_._1 != "diff").flatMap((_, i) =>
          c.argumentOption(i).collect { case e: Expression => e }
      )

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
    "signed int",
    "long",
    "long int",
    "signed long",
    "signed long int",
    "long long",
    "long long int",
    "signed long long",
    "signed long long int",
    "short",
    "short int",
    "signed short",
    "signed short int",
    // a plain `char` is signed or not by platform and is deliberately absent
    "signed char",
    "ssize_t",
    "ptrdiff_t",
    "intptr_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t"
  )

  /** GCC writes compound type names with the sign word last (`short unsigned`); every lookup in
    * this object normalises to the canonical order first. The bare spellings `unsigned` and
    * `signed` are `unsigned int` and `int` in C - libavformat's `unsigned count` parameters carry
    * the bare word, and without this every integral lookup on them would conclude nothing (the
    * one-sided bounds arm's `param:` extent and the unsigned-index check both read it). The `int`
    * of `short int`, `long int` and `long long int` is dropped: CDT spells the types of expressions
    * that way, declarations usually do not.
    */
  def normalizeTypeName(t: String): String =
    val words = t.stripPrefix("const ").trim.split("\\s+").toList
    val sign  = words.find(w => w == "unsigned" || w == "signed")
    val sized = words.exists(w => w == "short" || w == "long")
    val rest  = words.filterNot(w => sign.contains(w) || (sized && w == "int"))
    val norm  = (sign.toList ::: rest).mkString(" ")
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
    * The exclusion is not an identifier-only concern. A `mem-len` argument that is itself a call
    * (`memset(dst + off, 0, asf->size_left)`) expands through the SAME argument-to-argument edges
    * into the destination's subtree, which would make MS-INT-001 report the pointer arithmetic in a
    * copy's DESTINATION as "the length computation". Every expression node that sits as an argument
    * of a non-assignment call therefore excludes that call's argument subtree, exactly as
    * identifiers do.
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
    * traversal materialisation would be the bulk of the overlay's allocation.
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

  /** Every POINTER variable a null guard's condition tests: `p == NULL` / `NULL != p`, `!p`, or the
    * truth of `p` itself. Every shape is restricted to pointer-typed locals and parameters: FFmpeg
    * tests ints the same three ways (`size == 0`, `!ret`, `if (n)`), and `0` is also how the
    * frontend spells NULL, so an unrestricted shape reads every earlier use of an int counter as a
    * check-after-use. Shared by the null-deref rule and the derefs-param summary, which must agree
    * on what a guard is or a summary would contradict the rule that consumes it.
    *
    * A conjunction guards EVERY conjunct when it holds - `while (n && !n->marked)` narrows the
    * body's use of `n` exactly as a bare `if (n)` would - so the conjuncts are walked recursively.
    */
  def nullGuardKeysOf(cond: AstNode, pointerNames: Set[String]): List[String] =
    def pointerKey(e: AstNode): Option[String] = e match
      case i: Identifier if pointerNames.contains(i.name) => variableKey(i)
      case c: Call if c.name == "<operator>.cast" =>
          c.argumentOption(2).orElse(c.argumentOption(1)).flatMap(pointerKey)
      case _ => None
    cond match
      case and: Call if and.name == "<operator>.logicalAnd" =>
          and.argument.l.collect { case e: AstNode => e }
              .flatMap(nullGuardKeysOf(_, pointerNames))
              .distinct
      case cmp: Call
          if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
          val operands = Seq(1, 2).flatMap(cmp.argumentOption)
          if operands.exists(isNullLiteralNode) then
            operands.filterNot(isNullLiteralNode).flatMap(pointerKey).headOption.toList
          else Nil
      case not: Call if not.name == "<operator>.logicalNot" =>
          not.argumentOption(1).flatMap(pointerKey).toList
      case other => pointerKey(other).toList
  end nullGuardKeysOf

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
            cs.condition.flatMap(cond => nullGuardKeysOf(cond, pointerNames)).map(key => (key, cs))
        }
        .toMap

  /** The stores to a field that reach one read of it in the same method. `reaching`: each store of
    * the same field spelling, with its base the same unchanged variable, from which some CFG path
    * reaches the read without passing another such store. `dominated`: one of them runs on every
    * path to the read. `rewritable`: a call between a store and the read is handed the base pointer
    * or an address into the struct (a call handed a field's value cannot rewrite it).
    */
  final case class FieldStores(reaching: List[Call], dominated: Boolean, rewritable: Boolean):
    /** the one value the read sees: a single plain store, on every path, not rewritten since */
    def single: Option[Call] = reaching match
      case List(st) if dominated && !rewritable && st.name == "<operator>.assignment" => Some(st)
      case _                                                                          => None

  private def withoutCastsE(e: Expression): Expression = e match
    case c: Call if c.name == "<operator>.cast" =>
        c.argumentOption(2).orElse(c.argumentOption(1)).collect { case x: Expression => x }
            .map(withoutCastsE).getOrElse(e)
    case other => other

  def fieldStoresReaching(field: Call): FieldStores =
    def spelled(e: AstNode): String = e.code.replaceAll("\\s+", "")
    def baseOf(f: Call): Option[Identifier] =
        f.argumentOption(1).collect { case e: Expression => e }.map(withoutCastsE)
            .collect { case i: Identifier => i }
    val code   = spelled(field)
    val baseId = baseOf(field)
    val stores = field.method.ast.isCall.l.filter { a =>
        isAssignmentOperator(a.name) &&
        a.argumentOption(1).exists {
            case lhs: Call =>
                (lhs.name == "<operator>.fieldAccess" || lhs
                    .name == "<operator>.indirectFieldAccess") &&
                lhs.id != field.id && spelled(lhs) == code
            case _ => false
        }
    }
    val storeIds = stores.map(_.id()).toSet
    val reaching = stores.filter { st =>
        GuardPass.cfgReachesAvoiding(st._cfgOut.collectAll[CfgNode].l, field.id(), storeIds) &&
        baseId.exists(b =>
            st.argumentOption(1).collect { case lhs: Call => lhs }.flatMap(baseOf)
                .exists(sb => unchangedBetween(sb, b))
        )
    }
    val dominated = reaching.exists(st => field.dominatedBy.exists(_.id == st.id))
    val baseDecls = baseId.toList.flatMap(declOf).map(_.id()).toSet
    def namesBase(e: Expression): Boolean = withoutCastsE(e) match
      case i: Identifier => declOf(i).exists(d => baseDecls.contains(d.id()))
      case c: Call if c.name == "<operator>.addition" =>
          pointerOperandOf(c).exists(namesBase)
      case c: Call if c.name == "<operator>.addressOf" =>
          c.argumentOption(1).collect { case x: Expression => x }.exists(x =>
              x.ast.isIdentifier.l.exists(i => declOf(i).exists(d => baseDecls.contains(d.id())))
          )
      case _ => false
    val rewritable = reaching.nonEmpty && field.method.ast.isCall.l.exists { c =>
        !c.name.startsWith("<operator>") && c.argument.l.exists(namesBase) &&
        reaching.exists(st =>
            GuardPass.cfgReaches(st._cfgOut.collectAll[CfgNode].l, c.id(), avoid = st.id())
        ) && GuardPass.cfgReaches(c._cfgOut.collectAll[CfgNode].l, field.id(), avoid = c.id())
    }
    FieldStores(reaching, dominated, rewritable)
  end fieldStoresReaching

  /** `&x` handed to an inventoried memory call as its source: read through, never written. */
  def readOnlyAddress(addressOf: Call): Boolean =
      addressOf.tag.name(MemoryApiPass.TagSrc).nonEmpty &&
          addressOf.tag.name(MemoryApiPass.TagDst).isEmpty

  /** The declaration an occurrence refers to: a local or a parameter. */
  def declOf(i: Identifier): Option[StoredNode] =
      i._refOut.collectFirst { case d @ (_: Local | _: MethodParameterIn) => d }

  /** Every occurrence in its method that gives the variable a new value: assignment and increment
    * targets, and a written-through address (`get_len(&n)`; `memcpy(d, &n, sizeof n)` only reads).
    */
  def definitionSitesOf(i: Identifier): List[CfgNode] =
      declOf(i) match
        case None => Nil
        case Some(decl) =>
            i.method.ast.isIdentifier.l.filter { o =>
                declOf(o).exists(_.id() == decl.id()) && GuardPass.isDefinitionSite(o) &&
                !o._astIn.headOption.exists {
                    case c: Call => c.name == "<operator>.addressOf" && readOnlyAddress(c)
                    case _       => false
                }
            }

  /** No definition of `earlier`'s variable on a CFG path from `earlier` to `later` that does not
    * pass `earlier` again: the value read at `later` is the one `earlier` read. A loop that
    * re-reads the variable and reaches `later` without going back through `earlier` changes it; one
    * that reassigns it and comes back through `earlier` does not.
    */
  def unchangedBetween(earlier: Identifier, later: Identifier): Boolean =
      earlier.id() == later.id() ||
          GuardPass.statementRootOf(earlier).id() == GuardPass.statementRootOf(later).id() || {
              val start = earlier._cfgOut.collectAll[CfgNode].l
              !definitionSitesOf(earlier).exists { d =>
                  d.id() != earlier.id() &&
                  GuardPass.cfgReaches(start, d.id(), avoid = earlier.id()) &&
                  GuardPass.cfgReaches(
                    d._cfgOut.collectAll[CfgNode].l,
                    later.id(),
                    avoid = earlier.id()
                  )
              }
          }

end OverlayFacts
