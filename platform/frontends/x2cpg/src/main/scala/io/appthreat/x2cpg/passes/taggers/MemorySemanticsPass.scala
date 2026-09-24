package io.appthreat.x2cpg.passes.taggers

import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** What chen knows about memory on its own - the facts a hand-written project inventory (FFmpeg's
  * `configs/ffmpeg-memory-apis.json`) used to supply. Runs before [[MemoryApiPass]], which tags
  * call sites from `declared inventory ++ these summaries` (a declared entry always wins).
  *
  * **Function summaries**, per method NAME (same-named bodies that disagree conclude nothing), from
  * three kinds of evidence - never from a function's name:
  *
  *   - **declared attributes** (`fn-attr`, which c2cpg records from the GCC attribute syntax):
  *     `malloc` is a heap allocator whose result may be NULL; `alloc_size(i)` names the size
  *     argument and `alloc_size(i,j)` the count and size; `alloc_size` WITHOUT `malloc` on a
  *     function taking a pointer first is a reallocator (`av_realloc_array` - it may hand back its
  *     input); `malloc(dealloc[, i])` (GCC 11) makes `dealloc` the matching free of argument i;
  *     `returns_nonnull` rules the NULL result out; `nonnull(i, ...)` says the function reads
  *     through argument i; `access(read_only|write_only|read_write, ptr[, size])` gives the src/dst
  *     and size roles. This is how a header states the semantics of a library whose bodies are
  *     outside the analysed tree.
  *   - **bodies**, iterated to a bounded fixpoint so a wrapper of a wrapper chains: an allocator is
  *     a pointer-returning method every value-return of which flows from a known allocation (a NULL
  *     fallback allowed) with no free and no untrusted read; a free wrapper returns nothing and
  *     calls only known frees (`free(*pp)` included - the freep shape); a method whose value-return
  *     can be NULL (`return NULL;`, or the result of a nullable callee handed straight back) has a
  *     nullable return; a parameter passed unconditionally, unchanged, to a callee position with a
  *     dst/src/len/untrusted-read role inherits that role; a constructor that stores parameter j
  *     and `j + k` into two members of one object binds (j, k) as (buffer, capacity).
  *   - the **built-in libc inventory** seeds both: `malloc` is known before any wrapper over it.
  *
  * **Storage facts**, per variable: `mem-storage` on each LOCAL (`stack`, or `static` for a static
  * local or a file-scope variable) and each parameter (`param`); `mem-points-to` on each pointer
  * variable, one tag per kind of storage an assignment in the method points it at - `heap` (a known
  * allocation), `stack` (the address of a frame variable, a decayed frame array, `alloca`),
  * `static` (a static or global's address, a string literal). A pointer whose assignments reach
  * nothing classifiable carries no tag: unknown, not a guess.
  *
  * Tags: `mem-semantic` on the METHOD, valued `alloc:<family>`, `realloc:<family>`,
  * `free:<family>`, `len:<i>`, `count:<i>`, `dst:<i>`, `src:<i>`, `untrusted-read:<i>`,
  * `nullable-return`, `nonnull-return`, `nonnull-param:<i>`; `mem-semantic-evidence`
  * (`attribute`/`body`) beside them. C/C++ graphs only.
  */
class MemorySemanticsPass(atom: Cpg, externalConfig: Option[String] = None) extends CpgPass(atom):

  import MemorySemanticsPass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return
    val declared = MemApiVocab.inventory(externalConfig)
    val result   = summarize(atom, declared)
    val rows     = mutable.ListBuffer.empty[(StoredNode, String, String)]
    result.summaries.foreach { case (name, s) =>
        atom.method.nameExact(name).foreach { m =>
          s.values.foreach(v => rows += ((m, TagSemantic, v)))
          s.evidence.foreach(v => rows += ((m, TagEvidence, v)))
        }
    }
    rows ++= storageFacts(atom, declared ++ result.entries)
    rows.groupMap { case (_, tag, value) => (tag, value) } { case (node, _, _) => node }
        .foreach { case ((tag, value), nodes) =>
            nodes.iterator.distinct.newTagNodePair(tag, value).store()(using dstGraph)
        }
    val byEvidence = result.summaries.values.flatMap(_.evidence).groupBy(identity).view
        .mapValues(_.size).toMap
    if result.summaries.nonEmpty then
      println(
        s"MemorySemanticsPass: ${result.summaries.size} function summaries " +
            s"(attribute ${byEvidence.getOrElse(EvidenceAttribute, 0)}, " +
            s"body ${byEvidence.getOrElse(EvidenceBody, 0)})"
      )
  end run
end MemorySemanticsPass

object MemorySemanticsPass:

  final val TagSemantic = "mem-semantic"
  final val TagEvidence = "mem-semantic-evidence"
  final val TagStorage  = "mem-storage"
  final val TagPointsTo = "mem-points-to"

  final val EvidenceAttribute = "attribute"
  final val EvidenceBody      = "body"

  final val StorageStack  = "stack"
  final val StorageStatic = "static"
  final val StorageHeap   = "heap"
  final val StorageParam  = "param"

  private final val FamilyHeap = "heap"

  /** Bounds on the body fixpoint: each round lets a wrapper chain off the round before it. */
  private final val MaxRounds = 3

  /** One function's inferred semantics. `entry` is the call-site vocabulary [[MemoryApiPass]] tags
    * with; the null facts sit beside it.
    */
  final case class Summary(
    entry: MemApiVocab.MemApiEntry,
    nonnullReturn: Boolean = false,
    nonnullParams: Set[Int] = Set.empty,
    evidence: Set[String] = Set.empty
  ):
    def values: List[String] =
        entry.alloc.map(f => s"alloc:$f").toList ++
            entry.realloc.map(f => s"realloc:$f") ++
            entry.free.map(f => s"free:$f") ++
            entry.len.map(i => s"len:$i") ++
            entry.count.map(i => s"count:$i") ++
            entry.dst.map(i => s"dst:$i") ++
            entry.src.map(i => s"src:$i") ++
            entry.untrustedRead.map(i => s"untrusted-read:$i") ++
            Option.when(entry.nullableReturn && !nonnullReturn)("nullable-return") ++
            Option.when(nonnullReturn)("nonnull-return") ++
            nonnullParams.toList.sorted.map(i => s"nonnull-param:$i")

    def isEmpty: Boolean = values.isEmpty
  end Summary

  final case class Result(summaries: Map[String, Summary]):
    def entries: Map[String, MemApiVocab.MemApiEntry] =
        summaries.map { case (n, s) =>
            n -> s.entry.copy(nullableReturn = s.entry.nullableReturn && !s.nonnullReturn)
        }

  /** The inventory entries the pass concluded, read back from the METHOD tags when the pass ran, or
    * computed here when it did not (a caller running [[MemoryApiPass]] alone gets the same
    * knowledge). Names the declared inventory already covers are left to it.
    */
  def entriesFor(
    cpg: Cpg,
    declared: Map[String, MemApiVocab.MemApiEntry]
  ): Map[String, MemApiVocab.MemApiEntry] =
    val tagged = cpg.method.where(_.tag.nameExact(TagSemantic)).l
    if tagged.isEmpty then summarize(cpg, declared).entries
    else
      tagged
          .groupBy(_.name)
          .toList
          .flatMap { case (name, ms) =>
              entryFromValues(name, ms.flatMap(semanticValues).toSet).map(name -> _)
          }
          .filterNot { case (name, _) => declared.contains(name) }
          .toMap

  /** Parameters the declarations say a function reads through (`nonnull`), by function name - the
    * null-deref summary's evidence for a callee whose body is out of scope.
    */
  def nonnullParamsByName(cpg: Cpg): Map[String, Set[Int]] =
      cpg.method.where(_.tag.nameExact(TagSemantic)).l
          .map(m =>
              m.name -> semanticValues(m).collect {
                  case v if v.startsWith("nonnull-param:") =>
                      v.stripPrefix("nonnull-param:").toInt
              }.toSet
          )
          .filter(_._2.nonEmpty)
          .groupMapReduce(_._1)(_._2)(_ ++ _)

  private def semanticValues(m: Method): List[String] = m.tag.nameExact(TagSemantic).value.l

  private def entryFromValues(name: String, vs: Set[String]): Option[MemApiVocab.MemApiEntry] =
    def idx(prefix: String): Option[Int] =
        vs.collectFirst { case v if v.startsWith(prefix) => v.stripPrefix(prefix).toInt }
    def fam(prefix: String): Option[String] =
        vs.collectFirst { case v if v.startsWith(prefix) => v.stripPrefix(prefix) }
    val entry = MemApiVocab.MemApiEntry(
      name,
      dst = idx("dst:"),
      src = idx("src:"),
      len = idx("len:"),
      count = idx("count:"),
      alloc = fam("alloc:"),
      free = fam("free:"),
      realloc = fam("realloc:"),
      untrustedRead = idx("untrusted-read:"),
      nullableReturn = vs.contains("nullable-return")
    )
    Option.when(entry != MemApiVocab.MemApiEntry(name))(entry)

  // --------------------------------------------------------------------------------------------
  // inference
  // --------------------------------------------------------------------------------------------

  def summarize(cpg: Cpg, declared: Map[String, MemApiVocab.MemApiEntry]): Result =
    val out = mutable.LinkedHashMap.empty[String, Summary]

    // 1. declared attributes: every METHOD carrying one - a header stub or a definition
    val attrsByName = cpg.method
        .where(_.tag.nameExact(Defines.FunctionAttributeTag))
        .l
        .groupMapReduce(_.name)(m => m.tag.nameExact(Defines.FunctionAttributeTag).value.l.toSet)(
          _ ++ _
        )
    val deallocators = mutable.LinkedHashMap.empty[String, Int]
    attrsByName.foreach { case (name, attrs) =>
        val method = cpg.method.nameExact(name).l.headOption
        fromAttributes(name, attrs, method, deallocators).foreach(s => out(name) = s)
    }
    // GCC 11 `malloc(dealloc, i)`: the named deallocator releases its argument i
    deallocators.foreach { case (dealloc, _) =>
        if !declared.contains(dealloc) then
          out.updateWith(dealloc) {
              case Some(s) =>
                  Some(s.copy(
                    entry = s.entry.copy(free = Some(FamilyHeap)),
                    evidence = s.evidence + EvidenceAttribute
                  ))
              case None =>
                  Some(Summary(
                    MemApiVocab.MemApiEntry(dealloc, free = Some(FamilyHeap)),
                    evidence = Set(EvidenceAttribute)
                  ))
          }
    }

    // 2. bodies, to a bounded fixpoint over what is known so far
    val defined = cpg.method.filterNot(m => m.isExternal || m.name == "<global>")
        .filter(_.block.astChildren.nonEmpty)
        .l
        .groupBy(_.name)
    def known(name: String): Option[MemApiVocab.MemApiEntry] =
        declared.get(name).orElse(out.get(name).map(_.entry))
    var round   = 1
    var changed = true
    while changed && round <= MaxRounds do
      changed = false
      defined.foreach { case (name, methods) =>
          if !declared.contains(name) then
            val conclusions = methods.map(fromBody(_, known)).distinct
            // same-named bodies that disagree conclude nothing
            conclusions match
              case List(Some(bodyEntry)) =>
                  val merged = out.get(name) match
                    case Some(s) =>
                        // attributes and body agree or complement; a declared attribute keeps
                        // its own role values, the body fills the ones it left empty
                        s.copy(
                          entry = fillEmpty(s.entry, bodyEntry),
                          evidence = s.evidence + EvidenceBody
                        )
                    case None => Summary(bodyEntry, evidence = Set(EvidenceBody))
                  if !out.get(name).contains(merged) then
                    out(name) = merged
                    changed = true
              case _ => ()
      }
      round += 1
    end while
    // 3. capacity binders (a constructor remembering where its buffer ends)
    inferBinders(cpg).foreach { entry =>
        if !declared.contains(entry.name) then
          out.updateWith(entry.name) {
              case Some(s) => Some(s.copy(entry = fillEmpty(s.entry, entry)))
              case None    => Some(Summary(entry, evidence = Set(EvidenceBody)))
          }
    }

    Result(out.filterNot { case (name, s) => declared.contains(name) || s.isEmpty }.toMap)
  end summarize

  /** `base` with each role it leaves empty taken from `extra`. */
  private def fillEmpty(
    base: MemApiVocab.MemApiEntry,
    extra: MemApiVocab.MemApiEntry
  ): MemApiVocab.MemApiEntry =
      base.copy(
        dst = base.dst.orElse(extra.dst),
        src = base.src.orElse(extra.src),
        len = base.len.orElse(extra.len),
        count = base.count.orElse(extra.count),
        alloc = base.alloc.orElse(Option.when(base.realloc.isEmpty && base.free.isEmpty)(
          extra.alloc
        ).flatten),
        free = base.free.orElse(Option.when(base.alloc.isEmpty && base.realloc.isEmpty)(
          extra.free
        ).flatten),
        realloc = base.realloc.orElse(Option.when(base.alloc.isEmpty && base.free.isEmpty)(
          extra.realloc
        ).flatten),
        untrustedRead = base.untrustedRead.orElse(extra.untrustedRead),
        nullableReturn = base.nullableReturn || extra.nullableReturn
      )

  // --- attributes -------------------------------------------------------------------------------

  private val AttrPattern = """([A-Za-z_][A-Za-z0-9_]*)(?:\((.*)\))?""".r

  private def fromAttributes(
    name: String,
    attrs: Set[String],
    method: Option[Method],
    deallocators: mutable.LinkedHashMap[String, Int]
  ): Option[Summary] =
    val parsed = attrs.toList.collect { case AttrPattern(n, args) =>
        n -> Option(args).map(_.split(",").map(_.trim).filter(_.nonEmpty).toList).getOrElse(Nil)
    }
    def ints(args: List[String]): List[Int] = args.flatMap(_.toIntOption)
    val isMalloc                            = parsed.exists(_._1 == "malloc")
    val allocSize = parsed.collectFirst { case ("alloc_size", args) => ints(args) }
    val params    = method.map(_.parameter.l.sortBy(_.index)).getOrElse(Nil)
    val firstIsPointer =
        params.headOption.exists(p => OverlayFacts.isPointer(p.typeFullName.trim))
    val returnsPointer = method.exists(m =>
        OverlayFacts.isPointer(Option(m.methodReturn.typeFullName).getOrElse("").trim)
    )
    parsed.collect {
        case ("malloc", dealloc :: rest) if dealloc.toIntOption.isEmpty =>
            deallocators(dealloc) = rest.headOption.flatMap(_.toIntOption).getOrElse(1)
    }
    val (count, len) = allocSize match
      case Some(List(n, s)) => (Some(n), Some(s))
      case Some(List(s))    => (None, Some(s))
      case _                => (None, None)
    // alloc_size without malloc, on a function whose first argument is a pointer: the realloc
    // shape - the result may be the input, so it is not a fresh allocation `malloc` promises
    val isRealloc     = !isMalloc && allocSize.isDefined && firstIsPointer
    val isAlloc       = isMalloc || (allocSize.isDefined && !isRealloc && returnsPointer)
    val nonnullReturn = parsed.exists(_._1 == "returns_nonnull")
    val nonnullParams = parsed.collect {
        case ("nonnull", Nil) =>
            params.filter(p => OverlayFacts.isPointer(p.typeFullName)).map(_.index)
        case ("nonnull", args) => ints(args)
    }.flatten.toSet
    // access(mode, ptr-index[, size-index])
    val accesses = parsed.collect { case ("access", mode :: rest) => (mode, ints(rest)) }
    val dst      = accesses.collectFirst { case (m, p :: _) if m.contains("write") => p }
    val src      = accesses.collectFirst { case ("read_only", p :: _) => p }
    val accessLen = accesses.collectFirst { case (m, _ :: s :: _) if m.contains("write") => s }
        .orElse(accesses.collectFirst { case (_, _ :: s :: _) => s })
    val entry = MemApiVocab.MemApiEntry(
      name,
      dst = dst,
      src = src,
      len = len.orElse(accessLen),
      count = count,
      alloc = Option.when(isAlloc)(FamilyHeap),
      realloc = Option.when(isRealloc)(FamilyHeap),
      nullableReturn = (isAlloc || isRealloc) && !nonnullReturn
    )
    val s = Summary(entry, nonnullReturn, nonnullParams, Set(EvidenceAttribute))
    Option.unless(s.isEmpty)(s)
  end fromAttributes

  // --- bodies -----------------------------------------------------------------------------------

  private def fromBody(
    method: Method,
    known: String => Option[MemApiVocab.MemApiEntry]
  ): Option[MemApiVocab.MemApiEntry] =
    val calls               = method.call.l
    val real                = calls.filterNot(_.name.startsWith("<operator>"))
    def isProducer(c: Call) = known(c.name).exists(e => e.alloc.isDefined || e.realloc.isDefined)
    def isFree(c: Call)     = known(c.name).exists(_.free.isDefined)
    def isRead(c: Call) = known(c.name).exists(e => e.untrustedRead.isDefined || e.untrustedCall)
    val producers       = real.filter(isProducer)
    val frees           = real.filter(isFree)
    val reads           = real.filter(isRead)

    val wrapper: Option[MemApiVocab.MemApiEntry] =
        if producers.nonEmpty && frees.isEmpty && reads.isEmpty && real.forall(isProducer) then
          allocatorEntry(method, producers, known)
        else if frees.nonEmpty && producers.isEmpty && reads.isEmpty && real.forall(isFree) &&
          returnsNoValue(method)
        then Some(MemApiVocab.MemApiEntry(method.name, free = Some(FamilyHeap)))
        else None

    val nullable = returnsPointer(method) && !wrapper.exists(_.alloc.isDefined) &&
        valueReturns(method).exists(e => mayBeNull(e, known))
    val roles = inheritedRoles(method, real, known)
    val entry = fillEmpty(
      wrapper.getOrElse(MemApiVocab.MemApiEntry(method.name)),
      roles.copy(nullableReturn = nullable)
    )
    Option.when(entry != MemApiVocab.MemApiEntry(method.name))(entry)
  end fromBody

  private def valueReturns(method: Method): List[Expression] =
      method.ast.collectAll[Return].l.flatMap(_.astChildren.collectFirst { case e: Expression =>
          e
      })

  private def returnsNoValue(method: Method): Boolean = valueReturns(method).isEmpty

  private def returnsPointer(method: Method): Boolean =
      OverlayFacts.isPointer(Option(method.methodReturn.typeFullName).getOrElse("").trim)

  private def castOperand(c: Call): Option[Expression] =
      c.argumentOption(2).orElse(c.argumentOption(1))

  private def unwrapCasts(e: Expression): Expression = e match
    case c: Call if c.name == "<operator>.cast" => castOperand(c).map(unwrapCasts).getOrElse(e)
    case other                                  => other

  /** NULL as the preprocessor leaves it: a literal 0, `((void *)0)`, or an identifier with no
    * definition and no declaration in the method (a macro constant).
    */
  private def isNullValue(e: Expression): Boolean =
      AllocationStatePass.isNullLiteral(e, castOperand) || (unwrapCasts(e) match
        case i: Identifier =>
            i.name == "NULL" && i.method.local.nameExact(i.name).isEmpty &&
            i.method.parameter.nameExact(i.name).isEmpty
        case _ => false
      )

  /** Can this returned value be NULL, on the evidence: a NULL constant, a conditional with a NULL
    * branch, the unguarded result of a nullable callee, or a local one of whose definitions is one
    * of those.
    */
  private def mayBeNull(e: Expression, known: String => Option[MemApiVocab.MemApiEntry]): Boolean =
    def direct(x: Expression): Boolean = unwrapCasts(x) match
      case v if isNullValue(v) => true
      case c: Call if c.name == "<operator>.conditional" =>
          Seq(2, 3).flatMap(c.argumentOption).exists(direct)
      case c: Call if !c.name.startsWith("<operator>") =>
          known(c.name).exists(_.nullableReturn)
      case _ => false
    direct(e) || (unwrapCasts(e) match
      case i: Identifier =>
          OverlayFacts
              .reachingDefsIn(i)
              .collect { case d: Identifier => d }
              .flatMap(_._astIn.collectFirst {
                  case a: Call if a.name == "<operator>.assignment" => a
              })
              .flatMap(_.argumentOption(2))
              .exists(direct)
      case _ => false
    )
  end mayBeNull

  /** The allocator conclusion (C2, moved here from MemoryApiPass): a pointer-returning body at
    * least one of whose returns flows from a real allocation and every one of whose returns flows
    * from an allocation or is a NULL constant. The size role is the parameter feeding the wrapped
    * allocation's size, when exactly one does.
    */
  private def allocatorEntry(
    method: Method,
    producers: List[Call],
    known: String => Option[MemApiVocab.MemApiEntry]
  ): Option[MemApiVocab.MemApiEntry] =
    if !returnsPointer(method) then return None
    val producerIds = producers.map(_.id).toSet
    def flows(e: Expression): Boolean = unwrapCasts(e) match
      case c: Call if producerIds.contains(c.id) => true
      case c: Call if c.name == "<operator>.conditional" =>
          val bs = Seq(2, 3).flatMap(c.argumentOption)
          bs.forall(b => flows(b) || isNullValue(b)) && bs.exists(flows)
      case i: Identifier =>
          OverlayFacts
              .reachingDefsIn(i)
              .collect { case d: Identifier => d }
              .flatMap(_._astIn.collectFirst {
                  case a: Call if a.name == "<operator>.assignment" => a
              })
              .flatMap(_.argumentOption(2))
              .exists(x => flows(x))
      case _ => false
    val returns = valueReturns(method)
    if !returns.exists(flows) || !returns.forall(r => flows(r) || isNullValue(r)) then None
    else
      val sizeParams = (for
        call <- producers
        entry = known(call.name).get
        idx   <- entry.len.toList ++ entry.count.toList
        arg   <- call.argumentOption(idx).toList
        leaf  <- (arg +: arg.ast.collectAll[Expression].l).collect { case i: Identifier => i }
        param <- method.parameter.nameExact(leaf.name).l
      yield param.index).distinct
      Some(
        MemApiVocab.MemApiEntry(
          method.name,
          len = sizeParams match
            case List(i) => Some(i)
            case _       => None
          ,
          alloc = Option.when(producers.exists(c => known(c.name).exists(_.alloc.isDefined)))(
            FamilyHeap
          ),
          realloc = Option.when(
            producers.forall(c => known(c.name).exists(_.realloc.isDefined))
          )(FamilyHeap),
          nullableReturn = true
        )
      )
    end if
  end allocatorEntry

  /** A parameter handed UNCONDITIONALLY (the call's statement has no controlling condition) and
    * UNCHANGED (a plain identifier argument, never reassigned in the method) to a callee position
    * that carries a role, takes that role: `my_read(fd, buf, n) { return read(fd, buf, n); }` is a
    * reader of its argument 2 into a buffer of length 3. A role two parameters would claim is
    * dropped.
    */
  private def inheritedRoles(
    method: Method,
    calls: List[Call],
    known: String => Option[MemApiVocab.MemApiEntry]
  ): MemApiVocab.MemApiEntry =
    val params = method.parameter.l.map(p => p.name -> p.index).toMap
    val reassigned = method.call.nameExact("<operator>.assignment").argument(1)
        .collect { case i: Identifier => i.name }.toSet
    val found = mutable.HashMap.empty[String, mutable.Set[Int]]
    calls.foreach { c =>
        if GuardPass.statementRootOf(c)._cdgIn.isEmpty then
          known(c.name).foreach { e =>
            def claim(role: String, pos: Option[Int]): Unit =
                pos.flatMap(c.argumentOption).foreach {
                    case i: Identifier if params.contains(i.name) && !reassigned(i.name) =>
                        found.getOrElseUpdate(role, mutable.Set.empty) += params(i.name)
                    case _ => ()
                }
            claim("dst", e.dst)
            claim("src", e.src)
            claim("len", e.len)
            claim("read", e.untrustedRead)
          }
    }
    def one(role: String): Option[Int] = found.get(role).collect {
        case s if s.size == 1 => s.head
    }
    MemApiVocab.MemApiEntry(
      method.name,
      dst = one("dst"),
      src = one("src"),
      len = one("len"),
      untrustedRead = one("read")
    )
  end inheritedRoles

  /** The capacity-binder conclusions (F4, moved here from MemoryApiPass): a body that stores
    * parameter j into a member of parameter i and `param j + param k` into a second member of the
    * same object establishes (j, k) as a (buffer, capacity) pair. Same-named disagreeing bodies
    * conclude nothing.
    */
  private def inferBinders(cpg: Cpg): List[MemApiVocab.MemApiEntry] =
    def memberStoreOf(lhs: Expression): Option[(String, String)] = lhs match
      case c: Call
          if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
          for
            base   <- c.argumentOption(1).collect { case i: Identifier => i }
            member <- OverlayFacts.memberOf(c)
          yield (base.name, member)
      case _ => None
    val byMethod = mutable.LinkedHashMap.empty[
      Method,
      mutable.ListBuffer[(String, String, String, Option[String])]
    ]
    cpg.call.nameExact("<operator>.assignment").l.foreach { assignment =>
      val method = assignment.method
      if !method.isExternal then
        for
          lhs            <- assignment.argumentOption(1)
          (base, member) <- memberStoreOf(lhs)
          rhs            <- assignment.argumentOption(2)
        do
          rhs match
            case r: Call if r.name == "<operator>.addition" =>
                Seq(1, 2).flatMap(r.argumentOption).collect { case i: Identifier => i.name } match
                  case Seq(a, b) =>
                      byMethod.getOrElseUpdate(method, mutable.ListBuffer.empty) +=
                          ((base, member, a, Some(b)))
                  case _ => ()
            case i: Identifier =>
                byMethod.getOrElseUpdate(method, mutable.ListBuffer.empty) +=
                    ((base, member, i.name, None))
            case _ => ()
    }
    val concluded = mutable.LinkedHashMap.empty[String, MemApiVocab.MemApiEntry]
    val disagreed = mutable.HashSet.empty[String]
    byMethod.foreach { case (method, stores) =>
        val paramIndex = method.parameter.l.map(p => p.name -> p.index).toMap
        val directs = stores.collect {
            case (b, m, p, None) if paramIndex.contains(p) => ((b, p), m)
        }
        val offsets = stores.collect {
            case (b, m, p, Some(k)) if paramIndex.contains(p) && paramIndex.contains(k) =>
                ((b, p), (m, k))
        }
        val resolved = (for
          (keyD, memberA)      <- directs
          (keyO, (memberB, k)) <- offsets
          if keyD == keyO && memberA != memberB
        yield (paramIndex(keyD._2), paramIndex(k))).distinct.toList
        resolved match
          case (j, k) :: Nil =>
              val entry = MemApiVocab.MemApiEntry(method.name, dst = Some(j), len = Some(k))
              concluded.get(method.name) match
                case Some(existing) if existing != entry => disagreed += method.name
                case Some(_)                             => ()
                case None                                => concluded(method.name) = entry
          case _ => ()
    }
    concluded.filterNot { case (name, _) => disagreed.contains(name) }.values.toList
  end inferBinders

  // --- storage ----------------------------------------------------------------------------------

  private def isStaticLocal(l: Local): Boolean =
      l.tag.nameExact(Defines.StorageClassTag).value.l.contains(Defines.StorageClassStatic)

  private def isArrayType(t: String): Boolean =
      OverlayFacts.arrayExtent(t).isDefined || t.trim.endsWith("]")

  /** `mem-storage` on every variable and `mem-points-to` on every pointer variable (see the class
    * scaladoc).
    */
  private def storageFacts(
    cpg: Cpg,
    entries: Map[String, MemApiVocab.MemApiEntry]
  ): List[(StoredNode, String, String)] =
    val rows = mutable.ListBuffer.empty[(StoredNode, String, String)]
    cpg.method.filterNot(_.isExternal).foreach { method =>
      val fileScope = method.name == "<global>"
      val storageOf = mutable.HashMap.empty[String, String]
      method.local.foreach { l =>
        val s = if fileScope || isStaticLocal(l) then StorageStatic else StorageStack
        storageOf(l.name) = s
        rows += ((l, TagStorage, s))
      }
      method.parameter.foreach { p =>
        storageOf(p.name) = StorageParam
        rows += ((p, TagStorage, StorageParam))
      }
      if !fileScope then
        // the storage an assignment points a pointer variable at
        def pointsTo(rhs: Expression): Option[String] = unwrapCasts(rhs) match
          case c: Call if c.name == "<operator>.addressOf" =>
              c.argumentOption(1).map(unwrapCasts).flatMap {
                  case i: Identifier =>
                      storageOf.get(i.name) match
                        case Some(StorageStatic) => Some(StorageStatic)
                        case Some(_)             => Some(StorageStack)  // a local's or param's slot
                        case None                => Some(StorageStatic) // a global
                  case _ => None
              }
          case i: Identifier =>
              method.local.nameExact(i.name).l.headOption.filter(l => isArrayType(l.typeFullName))
                  .map(l => if isStaticLocal(l) then StorageStatic else StorageStack)
          case l: Literal if l.code.startsWith("\"") => Some(StorageStatic)
          case c: Call if !c.name.startsWith("<operator>") =>
              entries.get(c.name).flatMap { e =>
                  if e.alloc.contains("stack") then Some(StorageStack)
                  else if e.alloc.isDefined || e.realloc.isDefined then Some(StorageHeap)
                  else None
              }
          case _ => None
        val pointerVars =
            (method.local.l.map(l => l.name -> (l: StoredNode, l.typeFullName)) ++
                method.parameter.l.map(p => p.name -> (p: StoredNode, p.typeFullName))).toMap
                .filter { case (_, (_, t)) => OverlayFacts.isPointer(t.trim) }
        method.call.nameExact("<operator>.assignment").foreach { a =>
            (a.argumentOption(1), a.argumentOption(2)) match
              case (Some(lhs: Identifier), Some(rhs)) =>
                  pointerVars.get(lhs.name).foreach { case (decl, _) =>
                      pointsTo(rhs).foreach(kind => rows += ((decl, TagPointsTo, kind)))
                  }
              case _ => ()
        }
      end if
    }
    rows.toList
  end storageFacts
end MemorySemanticsPass
