package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{
    Call,
    Expression,
    Identifier,
    Literal,
    Method,
    Return,
    StoredNode
}
import io.shiftleft.codepropertygraph.generated.{Languages, PropertyNames}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Tags memory-API call sites and their arguments with the roles from [[MemApiVocab]]'s inventory.
  * First pass of the phase-2a overlay: **tags only, no findings, no detectors** - a bounds rule
  * later writes `tag.name("mem-len").argument` instead of hard-coding `argument(3)`, and gains
  * `snprintf`'s different arity and `read`'s different destination index from the resource file
  * alone.
  *
  * After the inventory is applied, the pass infers the wrapper layer a project builds over it (part
  * 3 task C2): a defined method every one of whose value-returns flows from an inventoried
  * `mem-alloc` or `mem-realloc` result - through casts and NULL fallbacks, with no free and no
  * untrusted read in the body - is itself an allocator, and a body whose only external calls are
  * inventoried `mem-free` calls is a free wrapper. The inferred roles are emitted as ORDINARY
  * `mem-alloc` / `mem-free` / `mem-realloc` / `mem-len` tags at the wrapper's call sites, so
  * ExtentPass and the rules need no second vocabulary. Inference is conservative: a body that
  * returns anything not derived from the allocation, or that calls anything beside the frees it
  * wraps, is left untagged; a conclusion that disagrees with the declared inventory is reported and
  * the declared entry wins. The summary line states what was concluded.
  *
  * Tags emitted (each alongside the `memory-safety` umbrella, the way [[PiiTagsPass]] emits
  * `pii-email` alongside `sensitive-data`):
  *   - `mem-dst` / `mem-src` / `mem-len`, valued with the API name, on the ARGUMENT playing that
  *     role; a count-by-size allocator's element count carries `mem-len` too, because the size that
  *     can overflow is the product (part 4, D1);
  *   - `mem-alloc` / `mem-free` / `mem-realloc`, valued with the family (`heap`, `new`, `mmap`,
  *     `file`, `socket`), on the call;
  *   - `untrusted-read`, valued with the API name, on the call and on the buffer it fills.
  *
  * The umbrella tag is what lets `atom reachables --sink-tag memory-safety` and a chennai session
  * see this work without a second output path.
  *
  * Conventions copied from the taggers this pass is modelled on: a plain `CpgPass` with ONE
  * traversal over calls (matches accumulated per tag, tags emitted in a single batch at the end,
  * never re-traversed per category - see [[PiiTagsPass]]), vocabulary in its own object over a
  * versioned JSON resource ([[CdxTagVocab]]), and the `externalConfig` hook of [[ChennaiTagsPass]]
  * so a team can declare an in-house `av_memcpy` wrapper without patching chen.
  *
  * Scoped to C/C++ graphs (`Languages.C`/`NEWC`): the inventory is keyed on bare libc names, and a
  * bare `read` or `free` in a Java/JS/Python graph must not be tagged as a memory API. Other
  * languages join when they carry their own inventory (plan track B).
  */
class MemoryApiPass(atom: Cpg, externalConfig: Option[String] = None) extends CpgPass(atom):

  import MemoryApiPass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !appliesTo(atom) then return

    val inventory = MemApiVocab.inventory(externalConfig)
    if inventory.isEmpty then return

    // One traversal over calls; matches accumulated per tag and emitted in a single batch.
    val matchesByTag =
        mutable.LinkedHashMap.empty[String, mutable.LinkedHashSet[(StoredNode, String)]]
    def record(tag: String, value: String, node: StoredNode): Unit =
        matchesByTag.getOrElseUpdate(tag, mutable.LinkedHashSet.empty) += ((node, value))

    atom.call.foreach { call =>
        inventory.get(call.name).foreach { entry =>
            tagCall(entry, call, record)
        }
    }

    // The wrapper layer over the inventory (C2): infer allocator/free roles from method bodies,
    // then tag the wrappers' call sites exactly as the inventory's own entries are tagged.
    inferWrappers(inventory, matchesByTag, record)

    // F4 (part 6): the capacity binders - a constructor that stores parameter j into a member
    // of parameter i and parameter j + parameter k into ANOTHER member of i (`s->buf = buf;
    // s->buf_end = buf + size`, the PutBitContext/init_put_bits shape) establishes that (j, k)
    // is a (buffer, capacity) pair. Concluded from the body, never from names, and emitted as
    // ordinary dst/len roles at the call sites - which is what makes a claimed capacity bigger
    // than the buffer's real extent visible to the bounds rules with no new vocabulary.
    val binders = inferBinders
    binders.foreach { entry =>
        atom.call.nameExact(entry.name).foreach { site => tagCall(entry, site, record) }
    }
    if binders.nonEmpty then
      println(
        s"MemoryApiPass: inferred ${binders.size} capacity-binder constructors from call shapes"
      )

    // The umbrella is emitted once per node across all categories, not once per (tag, value)
    // group: a `memcpy` destination carries `mem-dst` and the call carries `mem-alloc`-style
    // tags from several groups, and re-emitting `memory-safety` per group would attach the same
    // tag to the same node repeatedly.
    val umbrella = mutable.LinkedHashSet.empty[StoredNode]
    matchesByTag.foreach { case (tag, tagged) =>
        tagged.groupMap(_._2)(_._1).foreach { case (value, nodes) =>
            nodes.iterator.newTagNodePair(tag, value).store()(using dstGraph)
            umbrella ++= nodes
        }
    }
    umbrella.iterator.newTagNode(UmbrellaTag).store()(using dstGraph)
  end run

  private def tagCall(
    entry: MemApiVocab.MemApiEntry,
    call: Call,
    record: (String, String, StoredNode) => Unit
  ): Unit =
    def argAt(index: Int): Option[StoredNode] =
        call.argumentOption(index).collect { case s: StoredNode => s }

    entry.dst.foreach(i => argAt(i).foreach(n => record(TagDst, entry.name, n)))
    entry.src.foreach(i => argAt(i).foreach(n => record(TagSrc, entry.name, n)))
    entry.len.foreach(i => argAt(i).foreach(n => record(TagLen, entry.name, n)))
    // D1: a count-by-size allocator bounds the operation by the PRODUCT, so the element count
    // joins the size as a length role - the attacker-influenced factor carries mem-len too and
    // the overflow question can be asked about it (ValueOrigin gives it an origin from here).
    entry.count.foreach(i => argAt(i).foreach(n => record(TagLen, entry.name, n)))

    entry.alloc.foreach(family => record(TagAlloc, family, call))
    entry.free.foreach(family => record(TagFree, family, call))
    entry.realloc.foreach(family => record(TagRealloc, family, call))

    // E3: the entry DECLARES that its result may be NULL - pointer-returning allocators, the
    // strchr family. The fd-returning allocators (open, socket) deliberately do not: an int
    // fd's failure mode is -1, and conflating the two turned checked fds into null-deref
    // findings (c/cwe367_toctou.c's negative control).
    if entry.nullableReturn then
      record(TagNullableReturn, entry.name, call)

    entry.untrustedRead.foreach { i =>
      record(TagUntrustedRead, entry.name, call)
      argAt(i).foreach(n => record(TagUntrustedRead, entry.name, n))
    }
    if entry.untrustedCall then
      record(TagUntrustedRead, entry.name, call)
  end tagCall

  /** Infer the wrapper layer over the inventory (C2), from what the method bodies do - never from
    * their names. Candidates are only the (few) defined methods that CONTAIN an inventoried alloc
    * or free call, so the cost is a handful of small bodies, not a graph walk. Rounds repeat until
    * a fixpoint (bounded) so a wrapper of a wrapper is found too, with each round's conclusions
    * acting as inventory for the next.
    *
    * A method is an inferred allocator when it has a body, invokes no free and no untrusted read,
    * and every one of its value-returns flows from an allocation (identifier leaves whose
    * definitions terminate only in allocation calls or literals) - a NULL-on-failure fallback is
    * fine, returning the caller's own pointer or anything else is not. Its size role is the
    * parameter feeding the wrapped allocation's size argument, when exactly one does. A method is
    * an inferred free wrapper when its only external calls are the frees it wraps and it returns no
    * value. Anything else stays untagged.
    */
  private def inferWrappers(
    declared: Map[String, MemApiVocab.MemApiEntry],
    matchesByTag: mutable.LinkedHashMap[String, mutable.LinkedHashSet[(StoredNode, String)]],
    record: (String, String, StoredNode) => Unit
  ): List[MemApiVocab.MemApiEntry] =
    val inferred = mutable.LinkedHashMap.empty[String, MemApiVocab.MemApiEntry]
    // methods whose conclusion disagreed with the declaration: reported once, not once per round
    val reported = mutable.HashSet.empty[String]
    // the alloc/realloc/free/read call nodes the inventory produced, grown by each round's
    // conclusions so a wrapper of a wrapper chains. A realloc is a PRODUCER of a fresh pointer
    // for inference purposes and is kept out of the free set (D1): reading alloc and free as one
    // overlapping pair turned every realloc-only wrapper into "allocates and frees", a shape
    // neither conclusion branch accepts.
    val callsByTag = mutable.HashMap.empty[String, mutable.LinkedHashSet[Call]]
    def callsOf(tag: String): mutable.LinkedHashSet[Call] =
        callsByTag.getOrElseUpdate(
          tag,
          mutable.LinkedHashSet.from(
            matchesByTag.getOrElse(tag, mutable.LinkedHashSet.empty)
                .collect { case (c: Call, _) => c }
          )
        )
    val lenArgIds = matchesByTag.getOrElse(MemoryApiPass.TagLen, mutable.LinkedHashSet.empty)
        .map { case (node, _) => node.id }.toSet

    var round     = 1
    var concluded = true
    while concluded && round <= MaxInferenceRounds do
      concluded = false
      val allocIds   = callsOf(MemoryApiPass.TagAlloc).map(_.id).toSet
      val reallocIds = callsOf(MemoryApiPass.TagRealloc).map(_.id).toSet
      val freeIds    = callsOf(MemoryApiPass.TagFree).map(_.id).toSet
      val readIds    = callsOf(MemoryApiPass.TagUntrustedRead).map(_.id).toSet

      val candidates = (callsOf(MemoryApiPass.TagAlloc) ++ callsOf(MemoryApiPass.TagRealloc) ++
          callsOf(MemoryApiPass.TagFree))
          .map(_.method)
          .filterNot(_.isExternal)
          .toList
          .distinct

      candidates.foreach { method =>
          if !inferred.contains(method.name) && !reported.contains(method.name) then
            concludeWrapper(method, allocIds, reallocIds, freeIds, readIds, lenArgIds).foreach {
                entry =>
                    declared.get(method.name) match
                      case Some(d) if roleOf(d) != roleOf(entry) =>
                          // inference must say what it concluded, and must not quietly prefer
                          // either source when it disagrees with the declaration. Recorded so the
                          // next fixpoint round does not re-derive and re-report the same one.
                          reported += method.name
                          System.err.println(
                            s"warn: memory-api inference concludes ${method.name} is an " +
                                s"${roleOf(entry).getOrElse("?")} wrapper, but the declared " +
                                s"inventory gives it the role ${roleOf(d).getOrElse("none")}; " +
                                "keeping the declaration"
                          )
                      case Some(_) => () // the declaration already tagged these call sites
                      case None =>
                          inferred(method.name) = entry
                          concluded = true
                          atom.call.nameExact(method.name).foreach { site =>
                            tagCall(entry, site, record)
                            entry.alloc.foreach(_ => callsOf(MemoryApiPass.TagAlloc) += site)
                            entry.realloc.foreach(_ => callsOf(MemoryApiPass.TagRealloc) += site)
                            entry.free.foreach(_ => callsOf(MemoryApiPass.TagFree) += site)
                          }
            }
      }
      round += 1
    end while

    if inferred.nonEmpty then
      println(
        s"MemoryApiPass: inferred ${inferred.values.count(e => e.alloc.isDefined || e.realloc.isDefined)} " +
            s"allocator and ${inferred.values.count(_.free.isDefined)} free wrapper methods from call shapes"
      )
    inferred.values.toList
  end inferWrappers

  /** The capacity-binder conclusions (F4): methods whose body stores parameter j into a member of
    * parameter i, and `param j + param k` into a second member of the same parameter i. The
    * (buffer, capacity) constructor idiom - a context object that remembers where the buffer ends.
    * One scan over assignments builds the per-method store facts; a name carrying two disagreeing
    * bodies concludes nothing, exactly as the wrapper inference does.
    */
  private def inferBinders: List[MemApiVocab.MemApiEntry] =
    def memberStoreOf(lhs: Expression): Option[(String, String)] = lhs match
      case c: Call
          if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
          for
            base   <- c.argumentOption(1).collect { case i: Identifier => i }
            member <- OverlayFacts.memberOf(c)
          yield (base.name, member)
      case _ => None
    def paramOf(e: Expression): Option[String] = e.collect { case i: Identifier => i.name }
        .headOption

    val byMethod = mutable.LinkedHashMap.empty[Method, mutable.ListBuffer[(
      String,
      String,
      String,
      Option[String]
    )]]
    // (base param, member, stored param, offset param of the addition, if any)
    atom.call.name("<operator>.assignment").l.foreach { assignment =>
      val method = assignment.method
      if !method.isExternal then
        for
          lhs            <- assignment.argumentOption(1)
          (base, member) <- memberStoreOf(lhs)
          rhs            <- assignment.argumentOption(2)
        do
          rhs match
            case r: Call if r.name == "<operator>.addition" =>
                val operands = Seq(1, 2).flatMap(r.argumentOption)
                operands.collect { case i: Identifier => i.name } match
                  case Seq(a, b) =>
                      byMethod.getOrElseUpdate(method, mutable.ListBuffer.empty) +=
                          ((base, member, a, Some(b)))
                  case _ => ()
            case other =>
                paramOf(other).foreach(p =>
                    byMethod.getOrElseUpdate(method, mutable.ListBuffer.empty) +=
                        ((base, member, p, None))
                )
        end for
      end if
    }

    val concluded = mutable.LinkedHashMap.empty[String, MemApiVocab.MemApiEntry]
    val disagreed = mutable.HashSet.empty[String]
    byMethod.foreach { case (method, stores) =>
        val paramNames = method.parameter.l.map(_.name).toSet
        // a direct store of param j into (i, memberA), and a store of param j + param k into
        // (i, memberB != memberA), both through the same base parameter i
        val directs =
            stores.collect { case (b, m, p, None) if paramNames.contains(p) => ((b, p), m) }
        val offsets = stores.collect {
            case (b, m, p, Some(k)) if paramNames.contains(p) && paramNames.contains(k) =>
                ((b, p), (m, k))
        }
        val pairs = (for
          (keyD, memberA)      <- directs
          (keyO, (memberB, k)) <- offsets
          if keyD == keyO && memberA != memberB
        yield (keyD._1, keyD._2, k)).distinct
        val paramIndex = method.parameter.l.map(p => p.name -> p.index).toMap
        val resolved: List[(Int, Int)] = pairs.flatMap { case (_, j, k) =>
            for
              dstIdx <- paramIndex.get(j)
              lenIdx <- paramIndex.get(k)
            yield (dstIdx, lenIdx)
        }.toList.distinct
        resolved match
          case (j, k) :: Nil =>
              val entry = MemApiVocab.MemApiEntry(method.name, dst = Some(j), len = Some(k))
              concluded.updateWith(method.name) {
                  case Some(existing) =>
                      // a name shared by disagreeing bodies carries nothing, as for the wrappers
                      if existing != entry then disagreed += method.name
                      Some(existing)
                  case None => Some(entry)
              }
          case _ => ()
    }
    concluded.filterNot { case (name, _) => disagreed.contains(name) }.values.toList
  end inferBinders

  /** The wrapper conclusion for one candidate method, or none. Allocators need every value-return
    * to flow from an allocation (a realloc wrapper's return flows from its realloc - a producer of
    * a fresh pointer); free wrappers allow nothing in the body beside the frees they wrap.
    */
  private def concludeWrapper(
    method: Method,
    allocIds: Set[Long],
    reallocIds: Set[Long],
    freeIds: Set[Long],
    readIds: Set[Long],
    lenArgIds: Set[Long]
  ): Option[MemApiVocab.MemApiEntry] =
    val producerIds = allocIds ++ reallocIds
    val bodyCalls   = method.call.l
    val bodyProdIds = bodyCalls.map(_.id).toSet.intersect(producerIds)
    val bodyFreeIds = bodyCalls.map(_.id).toSet.intersect(freeIds)
    val bodyReadIds = bodyCalls.map(_.id).toSet.intersect(readIds)

    if bodyProdIds.nonEmpty && bodyFreeIds.isEmpty && bodyReadIds.isEmpty
      && bodyCalls.filterNot(_.name.startsWith("<operator>")).forall(c =>
          producerIds.contains(c.id)
      )
    then allocatorEntry(method, allocIds, reallocIds, lenArgIds)
    else if bodyFreeIds.nonEmpty && bodyProdIds.isEmpty && bodyReadIds.isEmpty
      && bodyCalls.filterNot(_.name.startsWith("<operator>")).forall(c => freeIds.contains(c.id))
      && returnsNoValue(method)
    then Some(MemApiVocab.MemApiEntry(method.name, free = Some(FamilyHeap)))
    else None
  end concludeWrapper

  private def allocatorEntry(
    method: Method,
    allocIds: Set[Long],
    reallocIds: Set[Long],
    lenArgIds: Set[Long]
  ): Option[MemApiVocab.MemApiEntry] =
    val producerIds = allocIds ++ reallocIds
    // F2 (part 6): an allocator hands out a POINTER. A method whose declared return is an
    // int can allocate into an out-parameter and return an error code (ff_get_extradata) -
    // inferring an allocator role for it marked every caller's error variable as a live
    // allocation, and the leak rule reported it at each exit
    if !OverlayFacts.isPointer(Option(method.methodReturn.typeFullName).getOrElse("")) then
      return None
    val valueReturns = method.ast.collectAll[Return].l
        .flatMap(_.astChildren.collect { case e: Expression => e })
    // at least one return must flow from a REAL allocation (the anchor - a literal anchors
    // nothing, or every `return 0` wrapper beside an allocation would qualify), and every
    // return must flow or be an external constant (the NULL-on-failure fallback)
    val anchored = valueReturns.exists {
        case _: Literal => false
        case e          => flowsFromAllocation(e, producerIds)
    }
    val allFlowish = valueReturns.forall(flowsOrNullConstant(_, producerIds))
    if !anchored || !allFlowish then None
    else
      // the size role is the parameter feeding the wrapped allocation's size argument, when
      // exactly one is - a size of `n * 4` still counts through its parameter
      val sizeParams = (for
        call <- method.call.l if producerIds.contains(call.id)
        arg  <- call.argument.l if lenArgIds.contains(arg.id)
        leaves = arg.ast.l.collect { case i: Identifier => i }.toList ++ List(arg)
            .collect { case i: Identifier => i }
        leaf  <- leaves
        param <- method.parameter.name(leaf.name).headOption
      yield param.index).distinct
      val len = sizeParams match
        case List(idx) => Some(idx)
        case _         => None
      // the family follows the body: a wrapper over plain allocations is an allocator, one over
      // reallocs only is a realloc wrapper, a mixed one is honestly both
      Some(
        MemApiVocab.MemApiEntry(
          method.name,
          len = len,
          alloc = Option.when(method.call.l.exists(c => allocIds.contains(c.id)))(FamilyHeap),
          realloc = Option.when(method.call.l.exists(c => reallocIds.contains(c.id)))(FamilyHeap)
        )
      )
    end if
  end allocatorEntry

  /** Does this expression's value come from an allocation: the allocation call itself, a cast of
    * one, a conditional whose branches all do, a literal (the NULL-on-failure fallback), or an
    * identifier at least one of whose direct definitions is an allocation call.
    */
  private def flowsFromAllocation(e: Expression, allocIds: Set[Long]): Boolean =
      e match
        case _: Literal    => true
        case i: Identifier =>
            // either the identifier IS the allocation's reach (a direct def) or it was assigned
            // one: `void *p = malloc(n)` defines p with the assignment, and the allocation sits
            // on that assignment's right side - the same walk allocExtentOf uses
            i._reachingDefIn.collectAll[StoredNode].l.exists {
                case c: Call => allocIds.contains(c.id)
                case _       => false
            } ||
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
                    case c: Call => allocIds.contains(c.id)
                    case _       => false
                }
        case c: Call =>
            c.name match
              case n if n.startsWith("<operator>.cast") =>
                  // the operand may sit at either argument index depending on how the frontend
                  // laid out the cast; a type operand, when present, is not a value and fails
                  // the recursion harmlessly
                  c.argument.l.collect { case x: Expression => x }
                      .exists(flowsFromAllocation(_, allocIds))
              case "<operator>.conditional" =>
                  // `cond ? p : NULL` flows; `cond ? 0 : NULL` is two constants and anchors
                  // nothing, the same reason a bare literal return does not anchor
                  val branches = Seq(2, 3).flatMap(c.argumentOption)
                  branches.nonEmpty && branches.forall(flowsOrNullConstant(_, allocIds)) &&
                  branches.exists {
                      case _: Literal => false
                      case b          => flowsFromAllocation(b, allocIds)
                  }
              case _ => allocIds.contains(c.id)
        case _ => false

  /** The fallback arm: a def-less identifier that is neither a local nor a parameter of the method
    * is an external constant (`NULL` arrives as an identifier, macro-expanded, with the enclosing
    * method as its only reaching definition), not a value in flight. It can ACCOMPANY an allocation
    * flow; it cannot be one - the anchor stays with flowsFromAllocation.
    */
  private def flowsOrNullConstant(e: Expression, allocIds: Set[Long]): Boolean =
      flowsFromAllocation(e, allocIds) ||
          (e match
            case i: Identifier =>
                i._reachingDefIn.collectAll[StoredNode].l.forall(_.isInstanceOf[Method]) &&
                i.method.local.name(i.name).l.isEmpty &&
                i.method.parameter.name(i.name).l.isEmpty
            case _ => false
          )

  private def returnsNoValue(method: Method): Boolean =
      method.ast.collectAll[Return].l
          .flatMap(_.astChildren)
          .isEmpty

  /** The one-word summary of an entry's alloc/realloc/free role, for the disagreement report. */
  private def roleOf(entry: MemApiVocab.MemApiEntry): Option[String] =
      if entry.alloc.isDefined then Some("allocator")
      else if entry.realloc.isDefined then Some("realloc")
      else if entry.free.isDefined then Some("free")
      else None
end MemoryApiPass

object MemoryApiPass:

  /** The umbrella tag every fine-grained tag is emitted alongside. */
  final val UmbrellaTag = "memory-safety"

  final val TagDst   = "mem-dst"
  final val TagSrc   = "mem-src"
  final val TagLen   = "mem-len"
  final val TagAlloc = "mem-alloc"
  final val TagFree  = "mem-free"

  /** The third family (D1): the call releases its input pointer and returns a fresh allocation. It
    * is deliberately NOT emitted as both `mem-alloc` and `mem-free` - every consumer reads those as
    * disjoint sets, and a realloc is honestly neither.
    */
  final val TagRealloc       = "mem-realloc"
  final val TagUntrustedRead = "untrusted-read"

  /** E3: the call's result may be NULL (allocation failure, or the strchr family's no-match NULL).
    * On the call node, for MS-NULL-001.
    */
  final val TagNullableReturn = "nullable-return"

  /** The family inferred wrappers emit; the inventory's own families are unchanged. */
  private final val FamilyHeap = "heap"

  /** Bounds on the wrapper-inference fixpoint: each round lets a wrapper of a wrapper chain off the
    * round before it. Three is already deeper than any wrapper layer seen in practice.
    */
  private final val MaxInferenceRounds = 3

  /** C/C++ graphs only: the inventory's names are bare libc calls, which must not tag same-named
    * functions in managed-language graphs.
    */
  def appliesTo(atom: Cpg): Boolean =
      atom.metaData.language.headOption.exists(Set(Languages.C, Languages.NEWC))
end MemoryApiPass
