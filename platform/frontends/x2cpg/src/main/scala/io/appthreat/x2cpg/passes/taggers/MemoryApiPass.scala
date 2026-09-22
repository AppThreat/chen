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
  * `mem-alloc` result - through casts and NULL fallbacks, with no free and no untrusted read in the
  * body - is itself an allocator, and a body whose only external calls are inventoried `mem-free`
  * calls is a free wrapper. The inferred roles are emitted as ORDINARY `mem-alloc` / `mem-free` /
  * `mem-len` tags at the wrapper's call sites, so ExtentPass and the rules need no second
  * vocabulary. Inference is conservative: a body that returns anything not derived from the
  * allocation, or that calls anything beside the frees it wraps, is left untagged; a conclusion
  * that disagrees with the declared inventory is reported and the declared entry wins. The summary
  * line states what was concluded.
  *
  * Tags emitted (each alongside the `memory-safety` umbrella, the way [[PiiTagsPass]] emits
  * `pii-email` alongside `sensitive-data`):
  *   - `mem-dst` / `mem-src` / `mem-len`, valued with the API name, on the ARGUMENT playing that
  *     role;
  *   - `mem-alloc` / `mem-free`, valued with the family (`heap`, `new`, `mmap`, `file`, `socket`),
  *     on the call;
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
    val inferred = inferWrappers(inventory, matchesByTag, record)

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

    entry.alloc.foreach(family => record(TagAlloc, family, call))
    entry.free.foreach(family => record(TagFree, family, call))

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
    // the alloc/free/read call nodes the inventory produced, grown by each round's conclusions
    // so a wrapper of a wrapper chains
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
      val allocIds = callsOf(MemoryApiPass.TagAlloc).map(_.id).toSet
      val freeIds  = callsOf(MemoryApiPass.TagFree).map(_.id).toSet
      val readIds  = callsOf(MemoryApiPass.TagUntrustedRead).map(_.id).toSet

      val candidates = (callsOf(MemoryApiPass.TagAlloc) ++ callsOf(MemoryApiPass.TagFree))
          .map(_.method)
          .filterNot(_.isExternal)
          .toList
          .distinct

      candidates.foreach { method =>
          if !inferred.contains(method.name) then
            concludeWrapper(method, allocIds, freeIds, readIds, lenArgIds).foreach { entry =>
                declared.get(method.name) match
                  case Some(d) if roleOf(d) != roleOf(entry) =>
                      // inference must say what it concluded, and must not quietly prefer
                      // either source when it disagrees with the declaration
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
                      atom.call.name(method.name).foreach { site =>
                        tagCall(entry, site, record)
                        entry.alloc.foreach(_ => callsOf(MemoryApiPass.TagAlloc) += site)
                        entry.free.foreach(_ => callsOf(MemoryApiPass.TagFree) += site)
                      }
            }
      }
      round += 1
    end while

    if inferred.nonEmpty then
      println(
        s"MemoryApiPass: inferred ${inferred.values.count(_.alloc.isDefined)} allocator and " +
            s"${inferred.values.count(_.free.isDefined)} free wrapper methods from call shapes"
      )
    inferred.values.toList
  end inferWrappers

  /** The wrapper conclusion for one candidate method, or none. Allocators need every value-return
    * to flow from an allocation; free wrappers allow nothing in the body beside the frees they
    * wrap.
    */
  private def concludeWrapper(
    method: Method,
    allocIds: Set[Long],
    freeIds: Set[Long],
    readIds: Set[Long],
    lenArgIds: Set[Long]
  ): Option[MemApiVocab.MemApiEntry] =
    val bodyCalls    = method.call.l
    val bodyAllocIds = bodyCalls.map(_.id).toSet.intersect(allocIds)
    val bodyFreeIds  = bodyCalls.map(_.id).toSet.intersect(freeIds)
    val bodyReadIds  = bodyCalls.map(_.id).toSet.intersect(readIds)

    if bodyAllocIds.nonEmpty && bodyFreeIds.isEmpty && bodyReadIds.isEmpty
      && bodyCalls.filterNot(_.name.startsWith("<operator>")).forall(c => allocIds.contains(c.id))
    then
      allocatorEntry(method, allocIds, lenArgIds)
    else if bodyFreeIds.nonEmpty && bodyAllocIds.isEmpty && bodyReadIds.isEmpty
      && bodyCalls.filterNot(_.name.startsWith("<operator>")).forall(c => freeIds.contains(c.id))
      && returnsNoValue(method)
    then Some(MemApiVocab.MemApiEntry(method.name, free = Some(FamilyHeap)))
    else None
  end concludeWrapper

  private def allocatorEntry(
    method: Method,
    allocIds: Set[Long],
    lenArgIds: Set[Long]
  ): Option[MemApiVocab.MemApiEntry] =
    val valueReturns = method.ast.collectAll[Return].l
        .flatMap(_.astChildren.collect { case e: Expression => e })
    // at least one return must flow from a REAL allocation (the anchor - a literal anchors
    // nothing, or every `return 0` wrapper beside an allocation would qualify), and every
    // return must flow or be an external constant (the NULL-on-failure fallback)
    val anchored = valueReturns.exists {
        case _: Literal => false
        case e          => flowsFromAllocation(e, allocIds)
    }
    val allFlowish = valueReturns.forall(flowsOrNullConstant(_, allocIds))
    if !anchored || !allFlowish then None
    else
      // the size role is the parameter feeding the wrapped allocation's size argument, when
      // exactly one is - a size of `n * 4` still counts through its parameter
      val sizeParams = (for
        call <- method.call.l if allocIds.contains(call.id)
        arg  <- call.argument.l if lenArgIds.contains(arg.id)
        leaves = arg.ast.l.collect { case i: Identifier => i }.toList ++ List(arg)
            .collect { case i: Identifier => i }
        leaf  <- leaves
        param <- method.parameter.name(leaf.name).headOption
      yield param.index).distinct
      val len = sizeParams match
        case List(idx) => Some(idx)
        case _         => None
      Some(MemApiVocab.MemApiEntry(method.name, len = len, alloc = Some(FamilyHeap)))
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
                  val branches = Seq(2, 3).flatMap(c.argumentOption)
                  branches.nonEmpty && branches.forall(flowsOrNullConstant(_, allocIds))
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

  /** The one-word summary of an entry's alloc/free role, for the disagreement report. */
  private def roleOf(entry: MemApiVocab.MemApiEntry): Option[String] =
      if entry.alloc.isDefined then Some("allocator")
      else if entry.free.isDefined then Some("free")
      else None
end MemoryApiPass

object MemoryApiPass:

  /** The umbrella tag every fine-grained tag is emitted alongside. */
  final val UmbrellaTag = "memory-safety"

  final val TagDst           = "mem-dst"
  final val TagSrc           = "mem-src"
  final val TagLen           = "mem-len"
  final val TagAlloc         = "mem-alloc"
  final val TagFree          = "mem-free"
  final val TagUntrustedRead = "untrusted-read"

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
