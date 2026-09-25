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
  * Beside the declared inventory, the pass tags the call sites of every function
  * [[MemorySemanticsPass]] summarised - wrappers found from their bodies, allocators declared by
  * their GCC attributes, nullable returns, inherited dst/src/len roles, capacity binders - with the
  * SAME tags, so ExtentPass and the rules need no second vocabulary. A declared entry always wins
  * over a conclusion.
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

    // What chen concluded on its own (MemorySemanticsPass): wrappers, attribute-declared
    // allocators, nullable returns, inherited roles, capacity binders. Tagged exactly like the
    // inventory's entries so no consumer needs a second vocabulary; a declared entry wins.
    val inferred = MemorySemanticsPass.entriesFor(atom, inventory)
    inferred.values.foreach { entry =>
        atom.call.nameExact(entry.name).foreach(site => tagCall(entry, site, record))
    }

    // The umbrella is emitted once per node across all categories, not once per (tag, value)
    // group: a `memcpy` destination carries `mem-dst` and the call carries `mem-alloc`-style
    // tags from several groups, and re-emitting `memory-safety` per group would attach the same
    // tag to the same node repeatedly.
    val umbrella = mutable.LinkedHashSet.empty[StoredNode]
    matchesByTag.foreach { case (tag, tagged) =>
        tagged.groupMap(_._2)(_._1).foreach { case (value, nodes) =>
            nodes.iterator.newTagNodePair(tag, value).store()(using dstGraph)
            // a result range is a value fact, not a memory role: a byte reader is no memory API
            if tag != TagReturnRange then umbrella ++= nodes
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

    entry.returnRange.foreach { case (lo, hi) => record(TagReturnRange, s"$lo:$hi", call) }
    entry.returnBits.foreach { i =>
        call.argumentOption(i).collect { case l: Literal => l.code.trim }.flatMap(_.toIntOption)
            .filter(n => n > 0 && n <= 64)
            .foreach(n => record(TagReturnRange, s"0:${(BigInt(1) << n) - 1}", call))
    }
  end tagCall

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

  /** The closed range the call's result lies in by construction, valued `lo:hi` (`avio_r8` is
    * `0:255`, `get_bits(gb, 4)` `0:15`): the vocabulary's `returnRange`/`returnBits`. On the call
    * node, for the index rules' value ranges ([[IndexRange]]).
    */
  final val TagReturnRange = "mem-return-range"

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
