package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, StoredNode}
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

  /** C/C++ graphs only: the inventory's names are bare libc calls, which must not tag same-named
    * functions in managed-language graphs.
    */
  def appliesTo(atom: Cpg): Boolean =
      atom.metaData.language.headOption.exists(Set(Languages.C, Languages.NEWC))
