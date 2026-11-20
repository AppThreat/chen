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
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Languages, PropertyNames}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Tags memory-API call sites and their arguments with the roles from [[MemApiVocab]]'s inventory.
  * First pass of the memory-safety overlay: **tags only, no findings, no detectors** - a bounds
  * rule later writes `tag.name("mem-len").argument` instead of hard-coding `argument(3)`, and gains
  * `snprintf`'s different arity and `read`'s different destination index from the resource file
  * alone.
  *
  * Beside the declared inventory, the pass tags the call sites of every function
  * [[MemorySemanticsPass]] summarised - wrappers found from their bodies, allocators declared by
  * their GCC attributes, nullable returns, inherited dst/src/len roles, capacity binders - with the
  * SAME tags, so ExtentPass and the rules need no second vocabulary. A declared entry always wins
  * over a conclusion.
  *
  * Beside both sits the DECLARED LIBRARY PROFILES: a translation unit whose primary source file
  * includes one of a profile's headers (the `includes` tags the C front ends write on that file's
  * FILE node) gets the profile's entries on its calls. A profile entry states what a header
  * declares for code whose body is outside the analysed tree, so it yields to everything the tree
  * itself says: an inventory entry (built-in or external config) and any body define a name, and a
  * call with no such definition takes the profile's entry over the name-level conclusions, which at
  * best guess from the spelling. `profilesMode` selects how a unit chooses: `auto` (the default) by
  * the includes it carries, `none` not at all, or a comma list of profile names that then applies
  * to every file. `reportProfiles` prints which profiles the run followed, for a caller that
  * reports the overlay's findings.
  *
  * Tags emitted (each alongside the `memory-safety` umbrella, the way [[PiiTagsPass]] emits
  * `pii-email` alongside `sensitive-data`):
  *   - `mem-dst` / `mem-src` / `mem-len`, valued with the API name, on the ARGUMENT playing that
  *     role; a count-by-size allocator's element count carries `mem-len` too, because the size that
  *     can overflow is the product;
  *   - `mem-alloc` / `mem-free` / `mem-realloc`, valued with the family (`heap`, `new`, `mmap`,
  *     `file`, `fd`), on the call; a release that accepts several families carries one `mem-free`
  *     per family;
  *   - `mem-region`, valued with the encoded region role (`alloc:<i>` / `alloc:ctx:<global>` for an
  *     allocation owned by the argument at `i` or by the named global, `create` / `create:<i>` for
  *     a region the call makes through its result or through the out-pointer at `i`, `destroy:<i>`
  *     / `reset:<i>` for the region the call empties or tears down), on the call - the region roles
  *     a profile declares and the region-alloc conclusions, consumed by [[AllocationStatePass]];
  *   - `mem-release` / `mem-acquire`, valued with the argument index of the object whose reference
  *     count the call drops or takes, on the call - a profile entry's declared `release`/`acquire`
  *     role, an inferred release conclusion, or the argument of a `grow`/`increments` fact (the
  *     acquire), consumed by [[AllocationStatePass]]'s owned-reference count;
  *   - `untrusted-read`, valued with the API name, on the call and on the buffer it fills;
  *   - `mem-object-size` on the destination size a FORTIFY wrapper receives.
  *
  * The API name is the one a spelling stands for: `__builtin___memcpy_chk` tags are valued
  * `memcpy`, so every rule reads a FORTIFY wrapper or a compiler builtin as the API itself.
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
  * languages join when they carry their own inventory.
  */
class MemoryApiPass(
  atom: Cpg,
  externalConfig: Option[String] = None,
  profilesMode: String = MemoryApiPass.ProfilesAuto,
  reportProfiles: Boolean = false
) extends CpgPass(atom):

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
        inventory.get(call.name).filterNot(expandsSameApiMacro(call, _, inventory)).foreach {
            entry => tagCall(entry, call, record)
        }
    }

    // a benchmark's input functions, by prefix: their results are the program's input
    val prefixes = MemApiVocab.untrustedPrefixes
    if prefixes.nonEmpty then
      atom.call.filterNot(c => inventory.contains(c.name)).foreach { c =>
          if prefixes.exists(c.name.startsWith) then record(TagUntrustedRead, c.name, c)
      }

    // What chen concluded on its own (MemorySemanticsPass): wrappers, attribute-declared
    // allocators, nullable returns, inherited roles, capacity binders. Tagged exactly like the
    // inventory's entries so no consumer needs a second vocabulary; a declared entry wins.
    // A call the graph RESOLVES to a method is tagged by that method's own conclusion (an
    // overload or an instantiated template the front end selected, judged by its own body); a
    // call no CALLEE edge resolves falls back to the name, which only same-named methods'
    // agreement earned. A selected profile's entry stands between the two: it states what a
    // header declares for a name no body in the tree defines, which is more than a name can say.
    val inferred = MemorySemanticsPass.entriesFor(atom, inventory)
    val own      = MemorySemanticsPass.ownEntriesFor(atom)
    val selected = profileSelection
    // names a body in the analysed tree defines: whatever that body says (or fails to say) is the
    // name's truth, so no profile entry reaches it
    val namesWithBodies =
        if selected.isEmpty then Set.empty[String]
        else
          atom.method.filterNot(m => m.isExternal || m.name == "<global>")
              .filter(_.block.astChildren.nonEmpty).name.l.toSet
    atom.call.filterNot(c => inventory.contains(c.name)).foreach { site =>
        resolvedCalleeOf(site).flatMap(m => own.get(m.id))
            .orElse(selectedEntryFor(site, selected, namesWithBodies, inventory))
            .orElse(inferred.get(site.name))
            .foreach { entry =>
                tagCall(entry.copy(name = site.name), site, record)
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
            // a result range is a value fact, not a memory role: a byte reader is no memory API
            if tag != TagReturnRange then umbrella ++= nodes
        }
    }
    umbrella.iterator.newTagNode(UmbrellaTag).store()(using dstGraph)
    if reportProfiles then println(profilesLine(selected))
  end run

  /** The profiles each file's calls follow: `auto` selects, per file that carries the include
    * record, the profiles whose header lists one of its includes; a comma list selects exactly
    * those profiles for every file with calls; `none` selects nothing. A forced name no profile
    * carries is reported on stderr, so a typo'd list cannot silently analyse like `none`.
    */
  private def profileSelection: Map[String, Map[String, MemApiVocab.MemApiProfile]] =
    val mode = profilesMode.trim
    if mode == ProfilesNone then Map.empty
    else if mode == ProfilesAuto then
      includesByFile
          .map((file, includes) => file -> MemApiVocab.selectProfiles(externalConfig, includes))
          .filterNot(_._2.isEmpty)
    else
      // profile names compare without case: `GLIB` is the glib profile
      val known  = MemApiVocab.profiles(externalConfig).map((name, p) => name.toLowerCase -> p)
      val wanted = mode.split(",").map(_.trim.toLowerCase).filter(_.nonEmpty).distinct.toSeq
      val chosen = wanted.sorted.flatMap(name => known.get(name).map(p => p.name -> p))
      (wanted.toSet -- known.keySet).toSeq.sorted.foreach { name =>
          System.err.println(s"warn: no memory-api profile named `$name`")
      }
      if chosen.isEmpty then Map.empty
      else
        // the forced list overrides what a unit includes: each file follows the forced
        // profiles whose entries its calls name
        val names = chosen.map((name, p) => name -> p.entries.map(_.name).toSet)
        atom.call.l.groupBy(c => fileOf(c)).toSeq.filter(_._1.nonEmpty).flatMap { (file, calls) =>
          val called = calls.map(_.name).toSet
          val used = chosen.filter((name, _) =>
              names.exists((n, es) => n == name && es.exists(called.contains))
          )
          Option.when(used.nonEmpty)(file -> used.toMap)
        }.toMap
    end if
  end profileSelection

  /** The `includes` tags on the graph's FILE nodes: for each translation unit's primary source
    * file, the basenames of the headers it includes (written by the C front ends' include record).
    * Same-named FILE nodes pool their tags, so a graph that grew a duplicate keeps every include.
    */
  private def includesByFile: Map[String, Set[String]] =
      atom.file.l
          .flatMap(file =>
              file.tag.nameExact(TagIncludes).value.l.map(file.name -> _)
          )
          .groupMap(_._1)(_._2)
          .view.mapValues(_.toSet).toMap

  /** The entry a selected profile declares for a call, when neither the inventory nor a body in the
    * analysed tree already owns the name. Two selected profiles declaring the same name is the
    * first profile's, in the profiles' name order, so the choice never depends on map iteration.
    */
  private def selectedEntryFor(
    call: Call,
    selected: Map[String, Map[String, MemApiVocab.MemApiProfile]],
    namesWithBodies: Set[String],
    inventory: Map[String, MemApiVocab.MemApiEntry]
  ): Option[MemApiVocab.MemApiEntry] =
    val declared = Option.when(selected.nonEmpty && !namesWithBodies.contains(call.name))(
      selected.get(fileOf(call)).map(_.values.toList.sortBy(_.name).flatMap(_.entries))
    ).flatten
    declared.flatMap(_.find(_.name == call.name))
        .filterNot(entry => expandsSameApiMacro(call, entry, inventory))

  /** The file a call sits in, the name its FILE node carries: through the containing method's
    * filename, which is what the file-creation overlay keys the FILE nodes by.
    */
  private def fileOf(call: Call): String =
      call.method.filename

  /** What the run says about the profiles it followed, printed beside the function-summary counts
    * the semantics pass reports: each selected profile with the number of files that selected it,
    * or why none did.
    */
  private def profilesLine(selected: Map[String, Map[String, MemApiVocab.MemApiProfile]]): String =
    val counts = selected.values.flatMap(_.keys).toSeq.groupBy(identity)
        .view.mapValues(_.size).toSeq.sortBy(_._1)
    val listed = counts.map((name, files) =>
        s"$name ($files ${if files == 1 then "file" else "files"})"
    ).mkString(", ")
    val mode = profilesMode.trim
    // a forced list names each forced profile the vocabulary knows, with the files whose
    // calls it declared, none included
    val forced =
        if mode == ProfilesAuto || mode == ProfilesNone then Nil
        else
          val known = MemApiVocab.profiles(externalConfig).keySet.map(n => n.toLowerCase -> n).toMap
          mode.split(",").map(_.trim.toLowerCase).filter(_.nonEmpty).distinct.flatMap(known.get)
              .sorted.toList
    val forcedListed = forced.map { name =>
      val files = counts.find(_._1 == name).map(_._2).getOrElse(0)
      s"$name ($files ${if files == 1 then "file" else "files"})"
    }.mkString(", ")
    val followed =
        if mode == ProfilesNone then ProfilesNone
        else if forced.nonEmpty then forcedListed
        else if listed.isEmpty then s"$ProfilesNone selected"
        else listed
    s"$PassName: memory-api profiles: $followed"
  end profilesLine

  /** The one method a call's CALLEE edges name - the linker's answer, not a name lookup, so an
    * overload or an instance the front end resolved speaks for its own body.
    */
  private def resolvedCalleeOf(call: Call): Option[Method] =
    import io.shiftleft.semanticcpg.language.NoResolve
    // exactly one: a call the linker binds to several methods (same-named statics, an
    // unresolved overload set) has no single body to speak for it
    call.callee(using NoResolve).collectAll[Method].dedup.l match
      case List(only) => Some(only)
      case _          => None

  /** Whether `call` is what a macro spelling the same API expands to - `alloca(n)` defined as
    * `__builtin_alloca(n)`, `memcpy` defined as `__builtin___memcpy_chk` under `_FORTIFY_SOURCE`.
    * The macro's call carries the roles, on the arguments as written; tagging both would report
    * every finding twice.
    */
  private def expandsSameApiMacro(
    call: Call,
    entry: MemApiVocab.MemApiEntry,
    inventory: Map[String, MemApiVocab.MemApiEntry]
  ): Boolean =
      call.dispatchType != DispatchTypes.INLINED &&
          call.inAst.collectAll[Call].exists(m =>
              m.dispatchType == DispatchTypes.INLINED &&
                  inventory.get(m.name).exists(_.apiName == entry.apiName)
          )

  private def tagCall(
    entry: MemApiVocab.MemApiEntry,
    call: Call,
    record: (String, String, StoredNode) => Unit
  ): Unit =
    def argAt(index: Int): Option[StoredNode] =
        call.argumentOption(index).collect { case s: StoredNode => s }

    val api = entry.apiName
    entry.dst.foreach(i => argAt(i).foreach(n => record(TagDst, api, n)))
    // the callee clamps one of its parameters to this literal: the effective value at this
    // call's argument is the smaller of the two (`clamp` is "<param index>:<literal>")
    entry.clamp.foreach { clamp =>
        clamp.split(":", 2) match
          case Array(i, k) =>
              for
                idx <- i.toIntOption
                lit <- Some(k).filter(_.forall(_.isDigit))
                n   <- argAt(idx)
              do record(TagClamp, lit, n)
          case _ => ()
    }
    entry.src.foreach(i => argAt(i).foreach(n => record(TagSrc, api, n)))
    entry.len.foreach(i => argAt(i).foreach(n => record(TagLen, api, n)))
    // A count-by-size allocator bounds the operation by the PRODUCT, so the element count
    // joins the size as a length role - the attacker-influenced factor carries mem-len too and
    // the overflow question can be asked about it (ValueOrigin gives it an origin from here).
    entry.count.foreach(i => argAt(i).foreach(n => record(TagLen, api, n)))
    entry.objectSize.foreach(i => argAt(i).foreach(n => record(TagObjectSize, api, n)))

    entry.alloc.foreach(family => record(TagAlloc, family, call))
    entry.freeFamilies.foreach(family => record(TagFree, family, call))
    entry.realloc.foreach(family => record(TagRealloc, family, call))

    // the region role: which argument owns what the call hands out (or empties), encoded so
    // the allocation state can find the region's handle at the call site
    entry.region.foreach { r =>
      val encoded = r match
        case MemApiVocab.MemRegion("allocate", Some(i), _)    => Some(s"alloc:$i")
        case MemApiVocab.MemRegion("allocate", None, Some(c)) => Some(s"alloc:ctx:$c")
        case MemApiVocab.MemRegion("create", arg, _) =>
            Some(arg.map(i => s"create:$i").getOrElse("create"))
        case MemApiVocab.MemRegion("destroy", Some(i), _) => Some(s"destroy:$i")
        case MemApiVocab.MemRegion("reset", Some(i), _)   => Some(s"reset:$i")
        case _                                            => None
      encoded.foreach(v => record(TagRegion, v, call))
    }

    // the reference roles: which argument's reference count the call drops (or takes), encoded
    // as the argument index so the allocation state finds the object at the call site. The
    // grow fact (a body's counter increment) IS the acquire
    entry.release.foreach(i => record(TagRelease, i.toString, call))
    // the argument whose resource the result takes over
    entry.retains.foreach(i => record(TagRetains, i.toString, call))
    // the pointer-to-pointer argument whose block the call moves out to its result
    entry.steal.foreach(i => record(TagSteal, i.toString, call))
    // a cleanup function: frees what the address it is handed points to
    if entry.cleanup then record(TagCleanup, "1", call)
    entry.acquire.orElse(entry.increments.map(_._1))
        .foreach(i => record(TagAcquire, i.toString, call))

    // the call reads through what it is handed and keeps none of it: a borrow, not an escape
    if entry.nonRetaining then
      record(TagNonRetaining, api, call)

    // the positions the call READS THROUGH, from this index on: the printf family's variadic
    // tail. The tag sits on the ARGUMENT (as dst/src do), so the state pass and the null rule
    // read the same positions the escape model does
    entry.readsFrom.foreach { from =>
        call.argument.l
            .filter(a => a.argumentIndex >= from)
            .collect { case s: StoredNode => s }
            .foreach(n => record(TagReadsArg, api, n))
    }

    // The entry DECLARES that its result may be NULL - pointer-returning allocators, the
    // strchr family. The fd-returning allocators (open, socket) deliberately do not: an int
    // fd's failure mode is -1, and conflating the two would turn checked fds into null-deref
    // findings.
    if entry.nullableReturn then
      record(TagNullableReturn, api, call)

    entry.untrustedRead.foreach { i =>
      record(TagUntrustedRead, api, call)
      argAt(i).foreach(n => record(TagUntrustedRead, api, n))
    }
    if entry.untrustedCall then
      record(TagUntrustedRead, api, call)

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

  /** Profiles mode: each translation unit selects the profiles whose headers its primary source
    * file includes.
    */
  final val ProfilesAuto = "auto"

  /** Profiles mode: no profile is selected, whatever a unit includes. */
  final val ProfilesNone = "none"

  /** The tag the C front ends leave on the FILE node of each translation unit's primary source
    * file, one per header it includes, valued with the header's basename. Read here to decide which
    * library's declared profile governs a file's calls.
    */
  private final val TagIncludes = "includes"

  /** The call drops one reference of the object its entry names: the declared `release` role, or
    * the body's zero-gated free conclusion. Valued with the object's argument index.
    */
  final val TagRelease = "mem-release"

  /** The call takes one reference of the object its entry names: the declared `acquire` role, or
    * the argument of a `grow`/`increments` fact. Valued with the object's argument index.
    */
  final val TagAcquire = "mem-acquire"

  /** The call's result takes over the resource of the argument at the index (`fdopen`'s
    * descriptor): from the call on, that argument is the result's to release.
    */
  final val TagRetains = "mem-retains"

  /** The call empties the slot at the index and hands its block to the result (`g_steal_pointer`'s
    * declared role, the same move the body-inferred `steals-param` effect makes).
    */
  final val TagSteal = "mem-steal"

  /** The call frees the block its first argument points to (`g_autoptr_cleanup_generic_gfree(&p)`),
    * a declared `cleanup` role: the release a scope-cleanup call of that function makes.
    */
  final val TagCleanup = "mem-cleanup"

  private final val PassName = "MemoryApiPass"

  final val TagDst = "mem-dst"
  final val TagSrc = "mem-src"
  final val TagLen = "mem-len"

  /** The argument a FORTIFY wrapper (`__memcpy_chk`) receives the destination's size in, as the
    * compiler worked it out: capacity evidence for [[ExtentPass]].
    */
  final val TagObjectSize = "mem-object-size"

  /** The literal the callee clamps its length argument to, valued with the literal. */
  final val TagClamp = "mem-clamp"
  final val TagAlloc = "mem-alloc"
  final val TagFree  = "mem-free"

  /** The third family: the call releases its input pointer and returns a fresh allocation. It is
    * deliberately NOT emitted as both `mem-alloc` and `mem-free` - every consumer reads those as
    * disjoint sets, and a realloc is honestly neither.
    */
  final val TagRealloc = "mem-realloc"

  /** The call's role in its library's pool or context scheme, valued with the encoded role: the
    * region an allocation belongs to (its argument at the index, or the named global context), the
    * region a create hands out through its result or an out-pointer, and the region a reset empties
    * or a destroy tears down. See [[MemApiVocab.MemRegion]] for the declared shape and
    * [[MemorySemanticsPass]] for the `region-alloc` conclusions.
    */
  final val TagRegion        = "mem-region"
  final val TagUntrustedRead = "untrusted-read"

  /** The call's result may be NULL (allocation failure, or the strchr family's no-match NULL). On
    * the call node, for MS-NULL-001.
    */
  final val TagNullableReturn = "nullable-return"

  /** The closed range the call's result lies in by construction, valued `lo:hi` (`avio_r8` is
    * `0:255`, `get_bits(gb, 4)` `0:15`): the vocabulary's `returnRange`/`returnBits`. On the call
    * node, for the index rules' value ranges ([[IndexRange]]).
    */
  final val TagReturnRange = "mem-return-range"

  /** The call reads through its arguments and retains none: the printf family. A hand-off to it is
    * a borrow, not an escape, so the allocation state's ownership question stands down.
    */
  final val TagNonRetaining = "mem-nonretaining"
  final val TagReadsArg     = "mem-reads-arg"

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
