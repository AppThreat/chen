package io.appthreat.x2cpg.passes.taggers

import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** What chen knows about memory on its own - the facts a hand-written, project-specific memory-apis
  * config would otherwise have to supply. Runs before [[MemoryApiPass]], which tags call sites from
  * `declared inventory ++ these summaries` (a declared entry always wins).
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
  *     frees its first parameter (`free(*pp)` with `*pp = NULL` included - the freep shape) on a
  *     path no condition but the parameter's own NULL tests controls; a destroy function is the
  *     same conclusion with member work beside the release - frees of the parameter's members,
  *     directly, in a loop over a list, or through another destroy function, calls of callees that
  *     neither free nor allocate, and assignments to fields; a method whose value-return can be
  *     NULL (`return NULL;`, or the result of a nullable callee handed straight back) has a
  *     nullable return; a parameter passed unconditionally, unchanged, to a callee position with a
  *     dst/src/len/untrusted-read role inherits that role; a constructor that stores parameter j
  *     and `j + k` into two members of one object binds (j, k) as (buffer, capacity).
  *   - **offset families**: an allocator whose every non-NULL value-return hands out a known
  *     allocation advanced by ONE constant amount is a family of its own, and a method that
  *     releases its parameter moved back by the same normalised amount through the same underlying
  *     family joins it. The amount is normalised to bytes (`h + 1` with `h` of struct type and
  *     `(char *)h + sizeof(*h)` are the same amount); an amount that cannot be normalised, or two
  *     different amounts, conclude no family. Pairing is by (amount, underlying family), never by
  *     name: every allocator and free of one key carries the one family string `offset:<name>` (the
  *     alphabetically first allocator's, a free alone naming itself), so the tag equality the
  *     wrong-deallocation rule compares IS the pair. A wrapper returning the allocation unchanged
  *     stays in the underlying family.
  *   - **region allocators**: a method whose every non-NULL value-return is pointer arithmetic over
  *     a field of ONE parameter (or over a local that parameter's value reached through), with no
  *     allocation behind the arithmetic, hands out memory owned by the region that parameter names
  *     \- the bump allocator's `return p->base + p->used;`. A NULL return is the exhaustion arm and
  *     the summary stays nullable; a body whose remaining returns fall back to a real allocation -
  *     the region-full case - records BOTH summaries, the region and the fallback's own family. The
  *     value names the parameter: `region-alloc:<i>`.
  *   - **reference releases**: a method that decrements a field of ONE parameter by one and, under
  *     the condition that the field reached zero, releases the parameter itself - frees it, hands
  *     it to a callee summarised as freeing it, or calls a function pointer it received as another
  *     argument (the container's release callback, the count field's address locating the
  *     container) - concludes `release:<i>`, the inferred twin of a profile's declared `release`
  *     role. The count field names the zero condition: a release gated by anything else (a flag, a
  *     comparison of another variable) concludes nothing, and a method that allocates or reads is
  *     no release at all.
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
    // each method's own conclusion, beside the name-level ones: a call the graph resolves to
    // this method reads THESE, so an overload the front end selected is judged by its own body
    if result.methodEntries.nonEmpty then
      atom.method.l.foreach { m =>
          result.methodEntries.get(m.id).foreach { entry =>
            Summary(entry).values.foreach(v => rows += ((m, TagOwn, v)))
            rows += ((m, TagEvidence, EvidenceBody))
          }
      }
    rows ++= storageFacts(atom, declared ++ result.entries)
    rows ++= returnRangeRows(atom)
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
            s"body ${byEvidence.getOrElse(EvidenceBody, 0)}, " +
            s"heuristic ${byEvidence.getOrElse(EvidenceHeuristic, 0)})"
      )
    // CHEN_MEMSEM_DEBUG=1: every summary, to check what a run concluded without a graph query
    if sys.env.get("CHEN_MEMSEM_DEBUG").contains("1") then
      result.summaries.toList.sortBy(_._1).foreach { case (name, s) =>
          System.err.println(
            s"memsem $name ${s.values.mkString(",")} [${s.evidence.toList.sorted.mkString(",")}]"
          )
      }
  end run
end MemorySemanticsPass

object MemorySemanticsPass:

  final val TagSemantic = "mem-semantic"
  final val TagEvidence = "mem-semantic-evidence"
  final val TagStorage  = "mem-storage"
  final val TagPointsTo = "mem-points-to"

  /** A method's OWN body conclusion, on the method itself: what a call whose CALLEE edge resolves
    * to it reads, independent of what same-named methods agree on (`mem-semantic` stays the
    * name-level, agreement-required channel).
    */
  final val TagOwn = "mem-semantic-own"

  final val EvidenceAttribute = "attribute"
  final val EvidenceBody      = "body"

  /** A name-and-signature guess, never a proof: [[MemorySafetyFindingPass]] reports a finding a
    * heuristic free triggers at `low`.
    */
  final val EvidenceHeuristic = "heuristic"

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
            // the region role a body concluded: the parameter whose region the result belongs to
            entry.region.collect {
                case MemApiVocab.MemRegion("allocate", Some(i), _) => s"region-alloc:$i"
            }.toList ++
            entry.len.map(i => s"len:$i") ++
            entry.count.map(i => s"count:$i") ++
            entry.dst.map(i => s"dst:$i") ++
            entry.src.map(i => s"src:$i") ++
            entry.untrustedRead.map(i => s"untrusted-read:$i") ++
            entry.clamp.map(kv => s"clamp:$kv") ++
            entry.increments.map((i, f) => s"grow:$i:$f") ++
            entry.release.map(i => s"release:$i") ++
            Option.when(entry.nullableReturn && !nonnullReturn)("nullable-return") ++
            Option.when(nonnullReturn)("nonnull-return") ++
            nonnullParams.toList.sorted.map(i => s"nonnull-param:$i")

    def isEmpty: Boolean = values.isEmpty
  end Summary

  final case class Result(
    summaries: Map[String, Summary],
    methodEntries: Map[Long, MemApiVocab.MemApiEntry] = Map.empty
  ):
    def entries: Map[String, MemApiVocab.MemApiEntry] =
        summaries.map { case (n, s) =>
            n -> s.entry.copy(nullableReturn = s.entry.nullableReturn && !s.nonnullReturn)
        }

  /** Each method's own body conclusion ([[TagOwn]] on the method), by method id: what a RESOLVED
    * call reads. Empty when the pass did not run (a caller gets the name-level channel alone).
    */
  def ownEntriesFor(cpg: Cpg): Map[Long, MemApiVocab.MemApiEntry] =
      cpg.method
          .where(_.tag.nameExact(TagOwn))
          .l
          .flatMap { m =>
              entryFromValues(m.name, m.tag.nameExact(TagOwn).value.l.toSet).map(m.id -> _)
          }
          .toMap

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

  /** The prefix of the `mem-semantic` value that names a function's closed return range. */
  final val ReturnRangePrefix = "ret-range:"

  /** The closed return range a function's own body spells: every value-return a constant - a
    * literal, an enumerator, a constant macro - and every same-named body agreeing (a body that
    * returns anything else says the name can return anything). A caller passing such a call's
    * result on knows the value it hands over. Falling off the end of a value-returning function and
    * using the result has no value in C at all, so it excludes nothing here.
    */
  private def returnRangeRows(cpg: Cpg): List[(StoredNode, String, String)] =
      cpg.method.isExternal(false).l.groupBy(_.name).values.toList.flatMap { bodies =>
        val ranges = bodies.map(bodyRange)
        if ranges.exists(_.isEmpty) then Nil
        else
          val lo = ranges.flatten.map(_._1).min
          val hi = ranges.flatten.map(_._2).max
          bodies.map(m => (m, TagSemantic, s"$ReturnRangePrefix$lo:$hi"))
      }

  private def bodyRange(m: Method): Option[(BigInt, BigInt)] =
    val returns = m.ast.isReturn.l
    val values = returns.flatMap(_.astChildren.collectFirst { case e: Expression => e }
        .flatMap(IndexRange.literal))
    Option.when(returns.nonEmpty && values.size == returns.size)((values.min, values.max))

  /** A METHOD's summarised return range, read back from the tag the pass wrote. */
  def returnRangeOf(m: Method): Option[(BigInt, BigInt)] =
      semanticValues(m).collectFirst {
          case v if v.startsWith(ReturnRangePrefix) =>
              v.stripPrefix(ReturnRangePrefix).split(":", 2)
      }.flatMap {
          case Array(lo, hi) =>
              scala.util.Try((BigInt(lo), BigInt(hi))).toOption
          case _ => None
      }

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
      region = vs.collectFirst {
          case v if v.startsWith("region-alloc:") =>
              v.stripPrefix("region-alloc:").toIntOption.filter(_ >= 1).map(i =>
                  MemApiVocab.MemRegion("allocate", arg = Some(i))
              )
      }.flatten,
      untrustedRead = idx("untrusted-read:"),
      clamp = vs.collectFirst {
          case v if v.startsWith("clamp:") =>
              v.stripPrefix("clamp:").split(":", 2) match
                case Array(i, k) if i.toIntOption.isDefined => s"$i:$k"
                case _                                      => null
      },
      nullableReturn = vs.contains("nullable-return"),
      increments = vs.collectFirst { case v if v.startsWith("grow:") => v.stripPrefix("grow:") }
          .flatMap(_.split(":", 2) match
            case Array(a, f) => a.toIntOption.filter(_ >= 1).filter(_ => f.nonEmpty).map(_ -> f)
            case _           => None
          ),
      release = idx("release:")
    )
    Option.when(entry != MemApiVocab.MemApiEntry(name))(entry)
  end entryFromValues

  // --------------------------------------------------------------------------------------------
  // inference
  // --------------------------------------------------------------------------------------------

  def summarize(cpg: Cpg, declared: Map[String, MemApiVocab.MemApiEntry]): Result =
    val out = mutable.LinkedHashMap.empty[String, Summary]

    // 1. declared attributes: every METHOD carrying one - a header stub or a definition - and
    // every CALL carrying one, which is where a header OUTSIDE the analysed input leaves them
    // (c2cpg builds no METHOD from an included declaration: libavutil/mem.h in a libavformat run)
    val attrsByName = mutable.LinkedHashMap.empty[String, Set[String]]
    def addAttrs(name: String, attrs: Iterable[String]): Unit =
        attrsByName(name) = attrsByName.getOrElse(name, Set.empty) ++ attrs
    cpg.method.where(_.tag.nameExact(Defines.FunctionAttributeTag)).foreach { m =>
        addAttrs(m.name, m.tag.nameExact(Defines.FunctionAttributeTag).value.l)
    }
    cpg.call.where(_.tag.nameExact(Defines.FunctionAttributeTag)).foreach { c =>
        addAttrs(c.name, c.tag.nameExact(Defines.FunctionAttributeTag).value.l)
    }
    val deallocators = mutable.LinkedHashMap.empty[String, Int]
    attrsByName.foreach { case (name, attrs) =>
        fromAttributes(name, attrs, declaredShape(cpg, name), deallocators)
            .foreach(s => out(name) = s)
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
    val sizes = TypeSizes(cpg)
    def known(name: String): Option[MemApiVocab.MemApiEntry] =
        declared.get(name).orElse(out.get(name).map(_.entry))
    var round   = 1
    var changed = true
    while changed && round <= MaxRounds do
      changed = false
      defined.foreach { case (name, methods) =>
          if !declared.contains(name) then
            val conclusions = methods.map(fromBody(_, known, sizes)).distinct
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
    // 2b. each body's OWN conclusion, whatever its name-sharers concluded: the fact a resolved
    // call reads. Computed with the settled name-level knowledge, after the fixpoint
    val own = (for
      (_, methods) <- defined
      m            <- methods
      if !declared.contains(m.name)
      entry <- fromBody(m, known, sizes)
    yield m.id -> entry).toMap
    // 3. capacity binders (a constructor remembering where its buffer ends)
    inferBinders(cpg).foreach { entry =>
        if !declared.contains(entry.name) then
          out.updateWith(entry.name) {
              case Some(s) => Some(s.copy(entry = fillEmpty(s.entry, entry)))
              case None    => Some(Summary(entry, evidence = Set(EvidenceBody)))
          }
    }

    // 4. a deallocator or reallocator whose body is not in scope and whose declaration says
    // nothing, guessed from its name and signature. Last, so no body conclusion builds on a guess.
    cpg.method.name.dedup.l.foreach { name =>
      val lower = name.toLowerCase
      if (lower.contains("free") || lower.contains("realloc")) && !declared.contains(name) &&
        !defined.contains(name) && !out.get(name).exists(s =>
            s.entry.alloc.isDefined || s.entry.realloc.isDefined || s.entry.free.isDefined
        )
      then
        val shape = declaredShape(cpg, name)
        val guess =
            if looksLikeDeallocator(name, shape) then
              Some(MemApiVocab.MemApiEntry(name, free = Some(FamilyHeap)))
            else reallocatorGuess(name, shape)
        guess.foreach { g =>
            out.updateWith(name) {
                case Some(s) =>
                    Some(s.copy(
                      entry = fillEmpty(g, s.entry),
                      evidence = s.evidence + EvidenceHeuristic
                    ))
                case None => Some(Summary(g, evidence = Set(EvidenceHeuristic)))
            }
        }
      end if
    }

    // the offset families pair here, with every conclusion settled: one key, one family string
    val (resolvedSummaries, resolvedOwn) = resolveOffsetFamilies(out, own)
    Result(
      resolvedSummaries.filterNot { case (name, s) => declared.contains(name) || s.isEmpty },
      resolvedOwn
    )
  end summarize

  /** Names of the functions whose memory role the name-and-signature heuristic supplied (it only
    * supplies one where nothing else did).
    */
  def heuristicSummaries(cpg: Cpg): Set[String] =
      cpg.method.where(_.tag.nameExact(TagEvidence).valueExact(EvidenceHeuristic)).name.toSet

  /** A function's declared return type and parameter types, in order. */
  final case class Shape(returnType: String, params: List[String]):
    def returnsPointer: Boolean = OverlayFacts.isPointer(returnType)
    def isPointerParam(index: Int): Boolean =
        params.lift(index - 1).exists(t => OverlayFacts.isPointer(t))
    def pointerParams: List[Int] = params.indices.map(_ + 1).filter(isPointerParam).toList

  private def isUnknownType(t: String): Boolean =
      t.isEmpty || t == Defines.Any || t == Defines.UnresolvedSignature

  /** `ret(p1,p2)` as c2cpg writes a call's (and a stub's) signature: split at the parameter list's
    * top-level commas.
    */
  private[taggers] def parseSignature(sig: String): Option[Shape] =
    val open = sig.indexOf('(')
    if open <= 0 || !sig.trim.endsWith(")") then None
    else
      val inner  = sig.trim.substring(open + 1, sig.trim.length - 1)
      val params = mutable.ListBuffer.empty[String]
      val cur    = new StringBuilder
      var depth  = 0
      inner.foreach {
          case ',' if depth == 0 => params += cur.toString.trim; cur.clear()
          case c =>
              if c == '(' then depth += 1 else if c == ')' then depth -= 1
              cur += c
      }
      if cur.nonEmpty then params += cur.toString.trim
      val ps = params.toList.filterNot(p => p.isEmpty || p == "void")
      Some(Shape(sig.take(open).trim, ps))

  /** The shape of `name`: from a METHOD whose return and parameters are typed, else from a
    * signature - the METHOD's, or that of a call to it (a stub [[MethodStubCreator]] made from
    * calls types every parameter ANY but keeps the call's declared signature).
    */
  private def declaredShape(cpg: Cpg, name: String): Option[Shape] =
    // every pick here is over content-sorted candidates: same-named methods in different files
    // (FFmpeg's per-demuxer read_header/read_close) carry different signatures, and which one a
    // traversal returns first is parse order - run-to-run nondeterministic
    val methods = cpg.method.nameExact(name).l
    val typed = methods
        .filter(m =>
            !isUnknownType(Option(m.methodReturn.typeFullName).getOrElse("").trim) &&
                m.parameter.nonEmpty && m.parameter.forall(p => !isUnknownType(p.typeFullName.trim))
        )
        .sortBy(m => (m.filename, m.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)))
        .headOption
        .map(m =>
            Shape(
              m.methodReturn.typeFullName.trim,
              m.parameter.l.sortBy(_.index).filter(_.index > 0).map(_.typeFullName.trim)
            )
        )
    typed
        .orElse(methods.iterator.map(m => Option(m.signature).getOrElse(""))
            .flatMap(parseSignature).toSet
            .filter(s => !isUnknownType(s.returnType))
            .toList.sortBy(s => (s.returnType, s.params.mkString(","))).headOption)
        .orElse(cpg.call.nameExact(name).signature.dedup.l.flatMap(parseSignature)
            .filter(s => !isUnknownType(s.returnType))
            .sortBy(s => (s.returnType, s.params.mkString(","))).headOption)
  end declaredShape

  private def normalisedType(t: String): String =
      t.replace("const", "").filterNot(_.isWhitespace)

  private val IntegerType =
      """(?:unsigned|signed|size_t|ssize_t|ptrdiff_t|int|long|short|u?int(?:8|16|32|64)_t)(?:int|long)*""".r

  private def isSizeType(t: String): Boolean =
    val n = normalisedType(t)
    n == Defines.Any || IntegerType.matches(n)

  /** `int av_reallocp(void *ptr, size_t size)`, `int av_reallocp_array(void *ptr, size_t nmemb,
    * size_t size)`: a function named `realloc` whose first parameter is an untyped pointer followed
    * by one size, or by a count and a size - the size is the last argument, the count the one
    * before it. The result is `realloc`, not `alloc`: it may hand back (or free) its input.
    */
  private def reallocatorGuess(
    name: String,
    shape: Option[Shape]
  ): Option[MemApiVocab.MemApiEntry] =
      if !name.toLowerCase.contains("realloc") then None
      else
        shape.flatMap { s =>
          val ps           = s.params.map(normalisedType)
          val firstUntyped = ps.headOption.exists(p => p == "void*" || p == "void**")
          if !firstUntyped || !ps.tail.forall(isSizeType) then None
          else
            ps.size match
              case 2 =>
                  Some(MemApiVocab.MemApiEntry(name, len = Some(2), realloc = Some(FamilyHeap)))
              case 3 =>
                  Some(MemApiVocab.MemApiEntry(
                    name,
                    count = Some(2),
                    len = Some(3),
                    realloc = Some(FamilyHeap)
                  ))
              case _ => None
        }

  /** A free of memory in general: `free` after at most a library prefix (`av_free`, `av_freep`,
    * `g_free`, `xfree`). A stem naming a type (`av_opt_free`, `av_frame_free`) frees what the
    * object HOLDS, not the pointer itself.
    */
  private val GenericFreeName = """(?:[a-z0-9]+_)?[a-z]{0,2}freep?[0-9]*""".r

  /** `void av_free(void *ptr)`, `void av_freep(void **p)`: a function returning nothing whose one
    * parameter is an untyped pointer and whose name says `free`.
    */
  private def looksLikeDeallocator(name: String, shape: Option[Shape]): Boolean =
      GenericFreeName.matches(name.toLowerCase) && shape.exists { s =>
          normalisedType(s.returnType) == "void" &&
          (s.params.map(normalisedType) match
            case List("void*") | List("void**") => true
            case _                              => false
          )
      }

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
        region = base.region.orElse(extra.region),
        untrustedRead = base.untrustedRead.orElse(extra.untrustedRead),
        clamp = base.clamp.orElse(extra.clamp),
        increments = base.increments.orElse(extra.increments),
        release = base.release.orElse(extra.release),
        nullableReturn = base.nullableReturn || extra.nullableReturn
      )

  // --- attributes -------------------------------------------------------------------------------

  private val AttrPattern = """([A-Za-z_][A-Za-z0-9_]*)(?:\((.*)\))?""".r

  private def fromAttributes(
    name: String,
    attrs: Set[String],
    shape: Option[Shape],
    deallocators: mutable.LinkedHashMap[String, Int]
  ): Option[Summary] =
    val parsed = attrs.toList.collect { case AttrPattern(n, args) =>
        n -> Option(args).map(_.split(",").map(_.trim).filter(_.nonEmpty).toList).getOrElse(Nil)
    }
    def ints(args: List[String]): List[Int] = args.flatMap(_.toIntOption)
    val isMalloc                            = parsed.exists(_._1 == "malloc")
    val allocSize      = parsed.collectFirst { case ("alloc_size", args) => ints(args) }
    val firstIsPointer = shape.exists(_.isPointerParam(1))
    val returnsPointer = shape.exists(_.returnsPointer)
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
        case ("nonnull", Nil)  => shape.map(_.pointerParams).getOrElse(Nil)
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

  /** How a free addresses the method's first parameter (through casts): directly (`free(p)`),
    * through the pointee (`free(*pp)`, the freep shape), or not at all - `free(b->ctx)` releases a
    * member, and the struct stays the caller's.
    */
  private def firstParamAddressing(method: Method, free: Call): Option[(String, Boolean)] =
    val first = method.parameter.l.find(_.index == 1).map(_.name)
    // the identifier must still hold the argument: `p = p->next; free(p)` releases another
    // block under the parameter's name
    def holdsArgument(i: Identifier): Boolean = OverlayFacts.holdsParameterValue(i)
    def root(e: AstNode): Option[(String, Boolean)] = e match
      case i: Identifier if holdsArgument(i)      => Some((i.name, false))
      case c: Call if c.name == "<operator>.cast" => c.argument.l.lastOption.flatMap(root)
      case c: Call if c.name == "<operator>.indirection" =>
          c.argumentOption(1).flatMap(root).map((n, _) => (n, true))
      case _ => None
    free.argumentOption(1).flatMap(root).filter((n, _) => first.contains(n))

  // --- offset families -------------------------------------------------------------------------

  /** A not-yet-named offset family: the bytes the allocator advances and the family of the
    * allocation underneath, until [[resolveOffsetFamilies]] gives the key its one name.
    */
  private final val OffsetPendingPrefix = "offset-pending:"

  private def offsetKeyOf(value: String): Option[(Long, String)] =
      value.stripPrefix(OffsetPendingPrefix).split(":", 2) match
        case Array(bytes, family) => bytes.toLongOption.filter(_ > 0).map(_ -> family)
        case _                    => None

  /** The bytes one type occupies: the LP64 width table, the members of a complete struct (a
    * flexible array member makes the whole size a question the allocation answers), a pointer's own
    * 8, and a typedef followed to what it names. `void` reads as one byte, which is how GNU C moves
    * a `void *`. A type none of that settles (an incomplete struct, an unfamiliar name) has no
    * size: an amount that cannot be normalised concludes no family.
    */
  private final class TypeSizes(cpg: Cpg):

    private val LeadingKeyword = """(?i)^(?:const|volatile|register|struct|union|enum)\s+""".r

    private def base(raw: String): String =
      var t      = raw.trim
      var before = ""
      while before != t do
        before = t
        t = LeadingKeyword.replaceAllIn(t, "").trim
      t

    /** The sizes the front ends evaluated themselves, read back off the graph: a `sizeof(T)` call
      * carries the value it folded to (`const-value`) and a cast to `T *` carries the bytes an
      * access through the result touches (`pointee-size`). Both spell one type's whole size, tail
      * padding included, which a member-by-member sum does not. Keyed by the type name as written;
      * more than one distinct value under one name (same-named types of different units) makes the
      * name unusable.
      */
    private val frontEndSizes: Map[String, Set[Long]] =
      val m = mutable.LinkedHashMap.empty[String, Set[Long]]
      def note(name: String, v: Long): Unit =
          if name.nonEmpty && name != Defines.Any then
            m.updateWith(name.trim)(prev => Some(prev.getOrElse(Set.empty) + v))
      cpg.call.nameExact("<operator>.sizeOf").foreach { sz =>
          sz.tag.nameExact(Defines.ConstValueTag).value.headOption.flatMap(_.toLongOption)
              .foreach(v =>
                  sz.argument.l.collectFirst { case e: Expression => e }.foreach(e =>
                      staticTypeOf(e).foreach(note(_, v))
                  )
              )
      }
      cpg.call.nameExact("<operator>.cast").foreach { cast =>
          cast.tag.nameExact(Defines.PointeeSizeTag).value.headOption.flatMap(_.toLongOption)
              .foreach(v => note(cast.typeFullName.stripSuffix("*").trim, v))
      }
      m.toMap

    /** The type names each typedef stands for, read once: every name a typedef aliases to `t`. */
    private lazy val aliasesOf: Map[String, List[String]] =
        cpg.typeDecl.l
            .flatMap(td => td.aliasTypeFullName.map(_.trim -> td.name))
            .groupMap(_._1)(_._2)

    /** The type declarations by name and by full name, read once. */
    private lazy val declsByName: Map[String, List[TypeDecl]] =
        cpg.typeDecl.l.flatMap(td => List(td.name -> td, td.fullName -> td)).groupMap(_._1)(_._2)
            .view.mapValues(_.distinct).toMap

    /** The front ends' own size of `t`, under its name and under every typedef name that stands for
      * it, when exactly one value is known.
      */
    private def frontEndSizeOf(t: String): Option[Long] =
      val names  = (t +: aliasesOf.getOrElse(t, Nil)).distinct
      val values = names.flatMap(n => frontEndSizes.getOrElse(n, Set.empty)).toSet
      Option.when(values.size == 1)(values.head)

    def ofName(raw: String, depth: Int = 3): Option[Long] = layoutOf(raw, depth).map(_._1)

    /** The size and alignment of the type `raw` names. A scalar is aligned to its size, a pointer
      * is 8 bytes, a struct is aligned to its strictest member, and a typedef is its target.
      */
    private def layoutOf(raw: String, depth: Int): Option[(Long, Long)] =
      val t = base(raw)
      if depth < 0 || t.isEmpty || t == Defines.Any then None
      else if t == "void" then Some((1L, 1L))
      else if t.endsWith("*") then Some((8L, 8L))
      else
        OverlayFacts.integralWidth(t).map(w => (w.toLong / 8, math.max(1L, w.toLong / 8)))
            .orElse(structLayout(t, depth))
            .orElse(OverlayFacts.typedefTarget(cpg, t).flatMap(layoutOf(_, depth - 1)))

    private val structLayouts = mutable.HashMap.empty[(String, Int), Option[(Long, Long)]]

    /** A struct's size and alignment, the front ends' own size first (theirs is the ABI's, padding
      * included): the computed layout fills in only where no sizeof or cast in the tree measured
      * the type, so the two sources never answer one type differently in a run. The alignment is
      * the computed layout's, or, for a measured struct whose members are not all known, the
      * largest power of two up to 8 that divides its size.
      */
    private def structLayout(t: String, depth: Int): Option[(Long, Long)] =
        structLayouts.getOrElseUpdate(
          (t, depth), {
              val computed = declsByName.getOrElse(t, Nil).map(computedLayout(_, depth)).distinct
              val layout = computed match
                case List(one) => one
                case _         => None
              frontEndSizeOf(t) match
                case Some(size) =>
                    val align = layout.map(_._2).getOrElse(
                      List(8L, 4L, 2L).find(a => size % a == 0).getOrElse(1L)
                    )
                    Some((size, align))
                case None => layout
          }
        )

    /** The layout the members spell: each member placed at the next offset its own alignment allows
      * (an array is aligned as its element), a union overlaying its members at one offset, and the
      * whole rounded up to the strictest member's alignment. A zero-length or flexible tail adds no
      * bytes. A member of no known size leaves the struct unknown.
      */
    private def computedLayout(td: TypeDecl, depth: Int): Option[(Long, Long)] =
      val members = OverlayFacts.membersOfTypeDecl(td)
      if members.isEmpty then None
      else
        val parts = members.map { m =>
            memberLayout(m.typeFullName, depth - 1).map { case (size, align) =>
                val inUnion =
                    m.tag.nameExact(Defines.TypeStorageTag).value.l.contains(
                      Defines.TypeStorageUnion
                    )
                (size, math.max(1L, align), inUnion)
            }
        }
        if parts.exists(_.isEmpty) then None
        else
          val laidOut                         = parts.flatten
          val align                           = laidOut.map(_._2).max
          def roundUp(n: Long, a: Long): Long = ((n + a - 1) / a) * a
          // the union storage tag is on every member of a union and on none of a struct's
          if laidOut.forall(_._3) then Some((roundUp(laidOut.map(_._1).max, align), align))
          else
            val end = laidOut.foldLeft(0L) { case (off, (size, a, _)) => roundUp(off, a) + size }
            Some((roundUp(end, align), align))
      end if
    end computedLayout

    private def memberLayout(t: String, depth: Int): Option[(Long, Long)] =
      val raw = t.trim
      if raw.endsWith("]") then
        // an array member of declared extent; `char data[]` is the flexible tail the
        // allocation sizes at run time, and the struct around it has no constant size
        OverlayFacts.arrayExtent(raw).flatMap(n =>
            layoutOf(raw.substring(0, raw.indexOf('[')).trim, depth).map { case (size, align) =>
                (size * n.toLong, align)
            }
        )
      else if OverlayFacts.isPointer(raw) then Some((8L, 8L))
      else layoutOf(raw, depth)

    /** The bytes pointer arithmetic over `pointerType` moves per unit: its pointee's size. */
    def pointeeOf(pointerType: String): Option[Long] =
      val t = pointerType.trim
      if !t.endsWith("*") then None else ofName(t.stripSuffix("*").trim)

    /** The pointee size of the value an operand holds: a cast's own measurement first (the
      * `pointee-size` tag the C front ends write), then the declared type of the expression, then
      * the type the cast itself spells (`(padded_t *)p` names the type even where the front end
      * typed the cast's result ANY and measured nothing).
      */
    def pointeeOfExpr(e: Expression): Option[Long] =
      def fromType(t: String): Option[Long] =
          Option(t).map(_.trim).filter(_.nonEmpty).filterNot(_ == Defines.Any).flatMap(pointeeOf)
      e match
        case c: Call if c.name == "<operator>.cast" =>
            c.tag.nameExact(Defines.PointeeSizeTag).value.headOption.flatMap(_.toLongOption)
                .orElse(fromType(c.typeFullName))
                .orElse(
                  c.argument.l
                      .find(_.argumentIndex == 1)
                      .map(written => base(written.code.stripSuffix("*")))
                      .filter(_.nonEmpty)
                      .flatMap(ofName(_))
                )
        case i: Identifier => fromType(i.typeFullName)
        case c: Call       => fromType(c.typeFullName)
        case _             => None

    /** The bytes an amount operand moves: a literal counts in pointee units, a sizeof already
      * counts bytes (the front end's own evaluation first), and a macro the preprocessor left
      * around either unwraps to the one expression it stands for. A literal over a pointee of no
      * known size, and a variable amount, have no normalised value.
      */
    def amountOf(op: Expression, pointee: Option[Long]): Option[Long] =
      val scaled: Literal => Option[Long] =
          l => pointee.flatMap(p => IndexRange.literal(l).map(k => k.toLong * p))
      unwrapCasts(op) match
        case l: Literal                               => scaled(l)
        case c: Call if c.name == "<operator>.sizeOf" => sizeOfBytes(c)
        case c: Call if !c.name.startsWith("<operator>") =>
            c.ast.isCall.nameExact("<operator>.sizeOf").l match
              case List(one) => sizeOfBytes(one)
              case _ =>
                  c.ast.collectAll[Literal].l match
                    case List(one) => scaled(one)
                    case _         => None
        case _ => None

    /** The bytes a `sizeof` folds to: the front end's own evaluation first, then the operand's
      * declared type, then the type as the operand spells it (`sizeof(padded_t)` where the plumbing
      * typed the operand `struct` and folded nothing).
      */
    private def sizeOfBytes(c: Call): Option[Long] =
        c.tag.nameExact(Defines.ConstValueTag).value.headOption.flatMap(_.toLongOption)
            .orElse {
                c.argument.l.collectFirst { case e: Expression => e }.flatMap { arg =>
                    staticTypeOf(arg).flatMap(ofName(_))
                        .orElse(ofName(base(arg.code)))
                }
            }
  end TypeSizes

  /** The declared type an expression node carries, where the generic Expression interface does not
    * expose it.
    */
  private def staticTypeOf(e: Expression): Option[String] =
      e match
        case i: Identifier => Option(i.typeFullName)
        case c: Call       => Option(c.typeFullName)
        case _             => None

  /** One pointer move an expression makes: the base value it moves, how far in bytes, and whether
    * it moves forward. Reads the pointer-arithmetic tag the C front ends write, so `h + 1`, `k +
    * p`, `(char *)p - PREFIX_SIZE`, `p--` and `h -= 1` all surface as one shape.
    */
  private final case class PointerMove(base: Expression, bytes: Long, forward: Boolean)

  private def pointerMoveOf(e: Expression, sizes: TypeSizes): Option[PointerMove] =
      unwrapCasts(e) match
        case c: Call =>
            OverlayFacts.pointerArithmeticOf(c).flatMap {
                case ("diff", _) => None // a pointer difference moves nothing
                case (kind, idx) =>
                    c.argumentOption(idx).collect { case x: Expression => x }.flatMap { b =>
                      val pointee = sizes.pointeeOfExpr(b)
                      val others =
                          c.argument.l.collect { case x: Expression => x }.filter(_.id != b.id).toList
                      val bytes = others match
                        case List(only) => sizes.amountOf(only, pointee)
                        case Nil        => pointee // p++ / p-- moves one pointee unit
                        case _          => None
                      bytes.map(PointerMove(b, _, kind == "add"))
                    }
            }
        case _ => None

  /** The right-hand sides of the plain assignments that define `i` and reach this occurrence. */
  private def assignmentRhssOf(i: Identifier): List[Expression] =
      OverlayFacts
          .reachingDefsIn(i)
          .collect { case d: Identifier if d.name == i.name => d }
          .flatMap(d =>
              d._astIn.collectFirst {
                  case a: Call
                      if a.name == "<operator>.assignment" &&
                          a.argumentOption(1).exists(_.id == d.id) => a
              }
          )
          .flatMap(_.argumentOption(2).collect { case e: Expression => e }.toList)

  /** One way a statement defines a local: a plain assignment of `rhs`, or a pointer move of the
    * value `base` holds (the compound assigns and the increment operators). None marks a definition
    * that is neither.
    */
  private sealed trait LocalDefinition
  private final case class Assigned(rhs: Expression) extends LocalDefinition
  private final case class Moved(bytes: Long, base: Expression, forward: Boolean)
      extends LocalDefinition

  private def definitionsOf(
    name: String,
    method: Method,
    sizes: TypeSizes
  ): List[Option[LocalDefinition]] =
    def definesLhs(c: Call): Boolean =
        c.argumentOption(1).exists {
            case i: Identifier => i.name == name
            case _             => false
        }
    method.ast.isCall.l.flatMap {
        case a if a.name == "<operator>.assignment" && definesLhs(a) =>
            a.argumentOption(2).collect { case e: Expression => Some(Assigned(e)) }.toList
        case c if OverlayFacts.isAssignmentOperator(c.name) && definesLhs(c) =>
            // the compound forms: a definition only where the pointer-arithmetic tag says so
            pointerMoveOf(c, sizes).map(m => Some(Moved(m.bytes, m.base, m.forward))).toList
        case u
            if Set(
              "<operator>.postIncrement",
              "<operator>.preIncrement",
              "<operator>.postDecrement",
              "<operator>.preDecrement"
            ).contains(u.name) && definesLhs(u) =>
            pointerMoveOf(u, sizes).map(m => Some(Moved(m.bytes, m.base, m.forward))).toList
        case _ => Nil
    }
  end definitionsOf

  /** Whether every condition controlling `c` is a NULL test of one of `tested`: the guard a
    * header-prefixed free puts around its release, in the spellings whose arithmetic or local
    * copies hide the tested name from the generic check.
    */
  private def onlyNullChecksOfNames(c: Call, tested: Set[String]): Boolean =
    def names(e: Expression, n: String): Boolean =
        unwrapCasts(e) match
          case i: Identifier => i.name == n
          case u: Call if u.name == "<operator>.logicalNot" =>
              u.argument.l.collect { case x: Expression => x }.exists(names(_, n))
          case cmp: Call
              if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
              val args = cmp.argument.l.collect { case x: Expression => unwrapCasts(x) }
              args.exists(names(_, n)) &&
              args.exists(a => AllocationStatePass.isNullLiteral(a, castOperand))
          case _ => false
    val conds = c._cdgIn.l.collect { case e: Expression => e }
    tested.exists(n => conds.nonEmpty && conds.forall(names(_, n)))

  /** The identifier a release's operand ultimately reads: itself, or the base its arithmetic moves.
    */
  private def releaseRootOf(e: Expression): Option[String] =
      unwrapCasts(e) match
        case i: Identifier => Some(i.name)
        case ar: Call =>
            OverlayFacts.pointerArithmeticOf(ar).flatMap((_, idx) =>
                ar.argumentOption(idx).collect { case x: Expression => x }.flatMap(releaseRootOf)
            )
        case _ => None

  /** The offset-allocator conclusion: a pointer-returning body whose every non-NULL value-return
    * hands out a known allocation advanced by ONE constant normalised amount. The advanced base may
    * be the producing call itself or a local every definition of which is that call (or NULL, on a
    * checked path); a producer family disagreement, an amount that cannot be normalised, or two
    * amounts anywhere, conclude nothing. The family travels as a pending key the pairing step
    * names; the size role and the nullable fact follow what the body itself returns.
    */
  private def offsetAllocatorOf(
    method: Method,
    producers: List[Call],
    known: String => Option[MemApiVocab.MemApiEntry],
    sizes: TypeSizes
  ): Option[MemApiVocab.MemApiEntry] =
    if !returnsPointer(method) then return None
    val producerIds = producers.map(_.id).toSet
    val families    = producers.flatMap(p => known(p.name).flatMap(_.alloc)).distinct
    if families.size != 1 then return None

    /** Whether the value a pointer move starts from is the allocation (or a NULL-fallback of it),
      * through a bounded walk of the base identifier's own definitions: a definition of the
      * allocation anchors it, a definition of NULL keeps the question open, and a definition that
      * steps the name itself forward (the `p = p + 8` spelling in its own definitions) is part of
      * the walk. Any other definition - a copy of a parameter, a backward or unanchored move - says
      * the value is not the allocation.
      */
    def basedOnProducerMove(move: PointerMove, depth: Int): Boolean =
        unwrapCasts(move.base) match
          case c: Call if producerIds.contains(c.id) => true
          case i: Identifier if depth > 0 =>
              val rhss = assignmentRhssOf(i)
              rhss.nonEmpty && rhss.exists(rhs => producerIds.contains(unwrapCasts(rhs).id)) &&
              rhss.forall(rhs =>
                  unwrapCasts(rhs) match
                    case c: Call if producerIds.contains(c.id) => true
                    case v if isNullValue(v)                   => true
                    case ar: Call =>
                        pointerMoveOf(rhs, sizes) match
                          case Some(m) if m.forward =>
                              unwrapCasts(m.base) match
                                case b: Identifier if b.name == i.name => true
                                case _ => basedOnProducerMove(m, depth - 1)
                          case _ => false
                    case _ => false
              )
          case _ => false

    def basedOnProducer(move: PointerMove): Boolean = basedOnProducerMove(move, 3)

    /** How far the returned value sits past the allocation: an arithmetic return names its amount,
      * and a returned identifier names it through its own definitions - the assignment of the
      * allocation counts no advance, and every forward pointer step of it (the `p++` statement
      * form, the compound assigns, and the assignment of forward arithmetic such as `p = p + 8`,
      * the mirror of the free side's move forms) adds its normalised bytes. A definition of any
      * other shape (a copy of a parameter or of another local, a backward move), two different step
      * amounts, or a return that is the allocation itself conclude nothing here.
      */
    def advanceOf(r: Expression): Option[Long] =
        unwrapCasts(r) match
          case c: Call if producerIds.contains(c.id) => Some(0L)
          case c: Call =>
              pointerMoveOf(c, sizes).filter(_.forward).filter(basedOnProducer).map(_.bytes)
          case i: Identifier =>
              val defs = definitionsOf(i.name, method, sizes)
              if defs.isEmpty then None
              else
                var anchored  = false
                var undefined = false
                val steps     = mutable.ListBuffer.empty[Long]
                defs.foreach {
                    case Some(Assigned(rhs)) =>
                        unwrapCasts(rhs) match
                          case pc: Call if producerIds.contains(pc.id) => anchored = true
                          case v if isNullValue(v)                     => ()
                          case ar: Call =>
                              pointerMoveOf(rhs, sizes) match
                                case Some(m) if m.forward && basedOnProducer(m) =>
                                    anchored = true
                                    steps += m.bytes
                                case _ => undefined = true
                          case _ => undefined = true
                    case Some(Moved(bytes, base, forward)) =>
                        if forward && basedOnProducer(PointerMove(base, bytes, forward)) then
                          anchored = true
                          steps += bytes
                        else undefined = true
                    case None => undefined = true
                }
                if undefined || !anchored then None
                else
                  val distinctSteps = steps.distinct.toList
                  if distinctSteps.sizeIs == 1 then Some(distinctSteps.head)
                  else if distinctSteps.isEmpty then Some(0L)
                  else None
              end if
          case _ => None
    val returns = valueReturns(method)
    if returns.isEmpty then return None
    // a NULL return is the failure arm; every value return must sit a definable distance past
    // the allocation, and one and the same positive distance, or the advances disagree
    val advances = returns.flatMap(r => if isNullValue(r) then Nil else advanceOf(r).toList)
    val valued   = returns.count(r => !isNullValue(r))
    if valued == 0 || advances.size != valued || advances.distinct.size != 1 ||
      advances.head <= 0
    then return None
    val sizeParams = (for
      call  <- producers
      entry <- known(call.name).toList
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
        alloc = Some(s"$OffsetPendingPrefix${advances.head}:${families.head}"),
        nullableReturn = returns.exists(mayBeNull(_, known))
      )
    )
  end offsetAllocatorOf

  /** The offset-free conclusion: a method returning nothing that releases its parameter moved back
    * by ONE constant normalised amount through a known free. The move back may sit in the call's
    * arithmetic, in the operators that step a local back, or in the assignment of an already-moved
    * pointer; every definition between the parameter and the release must be one of those, no
    * forward move may intervene, and each release must be unguarded or guarded only by NULL tests
    * of the value it releases.
    */
  private def offsetFreeOf(
    method: Method,
    frees: List[Call],
    known: String => Option[MemApiVocab.MemApiEntry],
    sizes: TypeSizes
  ): Option[MemApiVocab.MemApiEntry] =
    if !returnsNoValue(method) then return None
    val paramNames = method.parameter.l.map(_.name).toSet
    val families   = frees.flatMap(f => known(f.name).flatMap(_.free)).distinct
    if families.size != 1 then return None
    // the parameter a value copies, through casts and a local's plain assignments
    def paramBehind(e: Expression): Option[String] =
        unwrapCasts(e) match
          case i: Identifier if paramNames.contains(i.name) => Some(i.name)
          case i: Identifier =>
              assignmentRhssOf(i).flatMap(rhs =>
                  unwrapCasts(rhs) match
                    case x: Identifier if paramNames.contains(x.name) => Some(x.name)
                    case _                                            => None
              ) match
                case List(one) => Some(one)
                case _         => None
          case _ => None
    // how one release's operand relates to a parameter: the parameter, and the bytes moved back
    def releasedRelative(free: Call): Option[(String, Long)] =
        free.argumentOption(1).collect { case e: Expression => e }.flatMap { freed =>
          def movedBackFrom(e: Expression): Option[(String, Long)] =
              pointerMoveOf(e, sizes).filterNot(_.forward)
                  .flatMap(m => paramBehind(m.base).map(_ -> m.bytes))
          unwrapCasts(freed) match
            case i: Identifier =>
                val defs = definitionsOf(i.name, method, sizes)
                if defs.isEmpty then None
                else
                  val traced = defs.map {
                      case Some(Assigned(rhs)) =>
                          paramBehind(rhs)
                              .map(p => (p, None))
                              .orElse(movedBackFrom(rhs).map((p, k) => (p, Some(k))))
                      case Some(Moved(bytes, base, forward)) =>
                          if forward then None
                          else paramBehind(base).map(p => (p, Some(bytes)))
                      case None => None
                  }
                  if traced.forall(_.isDefined) then
                    val params  = traced.flatten.map(_._1).distinct
                    val amounts = traced.flatten.flatMap(_._2).distinct
                    if params.size == 1 && amounts.size == 1 then Some((params.head, amounts.head))
                    else None
                  else None
            case other => movedBackFrom(other)
          end match
        }
    // a guard names the value the release reads (the local it frees) or the parameter that
    // value copies: both spellings release exactly when a block is there
    def guardAllows(f: Call, param: String): Boolean =
        f._cdgIn.isEmpty || {
            val tested = f.argumentOption(1).collect { case e: Expression => e }
                .flatMap(releaseRootOf).map(Set(_)).getOrElse(Set.empty) + param
            onlyNullChecksOfNames(f, tested)
        }
    val released = frees.map(f => releasedRelative(f).filter((param, _) => guardAllows(f, param)))
    val distinct = released.flatten.distinct
    if released.forall(_.isDefined) && distinct.size == 1 then
      val (param, bytes) = distinct.head
      Some(
        MemApiVocab.MemApiEntry(
          method.name,
          free = Some(s"$OffsetPendingPrefix$bytes:${families.head}")
        )
      )
    else None
  end offsetFreeOf

  /** The region-allocator conclusion: a pointer-returning body whose every non-NULL value-return is
    * pointer arithmetic over a field of ONE parameter (or over a local that parameter's value
    * reached through), with no allocation behind the arithmetic - the bump allocator's `return
    * p->base + p->used;` - or hands back a region-summarised callee's result, passing its own
    * parameter where the callee names its region (the wrapper `array_get_next` returning
    * `array_get(array, next)`). A NULL return is the exhaustion arm and the summary stays nullable.
    * A body whose remaining returns hand back a real allocation - the region-full fallback -
    * records both summaries: the region role and the fallback's own family. A body where two
    * parameters could own the region, a field handed back unchanged, or a stray return from
    * anything but the region arm, an allocation, or the composed callee, concludes nothing.
    */
  private def regionAllocatorOf(
    method: Method,
    producers: List[Call],
    known: String => Option[MemApiVocab.MemApiEntry]
  ): Option[MemApiVocab.MemApiEntry] =
    if !returnsPointer(method) || producers.isEmpty && valueReturns(method).isEmpty then
      return None
    val producerIds = producers.map(_.id).toSet

    /** The parameter whose value the expression's identifier denotes: the parameter itself, or a
      * local every definition of which copies the parameter in (NULL definitions keep the question
      * open).
      */
    def valueParamOf(i: Identifier, depth: Int): Option[Int] =
        method.parameter.l.find(p => p.index > 0 && p.name == i.name).map(_.index).orElse {
            if depth <= 0 then None
            else
              val rhss = assignmentRhssOf(i)
              if rhss.isEmpty then None
              else if rhss.exists(rhs =>
                    !isNullValue(rhs) && (unwrapCasts(rhs) match
                      case b: Identifier => valueParamOf(b, depth - 1).isEmpty
                      case _             => true
                    )
                )
              then None
              else
                rhss.flatMap(rhs =>
                    if isNullValue(rhs) then None
                    else
                      unwrapCasts(rhs) match
                        case b: Identifier => valueParamOf(b, depth - 1)
                        case _             => None
                ).distinct match
                  case List(one) => Some(one)
                  case _         => None
        }

    /** The parameter whose field the expression reads or moves within: pointer arithmetic whose
      * operand is `p->base` (the field of the parameter), that field access itself, and a returned
      * local that names either through definitions that are themselves one of them, or NULL on the
      * exhaustion arm.
      */
    def regionParamOf(e: Expression, depth: Int): Option[Int] =
        unwrapCasts(e) match
          case c: Call =>
              OverlayFacts.pointerArithmeticOf(c).flatMap { (_, idx) =>
                  c.argumentOption(idx).collect { case x: Expression => x }.flatMap { x =>
                    // the moved base may sit behind the typed spelling's cast
                    // (`(char *)(p->base + i)`): the same field the region names
                    val operand = unwrapCasts(x)
                    operand match
                      case fa: Call
                          if fa.name == "<operator>.fieldAccess" ||
                              fa.name == "<operator>.indirectFieldAccess" =>
                          fa.argumentOption(1).collect { case i: Identifier => i }
                              .flatMap(valueParamOf(_, depth))
                      case i: Identifier if depth > 0 =>
                          val rhss = assignmentRhssOf(i)
                          if rhss.isEmpty then None
                          else
                            val params = rhss.map(rhs =>
                                if isNullValue(rhs) then Some(0)
                                else regionParamOf(rhs, depth - 1)
                            )
                            if params.exists(_.isEmpty) then None
                            else
                              val names = params.flatten.filter(_ > 0).distinct
                              if names.sizeIs == 1 then Some(names.head) else None
                      case _ => None
                  }
              }
          // a field handed straight back (`return p->base;`) reads the parameter's field but
          // computes nothing: not the arithmetic the region-allocator conclusion asks for
          case _: Call => None
          case i: Identifier if depth > 0 =>
              val rhss = assignmentRhssOf(i)
              if rhss.isEmpty then None
              else
                val params = rhss.map(rhs =>
                    if isNullValue(rhs) then Some(0)
                    else regionParamOf(rhs, depth - 1)
                )
                if params.exists(_.isEmpty) then None
                else
                  val names = params.flatten.filter(_ > 0).distinct
                  if names.sizeIs == 1 then Some(names.head) else None
          case _ => None

    /** Whether the value flows from a real allocation: the producing call itself, through a
      * conditional's arms, or through a local's definitions - the fallback arm's reach.
      */
    def flowsFromAllocation(e: Expression, depth: Int): Boolean =
        unwrapCasts(e) match
          case c: Call if producerIds.contains(c.id) => true
          case _ if depth <= 0                       => false
          case c: Call if c.name == "<operator>.conditional" =>
              Seq(2, 3).flatMap(c.argumentOption).exists(flowsFromAllocation(_, depth - 1))
          case i: Identifier =>
              OverlayFacts
                  .reachingDefsIn(i)
                  .collect { case d: Identifier => d }
                  .flatMap(_._astIn.collectFirst {
                      case a: Call if a.name == "<operator>.assignment" => a
                  })
                  .flatMap(_.argumentOption(2))
                  .exists(flowsFromAllocation(_, depth - 1))
          case _ => false

    end flowsFromAllocation

    /** The composed region: a return that hands back a region-summarised callee's result, with the
      * wrapper passing its own parameter where the callee names its region - `array_get_next`
      * returning `array_get(array, next)`, whose region is argument 1, names its own `array`
      * parameter there. The wrapper's region is that parameter's position, so every call site of
      * the wrapper keys its blocks the way the callee's call sites do.
      */
    def regionComposedParamOf(v: Expression): Option[Int] =
        unwrapCasts(v) match
          case c: Call =>
              for
                region <- known(c.name).flatMap(_.region)
                if region.role == "allocate"
                idx <- region.arg
                arg <- c.argumentOption(idx)
                base <- unwrapCasts(arg) match
                  case i: Identifier => Some(i)
                  case _             => None
                param <- method.parameter.l.find(p => p.index > 0 && p.name == base.name)
              yield param.index
          case _ => None

    val returns = valueReturns(method)
    if returns.isEmpty then return None
    val valued = returns.filterNot(isNullValue)
    if valued.isEmpty then return None
    // the composed wrapper first: its evidence is a region-summarised callee whose
    // result every value return hands back - the array's own maintenance callees
    // beside it do not take the region away
    val composedParams = valued.flatMap(v => regionComposedParamOf(v).toList)
    if composedParams.size == valued.size && composedParams.distinct.size == 1 then
      return Some(
        MemApiVocab.MemApiEntry(
          method.name,
          region = Some(MemApiVocab.MemRegion("allocate", arg = Some(composedParams.head))),
          nullableReturn = returns.exists(mayBeNull(_, known))
        )
      )
    // every value return is the region arm, the region-full fallback's allocation, or the
    // composed hand-back of a region-summarised callee's result
    val classified = valued.map { v =>
        regionParamOf(v, 3)
            .map(Right(_))
            .orElse(regionComposedParamOf(v))
            .getOrElse(Left(v))
    }
    val regionParams = classified.collect { case Right(i) => i }.distinct
    val fallbackArms = classified.collect { case Left(v) => v }
    if regionParams.sizeIs != 1 then return None
    if fallbackArms.isEmpty then
      // the pure bump shape: the region role alone. A producer that only REGROWS the
      // region's own storage (a realloc of the array the blocks live in) is the region's
      // maintenance, not a new block beside it; a producer that allocates new memory is
      // a real fallback arm and refuses the pure conclusion
      if producers.exists(p => known(p.name).flatMap(_.alloc).isDefined) then return None
      Some(
        MemApiVocab.MemApiEntry(
          method.name,
          region = Some(MemApiVocab.MemRegion("allocate", arg = Some(regionParams.head))),
          nullableReturn = returns.exists(mayBeNull(_, known))
        )
      )
    else
      // the fallback arm hands out a real allocation; both summaries travel together
      if producers.isEmpty || fallbackArms.exists(!flowsFromAllocation(_, 3)) then return None
      val families = producers.flatMap(c => known(c.name).flatMap(_.alloc)).distinct
      if families.sizeIs != 1 then return None
      Some(
        MemApiVocab.MemApiEntry(
          method.name,
          alloc = Some(families.head),
          region = Some(MemApiVocab.MemRegion("allocate", arg = Some(regionParams.head))),
          nullableReturn = returns.exists(mayBeNull(_, known))
        )
      )
    end if
  end regionAllocatorOf

  /** Name every pending offset-family key: all allocators and frees of one (amount, underlying
    * family) carry the one string `offset:<name>`, so the tag equality the wrong-deallocation rule
    * compares is the pair. The name is the alphabetically first allocator's (the method that
    * establishes the family); a key no allocator holds is named after its alphabetically first
    * free. The naming is injective over keys: two keys that share a first-name anchor (the own
    * channel can hold same-named methods whose bodies concluded different keys) get that anchor
    * suffixed with the key's own amount and underlying family, so distinct keys never share a
    * family string and a release can never pair across them through a name.
    */
  private def resolveOffsetFamilies(
    summaries: mutable.LinkedHashMap[String, Summary],
    own: Map[Long, MemApiVocab.MemApiEntry]
  ): (Map[String, Summary], Map[Long, MemApiVocab.MemApiEntry]) =
    val allocNames =
        mutable.LinkedHashMap.empty[(Long, String), mutable.SortedSet[String]]
    val freeNames =
        mutable.LinkedHashMap.empty[(Long, String), mutable.SortedSet[String]]
    def scan(name: String, entry: MemApiVocab.MemApiEntry): Unit =
      entry.alloc
          .filter(_.startsWith(OffsetPendingPrefix))
          .flatMap(offsetKeyOf)
          .foreach(k => allocNames.getOrElseUpdate(k, mutable.SortedSet.empty) += name)
      entry.free
          .filter(_.startsWith(OffsetPendingPrefix))
          .flatMap(offsetKeyOf)
          .foreach(k => freeNames.getOrElseUpdate(k, mutable.SortedSet.empty) += name)
    summaries.foreach { (name, s) => scan(name, s.entry) }
    own.values.foreach(e => scan(e.name, e))
    val named: Map[(Long, String), String] =
        (allocNames.keySet ++ freeNames.keySet)
            .groupMap { k =>
              val anchor = allocNames.get(k).flatMap(_.headOption)
                  .orElse(freeNames.get(k).flatMap(_.headOption))
                  .getOrElse(FamilyHeap)
              s"offset:$anchor"
            }(identity)
            .view
            .flatMap { (anchor, ks) =>
                if ks.size == 1 then ks.map(k => k -> anchor)
                else ks.map(k => k -> s"$anchor:${k._1}:${k._2}")
            }
            .toMap
    def familyOf(key: (Long, String)): String =
        named.getOrElse(key, s"offset:$FamilyHeap")
    def resolved(value: String): String =
        if value.startsWith(OffsetPendingPrefix) then
          offsetKeyOf(value).map(familyOf).getOrElse(FamilyHeap)
        else value
    def resolveEntry(e: MemApiVocab.MemApiEntry): MemApiVocab.MemApiEntry =
        e.copy(
          alloc = e.alloc.map(resolved),
          free = e.free.map(resolved),
          realloc = e.realloc.map(resolved)
        )
    (
      summaries.map { (name, s) => name -> s.copy(entry = resolveEntry(s.entry)) }.toMap,
      own.view.mapValues(resolveEntry).toMap
    )
  end resolveOffsetFamilies

  private def fromBody(
    method: Method,
    known: String => Option[MemApiVocab.MemApiEntry],
    sizes: TypeSizes
  ): Option[MemApiVocab.MemApiEntry] =
    val calls               = method.call.l
    val real                = calls.filterNot(_.name.startsWith("<operator>"))
    def isProducer(c: Call) = known(c.name).exists(e => e.alloc.isDefined || e.realloc.isDefined)
    def isFree(c: Call)     = known(c.name).exists(_.free.isDefined)
    def isRead(c: Call) = known(c.name).exists(e => e.untrustedRead.isDefined || e.untrustedCall)
    val producers       = real.filter(isProducer)
    val frees           = real.filter(isFree)
    val reads           = real.filter(isRead)

    // `*pp = NULL` - whose pointee the method resets (the freep shape's second half). The cast
    // a typed spelling needs (`*(void **)p = NULL`) is read through
    val nulledPointees = calls.collect {
        case a if a.name == "<operator>.assignment" && a.argumentOption(2).exists(isNullValue) =>
            a.argumentOption(1).map(unwrapCasts).collect {
                case d: Call if d.name == "<operator>.indirection" => d
            }.flatMap(_.argumentOption(1).map(unwrapCasts)).collect { case i: Identifier => i.name }
    }.flatten.toSet
    // a destroy function's own release of its argument: a free of the first parameter (directly,
    // or through the pointee for a pointer-to-pointer) that no condition controls, or whose only
    // controlling conditions are NULL tests of that parameter - whenever the argument names a
    // block, the release runs. A free through the pointee additionally needs the reset: the free
    // summary's call-site model leaves the caller null, not dangling
    def releasesParam(free: Call): Boolean =
        firstParamAddressing(method, free).exists { (name, throughPointee) =>
            (!throughPointee || nulledPointees.contains(name)) &&
            (free._cdgIn.isEmpty || AllocationStatePass.onlyNullChecksOf(free))
        }
    // the calls a destroy function may make beside that release: frees of anything (the
    // argument, its members, another destroy's argument) and calls of callees that neither free
    // nor allocate. An allocation is work the free summary does not describe
    def destroyCall(c: Call): Boolean =
        isFree(c) || known(c.name).forall(e =>
            e.free.isEmpty && e.alloc.isEmpty && e.realloc.isEmpty
        )
    val isDestroy = frees.nonEmpty && producers.isEmpty && reads.isEmpty &&
        returnsNoValue(method) && frees.exists(releasesParam) && real.forall(destroyCall)

    // an offset family: the allocation handed out advanced by one constant amount, or the
    // parameter released moved back by the same normalised amount. Failure handling beside the
    // allocation (an abort, a log call) is part of the shape, so the allocator conclusion's gate
    // stays broader than the plain wrapper's every-call-produces condition; its own requirement
    // is that every value return sits a constant normalised distance past the allocation
    val offsetAlloc =
        if producers.nonEmpty && frees.isEmpty && reads.isEmpty then
          offsetAllocatorOf(method, producers, known, sizes)
        else None
    // a region allocator: every value return is arithmetic over a field of one parameter, or the
    // region arm beside a fallback arm's real allocation. Tried after the offset families, whose
    // advanced-allocation returns are the shape a region conclusion would otherwise misread
    val regionAlloc =
        if frees.isEmpty && reads.isEmpty then regionAllocatorOf(method, producers, known)
        else None
    val offsetFree =
        if frees.nonEmpty && producers.isEmpty && reads.isEmpty && returnsNoValue(method) &&
          real.forall(destroyCall)
        then offsetFreeOf(method, frees, known, sizes)
        else None
    // a destroy (or plain free wrapper) releases through the family its releases share: a free
    // wrapper is heap, a munmap wrapper is mmap, and releases of more than one family stay the
    // heap reading (the summary names one family, not several)
    val wrapper: Option[MemApiVocab.MemApiEntry] =
        if producers.nonEmpty && frees.isEmpty && reads.isEmpty && real.forall(isProducer) then
          // the advanced return wins: an allocator handing out `p++`'d storage is a family of
          // its own even though the body's plain-flow shape also concludes. The region
          // conclusion comes before the plain allocator entry: a wrapper whose value returns
          // are the region's own arithmetic (`array_insert` handing back `pointer +
          // index * item_size` after the regrow) hands out REGION blocks, and an entry that
          // carries only the regrow's family would strip the region from the tracked results
          offsetAlloc.orElse(regionAlloc).orElse(allocatorEntry(method, producers, known))
        else if isDestroy then
          val releasedFamilies = frees.flatMap(f => known(f.name).flatMap(_.free)).distinct
          Some(
            MemApiVocab.MemApiEntry(
              method.name,
              free = Some(releasedFamilies match
                case List(one) => one
                case _         => FamilyHeap
              )
            )
          )
        else offsetAlloc.orElse(offsetFree).orElse(regionAlloc)

    val nullable = returnsPointer(method) && !wrapper.exists(_.alloc.isDefined) &&
        valueReturns(method).exists(e => mayBeNull(e, known))
    val roles = inheritedRoles(method, real, known)
    // a callee that READS through one pointer parameter and STORES through another
    // fills that out-parameter with bytes from the caller's buffer - the parse_leb shape, where
    // obu_size is written from the bytes parse_leb() reads and no in-method def of it exists
    val inferred = roles.copy(
      nullableReturn = nullable,
      untrustedRead = roles.untrustedRead.orElse(untrustedOutParamIndex(method)),
      increments = counterIncrementOf(method),
      clamp = clampedParamOf(method, known),
      release = roles.release.orElse(
        referenceReleaseOf(method, calls, frees, producers, reads, real, known)
            .flatMap(_.release)
      )
    )
    val entry = fillEmpty(wrapper.getOrElse(MemApiVocab.MemApiEntry(method.name)), inferred)
    Option.when(entry != MemApiVocab.MemApiEntry(method.name))(entry)
  end fromBody

  /** The bound a parameter is clamped to inside the body: `if (n > K) n = L;` with literals and L
    * <= K leaves n at most K after the statement, whatever the caller passed - encoded as the
    * parameter's index and K. The store must be the `if`'s own branch under exactly that test, and
    * the only store to the parameter in the body; anything else is no clamp.
    */
  private def clampedParamOf(
    method: Method,
    known: String => Option[MemApiVocab.MemApiEntry]
  ): Option[String] =
    def literal(e: Expression): Option[BigInt] = e match
      case l: Literal => IndexRange.literalValue(l.code)
      case _          => None
    val stores = method.call.filter(c => OverlayFacts.isAssignmentOperator(c.name)).l
    def storesTo(name: String) =
        stores.filter(_.argumentOption(1).exists {
            case i: Identifier => i.name == name
            case _             => false
        })
    val clamps = method.parameter.l.flatMap { p =>
        storesTo(p.name) match
          case List(store) =>
              for
                bound <-
                    store.argumentOption(2).collect { case e: Expression => e }.flatMap(literal)
                test <- store.inAst.collectAll[ControlStructure].headOption
                    .filter(_.controlStructureType == ControlStructureTypes.IF)
                    .flatMap(_.condition.headOption).collect { case c: Call => c }
                if test.name == "<operator>.greaterThan"
                if test.argumentOption(1).exists {
                    case i: Identifier => i.name == p.name
                    case _             => false
                }
                k <- test.argumentOption(2).collect { case e: Expression => e }.flatMap(literal)
                if bound <= k && k >= 0
              yield s"${p.index}:$k"
          case _ => None
    }
    clamps match
      case List(one) => Some(one)
      case _         => None
  end clampedParamOf

  /** The parameter a method stores through while reading through a different pointer parameter:
    * `int parse_leb(const uint8_t *buf, int n, uint32_t *out) { ... *out = v; }` fills `out` with a
    * value derived from the bytes it read out of `buf`. The stored bytes are the caller's buffer's
    * contents, so the out-param joins the untrusted-read family: a value the caller cannot bound
    * without a guard. Plain setter shapes store a computed constant or a caller value and read
    * nothing, and stay what they were.
    */
  private def untrustedOutParamIndex(method: Method): Option[Int] =
    def paramName(e: Expression): Option[String] = unwrapCasts(e) match
      case i: Identifier => Option.when(method.parameter.nameExact(i.name).nonEmpty)(i.name)
      case _             => None
    // the parameter a dereference reads or writes through: p[i], *p, *p++
    def through(e: Expression): Option[String] = unwrapCasts(e) match
      case c: Call if c.name.matches("<operator>\\.(pre|post)Increment") =>
          c.argumentOption(1).collect { case x: Expression => x }.flatMap(through)
      case other => paramName(other)
    // the dereferences that READ: an element access or deref anywhere except the TARGET side
    // of an assignment (`*out = v` writes through the parameter, it does not read it)
    val isStoreTarget: Call => Boolean = c =>
        c._astIn.collectFirst { case a: Call => a }.exists { a =>
            OverlayFacts.isAssignmentOperator(a.name) &&
            a.argumentOption(1).exists(_.id == c.id)
        }
    val readParams = method.call
        .name("<operator>.indexAccess|<operator>.indirectIndexAccess|<operator>.indirection").l
        .filterNot(isStoreTarget)
        .flatMap(c => c.argumentOption(1).collect { case e: Expression => e }.flatMap(through))
        .toSet
    if readParams.isEmpty then None
    else
      val stored = mutable.LinkedHashSet.empty[Int]
      method.call
          .filter(a => OverlayFacts.isAssignmentOperator(a.name))
          .l.foreach { a =>
              // `*out = v` and the compound `*out |= v` both store through the parameter
              a.argumentOption(1).collect { case e: Expression => e }.foreach { lhs =>
                  lhs match
                    case c: Call if c.name == "<operator>.indirection" =>
                        c.argumentOption(1).collect { case e: Expression => e }
                            .flatMap(through)
                            .filterNot(readParams.contains)
                            .foreach(name => stored += method.parameter.nameExact(name).head.index)
                    case _ => ()
              }
          }
      stored.toList match
        case List(i) => Some(i) // two out-params would make the role ambiguous
        case _       => None
    end if
  end untrustedOutParamIndex

  /** The (argument index, field) a method's body increments by one - `p->count++`, `++p->count`,
    * `p->count += k`, `p->count = p->count + k` and the `a[p->count++] = v` embedding - where `p`
    * is the method's own parameter. The counter's definition is hidden from the caller
    * (avformat_new_stream increments s->nb_streams), which is what makes a loop-carried index on
    * the field invisible to every in-method walk. One (index, field): a body that grows two
    * counters concludes nothing about either.
    */
  private def counterIncrementOf(method: Method): Option[(Int, String)] =
    def fieldOf(e: Expression): Option[(String, String)] = e match
      case c: Call
          if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
          for
            base   <- c.argumentOption(1).collect { case i: Identifier => i }
            member <- OverlayFacts.memberOf(c)
          yield (base.name, member)
      case _ => None
    val paramFields = mutable.LinkedHashSet.empty[(Int, String)]
    def note(e: Expression): Unit = fieldOf(e).foreach { (base, member) =>
        method.parameter.nameExact(base).headOption.foreach(p => paramFields += ((p.index, member)))
    }
    method.call.nameExact("<operator>.postIncrement", "<operator>.preIncrement").l
        .foreach(c => c.argumentOption(1).collect { case e: Expression => e }.foreach(note))
    method.call.nameExact("<operator>.assignmentPlus").l.foreach { c =>
      // p->f += k grows the counter only for a non-negative literal k
      val growsByLiteral = c.argumentOption(2).flatMap(IndexRange.literal).exists(_ >= 0)
      if growsByLiteral then c.argumentOption(1).collect { case e: Expression => e }.foreach(note)
    }
    method.call.nameExact("<operator>.assignment").l.foreach { a =>
        (a.argumentOption(1), a.argumentOption(2)) match
          case (Some(lhs: Expression), Some(rhs: Call)) if rhs.name == "<operator>.addition" =>
              val operands = rhs.argument.l.collect { case e: Expression => e }
              val literal  = operands.exists(x => IndexRange.literal(x).exists(_ >= 0))
              fieldOf(lhs).foreach { key =>
                  if literal && operands.flatMap(fieldOf).contains(key) then note(lhs)
              }
          case _ => ()
    }
    paramFields.toList match
      case List(one) => Some(one)
      case _         => None
  end counterIncrementOf

  /** The (struct base, member) pair a field-access expression names: `p->refs`, `p.refs`. */
  private def countedFieldOf(e: Expression): Option[(String, String)] = e match
    case c: Call
        if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
        for
          base   <- c.argumentOption(1).collect { case i: Identifier => i }
          member <- OverlayFacts.memberOf(c)
        yield (base.name, member)
    case _ => None

  /** The reference-release conclusion: a method that decrements a field of ONE parameter by one
    * and, under the condition that the field reached zero, releases the parameter itself. The
    * release is a direct free of the parameter, a call the tree summarised as freeing it (the
    * destroy summary), or a call through a function pointer the method received as another argument
    * (the container's release callback: the count field's address locates the container). The zero
    * condition compares the count field - directly, or through its own decrement (`if (--o->refs ==
    * 0)`), with zero or with the one count the free consumes (`if (o->refs == 1)` beside the
    * decrement on the other arm); every condition controlling the release must be such a
    * comparison, so a flag-gated or otherwise-conditioned release concludes nothing. A body that
    * allocates or reads is no release, and the release must leave the parameter itself, not only
    * its members, on the zero path.
    */
  private def referenceReleaseOf(
    method: Method,
    calls: List[Call],
    frees: List[Call],
    producers: List[Call],
    reads: List[Call],
    real: List[Call],
    known: String => Option[MemApiVocab.MemApiEntry]
  ): Option[MemApiVocab.MemApiEntry] =
    if producers.nonEmpty || reads.nonEmpty ||
      !real.forall(c => known(c.name).forall(e => e.alloc.isEmpty && e.realloc.isEmpty))
    then None
    else
      val paramIndex = method.parameter.l.map(p => p.name -> p.index).toMap
      // the (base, member) fields the body decrements by one
      val decremented = mutable.LinkedHashSet.empty[(String, String)]
      method.call.nameExact("<operator>.postDecrement", "<operator>.preDecrement").l
          .foreach(c =>
              c.argumentOption(1).collect { case e: Expression => e }
                  .flatMap(countedFieldOf).foreach(decremented += _)
          )
      method.call.nameExact("<operator>.assignmentMinus").l.foreach { c =>
          c.argumentOption(2).flatMap(IndexRange.literal).foreach { k =>
              if k == 1 then
                c.argumentOption(1).collect { case e: Expression => e }
                    .flatMap(countedFieldOf).foreach(decremented += _)
          }
      }
      method.call.nameExact("<operator>.assignment").l.foreach { a =>
          (a.argumentOption(1), a.argumentOption(2)) match
            case (Some(lhs: Expression), Some(rhs: Call)) if rhs.name == "<operator>.subtraction" =>
                val operands = rhs.argument.l.collect { case e: Expression => e }
                val one      = operands.exists(x => IndexRange.literal(x).contains(1))
                countedFieldOf(lhs).foreach { field =>
                    if one && operands.flatMap(countedFieldOf).contains(field) then
                      decremented += field
                }
            case _ => ()
      }
      // the count field an operand names, and how: read as it is, decremented before the read
      // (`--o->refs`), or decremented after it (`o->refs--`)
      def countOperandOf(e: Expression): Option[((String, String), String)] =
          countedFieldOf(e).map(_ -> "read").orElse {
              e match
                case c: Call
                    if c.name == "<operator>.preDecrement" || c.name == "<operator>.postDecrement" =>
                    c.argumentOption(1).collect { case x: Expression => x }.flatMap(countedFieldOf)
                        .map(_ -> (if c.name == "<operator>.preDecrement" then "pre" else "post"))
                case _ => None
          }
      // a decrement of the field written before `cond`, by line: the count `cond` reads has
      // already dropped
      def decrementedBefore(cond: Expression, field: (String, String)): Boolean =
        val line = cond.lineNumber.map(_.toInt).getOrElse(Int.MaxValue)
        method.call.l.exists { c =>
            c.lineNumber.exists(_.toInt < line) && (c.name match
              case "<operator>.preDecrement" | "<operator>.postDecrement" |
                  "<operator>.assignmentMinus" =>
                  c.argumentOption(1).collect { case x: Expression => x }
                      .flatMap(countedFieldOf).contains(field)
              case "<operator>.assignment" =>
                  c.argumentOption(1).collect { case x: Expression => x }
                      .flatMap(countedFieldOf).contains(field) &&
                  c.argumentOption(2).exists {
                      case sub: Call if sub.name == "<operator>.subtraction" => true
                      case _                                                 => false
                  }
              case _ => false
            )
        }
      // whether the count is zero when `cond` holds (Some(true)), when it fails (Some(false)),
      // or neither can be read off it. Only the whole condition counts: a zero test joined to a
      // flag (`--o->refs == 0 && o->owned`) is a gated release, not a release. The compared
      // value must mean the last reference for the operand's form: 0 after the decrement, 1 for
      // the value read before a post-decrement, and 1 for a count read before any decrement
      // (`if (o->refcount == 1) free(o); else o->refcount--;`)
      def zeroWhen(cond: Expression, field: (String, String)): Option[Boolean] =
          unwrapCasts(cond) match
            case cmp: Call
                if cmp.name == "<operator>.equals" || cmp.name == "<operator>.notEquals" =>
                val operands = cmp.argument.l.collect { case x: Expression => x }
                val counted  = operands.flatMap(countOperandOf).filter(_._1 == field)
                val literal  = operands.flatMap(IndexRange.literal(_))
                val meansZero = (counted, literal) match
                  case (List((_, form)), List(v)) =>
                      (v == 0 && form != "post") || (v == 1 && form == "post") ||
                      (v == 1 && form == "read" && !decrementedBefore(cmp, field))
                  case _ => false
                Option.when(meansZero)(cmp.name == "<operator>.equals")
            case not: Call if not.name == "<operator>.logicalNot" =>
                not.argumentOption(1).collect { case x: Expression => x }.flatMap(countOperandOf)
                    .collect { case (f, form) if f == field && form != "post" => true }
            case other =>
                countOperandOf(other).collect {
                    case (f, form) if f == field && form != "post" =>
                        false
                }
      // the release sits on the side of its controlling `if` where the count is zero
      def zeroCondition(cond: Expression, field: (String, String), release: Call): Boolean =
          zeroWhen(cond, field).exists { zeroWhenTrue =>
              cond._astIn.collectFirst { case cs: ControlStructure => cs }
                  .filter(_.controlStructureType == ControlStructureTypes.IF)
                  .exists { cs =>
                    val inTrueBranch = cs.whenTrue.ast.id.toSet.contains(release.id)
                    inTrueBranch == zeroWhenTrue
                  }
          }
      // the parameter a candidate release releases: the identifier itself, not a member read
      def releasedParamOf(rc: Call): Option[Int] =
          rc.argumentOption(1).map(unwrapCasts).collect { case i: Identifier => i.name }
              .flatMap(paramIndex.get)
      // a call through a function pointer the method received: the callee expression is the
      // call's receiver child (no argument edge of its own), the released object its first
      // argument
      def releaseCallbackOf(rc: Call): Boolean =
          rc.astChildren.exists {
              case i: Identifier if !rc.argument.l.exists(_.id == i.id) =>
                  paramIndex.contains(i.name)
              case _ => false
          } && releasedParamOf(rc).isDefined
      // the candidate releases of the parameter itself: a free of it, a summarised destroy of
      // it, a call through a parameter-named function pointer (the release callback). The
      // pointer call reaches here beside the named calls: its name is the operator's
      val candidates =
          frees.filter(f => releasedParamOf(f).isDefined) ++
              calls.filterNot(frees.contains).filter { rc =>
                  if rc.name == "<operator>.pointerCall" then releaseCallbackOf(rc)
                  else
                    !rc.name.startsWith("<operator>") &&
                    (paramIndex.contains(rc.name) ||
                        (known(rc.name).exists(_.free.isDefined) &&
                            releasedParamOf(rc).isDefined))
              }
      val released = candidates.map { rc =>
          releasedParamOf(rc).flatMap { idx =>
            val pname  = method.parameter.l.find(_.index == idx).map(_.name).getOrElse("")
            val fields = decremented.filter(_._1 == pname)
            val conds  = rc._cdgIn.l.collect { case e: Expression => e }
            Option.when(
              fields.nonEmpty && conds.nonEmpty &&
                  conds.forall(c => fields.exists(f => zeroCondition(c, f, rc)))
            )(idx)
          }
      }
      if candidates.isEmpty then None
      else if released.forall(_.isDefined) then
        released.flatten.distinct.toList match
          case List(one) => Some(MemApiVocab.MemApiEntry(method.name, release = Some(one)))
          case _         => None
      else None
    end if
  end referenceReleaseOf

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

  /** The allocator conclusion: a pointer-returning body at least one of whose returns flows from a
    * real allocation and every one of whose returns flows from an allocation or is a NULL constant.
    * The size role is the parameter feeding the wrapped allocation's size, when exactly one does.
    */
  private def allocatorEntry(
    method: Method,
    producers: List[Call],
    known: String => Option[MemApiVocab.MemApiEntry]
  ): Option[MemApiVocab.MemApiEntry] =
    if !returnsPointer(method) then return None
    val producerIds = producers.map(_.id).toSet
    // a definition already on the walk adds nothing: a loop's copy cycle (`q = p; p = q;`)
    // would otherwise walk forever
    def flows(e: Expression, seen: Set[Long] = Set.empty): Boolean = unwrapCasts(e) match
      case c: Call if producerIds.contains(c.id) => true
      case c: Call if c.name == "<operator>.conditional" =>
          val bs = Seq(2, 3).flatMap(c.argumentOption)
          bs.forall(b => flows(b, seen) || isNullValue(b)) && bs.exists(flows(_, seen))
      case i: Identifier =>
          OverlayFacts
              .reachingDefsIn(i)
              .collect { case d: Identifier if !seen.contains(d.id) => d }
              .exists { d =>
                  d._astIn.collectFirst {
                      case a: Call if a.name == "<operator>.assignment" => a
                  }.flatMap(_.argumentOption(2)).exists(flows(_, seen + d.id))
              }
      case _ => false
    val returns = valueReturns(method)
    if !returns.exists(flows(_)) || !returns.forall(r => flows(r) || isNullValue(r)) then None
    else
      val sizeParams = (for
        call <- producers
        entry = known(call.name).get
        idx   <- entry.len.toList ++ entry.count.toList
        arg   <- call.argumentOption(idx).toList
        leaf  <- (arg +: arg.ast.collectAll[Expression].l).collect { case i: Identifier => i }
        param <- method.parameter.nameExact(leaf.name).l
      yield param.index).distinct
      // the family a wrapper hands out is the one its producers share: a wrapper of a wrapper
      // keeps the family the inner one was concluded with (an offset family, mmap, the heap), and
      // producers that disagree about the family hand out nothing nameable
      val allocFamilies   = producers.flatMap(c => known(c.name).flatMap(_.alloc)).distinct
      val reallocFamilies = producers.flatMap(c => known(c.name).flatMap(_.realloc)).distinct
      Some(
        MemApiVocab.MemApiEntry(
          method.name,
          len = sizeParams match
            case List(i) => Some(i)
            case _       => None
          ,
          alloc = allocFamilies match
            case List(one) => Some(one)
            case _         => None
          ,
          realloc = reallocFamilies match
            case List(one) => Some(one)
            case _         => None
          ,
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

  /** The capacity-binder conclusions: a body that stores parameter j into a member of parameter i
    * and `param j + param k` into a second member of the same object establishes (j, k) as a
    * (buffer, capacity) pair. Same-named disagreeing bodies conclude nothing.
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
