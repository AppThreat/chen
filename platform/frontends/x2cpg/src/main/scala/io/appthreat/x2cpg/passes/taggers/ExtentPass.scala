package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS2: how big is this buffer, as a fact on the graph.
  *
  * For every destination argument of a memory-writing call ([[MemoryApiPass]]'s `mem-dst`), derive
  * the buffer's capacity and tag it `extent` (valued) plus the `memory-safety` umbrella:
  *
  *   - `const:128` - a declared array (`char buf[128]`, through a `#define`, and struct members:
  *     `int[16]` is in `typeFullName`, confirmed by part-1 task A5);
  *   - `sizeof:<expr>` - `sizeof(x)` in the allocation that produced the pointer, or as the copy's
  *     own length argument against the same buffer;
  *   - `alloc:<id>` - the size argument of the `mem-alloc` call that produced the pointer;
  *   - `param:<name>` - a capacity parameter paired with a buffer parameter (the R1 adjacent-pair
  *     detection promoted out of the prototype query, predicate unchanged);
  *   - `field:<name>` - a struct member holding the length beside the buffer (`payload` /
  *     `payload_len`);
  *   - `unknown` - everything else.
  *
  * `unknown` is load-bearing: a detector that needs an extent must not fire when it sees it. A pass
  * that quietly guesses here is worse than one that admits ignorance, because the guess becomes a
  * false positive nobody can trace - so the fallback is an explicit tag, not silence.
  *
  * The declaration the extent came from (Local, Member, or the buffer's paired MethodParameterIn)
  * is tagged with the same value, so a guard comparison can be matched against a buffer's extent
  * without re-deriving it. Follows the MemoryApiPass conventions: one traversal, matches
  * accumulated per tag, single batched emit, C/C++ graphs only.
  */
class ExtentPass(atom: Cpg) extends CpgPass(atom):

  import ExtentPass.*
  import OverlayFacts.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !MemoryApiPass.appliesTo(atom) then return

    val argExtents  = mutable.LinkedHashMap.empty[StoredNode, String]
    val declExtents = mutable.LinkedHashMap.empty[StoredNode, String]

    OverlayFacts
        .memoryArgumentSites(atom)
        .groupBy { case (call, _, _) => call }
        .foreach { case (call, rows) =>
            val dstArgs = rows.collect { case (_, e, MemoryApiPass.TagDst) => e }
            val lenArg  = rows.collectFirst { case (_, e, MemoryApiPass.TagLen) => e }

            dstArgs.foreach { dst =>
              // The copy's own `sizeof(buf)` length is an extent fact about buf.
              val sizeofInCopy =
                  for
                    len     <- lenArg
                    operand <- sizeOfOperand(len)
                    dstKey  <- variableKey(dst)
                    lenKey  <- variableKey(operand)
                    if dstKey == lenKey
                  yield s"$ValueSizeof:${operand.code}"

              extentOf(dst, call.method, sizeofInCopy) match
                case Some((value, decls)) =>
                    argExtents(dst) = value
                    decls.foreach(d => declExtents(d) = value)
                case None =>
                    argExtents(dst) = ValueUnknown
            }
        }

    OverlayFacts.emitTags(
      dstGraph,
      (argExtents.toList ++ declExtents.toList).map { case (node, value) =>
          (node, TagExtent, value)
      }
    )
  end run

  /** Resolve the capacity of a `mem-dst` argument expression. Returns the extent value and, where
    * one exists, the declaration nodes it was derived from.
    */
  private def extentOf(
    dst: Expression,
    method: Method,
    sizeofInCopy: Option[String]
  ): Option[(String, List[StoredNode])] =
      dst match
        case c: Call if c.name == "<operator>.addressOf" =>
            c.argumentOption(1).flatMap(extentOf(_, method, None))
        case c: Call
            if c.name == "<operator>.indexAccess" || c.name == "<operator>.indirectIndexAccess" =>
            // &buf[off] still writes into buf's capacity
            c.argumentOption(1).flatMap(extentOf(_, method, None))
        case i: Identifier =>
            extentOfVariable(i.name, i, method, sizeofInCopy)
        case c: Call
            if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indirectFieldAccess" =>
            extentOfField(c)
        case _ =>
            sizeofInCopy.map(v => (v, List.empty[StoredNode]))

  private def extentOfVariable(
    name: String,
    use: Expression,
    method: Method,
    sizeofInCopy: Option[String]
  ): Option[(String, List[StoredNode])] =
      // A declared array beats everything else: the size is in the type.
      method.local.name(name).headOption.flatMap { local =>
          arrayExtent(local.typeFullName).map(n => (s"$ValueConst:$n", List(local)))
      }.orElse {
          // A buffer parameter with an adjacent capacity parameter (the R1 pairing). The
          // parameter declaration carries the extent so guards can match against it.
          for
            param <- method.parameter.name(name).headOption
            cap   <- paramExtentOf(param)
          yield (s"$ValueParam:$cap", List(param))
      }.orElse {
          sizeofInCopy.map(v => (v, List.empty))
      }.orElse {
          // A pointer whose definition is an inventoried allocation.
          allocExtentOf(use).map(v => (v, List.empty))
      }

  /** The capacity parameter beside a buffer parameter: adjacency in the signature plus the
    * pointer/integral type pattern, exactly the predicate the prototype query validated against the
    * real CVE. Names are deliberately not consulted.
    */
  private def paramExtentOf(buf: MethodParameterIn): Option[String] =
    val params = buf.method.parameter.l.sortBy(_.index)
    params.sliding(2).collectFirst {
        case Seq(l, r) if l == buf && isIntegral(r.typeFullName) => r.name
        case Seq(l, r) if r == buf && isIntegral(l.typeFullName) => l.name
    }

  /** `alloc:<size-argument id>`, or `sizeof:<expr>` when the size argument is a sizeof. */
  private def allocExtentOf(use: Expression): Option[String] =
      OverlayFacts
          .reachingDefsIn(use)
          .collect { case d: Identifier => d }
          .flatMap { defNode =>
              defNode._astIn.collectFirst { case a: Call if a.name == "<operator>.assignment" => a }
          }
          .flatMap { assignment =>
              assignment.argumentOption(2).collect { case alloc: Call => alloc }
          }
          .find(alloc => alloc.tag.name(MemoryApiPass.TagAlloc).l.nonEmpty)
          .flatMap { alloc =>
              alloc.argument.l
                  .find(arg => arg.tag.name(MemoryApiPass.TagLen).l.nonEmpty)
                  .map {
                      case sz: Call if sz.name.startsWith("<operator>.sizeOf") =>
                          s"$ValueSizeof:${sz.code}"
                      case sizeArg => s"$ValueAlloc:${sizeArg.id}"
                  }
          }

  private def extentOfField(fieldAccess: Call): Option[(String, List[StoredNode])] =
      OverlayFacts.memberRefOf(atom, fieldAccess).flatMap { member =>
          arrayExtent(member.typeFullName)
              .map(n => (s"$ValueConst:$n", List(member)))
              .orElse(siblingLengthOf(member).map(sib => (s"$ValueField:$sib", List(member))))
      }

  /** A struct member holding the length beside a pointer member, by the C `_len`/`_size` suffix
    * convention (`payload` / `payload_len`).
    */
  private def siblingLengthOf(member: Member): Option[String] =
    val wanted = Set(s"${member.name}_len", s"${member.name}_size")
    member.typeDecl.member.l
        .filter(m => m != member && isIntegral(m.typeFullName))
        .find(m => wanted.contains(m.name))
        .map(_.name)

  private def sizeOfOperand(len: Expression): Option[Expression] = len match
    case c: Call if c.name.startsWith("<operator>.sizeOf") => c.argumentOption(1)
    case _                                                 => None
end ExtentPass

object ExtentPass:
  final val TagExtent = "extent"

  final val ValueConst   = "const"
  final val ValueSizeof  = "sizeof"
  final val ValueAlloc   = "alloc"
  final val ValueParam   = "param"
  final val ValueField   = "field"
  final val ValueUnknown = "unknown"

  def appliesTo(atom: Cpg): Boolean = MemoryApiPass.appliesTo(atom)
