package io.appthreat.c2cpg.passes

import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** How each local, parameter and global is referenced, as tags on its declaration
  * ([[Defines.ReferenceKindTag]]), after the kinds a C/C++ compiler's cross-reference records:
  *
  *   - `address-taken`: the operand of `&` (also `&v.member`, `&v[i]`), an array passed to a call
  *     (it decays to a pointer to the array), or an argument bound to a non-const reference
  *     parameter of a function the graph holds. The variable can then change without being named;
  *   - `modified`: assigned, compound-assigned, incremented or decremented after its declaration,
  *     also through a member or an element of it (`v.f = x`, `a[i] = x` for an array `a`). A
  *     declaration's own initializer is not a modification;
  *   - `read-only`: neither of the above.
  */
class ReferenceKindPass(cpg: Cpg) extends CpgPass(cpg):

  import ReferenceKindPass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val kinds = mutable.LinkedHashMap.empty[StoredNode, mutable.LinkedHashSet[String]]
    def note(variable: StoredNode, kind: String): Unit =
        kinds.getOrElseUpdate(variable, mutable.LinkedHashSet.empty) += kind

    // the globals of each file, by name, for the identifiers no REF edge links
    val globalsByFile = cpg.method.nameExact("<global>").l.groupBy(_.filename).map {
        (file, methods) => file -> methods.flatMap(_.local.l).map(l => l.name -> l).toMap
    }
    def variableOf(i: Identifier): Option[StoredNode] =
        i._refOut.collectFirst { case d @ (_: Local | _: MethodParameterIn) => d }
            .orElse(globalsByFile.get(i.method.filename).flatMap(_.get(i.name)))

    // every variable starts read-only; the frontend's graph has no CONTAINS edges yet, so the
    // locals come from the whole graph rather than per method
    cpg.local.foreach(note(_, ReadOnly))
    cpg.method.isExternal(false).parameter.foreach(note(_, ReadOnly))

    cpg.identifier.foreach { i =>
        variableOf(i).foreach { variable =>
            referenceKindOf(i, variable).foreach(note(variable, _))
        }
    }

    val tags = mutable.HashMap.empty[String, NewTag]
    kinds.foreach { (variable, found) =>
      val effective =
          if found.exists(_ != ReadOnly) then found.filterNot(_ == ReadOnly) else found
      effective.foreach { kind =>
        val tag = tags.getOrElseUpdate(
          kind, {
              val t = NewTag().name(Defines.ReferenceKindTag).value(kind)
              dstGraph.addNode(t)
              t
          }
        )
        dstGraph.addEdge(variable, tag, EdgeTypes.TAGGED_BY)
      }
    }
  end run

  /** What one occurrence of a variable does to it. */
  private def referenceKindOf(i: Identifier, variable: StoredNode): Option[String] =
    // climb through `.` and `[]` on the variable's own storage: `v.f`, `a[i]` for an array a
    val storage = storageChainTop(i, variable)
    storage._astIn.collectFirst { case c: Call => c } match
      case Some(c) if c.name == Operators.addressOf => Some(AddressTaken)
      case Some(c) if isWrite(c) && c.argumentOption(1).exists(_.id() == storage.id()) =>
          if storage.id() == i.id() && isInitializerOf(c, variable) then None
          else Some(Modified)
      case Some(c) if storage.id() == i.id() && isArray(variable) && isCallOutward(c) =>
          Some(AddressTaken)
      case Some(c) if bindsToReference(c, storage) => Some(AddressTaken)
      case _                                       => None

  /** The outermost `.`/`[]` expression over `i` that still names `variable`'s own storage. */
  private def storageChainTop(i: Identifier, variable: StoredNode): Expression =
    var top: Expression = i
    var climbing        = true
    while climbing do
      top._astIn.collectFirst { case c: Call => c } match
        case Some(c)
            if c.argumentOption(1).exists(_.id() == top.id()) &&
                (c.name == Operators.fieldAccess ||
                    (Set(Operators.indexAccess, Operators.indirectIndexAccess).contains(c.name) &&
                        top.id() == i.id() && isArray(variable))) =>
            top = c
        case _ => climbing = false
    top

  private def isWrite(c: Call): Boolean =
      c.name.startsWith("<operator>.assignment") || IncDec.contains(c.name)

  /** `int n = 5;`: the frontend writes the declarator's initializer as an assignment at the
    * declarator's own position.
    */
  private def isInitializerOf(c: Call, variable: StoredNode): Boolean =
      c.name == Operators.assignment && (variable match
        case l: Local =>
            l.lineNumber.isDefined && l.lineNumber == c.lineNumber &&
            l.columnNumber == c.columnNumber
        case _ => false
      )

  private def isArray(variable: StoredNode): Boolean = variable match
    case l: Local             => l.typeFullName.contains('[')
    case p: MethodParameterIn => false
    case _                    => false

  /** A call that is not an operator: the array argument leaves as a pointer. */
  private def isCallOutward(c: Call): Boolean = !c.name.startsWith("<operator>")

  /** The non-const reference parameters of each method the graph holds, by full name. */
  private lazy val referenceParameters: Map[String, Set[Int]] =
      cpg.method.l.flatMap { m =>
        val indices = m.parameter.l.filter { p =>
          val t = p.typeFullName.trim
          t.endsWith("&") && !t.startsWith("const ")
        }.map(_.index)
        Option.when(indices.nonEmpty)(m.fullName -> indices.toSet)
      }.toMap

  /** An argument bound to a non-const reference parameter of a method the graph holds. */
  private def bindsToReference(c: Call, arg: Expression): Boolean =
      referenceParameters.get(c.methodFullName).exists(_.contains(arg.argumentIndex))
end ReferenceKindPass

object ReferenceKindPass:
  final val AddressTaken = "address-taken"
  final val Modified     = "modified"
  final val ReadOnly     = "read-only"

  private val IncDec = Set(
    Operators.preIncrement,
    Operators.postIncrement,
    Operators.preDecrement,
    Operators.postDecrement
  )
