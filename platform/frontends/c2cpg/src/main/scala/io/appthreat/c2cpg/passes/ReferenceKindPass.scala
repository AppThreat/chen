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
  *     (it decays to a pointer to the array), an argument bound to a reference parameter, or the
  *     object of a member call (`this`). A variable that is itself a reference takes nothing: its
  *     referent's address was taken where it was bound;
  *   - `modified`: assigned (also through a class's assignment operator), compound-assigned,
  *     incremented or decremented after its declaration, also through a member or an element of it
  *     (`v.f = x`, `a[i] = x` for an array `a`). A declaration's own initializer is not a
  *     modification;
  *   - `read-only`: neither of the above.
  */
class ReferenceKindPass(cpg: Cpg, arrayTypedefs: Set[String] = Set.empty) extends CpgPass(cpg):

  import ReferenceKindPass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val kinds = mutable.LinkedHashMap.empty[StoredNode, mutable.LinkedHashSet[String]]
    def note(variable: StoredNode, kind: String): Unit =
        kinds.getOrElseUpdate(variable, mutable.LinkedHashSet.empty) += kind

    // a global is linked like a local (a REF edge to its LOCAL in the file's `<global>`); a name
    // with no REF edge is not a variable this graph declares
    def variableOf(i: Identifier): Option[StoredNode] =
        i._refOut.collectFirst { case d @ (_: Local | _: MethodParameterIn) => d }

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
      // a class object's assignment operator (`s = t` calling `Status::operator=`) writes it
      case Some(c) if isAssignmentOperatorCall(c) && isAssignedOperand(c, storage) =>
          Some(Modified)
      case Some(c) if storage.id() == i.id() && isArray(variable) && isCallOutward(c) =>
          Some(AddressTaken)
      // the object of a member call: `this` is its address. Through a pointer (`p->f()`) the
      // call receives the pointer's value, and through a reference the referent's address
      case Some(c)
          if isCallOutward(c) && storage.argumentIndex == 0 &&
              c.argumentOption(0).exists(_.id() == storage.id()) &&
              !isPointerVariable(variable) && !isReferenceVariable(variable) =>
          Some(AddressTaken)
      case Some(c) if !isReferenceVariable(variable) && bindsToReference(c, storage) =>
          Some(AddressTaken)
      case _ => None
    end match
  end referenceKindOf

  /** A user-defined assignment operator the frontend linked (`operator-call` names the built-in
    * operator it is written with).
    */
  private def isAssignmentOperatorCall(c: Call): Boolean =
      c.tag.nameExact(Defines.OperatorCallTag).value.exists(v =>
          v.startsWith("<operator>.assignment") || v.startsWith("<operators>.assignment")
      )

  /** The operand an assignment operator writes: the receiver of a member operator, the first
    * argument of a free one.
    */
  private def isAssignedOperand(c: Call, operand: Expression): Boolean =
      c.argumentOption(0).exists(_.id() == operand.id()) ||
          (c.argumentOption(0).isEmpty && c.argumentOption(1).exists(_.id() == operand.id()))

  /** A variable declared as a reference: binding it or calling through it reaches the referent. The
    * type the graph records drops the `&`, so it is read off the declaration (`const Options
    * &options`).
    */
  private def isReferenceVariable(variable: StoredNode): Boolean = variable match
    case l: Local             => declaresReference(l.code, l.name)
    case p: MethodParameterIn => declaresReference(p.code, p.name)
    case _                    => false

  private def declaresReference(code: String, name: String): Boolean =
      code.trim.stripSuffix(name).trim.endsWith("&")

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

  /** Any assignment or increment. The schema spells six compound forms `<operators>.assignment...`
    * (`%=`, `<<=`, `>>=`, `&=`, `|=`, `^=`).
    */
  private def isWrite(c: Call): Boolean =
      c.name.startsWith("<operator>.assignment") || c.name.startsWith("<operators>.assignment") ||
          IncDec.contains(c.name)

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

  private def isPointerVariable(variable: StoredNode): Boolean = variable match
    case l: Local             => l.typeFullName.trim.endsWith("*")
    case p: MethodParameterIn => p.typeFullName.trim.endsWith("*")
    case _                    => false

  /** A local of array type, also through typedefs (`jmp_buf`). A parameter declared as an array is
    * a pointer.
    */
  private def isArray(variable: StoredNode): Boolean = variable match
    case l: Local => isArrayType(l.typeFullName, 0)
    case _        => false

  private lazy val typeAliases: Map[String, String] =
      cpg.typeDecl.flatMap(td => td.aliasTypeFullName.map(td.fullName -> _)).toMap

  @scala.annotation.tailrec
  private def isArrayType(t: String, depth: Int): Boolean =
      t.contains('[') || arrayTypedefs.contains(t) || (depth < 8 && (typeAliases.get(t) match
        case Some(alias) => isArrayType(alias, depth + 1)
        case None        => false
      ))

  /** A call that is not an operator: the array argument leaves as a pointer. */
  private def isCallOutward(c: Call): Boolean = !c.name.startsWith("<operator>")

  /** An argument bound to a reference parameter, const or not, by the call's signature
    * (`void(int&)`): the callee receives the variable's address. A function only a header declares
    * has no METHOD to ask.
    */
  private def bindsToReference(c: Call, arg: Expression): Boolean =
      arg.argumentIndex >= 1 && !c.name.startsWith("<operator>") &&
          parameterTypes(c.signature).lift(arg.argumentIndex - 1).exists { t =>
            val tt = t.trim
            tt.endsWith("&") && !tt.endsWith("&&")
          }

  /** The parameter types of a signature `ret(a,b<c,d>,e)`, split at top-level commas. */
  private def parameterTypes(signature: String): List[String] =
    val open = signature.indexOf('(')
    if open < 0 || !signature.endsWith(")") then Nil
    else
      val inner   = signature.substring(open + 1, signature.length - 1)
      val parts   = mutable.ListBuffer.empty[String]
      var depth   = 0
      val current = new StringBuilder
      inner.foreach {
          case ',' if depth == 0 =>
              parts += current.toString; current.clear()
          case ch =>
              if ch == '<' || ch == '(' then depth += 1
              if ch == '>' || ch == ')' then depth -= 1
              current += ch
      }
      if current.nonEmpty then parts += current.toString
      parts.toList.map(_.trim).filter(_.nonEmpty)
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
