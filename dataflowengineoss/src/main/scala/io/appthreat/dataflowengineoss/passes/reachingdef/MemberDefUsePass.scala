package io.appthreat.dataflowengineoss.passes.reachingdef

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{
    Call,
    Expression,
    FieldIdentifier,
    Identifier,
    Local,
    Method,
    MethodParameterIn
}
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Languages, Operators, PropertyNames}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Links writes of a C++ class's data member in one of its member functions to the member's reads
  * in the others.
  *
  * An object carries its state from one member function to the next - a constructor stores a value
  * that the destructor or a later method uses - but reaching definitions are computed per function,
  * and the frontend writes an implicit member access (`data`, for `this->data`) as a bare name. As
  * for static members and globals, the link is flow-insensitive and per class, not per object:
  * every write of `C::m` reaches every read of `C::m` in another member function of `C`.
  *
  * A write is an assignment to the member, linked from the assignment (its value is the one
  * stored), or the member passed to a call, which may write through it; whether the callee does is
  * decided by its semantics when flows are queried.
  */
class MemberDefUsePass(cpg: Cpg) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val language = cpg.metaData.language.headOption.getOrElse("")
    if language != Languages.NEWC && language != Languages.C then return

    val membersOf: Map[String, Set[String]] = cpg.typeDecl.isExternal(false)
        .map(td => td.fullName -> td.member.name.toSet)
        .filter(_._2.nonEmpty)
        .toMap
    if membersOf.isEmpty then return

    val accesses = cpg.method.isExternal(false).flatMap { method =>
        ownerOf(method).flatMap(owner => membersOf.get(owner).map(owner -> _)).toList.flatMap {
            (owner, members) =>
                memberAccesses(method, members).map((member, node) => (owner, member, node))
        }
    }.l

    accesses.groupBy(a => (a._1, a._2)).foreach { case ((owner, member), sameMember) =>
        val nodes  = sameMember.map(_._3)
        val writes = nodes.flatMap(writeOf)
        writes.foreach { write =>
          val writer = write.method
          nodes.foreach { read =>
              if read != write && read.method != writer then
                dstGraph.addEdge(
                  write,
                  read,
                  EdgeTypes.REACHING_DEF,
                  PropertyNames.VARIABLE,
                  s"$owner.$member"
                )
          }
        }
    }
  end run

  /** The class a member function belongs to: its full name up to the function's own name. */
  private def ownerOf(method: Method): Option[String] =
    val qualified = method.fullName.takeWhile(_ != ':')
    val dot       = qualified.lastIndexOf('.')
    Option.when(dot > 0 && qualified.substring(dot + 1) == method.name)(qualified.substring(0, dot))

  /** The accesses of the class's members in a member function: `this->m`, and `m` where the name is
    * no local or parameter of the function.
    */
  private def memberAccesses(method: Method, members: Set[String]): List[(String, Expression)] =
    val implicitAccesses = method.ast.isIdentifier.filter { id =>
        members.contains(id.name) && !id._refOut.exists {
            case _: Local | _: MethodParameterIn => true
            case _                               => false
        }
    }.map(id => id.name -> (id: Expression)).l
    val explicitAccesses = method.ast.isCall.nameExact(Operators.indirectFieldAccess).flatMap {
        access =>
          val onThis = access.argumentOption(1).exists {
              case id: Identifier => id.name == "this"
              case _              => false
          }
          access.argument.collectAll[FieldIdentifier].headOption
              .filter(f => onThis && members.contains(f.canonicalName))
              .map(f => f.canonicalName -> (access: Expression))
    }.l
    implicitAccesses ++ explicitAccesses

  /** The node that defines the member's new value: an assignment (whose value is the one stored;
    * the member's bare name is no definition of the function's own), or the member passed to a
    * call.
    */
  private def writeOf(access: Expression): Option[Expression] =
      access.inCall.headOption.flatMap { call =>
          if call.name.startsWith("<operator>.assignment") ||
            call.name.startsWith("<operators>.assignment")
          then Option.when(access.argumentIndex == 1)(call)
          else Option.when(!call.name.startsWith("<operator") && access.argumentIndex >= 1)(access)
      }
end MemberDefUsePass
