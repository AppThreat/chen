package io.appthreat.dataflowengineoss.passes.reachingdef

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, ModifierTypes, Operators, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.{
    Call,
    Expression,
    FieldIdentifier,
    Identifier
}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Links writes of a static member to reads of it, across methods.
  *
  * Reaching definitions are computed per method, and a static member has no carrier between two of
  * them: an instance field rides on `this`, which is a parameter on both sides, but `Config.current
  * \= tainted` in one method and `use(Config.current)` in another share only the member itself.
  * Without an edge between them the flow simply ends - and holders, caches, registries and "current
  * request" singletons are exactly where a value gets parked between the code that receives it and
  * the code that uses it.
  *
  * The model is deliberately coarse, and flow-INSENSITIVE by construction: every write of a member
  * reaches every read of it, regardless of order or of whether the two can run in the same
  * execution. That is the sound direction for taint - a missed flow is a missed finding, whereas an
  * extra one is a path a reviewer can dismiss - and it is the only ordering claim that holds when
  * the two methods may be called in any order, from anywhere, by any thread. Which is the normal
  * case for mutable static state.
  *
  * Only members the graph actually declares as static are linked, so nothing here fires on an
  * instance field (already carried by `this`) or on a member of some external type the graph has
  * merely seen named.
  */
class StaticMemberDefUsePass(cpg: Cpg) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val staticMembers = cpg.typeDecl.internal.flatMap { typeDecl =>
        typeDecl.member
            .where(_.modifier.modifierTypeExact(ModifierTypes.STATIC))
            .name
            .map(name => s"${typeDecl.fullName}.$name")
    }.toSet

    if staticMembers.isEmpty then return

    // Filter before materializing: only accesses OF A STATIC MEMBER are kept, so the intermediate
    // list is the handful of them rather than every field access in the graph.
    val accesses = cpg.call
        .nameExact(Operators.fieldAccess, Operators.indirectFieldAccess)
        .flatMap(access => memberKey(access).filter(staticMembers.contains).map(_ -> access))
        .l
        .groupBy(_._1)
        .view
        .mapValues(_.map(_._2))
        .toMap

    accesses.foreach { case (member, sameMember) =>
        val writes = sameMember.filter(isAssignmentTarget)
        if writes.nonEmpty then
          // Every other access of the member is a destination, writes included: a write is also a
          // read for anything downstream of it, so without linking write to write
          // `a() { S.x = t; } b() { S.x = S.x + "!"; } c() { use(S.x); }` would lose the flow at
          // the intermediate write.
          writes.foreach { write =>
              sameMember.foreach { read =>
                  if read != write then
                    dstGraph.addEdge(
                      write,
                      read,
                      EdgeTypes.REACHING_DEF,
                      PropertyNames.VARIABLE,
                      member
                    )
              }
          }
    }
  end run

  /** `Owner.name` for a field access that names a member of a type, or None for anything else. */
  private def memberKey(access: Call): Option[String] =
    val field = access.argument.collectAll[FieldIdentifier].headOption.map(_.canonicalName)
    val owner = access.argument.collectAll[Identifier].headOption.flatMap { identifier =>
        // A static access is written on the TYPE (`Config.current`), so the receiver identifier's
        // own type name is the declaring type. Its `typeFullName` is what the graph indexes by.
        Option(identifier.typeFullName).filter(t => t.nonEmpty && t != "ANY")
    }
    for
      f <- field
      o <- owner
    yield s"$o.$f"

  /** True when this access is the left-hand side of an assignment, i.e. a write of the member. */
  private def isAssignmentTarget(access: Expression): Boolean =
      access.argumentIndex == 1 && access.inCall.exists(c =>
          c.name.startsWith("<operator>.assignment")
      )
end StaticMemberDefUsePass
