package io.appthreat.pysrc2cpg

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.appthreat.x2cpg.passes.frontend.XTypeRecovery
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Propagates resolved method return types to their call sites. PythonTypeRecovery infers a
  * method's return type from its body, but can only use it at call sites it can resolve *during*
  * recovery; callees that PythonTypeHintCallLinker resolves afterwards (in particular cross-file
  * calls into the same package) leave their callers untyped. This pass runs after the linker, reads
  * the (declared or inferred) METHOD_RETURN types, and writes them onto the call node and its
  * assignment target.
  *
  * Only declared/inferred method-return facts are used - never a traversal that derives new ones
  *   - so a single sweep reaches a fixpoint by construction and recursive or mutually-recursive
  *     functions cannot loop.
  */
class PythonCallSiteReturnTypePass(cpg: Cpg) extends ForkJoinParallelCpgPass[Call](cpg):

  private def isRecoverable(t: String): Boolean =
      t != Constants.ANY && !XTypeRecovery.isDummyType(t) && !t.contains("<operator>.")

  /** methodFullName -> return types, from method declarations only.
    *
    * Deliberately a `Seq`, not a `Set`: the head becomes the call's primary `typeFullName`, and
    * `Set.head` would pick an arbitrary hash-ordered element - possibly an inferred candidate over
    * the declared `METHOD_RETURN` type. Declaration order is `typeFullName` first, so the head is
    * the annotation whenever there is one.
    */
  private lazy val returnTypes: Map[String, Seq[String]] =
      cpg.method
          .map { m =>
            val mr = m.methodReturn
            val ts =
                (mr.typeFullName +: mr.dynamicTypeHintFullName).filter(isRecoverable).distinct
            m.fullName -> ts
          }
          .filter(_._2.nonEmpty)
          .toMap

  override def generateParts(): Array[Call] =
      cpg.call
          .filter(c =>
              !c.name.startsWith("<operator>") && returnTypes.contains(c.methodFullName)
          )
          .toArray

  override def runOnPart(builder: DiffGraphBuilder, call: Call): Unit =
      returnTypes.get(call.methodFullName).foreach { ts =>
        if call.typeFullName == Constants.ANY then
          builder.setNodeProperty(call, PropertyNames.TYPE_FULL_NAME, ts.head)
          if ts.size > 1 then
            builder.setNodeProperty(
              call,
              PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME,
              ts
            )
        // `x = f(...)` (direct) or `x = self.f(...)` (dispatch): type the assignment
        // target and the local it declares.
        call.inCall
            .nameExact(io.shiftleft.codepropertygraph.generated.Operators.assignment)
            .foreach { assignment =>
                assignment.argument.argumentIndex(1).foreach {
                    case i: Identifier if i.typeFullName == Constants.ANY =>
                        builder.setNodeProperty(i, PropertyNames.TYPE_FULL_NAME, ts.head)
                        call.method.local.nameExact(i.name).foreach { local =>
                            if local.typeFullName == Constants.ANY then
                              builder.setNodeProperty(
                                local,
                                PropertyNames.TYPE_FULL_NAME,
                                ts.head
                              )
                        }
                    case _ =>
                }
            }
      }
  end runOnPart
end PythonCallSiteReturnTypePass
