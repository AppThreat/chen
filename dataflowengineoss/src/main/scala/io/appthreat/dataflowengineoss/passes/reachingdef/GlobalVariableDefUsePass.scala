package io.appthreat.dataflowengineoss.passes.reachingdef

import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Expression, Identifier, Literal, Local}
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, PropertyNames}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Links writes of a C/C++ file-scope variable in one function to its reads in the others.
  *
  * Reaching definitions are computed per function, and a global has no carrier between two of them:
  * `g = tainted;` in one function and `use(g)` in another share only the variable. As
  * [[StaticMemberDefUsePass]] does for static members, every write reaches every read in another
  * function, regardless of order: the functions may run in any order, from anywhere.
  *
  * A write is an assignment to the variable or the variable passed to a call, which may write
  * through it (`strcpy(g, src)`): whether the callee does is decided by its semantics when flows
  * are queried. One variable is one declaration under linkage: a `static` global is its file's own,
  * an external one is the same variable in every file that declares it (`extern char *g;`).
  */
class GlobalVariableDefUsePass(cpg: Cpg) extends CpgPass(cpg):

  import GlobalVariableDefUsePass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    // the file-scope declarations: the locals directly in a `<global>` method's body (its `local`
    // traversal reaches the locals of every function the file defines)
    val globals = cpg.method.nameExact(GlobalMethodName).block.astChildren.isLocal.l
    if globals.isEmpty then return
    val keyOf = globals.map(l => l -> variableKey(l)).toMap

    val occurrences = globals.flatMap(l => l.referencingIdentifiers.l.map(keyOf(l) -> _))
        .groupBy(_._1).view.mapValues(_.map(_._2)).toMap

    occurrences.foreach { (key, identifiers) =>
      val writes = identifiers.filter(isWrite)
      if writes.nonEmpty then
        writes.foreach { write =>
          val writer = write.method
          identifiers.foreach { read =>
              if read != write && read.method != writer then
                dstGraph.addEdge(
                  write,
                  read,
                  EdgeTypes.REACHING_DEF,
                  PropertyNames.VARIABLE,
                  key.name
                )
          }
        }
    }
  end run

  private case class VariableKey(name: String, file: Option[String])

  /** A static global is its file's own; an external one is shared by name. */
  private def variableKey(local: Local): VariableKey =
    val isStatic =
        local.tag.nameExact(Defines.StorageClassTag).value.contains(Defines.StorageClassStatic)
    VariableKey(local.name, Option.when(isStatic)(local.method.filename.headOption.getOrElse("")))

  /** An assignment of a value that is not a constant, or the variable passed to a call. A constant
    * (`static const size_t limit = 64;`, `g = 0;`) carries no data to follow, and the constant
    * analyses read such a global from its own initialiser.
    */
  private def isWrite(identifier: Identifier): Boolean =
      identifier.inCall.headOption.exists { call =>
          if call.name.startsWith("<operator>.assignment") ||
            call.name.startsWith("<operators>.assignment")
          then identifier.argumentIndex == 1 && !call.argumentOption(2).exists(isConstant)
          else !call.name.startsWith("<operator") && identifier.argumentIndex >= 1
      }

  private def isConstant(value: Expression): Boolean =
      value.isInstanceOf[Literal] || value.tag.nameExact(Defines.ConstValueTag).nonEmpty
end GlobalVariableDefUsePass

object GlobalVariableDefUsePass:
  private val GlobalMethodName = "<global>"
