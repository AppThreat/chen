package io.appthreat.c2cpg.passes

import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{Local, MethodParameterIn, NewTag}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** Tags the identifiers that read a header constant with its compile-time value
  * ([[Defines.ConstValueTag]]): the AST pass recorded `name -> value` for `const`/`constexpr`
  * integrals it could resolve but not see defined. An identifier bound to a local or a parameter is
  * that variable, not the constant, and is left alone.
  */
class ConstantTagPass(cpg: Cpg, constants: Map[String, Long]) extends CpgPass(cpg):
  override def run(dstGraph: DiffGraphBuilder): Unit =
      if constants.nonEmpty then
        val tags = constants.map((name, value) =>
            name -> NewTag().name(Defines.ConstValueTag).value(value.toString)
        )
        var used = Set.empty[String]
        cpg.identifier.filter(i => constants.contains(i.name)).foreach { i =>
          val local = i._refOut.exists {
              case _: Local | _: MethodParameterIn => true
              case _                               => false
          }
          if !local then
            if !used.contains(i.name) then
              dstGraph.addNode(tags(i.name))
              used += i.name
            dstGraph.addEdge(i, tags(i.name), EdgeTypes.TAGGED_BY)
        }
