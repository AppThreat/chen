package io.appthreat.c2cpg.passes

import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.passes.linking.InternalLinkage
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, ModifierTypes}
import io.shiftleft.codepropertygraph.generated.nodes.{Method, NewTag}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** A function's prototypes and its definition are one function, across files: the attributes a
  * prototype declares (`__attribute__((malloc))` in a header) belong to the definition another file
  * holds, which the call linkers then pick over the prototype. A prototype with internal linkage
  * (`static`) speaks only for the definition in its own file.
  */
class DeclarationAttributesPass(cpg: Cpg) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val cFamily = cpg.method.isExternal(false).l.filter(m => InternalLinkage.isCFamily(m.filename))
    val tags    = mutable.HashMap.empty[String, NewTag]
    cFamily.groupBy(_.fullName).values.filter(_.sizeIs > 1).foreach { methods =>
      val (definitions, prototypes) = methods.partition(isDefinition)
      definitions.foreach { definition =>
        val present = attributesOf(definition).toSet
        val declared = prototypes
            .filter(p => !isStatic(p) || p.filename == definition.filename)
            .flatMap(attributesOf)
            .distinct
            .filterNot(present.contains)
        declared.foreach { attr =>
          val tag = tags.getOrElseUpdate(
            attr, {
                val t = NewTag().name(Defines.FunctionAttributeTag).value(attr)
                dstGraph.addNode(t)
                t
            }
          )
          dstGraph.addEdge(definition, tag, EdgeTypes.TAGGED_BY)
        }
      }
    }
  end run

  private def attributesOf(m: Method): List[String] =
      m.tag.nameExact(Defines.FunctionAttributeTag).value.l

  private def isStatic(m: Method): Boolean =
      m.modifier.modifierType(ModifierTypes.STATIC).nonEmpty

  /** A prototype's METHOD has an empty block without a position. */
  private def isDefinition(m: Method): Boolean =
      m.block.exists(b => b.lineNumber.isDefined || b.astChildren.nonEmpty)
end DeclarationAttributesPass
