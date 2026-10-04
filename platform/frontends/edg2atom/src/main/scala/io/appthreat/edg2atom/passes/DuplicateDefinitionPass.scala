package io.appthreat.edg2atom.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Method, StoredNode, TypeDecl}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** One copy of each definition several translation units wrote: the template instances each unit
  * writes from the project headers it uses (the same template with the same arguments is the same
  * code whichever unit wrote it). Copies are the same definition at the same place: the same full
  * name, file, position and code. Of a class's copies, the one with the most members and member
  * functions is kept; a method's lambdas go with it.
  */
class DuplicateDefinitionPass(cpg: Cpg) extends CpgPass(cpg):

  override def run(diffGraph: DiffGraphBuilder): Unit =
    val removed       = mutable.HashSet.empty[StoredNode]
    val tagsOfRemoved = mutable.LinkedHashSet.empty[StoredNode]
    def remove(node: AstNode): Unit =
        node.ast.l.foreach { n =>
            if removed.add(n) then
              n.tag.foreach(tagsOfRemoved.add)
              diffGraph.removeNode(n)
        }

    cpg.typeDecl.isExternal(false).filterNot(_.name == "<global>").l
        .groupBy(t => (t.fullName, t.filename, t.lineNumber, t.columnNumber))
        .valuesIterator.filter(_.size > 1).foreach { copies =>
          val kept = copies.maxBy(t => (t.astChildren.size, -t.id))
          copies.filterNot(_ == kept).foreach(remove)
        }

    val methods = cpg.method.isExternal(false).filterNot(_.name == "<global>").l
        .filterNot(removed.contains)
    methods.groupBy(m => (m.fullName, m.filename, m.lineNumber, m.columnNumber, m.code))
        .valuesIterator.filter(_.size > 1).foreach { copies =>
          val kept = copies.minBy(_.id)
          copies.filterNot(_ == kept).foreach { m =>
            remove(m)
            // its lambdas, written beside it
            methods.filter(l => l.fullName.startsWith(m.fullName + ".") && l.id != m.id)
                .filterNot(removed.contains).foreach(remove)
          }
        }
    // a tag node can tag several nodes (the CDT frontend shares one per name and value)
    tagsOfRemoved.foreach { t =>
        if t._taggedByIn.forall(removed.contains) && removed.add(t) then diffGraph.removeNode(t)
    }
  end run
end DuplicateDefinitionPass
