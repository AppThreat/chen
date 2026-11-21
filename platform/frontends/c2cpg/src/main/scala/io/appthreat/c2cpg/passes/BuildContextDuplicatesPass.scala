package io.appthreat.c2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Method, StoredNode, TypeDecl}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** The identical copies of one definition that the build contexts of a file wrote: with
  * `--c-build-contexts all` the extra contexts of a file are analysed in full, and a function whose
  * body is the same in every context is kept once, the copy the first context wrote. A function's
  * copies are the methods of one file under one full name with the same body, wherever in the file
  * each context placed it (the arms of a conditional put one function on different lines); a copy
  * whose body differs carries its context's name by then (see [[BuildContextCopies]]). A class's
  * copies are the same definition at the same place; of them, the one with the most members and
  * member functions is kept, and a member function only another copy holds moves to the kept one. A
  * method's lambdas go with it. The pass runs only when the extra contexts are analysed: the graph
  * they join otherwise holds no copies to remove.
  */
class BuildContextDuplicatesPass(cpg: Cpg, extraContextsAnalysed: Boolean) extends CpgPass(cpg):

  override def run(diffGraph: DiffGraphBuilder): Unit =
      if !extraContextsAnalysed then ()
      else
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
              val kept        = copies.maxBy(t => (t.astChildren.size, -t.id))
              val keptMembers = mutable.HashSet.from(kept.astChildren.isMethod.fullName.l)
              copies.filterNot(_ == kept).foreach { copy =>
                // a member function only this copy holds, a context's own body of it, moves
                val moved = copy.astChildren.isMethod.l.filter(m => keptMembers.add(m.fullName))
                val stays = moved.flatMap(_.ast.l).toSet[StoredNode]
                moved.foreach(m => diffGraph.addEdge(kept, m, EdgeTypes.AST))
                copy.ast.l.filterNot(stays.contains).foreach { n =>
                    if removed.add(n) then
                      n.tag.foreach(tagsOfRemoved.add)
                      diffGraph.removeNode(n)
                }
              }
            }

        val methods = cpg.method.isExternal(false).filterNot(_.name == "<global>").l
            .filterNot(removed.contains)
        val byFullName = methods.groupBy(_.fullName)
        // the lambdas a method refers to, and theirs: each unit numbers its own
        def lambdasOf(m: Method): Set[String] =
          val found = mutable.LinkedHashSet.empty[String]
          var next  = m.ast.isMethodRef.methodFullName.toSet
          while next.nonEmpty do
            found ++= next
            next = next.flatMap(byFullName.getOrElse(_, Nil)).flatMap(
              _.ast.isMethodRef.methodFullName.l
            ) -- found
          found.toSet
        methods.groupBy(m => (m.fullName, m.filename))
            .valuesIterator.filter(_.size > 1)
            .flatMap(_.groupBy(BuildContextCopies.bodyDigestOf).valuesIterator)
            .filter(_.size > 1).foreach { copies =>
              val kept        = copies.minBy(_.id)
              val keptLambdas = lambdasOf(kept)
              copies.filterNot(_ == kept).foreach { m =>
                remove(m)
                // its lambdas, written beside it: those the copy kept does not refer to
                (lambdasOf(m) -- keptLambdas).flatMap(byFullName.getOrElse(_, Nil))
                    .filterNot(removed.contains).foreach(remove)
              }
            }
        // a tag node can tag several nodes (the frontend shares one per name and value)
        tagsOfRemoved.foreach { t =>
            if t._taggedByIn.forall(removed.contains) && removed.add(t) then diffGraph.removeNode(t)
        }
  end run
end BuildContextDuplicatesPass
