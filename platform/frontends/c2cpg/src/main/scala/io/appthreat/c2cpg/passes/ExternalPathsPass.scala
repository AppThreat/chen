package io.appthreat.c2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.{Method, TypeDecl}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.util.Try

/** Marks the methods and types of vendored paths external (`--external-paths`, decision 0001 P5):
  * code a project carries from someone else (`third_party/`, a copied single-header library) is
  * parsed as always - its bodies and types are needed - but it is not the project's own code, and
  * uses of it from the project are uses of a dependency. The pattern is matched against each file's
  * path as the graph names it, relative to the input root, with either separator.
  */
class ExternalPathsPass(cpg: Cpg, pattern: String) extends CpgPass(cpg):

  private val regex = Try(pattern.r).toOption

  override def run(dstGraph: overflowdb.BatchedUpdate.DiffGraphBuilder): Unit =
      regex.foreach { re =>
        def vendored(path: String): Boolean =
            path.nonEmpty && re.findFirstMatchIn(path.replace('\\', '/')).isDefined
        cpg.method.isExternal(false).l.foreach { m =>
            if vendored(m.filename) then
              dstGraph.setNodeProperty(m.asInstanceOf[Method], PropertyNames.IS_EXTERNAL, true)
        }
        cpg.typeDecl.isExternal(false).l.foreach { t =>
            if vendored(t.filename) then
              dstGraph.setNodeProperty(t.asInstanceOf[TypeDecl], PropertyNames.IS_EXTERNAL, true)
        }
      }
