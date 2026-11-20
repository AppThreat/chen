package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.astcreation.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{NewFile, NewTag}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** The `#include` record per translation unit: for every header a unit's primary source file
  * includes, a tag [[Defines.IncludesTag]] valued with the header's basename on that file's FILE
  * node. Only the unit's own active includes are recorded (an include in a conditional branch the
  * preprocessor skipped selects nothing), because both C front ends write an IMPORT node only for
  * those (a header's own includes belong to the header's AST), and the record is read back from the
  * IMPORTs: what rides the AST rides the AST cache, so a warm run replays the includes with
  * everything else.
  *
  * The basename rather than the whole spelled path, because a unit spells an include as its include
  * paths allow (`<glib.h>`, `"glib/glib.h"`): the header's own name is the only part every spelling
  * agrees on, and what a file includes matters, not how it found it.
  */
class IncludeRecordPass(cpg: Cpg) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    // An IMPORT carries no filename of its own; the file it belongs to is the translation
    // unit's namespace block it sits under.
    val importsByUnit =
        cpg.namespaceBlock.l
            .flatMap(ns => Option.when(ns.filename.nonEmpty)(ns.filename -> ns.ast.isImport.l))
            .filter(_._2.nonEmpty)
    if importsByUnit.nonEmpty then
      val fileByName = cpg.file.l.groupBy(_.name)
      importsByUnit.sortBy(_._1).foreach { case (unit, imports) =>
          val active = imports.filter(_.tag.nameExact(Defines.IncludeInactiveTag).isEmpty)
          val basenames = active.map(imp =>
              IncludeRecordPass.basename(
                imp.importedEntity.orElse(imp.importedAs).getOrElse("")
              )
          ).filter(_.nonEmpty).distinct.sorted
          if basenames.nonEmpty then
            // one FILE node per unit: the node the file-creation overlay later links the
            // unit's methods to, created here when no node carries its name yet
            fileByName.get(unit).flatMap(_.headOption) match
              case Some(existing) =>
                  basenames.foreach { basename =>
                      dstGraph.addEdge(
                        existing,
                        NewTag().name(Defines.IncludesTag).value(basename),
                        EdgeTypes.TAGGED_BY
                      )
                  }
              case None =>
                  val created = NewFile().name(unit).order(0)
                  dstGraph.addNode(created)
                  basenames.foreach { basename =>
                      dstGraph.addEdge(
                        created,
                        NewTag().name(Defines.IncludesTag).value(basename),
                        EdgeTypes.TAGGED_BY
                      )
                  }
          end if
      }
    end if
  end run

end IncludeRecordPass

object IncludeRecordPass:

  /** The header's own name, whatever path the include spelled it with. */
  def basename(include: String): String =
      include.substring(math.max(include.lastIndexOf('/'), include.lastIndexOf('\\')) + 1)
