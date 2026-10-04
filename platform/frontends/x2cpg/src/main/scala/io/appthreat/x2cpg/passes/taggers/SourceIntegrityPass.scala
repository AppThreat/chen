package io.appthreat.x2cpg.passes.taggers

import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.utils.UnicodeSkeleton
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Unicode that hides what source code does:
  *
  *   - `unicode-confusable` (valued with the names it can be mistaken for) on identifiers and
  *     declarations whose name looks like a different name of the same file - the UTS #39 skeletons
  *     are equal (`pаssword` with a Cyrillic `а`, and `password`). At least one of the names is not
  *     ASCII: ASCII names that only look alike (`rn`, `m`) are left alone;
  *   - `unicode-bidi-control` (valued with the code points, `U+202E`) on string literals that
  *     contain bidirectional formatting characters, which can make the code a reviewer reads differ
  *     from the code that is compiled (CVE-2021-42574). A comment cannot carry a tag: the method
  *     around it does (the file's `<global>` method outside any function), valued `<line>:<code
  *     points>`.
  */
class SourceIntegrityPass(cpg: Cpg) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val tags = mutable.HashMap.empty[(String, String), NewTag]
    def tag(node: StoredNode, name: String, value: String): Unit =
      val t = tags.getOrElseUpdate(
        (name, value), {
            val created = NewTag().name(name).value(value)
            dstGraph.addNode(created)
            created
        }
      )
      dstGraph.addEdge(node, t, EdgeTypes.TAGGED_BY)

    confusables(tag)
    cpg.literal.foreach { l =>
      val controls = UnicodeSkeleton.bidiControlsIn(l.code)
      if controls.nonEmpty then tag(l, Defines.UnicodeBidiControlTag, controls.mkString(","))
    }
    // a COMMENT takes no tag: the method around it does, with the comment's line
    lazy val methodsByFile = cpg.method.isExternal(false).l.groupBy(_.filename)
    cpg.comment.foreach { c =>
      val controls = UnicodeSkeleton.bidiControlsIn(c.code)
      if controls.nonEmpty then
        val line    = c.lineNumber.map(_.toInt)
        val file    = c.filename
        val methods = methodsByFile.getOrElse(file, Nil)
        val enclosing = methods.filter(m =>
            line.exists(l =>
                m.lineNumber.exists(_ <= l) && m.lineNumberEnd.exists(_ >= l) &&
                    m.name != "<global>"
            )
        ).sortBy(m =>
            m.lineNumberEnd.map(_.toInt).getOrElse(0) - m.lineNumber.map(_.toInt).getOrElse(0)
        )
            .headOption.orElse(methods.find(_.name == "<global>"))
        enclosing.foreach(m =>
            tag(m, Defines.UnicodeBidiControlTag, s"${line.getOrElse(0)}:${controls.mkString(",")}")
        )
    }
  end run

  /** The named nodes of each file: identifiers, and the declarations they name. */
  private def confusables(tag: (StoredNode, String, String) => Unit): Unit =
    val byFile = mutable.LinkedHashMap.empty[String, mutable.ListBuffer[(String, StoredNode)]]
    def add(file: String, name: String, node: StoredNode): Unit =
        if name.nonEmpty then
          byFile.getOrElseUpdate(file, mutable.ListBuffer.empty) += ((name, node))
    cpg.method.isExternal(false).foreach { m =>
      val file = m.filename
      add(file, m.name, m)
      m.parameter.foreach(p => add(file, p.name, p))
      m.local.foreach(l => add(file, l.name, l))
      m.ast.isIdentifier.foreach(i => add(file, i.name, i))
    }
    cpg.typeDecl.isExternal(false).foreach { td =>
      add(td.filename, td.name, td)
      td.member.foreach(mb => add(td.filename, mb.name, mb))
    }
    byFile.values.foreach { named =>
        // only files that have a non-ASCII name can hold a confusable pair
        if named.exists((n, _) => !UnicodeSkeleton.isAscii(n)) then
          val namesBySkeleton = named.map(_._1).distinct.groupBy(UnicodeSkeleton.skeleton)
          named.foreach { (name, node) =>
            val lookalikes = namesBySkeleton(UnicodeSkeleton.skeleton(name)).filterNot(_ == name)
            if lookalikes.nonEmpty && (lookalikes :+ name).exists(n => !UnicodeSkeleton.isAscii(n))
            then tag(node, Defines.UnicodeConfusableTag, lookalikes.sorted.mkString(","))
          }
    }
  end confusables
end SourceIntegrityPass
