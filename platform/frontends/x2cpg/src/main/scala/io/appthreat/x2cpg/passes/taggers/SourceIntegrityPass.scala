package io.appthreat.x2cpg.passes.taggers

import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.utils.UnicodeSkeleton
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, NodeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.nio.file.{Files, Paths}
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** Unicode that hides what source code does:
  *
  *   - `unicode-confusable` (valued with the names it can be mistaken for) on identifiers, calls
  *     and declarations whose name looks like a different name of the same file - the UTS #39
  *     skeletons are equal (`pаssword` with a Cyrillic `а`, and `password`). At least one of the
  *     names is not ASCII: ASCII names that only look alike (`rn`, `m`) are left alone;
  *   - `unicode-confusable` (valued with the spelling) on a name the file spells with Unicode
  *     escapes: JavaScript's `\u0065val(x)` calls `eval`, as Python's `ｅｖａｌ(x)` does;
  *   - `unicode-hidden-code` on the method around a Java Unicode escape that ends a line, a comment
  *     or a literal: Java translates escapes before it lexes (JLS 3.3), so `// \u000a code()`
  *     compiles code(). Valued `<line>:<escapes>`;
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
    escapedSpellings(tag)
    cpg.literal.foreach { l =>
      val controls = UnicodeSkeleton.bidiControlsIn(l.code)
      if controls.nonEmpty then tag(l, Defines.UnicodeBidiControlTag, controls.mkString(","))
    }
    // a COMMENT takes no tag: the method around it does, with the comment's line
    cpg.comment.foreach { c =>
      val controls = UnicodeSkeleton.bidiControlsIn(c.code)
      if controls.nonEmpty then
        val line = c.lineNumber.map(_.toInt).getOrElse(0)
        enclosingMethod(c.filename, line).foreach(m =>
            tag(m, Defines.UnicodeBidiControlTag, s"$line:${controls.mkString(",")}")
        )
    }
    javaUnicodeEscapes(tag)
  end run

  private lazy val methodsByFile = cpg.method.isExternal(false).l.groupBy(_.filename)

  /** The innermost method around `line` of `file`, or the file's `<global>` method. */
  private def enclosingMethod(file: String, line: Int): Option[Method] =
    val methods = methodsByFile.getOrElse(file, Nil)
    methods
        .filter(m =>
            m.lineNumber.exists(_ <= line) && m.lineNumberEnd.exists(_ >= line) &&
                m.name != "<global>"
        )
        .sortBy(m =>
            m.lineNumberEnd.map(_.toInt).getOrElse(0) - m.lineNumber.map(_.toInt).getOrElse(0)
        )
        .headOption
        .orElse(methods.find(_.name == "<global>"))

  /** The named nodes of each file: identifiers, and the declarations they name. A TYPE_DECL cannot
    * carry a TAGGED_BY edge in the schema (writing one fails the whole pass), so its name only
    * takes part in the comparison; the identifiers and members spelling it are tagged.
    */
  private def confusables(tag: (StoredNode, String, String) => Unit): Unit =
    val byFile = mutable.LinkedHashMap.empty[String, mutable.ListBuffer[(String, StoredNode)]]
    def add(file: String, name: String, node: StoredNode): Unit =
        if name.nonEmpty then
          byFile.getOrElseUpdate(file, mutable.ListBuffer.empty) += ((name, node))
    def taggable(node: StoredNode): Boolean = !node.isInstanceOf[TypeDecl]
    cpg.method.isExternal(false).foreach { m =>
      val file = m.filename
      add(file, m.name, m)
      m.parameter.foreach(p => add(file, p.name, p))
      m.local.foreach(l => add(file, l.name, l))
      m.ast.isIdentifier.foreach(i => add(file, i.name, i))
      m.ast.isCall.foreach(c => if !c.name.startsWith("<operator") then add(file, c.name, c))
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
            if lookalikes.nonEmpty && (lookalikes :+ name).exists(n =>
                  !UnicodeSkeleton.isAscii(n)
              ) &&
              taggable(node)
            then tag(node, Defines.UnicodeConfusableTag, lookalikes.sorted.mkString(","))
          }
    }
  end confusables

  /** Names whose code spells them with Unicode escapes. The frontend names the node as the language
    * means it and keeps the spelling in its code.
    */
  private def escapedSpellings(tag: (StoredNode, String, String) => Unit): Unit =
    def check(node: StoredNode, name: String, code: String): Unit =
        if code.contains("\\u") then
          UnicodeSkeleton.escapedSpelling(code, name).foreach(tag(
            node,
            Defines.UnicodeConfusableTag,
            _
          ))
    cpg.identifier.foreach(i => check(i, i.name, i.code))
    cpg.graph.nodes(NodeTypes.FIELD_IDENTIFIER).asScala.collect { case f: FieldIdentifier =>
        check(f, f.canonicalName, f.code)
    }
    cpg.parameter.foreach(p => check(p, p.name, p.code))
    cpg.call.foreach(c => if !c.name.startsWith("<operator") then check(c, c.name, c.code))

  /** Java files read as the file is: the frontend parsed them with the escapes translated, so its
    * names and code no longer show them.
    */
  private def javaUnicodeEscapes(tag: (StoredNode, String, String) => Unit): Unit =
    val root = cpg.metaData.root.headOption.getOrElse("")
    cpg.file.nameNot("<.*").filter(_.name.endsWith(".java")).foreach { file =>
      val path = Paths.get(file.name) match
        case p if p.isAbsolute => p
        case p                 => Paths.get(root).resolve(p)
      Try(Files.readString(path)).filter(_.contains("\\u")).foreach { text =>
        val escapes = JavaUnicodeEscapes.scan(text)
        JavaUnicodeEscapes.hiddenCode(text, escapes).foreach { (line, spellings) =>
            enclosingMethod(file.name, line).foreach(m =>
                tag(m, Defines.UnicodeHiddenCodeTag, s"$line:${spellings.mkString(",")}")
            )
        }
        val spelled = JavaUnicodeEscapes.escapedNames(text)
        if spelled.nonEmpty then
          def check(node: StoredNode, name: String, line: Option[Int]): Unit =
              line.flatMap(l => spelled.get((l, name))).foreach(
                tag(node, Defines.UnicodeConfusableTag, _)
              )
          val methods = methodsByFile.getOrElse(file.name, Nil)
          methods.foreach { m =>
            check(m, m.name, m.lineNumber.map(_.toInt))
            m.parameter.foreach(p => check(p, p.name, p.lineNumber.map(_.toInt)))
            m.local.foreach(l => check(l, l.name, l.lineNumber.map(_.toInt)))
            m.ast.foreach {
                case i: Identifier      => check(i, i.name, i.lineNumber.map(_.toInt))
                case f: FieldIdentifier => check(f, f.canonicalName, f.lineNumber.map(_.toInt))
                case c: Call if !c.name.startsWith("<operator") =>
                    check(c, c.name, c.lineNumber.map(_.toInt))
                case _ =>
            }
          }
          cpg.typeDecl.filenameExact(file.name).member.foreach(mb =>
              check(mb, mb.name, mb.lineNumber.map(_.toInt))
          )
        end if
      }
    }
  end javaUnicodeEscapes
end SourceIntegrityPass

/** Java's Unicode escapes (JLS 3.3), read from a file as written: `\uXXXX` with any number of `u`,
  * when its backslash is preceded by an even number of backslashes.
  */
object JavaUnicodeEscapes:

  /** An escape: its offsets in the file, its line, the character it is. */
  final case class Escape(start: Int, end: Int, line: Int, char: Char):
    def spelling(text: String): String = text.substring(start, end)

  def scan(text: String): List[Escape] =
    val escapes = mutable.ListBuffer.empty[Escape]
    var line    = 1
    var i       = 0
    var slashes = 0 // contiguous backslashes before i
    while i < text.length do
      val c = text.charAt(i)
      if c == '\\' && slashes % 2 == 0 && i + 1 < text.length && text.charAt(i + 1) == 'u' then
        var j = i + 1
        while j < text.length && text.charAt(j) == 'u' do j += 1
        val hex = text.slice(j, j + 4)
        if hex.length == 4 && hex.forall(Character.digit(_, 16) >= 0) then
          escapes += Escape(i, j + 4, line, Integer.parseInt(hex, 16).toChar)
          i = j + 4
          slashes = 0
        else
          slashes += 1
          i += 1
      else
        if c == '\n' then line += 1
        slashes = if c == '\\' then slashes + 1 else 0
        i += 1
    escapes.toList
  end scan

  /** The lines with escapes that end a line, a comment or a literal, or open a comment: a line
    * terminator, a quote, or a `/*`, `*/` or `//` one of whose characters is an escape.
    */
  def hiddenCode(text: String, escapes: List[Escape]): List[(Int, List[String])] =
    val byStart = escapes.map(e => e.start -> e).toMap
    // the file as Java reads it: each character with the escape it came from
    val decoded = mutable.ArrayBuffer.empty[(Char, Option[Escape])]
    var i       = 0
    while i < text.length do
      byStart.get(i) match
        case Some(e) =>
            decoded += ((e.char, Some(e)))
            i = e.end
        case None =>
            decoded += ((text.charAt(i), None))
            i += 1
    val hidden = mutable.LinkedHashSet.empty[Escape]
    decoded.indices.foreach { k =>
      val (c, from) = decoded(k)
      from.foreach(e => if "\n\r\"'".contains(c) then hidden += e)
      if k + 1 < decoded.length then
        val (next, nextFrom) = decoded(k + 1)
        val pair             = s"$c$next"
        if (pair == "/*" || pair == "*/" || pair == "//") && (from.isDefined || nextFrom.isDefined)
        then
          from.foreach(hidden += _)
          nextFrom.foreach(hidden += _)
    }
    hidden.toList.groupBy(_.line).toList.sortBy(_._1).map((line, es) =>
        line -> es.map(_.spelling(text)).distinct
    )
  end hiddenCode

  /** (line, name) of each name the file spells with escapes, to the spelling. */
  def escapedNames(text: String): Map[(Int, String), String] =
    val lineStarts = text.indices.filter(text.charAt(_) == '\n').map(_ + 1).prepended(0)
    def lineOf(offset: Int): Int =
      val k = java.util.Arrays.binarySearch(lineStarts.toArray, offset)
      if k >= 0 then k + 1 else -k - 1
    UnicodeSkeleton.escapedNameTokens(text)
        .map((offset, token) => (lineOf(offset), UnicodeSkeleton.decodeEscapes(token)) -> token)
        .toMap
end JavaUnicodeEscapes
