package io.appthreat.edg2atom.parser

import ujson.Value

import scala.collection.mutable

/** One translation unit as edga wrote it (schema `edga/1`): tables by id, and access helpers for
  * the nodes of its routine bodies.
  */
final class EdgaUnit(val root: Value):

  val path: String     = root("tu").obj.get("path").map(_.str).getOrElse("")
  val status: String   = root("tu").obj.get("status").map(_.str).getOrElse("failed")
  val language: String = root("tu").obj.get("language").map(_.str).getOrElse("c")
  def isCpp: Boolean   = language == "c++"

  private def table(name: String): Seq[Value] =
      root.obj.get(name).map(_.arr.toSeq).getOrElse(Seq.empty)

  val files: Map[Long, FileEntry] = table("files").map { f =>
    val id = f("id").num.toLong
    id -> FileEntry(
      id,
      f("path").str,
      f.obj.get("system").exists(_.bool),
      f.obj.get("inRoot").exists(_.bool),
      f.obj.get("includedFrom").map(v => (v(0).num.toLong, v(1).num.toInt))
    )
  }.toMap

  val types: Map[Long, Value]  = table("types").map(t => t("id").num.toLong -> t).toMap
  val macros: Map[Long, Value] = table("macros").map(m => m("id").num.toLong -> m).toMap
  val invocations: Map[Long, Value] =
      table("macroInvocations").map(m => m("id").num.toLong -> m).toMap

  /** The unit's inline namespaces, qualified (`std::__1`), longest first. */
  val inlineNamespaces: Seq[String] =
      table("inlineNamespaces").collect { case ujson.Str(n) => n }.sortBy(n => -n.length)

  val routines: Seq[Value]    = table("routines")
  val globals: Seq[Value]     = table("globals")
  val diagnostics: Seq[Value] = table("diagnostics")

  val routinesById: Map[Long, Value] = routines.map(r => r("id").num.toLong -> r).toMap

  /** The file a translation unit is: file 0, the primary source file. */
  def primaryFile: Option[FileEntry] = files.get(0L)

  /** The top-level invocation an invocation was expanded in (itself when it has no parent). */
  def topLevelInvocation(index: Long): Long =
    var current = index
    var guard   = 0
    while guard < 1000 && invocations.get(current).exists(i => i("parent").num.toLong > 0) do
      current = invocations(current)("parent").num.toLong
      guard += 1
    current
end EdgaUnit

final case class FileEntry(
  id: Long,
  path: String,
  system: Boolean,
  inRoot: Boolean,
  includedFrom: Option[(Long, Int)]
)

/** A position: `[file, line, column]`. */
final case class Pos(file: Long, line: Int, column: Int)

object EdgaUnit:
  def parse(text: String): EdgaUnit = new EdgaUnit(ujson.read(text))

  def pos(v: Value): Option[Pos] =
      v match
        case ujson.Arr(items) if items.size == 3 =>
            Some(Pos(items(0).num.toLong, items(1).num.toInt, items(2).num.toInt))
        case _ => None

  extension (v: Value)
    def field(name: String): Option[Value] = v match
      case o: ujson.Obj => o.value.get(name).filterNot(_.isNull)
      case _            => None
    def string(name: String): Option[String] = field(name).collect { case ujson.Str(s) => s }
    def long(name: String): Option[Long]     = field(name).collect { case ujson.Num(n) => n.toLong }
    def flag(name: String): Boolean          = field(name).exists(_.boolOpt.contains(true))
    def list(name: String): Seq[Value]       = field(name).map(_.arr.toSeq).getOrElse(Seq.empty)
    def position: Option[Pos]                = field("p").flatMap(EdgaUnit.pos)
    def origin: Option[Pos]                  = field("po").flatMap(EdgaUnit.pos)
    def kind: String                         = string("k").getOrElse("")
end EdgaUnit
