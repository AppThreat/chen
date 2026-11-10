package io.appthreat.edg2atom.parser

import ujson.Value

import scala.collection.mutable

/** One translation unit as edga wrote it (schema `edga/1`): tables by id, and access helpers for
  * the nodes of its routine bodies.
  */
final class EdgaUnit(val root: Value):
  import EdgaUnit.{flag, string}

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
      EdgaUnit.hostPath(f("path").str),
      f.obj.get("system").exists(_.bool),
      f.obj.get("inRoot").exists(_.bool),
      f.obj.get("includedFrom").map(v => (v(0).num.toLong, v(1).num.toInt)),
      f.string("written"),
      f.flag("systemInclude")
    )
  }.toMap

  val types: Map[Long, Value] = table("types").map(t => t("id").num.toLong -> t).toMap

  /** The unit's file- and namespace-scope enumerators, each with where it is declared (edga 0.2's
    * `enumerators`; empty from an older export).
    */
  val enumerators: Seq[Value]  = table("enumerators")
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

  /** The unit's global variables by id: an expression reads one through its `var` reference. */
  val globalsById: Map[Long, Value] = globals.map(g => g("id").num.toLong -> g).toMap

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
  includedFrom: Option[(Long, Int)],
  written: Option[String] = None,
  systemInclude: Boolean = false
)

/** A position: `[file, line, column]`. */
final case class Pos(file: Long, line: Int, column: Int)

object EdgaUnit:
  def parse(text: String): EdgaUnit = new EdgaUnit(ujson.read(text))

  private val hostPaths = new java.util.concurrent.ConcurrentHashMap[String, String]()

  /** A file's path as the rest of the frontend spells it. On Windows edga writes the path the front
    * end opened, with `/` separators and the 8.3 short names a temporary directory such as
    * `C:/Users/RUNNER~1/...` can carry, while the project's own paths, the preinclude files and the
    * CDT frontend's tags use the real path, `C:\Users\runneradmin\...`; there the path is resolved
    * to its real form. Elsewhere edga's path is already the real one and is kept as written.
    */
  def hostPath(path: String): String =
      if !scala.util.Properties.isWin || path.isEmpty then path
      else
        hostPaths.computeIfAbsent(
          path,
          p =>
              // a name the file system cannot hold (`<built-in>`) stays as edga wrote it
              scala.util.Try(java.nio.file.Paths.get(p)).map { file =>
                  scala.util.Try(file.toRealPath()).getOrElse(file.toAbsolutePath.normalize)
                      .toString
              }.getOrElse(p)
        )

  /** The document straight from the bytes edga wrote: no intermediate string of the whole unit */
  def parseBytes(bytes: Array[Byte]): EdgaUnit = new EdgaUnit(ujson.read(bytes))

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
