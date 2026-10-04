package io.appthreat.c2cpg.parser

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.ConcurrentHashMap
import scala.collection.mutable
import scala.util.Try

/** Which translation units include each header of the project, read from the `#include` lines (and
  * header-unit imports) of the project's files and resolved as the preprocessor would: a quoted
  * name next to the including file first, then on the include search path, then by its trailing
  * path segments among the project's headers.
  *
  * A header has no language of its own: it is compiled as part of the units that include it. A
  * header is C++ when a C++ unit includes it (directly or through other headers); the flags it is
  * parsed with are those of the first such unit.
  */
final class IncludeGraph(
  projectFiles: Set[Path],
  includePathsOf: Path => Seq[Path],
  headerFileFinder: HeaderFileFinder
):

  private val includesCache = new ConcurrentHashMap[(Path, Seq[Path]), Seq[Path]]()

  private val Directive =
      """^\s*#\s*(?:include|include_next|import)\s*([<"])([^>"]+)[>"]""".r.unanchored
  private val HeaderUnit = """^\s*(?:export\s+)?import\s*([<"])([^>"]+)[>"]\s*;""".r.unanchored

  /** The project files `file` includes, as `unit` (whose include search path applies) sees them. */
  private def includesOf(file: Path, unit: Path): Seq[Path] =
      includesCache.computeIfAbsent(
        (file, includePathsOf(unit)),
        key =>
          val f = key._1
          val lines = Try(Files.readAllLines(f, StandardCharsets.UTF_8)).toOption
              .orElse(Try(Files.readAllLines(f, StandardCharsets.ISO_8859_1)).toOption)
              .map(_.toArray(Array.empty[String]).toSeq).getOrElse(Nil)
          lines.flatMap {
              case Directive(kind, name)  => resolve(name, kind == "\"", f, unit)
              case HeaderUnit(kind, name) => resolve(name, kind == "\"", f, unit)
              case _                      => None
          }.distinct
      )

  private def resolve(name: String, quoted: Boolean, includer: Path, unit: Path): Option[Path] =
    val local    = if quoted then Option(includer.getParent).map(_.resolve(name)) else None
    val searched = local.toSeq ++ includePathsOf(unit).map(_.resolve(name))
    searched.map(_.normalize).find(projectFiles.contains)
        .orElse(
          headerFileFinder.find(name, Some(includer)).map(p =>
              Paths.get(p).toAbsolutePath.normalize
          )
              .filter(projectFiles.contains)
              // a bare basename match must agree on the path segments the include spells out
              .filter(p => p.endsWith(Paths.get(name).normalize))
        )

  /** The project headers `unit` includes, directly or through other headers, in the order they are
    * reached.
    */
  def reachableFrom(unit: Path): Seq[Path] =
    val seen  = mutable.LinkedHashSet.empty[Path]
    val queue = mutable.Queue.from(includesOf(unit, unit))
    while queue.nonEmpty do
      val header = queue.dequeue()
      if header != unit && seen.add(header) then includesOf(header, unit).foreach(queue.enqueue)
    seen.toSeq

  /** For each header reached from `units`: the first unit (in the order given) of each language
    * that includes it.
    */
  def includers(units: Seq[(Path, SourceLanguage)]): Map[Path, Map[SourceLanguage, Path]] =
    val result  = mutable.HashMap.empty[Path, mutable.Map[SourceLanguage, Path]]
    val visited = SourceLanguage.values.map(_ -> mutable.HashSet.empty[Path]).toMap
    units.foreach { (unit, language) =>
      val seen  = visited(language)
      val queue = mutable.Queue.empty[Path]
      includesOf(unit, unit).foreach(queue.enqueue)
      while queue.nonEmpty do
        val header = queue.dequeue()
        if header != unit && seen.add(header) then
          result.getOrElseUpdate(header, mutable.HashMap.empty).getOrElseUpdate(language, unit)
          includesOf(header, unit).foreach(queue.enqueue)
    }
    result.view.mapValues(_.toMap).toMap
end IncludeGraph

object IncludeGraph:

  private val CppOnlyLine =
      """^\s*(?:class\s+\w+[^;]*[{:]|namespace\s+\w*\s*\{|template\s*<|using\s+namespace\s|(?:public|private|protected)\s*:|extern\s+"C\+\+"|#\s*include\s*<(?:iostream|string|vector|memory|map|cstdint|cstdio|cstdlib|cstring|algorithm|utility|functional)>)""".r

  /** Whether `file`, a header no unit includes, reads as C++: it declares a class, namespace or
    * template, or includes a C++ standard header.
    */
  def readsAsCpp(file: Path): Boolean =
      Try(Files.readAllLines(file, StandardCharsets.UTF_8)).toOption
          .orElse(Try(Files.readAllLines(file, StandardCharsets.ISO_8859_1)).toOption)
          .exists(lines =>
              lines.toArray(Array.empty[String]).exists(l => CppOnlyLine.findFirstIn(l).isDefined)
          )
