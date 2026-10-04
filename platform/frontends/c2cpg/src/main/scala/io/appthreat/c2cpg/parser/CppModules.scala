package io.appthreat.c2cpg.parser

import java.io.BufferedReader
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.util.concurrent.ConcurrentHashMap
import scala.util.Try
import scala.util.matching.Regex

/** C++20 modules, read by a parser that has none (CDT).
  *
  * A module unit is parsed as an ordinary translation unit after its module syntax is rewritten,
  * line by line, into what it means for the declarations it can see:
  *   - an import of a header unit (`import <vector>;`, `import "a.h";`) is the `#include` of that
  *     header;
  *   - an import of a named module or partition (`import hello;`, `import :format;`) includes the
  *     interface unit that declares it, found in the project; an implementation unit (`module
  *     hello;`) implicitly imports its primary interface in the same way;
  *   - an interface unit's module declaration becomes `#pragma once`, so a module imported along
  *     two paths is seen once; other module declarations, the global module fragment's `module;`
  *     and `module :private;` carry nothing for the parser and are blanked;
  *   - `export { ... }` loses its `export` and braces (an exported declaration's `export` is erased
  *     by the preprocessor, see [[CdtParser]]).
  *
  * Only those lines change, and line breaks are kept, so every other line keeps its number. An
  * import of a module the project does not declare (the standard library's `import std;` among
  * them) is blanked. Outside a module unit, `import name;` is a module import only when the project
  * declares `name`: until C++20 the line is a declaration of a variable named `name`.
  */
object CppModules:

  /** The extensions compilers use for module interface units. */
  val ModuleUnitExtensions: Set[String] = Set(".cppm", ".ccm", ".cxxm", ".c++m", ".ixx", ".mxx")

  def isModuleUnitFile(path: String): Boolean = ModuleUnitExtensions.exists(path.endsWith)

  /** The module declaration a unit starts with. */
  final case class ModuleDeclaration(name: String, partition: Option[String], exported: Boolean):
    def isInterface: Boolean        = exported
    def isPrimaryInterface: Boolean = exported && partition.isEmpty
    def isImplementation: Boolean   = !exported && partition.isEmpty

  private val Name       = """[A-Za-z_][\w.]*"""
  private val Attributes = """(?:\[\[[^\]]*\]\]\s*)?"""
  private val ModuleDecl: Regex =
      s"""^\\s*(export\\s+)?module\\s+($Name)\\s*(?::\\s*($Name))?\\s*$Attributes;\\s*$$""".r
  private val GlobalFragment: Regex  = """^\s*module\s*;\s*$""".r
  private val PrivateFragment: Regex = """^\s*module\s*:\s*private\s*;\s*$""".r
  private val HeaderImport: Regex =
      s"""^\\s*(?:export\\s+)?import\\s*(<[^>]+>|"[^"]+")\\s*$Attributes;\\s*$$""".r
  private val NamedImport: Regex =
      s"""^\\s*(export\\s+)?import\\s+($Name)\\s*$Attributes;\\s*$$""".r
  private val PartitionImport: Regex =
      s"""^\\s*(?:export\\s+)?import\\s*:\\s*($Name)\\s*$Attributes;\\s*$$""".r

  private val StandardLibraryModules = Set("std", "std.compat")

  /** The module declaration `lines` start with: the first line that is not blank, a comment, a
    * preprocessor directive (with its continuation lines) or the global module fragment's
    * `module;`. None when that line is not a module declaration.
    */
  def declarationIn(lines: Iterator[String]): Option[ModuleDeclaration] =
    var inComment    = false
    var continuation = false
    var result       = Option.empty[ModuleDeclaration]
    var decided      = false
    while !decided && lines.hasNext do
      val raw = lines.next()
      if continuation then continuation = raw.endsWith("\\")
      else
        val text = stripComments(raw, inComment)
        inComment = text._2
        val line = text._1.trim
        if line.isEmpty then ()
        else if line.startsWith("#") then continuation = raw.endsWith("\\")
        else if GlobalFragment.matches(line) then ()
        else
          decided = true
          result = line match
            case ModuleDecl(exported, name, partition) =>
                Some(ModuleDeclaration(name, Option(partition), exported != null))
            case _ => None
    result
  end declarationIn

  /** `line` without its comments, and whether a block comment is still open at its end. */
  private def stripComments(line: String, inComment: Boolean): (String, Boolean) =
    val out  = new StringBuilder
    var open = inComment
    var i    = 0
    while i < line.length do
      if open then
        val end = line.indexOf("*/", i)
        if end < 0 then i = line.length
        else
          open = false
          i = end + 2
      else if line.startsWith("//", i) then i = line.length
      else if line.startsWith("/*", i) then
        open = true
        i += 2
      else
        out.append(line.charAt(i))
        i += 1
    (out.toString, open)

  private def declarationOfFile(path: Path): Option[ModuleDeclaration] =
      Try {
          val reader: BufferedReader = Files.newBufferedReader(path, StandardCharsets.UTF_8)
          try declarationIn(Iterator.continually(reader.readLine()).takeWhile(_ != null))
          finally reader.close()
      }.toOption.flatten

  /** The module units of a project, found by their module declarations. Files with a module unit
    * extension are read first; the other C++ files only when an import names a module none of them
    * declares. Only the lines up to a file's first declaration are read.
    */
  final class ModuleIndex(moduleUnitFiles: Seq[Path], otherCppFiles: => Seq[Path]):

    private val declarations = new ConcurrentHashMap[Path, Option[ModuleDeclaration]]()
    private val rewritten    = new ConcurrentHashMap[Path, Array[Char]]()

    // interfaces and partitions can be imported; an implementation unit cannot
    private def scan(files: Seq[Path]): Map[String, Path] =
        files.flatMap { f =>
            moduleOf(f).filter(d => d.exported || d.partition.isDefined)
                .map(d => key(d.name, d.partition) -> f)
        }.groupBy(_._1).view.mapValues(_.map(_._2).minBy(_.toString)).toMap

    private lazy val primary: Map[String, Path] = scan(moduleUnitFiles)
    private lazy val all: Map[String, Path]     = scan(otherCppFiles) ++ primary

    private def key(name: String, partition: Option[String]): String =
        partition.map(p => s"$name:$p").getOrElse(name)

    def moduleOf(file: Path): Option[ModuleDeclaration] =
        declarations.computeIfAbsent(file.toAbsolutePath.normalize, declarationOfFile)

    /** The unit that declares module `name` (its primary interface), or its partition. */
    def unitOf(name: String, partition: Option[String] = None): Option[Path] =
      val k = key(name, partition)
      primary.get(k).orElse(all.get(k))

    /** `chars`, the content of `file`, with its module syntax rewritten (see [[CppModules]]); the
      * same array when it has none.
      */
    def rewrite(file: Path, chars: Array[Char]): Array[Char] =
        // remembered either way: a header is read into many units
        rewritten.computeIfAbsent(
          file.toAbsolutePath.normalize,
          f => if mayHaveModuleSyntax(chars) then rewriteLines(f, chars) else chars
        )

    private def rewriteLines(file: Path, chars: Array[Char]): Array[Char] =
      val text         = new String(chars)
      val declaration  = declarationIn(text.linesIterator)
      val isModuleUnit = declaration.isDefined || isModuleUnitFile(file.toString)
      def include(target: Option[Path]): String =
          target.filterNot(_ == file).map(t => s"#include \"${t.toString.replace('\\', '/')}\"")
              .getOrElse("")
      var changed = false
      val lines = text.split("\n", -1).map { line =>
        val replacement = line match
          case GlobalFragment() | PrivateFragment() => Some("")
          case ModuleDecl(_, _, _) if declaration.nonEmpty =>
              declaration.map { d =>
                  if d.isInterface then "#pragma once"
                  else if d.isImplementation then include(unitOf(d.name))
                  else ""
              }
          case HeaderImport(header) => Some(s"#include $header")
          case PartitionImport(partition) =>
              Some(include(declaration.flatMap(d => unitOf(d.name, Some(partition)))))
          case NamedImport(_, name) if StandardLibraryModules.contains(name) => Some("")
          case NamedImport(_, name) =>
              unitOf(name) match
                case found @ Some(_)      => Some(include(found))
                case None if isModuleUnit => Some("")
                case None                 => None
          case _ => None
        replacement match
          case Some(r) =>
              changed = true
              r
          case None => line
      }
      val joined = lines.mkString("\n")
      val result = withoutExportBlocks(joined)
      if !changed && (result eq joined) then chars else result.toCharArray
    end rewriteLines
  end ModuleIndex

  /** Whether `chars` may hold module syntax: a line starting with `module`, `import` or `export`.
    */
  private def mayHaveModuleSyntax(chars: Array[Char]): Boolean =
    var i         = 0
    var lineStart = true
    val n         = chars.length
    while i < n do
      val c = chars(i)
      if c == '\n' then lineStart = true
      else if lineStart && (c == ' ' || c == '\t') then ()
      else if lineStart then
        if startsWithWord(chars, i, "module") || startsWithWord(chars, i, "import") ||
          startsWithWord(chars, i, "export")
        then return true
        lineStart = false
      i += 1
    false

  private def startsWithWord(chars: Array[Char], at: Int, word: String): Boolean =
      at + word.length <= chars.length && word.indices.forall(k => chars(at + k) == word(k)) &&
          (at + word.length == chars.length || !Character.isJavaIdentifierPart(
            chars(at + word.length)
          ))

  /** `text` with every `export { ... }` replaced by its contents: `export`, the opening brace and
    * the matching closing brace become spaces. Comments, string and character literals are skipped.
    */
  def withoutExportBlocks(text: String): String =
    val chars   = text.toCharArray
    var changed = false
    var i       = 0
    val n       = chars.length
    def skipLiteral(from: Int): Int =
      val quote = chars(from)
      var j     = from + 1
      while j < n && chars(j) != quote && chars(j) != '\n' do
        if chars(j) == '\\' then j += 1
        j += 1
      j
    def skipTrivia(from: Int): Int =
      var j     = from
      var moved = true
      while moved && j < n do
        moved = false
        while j < n && Character.isWhitespace(chars(j)) do j += 1
        if j + 1 < n && chars(j) == '/' && chars(j + 1) == '/' then
          while j < n && chars(j) != '\n' do j += 1
          moved = true
        else if j + 1 < n && chars(j) == '/' && chars(j + 1) == '*' then
          val end = text.indexOf("*/", j + 2)
          j = if end < 0 then n else end + 2
          moved = true
      j
    def matchingBrace(open: Int): Int =
      var depth = 0
      var j     = open
      while j < n do
        chars(j) match
          case '{' => depth += 1
          case '}' =>
              depth -= 1
              if depth == 0 then return j
          case '"' | '\'' => j = skipLiteral(j)
          case '/' if j + 1 < n && (chars(j + 1) == '/' || chars(j + 1) == '*') =>
              j = skipTrivia(j) - 1
          case _ =>
        j += 1
      -1
    while i < n do
      chars(i) match
        case '"' | '\'' => i = skipLiteral(i) + 1
        case '/' if i + 1 < n && (chars(i + 1) == '/' || chars(i + 1) == '*') => i = skipTrivia(i)
        case 'e'
            if startsWithWord(chars, i, "export") &&
                (i == 0 || !Character.isJavaIdentifierPart(chars(i - 1))) =>
            val brace = skipTrivia(i + "export".length)
            if brace < n && chars(brace) == '{' then
              val close = matchingBrace(brace)
              if close > 0 then
                (i until i + "export".length).foreach(k => chars(k) = ' ')
                chars(brace) = ' '
                chars(close) = ' '
                changed = true
            i += "export".length
        case _ => i += 1
    if changed then new String(chars) else text
  end withoutExportBlocks
end CppModules
