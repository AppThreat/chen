package io.appthreat.c2cpg.parser

import org.eclipse.cdt.core.dom.ast.{
    ASTVisitor,
    IASTDeclaration,
    IASTName,
    IASTPreprocessorIfndefStatement,
    IASTPreprocessorIncludeStatement,
    IASTPreprocessorMacroDefinition,
    IASTPreprocessorPragmaStatement,
    IASTPreprocessorStatement,
    IASTTranslationUnit,
    IProblemBinding
}
import org.eclipse.cdt.core.dom.ast.cpp.ICPPASTLinkageSpecification
import org.eclipse.cdt.internal.core.model.ASTStringUtil

import java.nio.file.{Path, Paths}
import scala.collection.mutable
import scala.util.Try

/** Decides whether a header's AST is built from the parse of the unit that includes it (its owner)
  * instead of from a parse of the header on its own. A header cannot stand on its own when its
  * content only makes sense at the position it is included at, or when it leaves names unresolved
  * that the owner declares before the `#include`: a list of `X(...)` lines expanded inside an
  * `enum` or a `switch` body, or a function whose parameter uses a typedef the includer declares
  * first. Both checks read the parses that already happen: the header's own parse for the names it
  * cannot resolve and the presence of an include guard, and the owner's parse for where the header
  * is included and what is declared before it.
  */
object HeaderFromOwner:

  /** Whether the header's AST comes from `ownerTu` (the parse of the unit that includes it) rather
    * than from the header's own parse `headerTu`. Nothing is taken from the owner when the owner
    * does not include the header through a directive its parse resolved.
    */
  def takenFromOwner(
    headerTu: IASTTranslationUnit,
    header: Path,
    ownerTu: IASTTranslationUnit
  ): Boolean = takenFromOwner(header, ownerTu, isGuarded(headerTu), unresolvedNames(headerTu))

  /** [[takenFromOwner]] with the header's guard and unresolved names already read from its parse.
    */
  def takenFromOwner(
    header: Path,
    ownerTu: IASTTranslationUnit,
    guarded: Boolean,
    unresolved: Set[String]
  ): Boolean =
    val directives = directivesFor(ownerTu, header)
    if directives.isEmpty then false
    else if !guarded && directives.exists(includedInsideDeclaration(ownerTu, _)) then true
    else
      unresolved.nonEmpty && directives.exists { directive =>
          declaredBefore(ownerTu, directive).exists(unresolved.contains)
      }

  /** Whether the owner's source text leaves room for [[takenFromOwner]] to hold, read before the
    * owner is parsed a second time on the header's behalf. It is a necessary condition, never a
    * sufficient one: some line of the owner includes a file of the header's name, and before the
    * last such line either the owner is inside braces (where an unguarded header can only expand
    * inside a declaration) or the owner's own text spells one of the names the header leaves
    * unresolved. A header whose owner fails it keeps its own parse without the owner being parsed.
    */
  def ownerMayProvide(
    ownerText: Array[Char],
    header: Path,
    guarded: Boolean,
    unresolved: Set[String]
  ): Boolean =
    val text     = stripCommentsAndLiterals(new String(ownerText))
    val baseName = Option(header.getFileName).map(_.toString).getOrElse("")
    val include  = """(?m)^[ \t]*#[ \t]*include[ \t]*["<]([^">]*)[">]""".r
    val lastInclude = include.findAllMatchIn(text)
        .filter(m => m.group(1).replace('\\', '/').split('/').lastOption.contains(baseName))
        .map(_.start)
        .maxOption
    lastInclude.exists { offset =>
      val before = text.substring(0, offset)
      (!guarded && before.count(_ == '{') > before.count(_ == '}')) ||
      (unresolved.nonEmpty &&
          """[A-Za-z_][A-Za-z0-9_]*""".r.findAllIn(before).exists(unresolved.contains))
    }

  /** The text with its comments and string and character literals blanked, keeping every offset, so
    * a brace or a name inside them is not read as code.
    */
  private def stripCommentsAndLiterals(text: String): String =
    val out = text.toCharArray
    var i   = 0
    def blank(from: Int, until: Int): Unit =
        (from until math.min(until, out.length)).foreach(j => if out(j) != '\n' then out(j) = ' ')
    while i < out.length do
      val c = out(i)
      if c == '/' && i + 1 < out.length && out(i + 1) == '/' then
        val end = text.indexOf('\n', i) match
          case -1 => out.length
          case n  => n
        blank(i, end)
        i = end
      else if c == '/' && i + 1 < out.length && out(i + 1) == '*' then
        val end = text.indexOf("*/", i + 2) match
          case -1 => out.length
          case n  => n + 2
        blank(i, end)
        i = end
      else if c == '"' || c == '\'' then
        var j = i + 1
        while j < out.length && out(j) != c && out(j) != '\n' do
          if out(j) == '\\' then j += 1
          j += 1
        // an include line's quoted name is kept: it is what the directive is matched by
        if !isIncludeLine(text, i) then blank(i + 1, j)
        i = j + 1
      else i += 1
      end if
    end while
    String.valueOf(out)
  end stripCommentsAndLiterals

  /** Whether the position lies on a preprocessor include line, whose quoted name is kept. */
  private def isIncludeLine(text: String, at: Int): Boolean =
    val lineStart = text.lastIndexOf('\n', at) + 1
    text.substring(lineStart, at).trim.replaceAll("\\s+", "").startsWith("#include")

  /** The include directives of the unit's parse that resolved to `header`. */
  def directivesFor(tu: IASTTranslationUnit, header: Path): Seq[IASTPreprocessorIncludeStatement] =
      tu.getIncludeDirectives.toSeq
          .filter(include => include.isResolved && sameFile(include.getPath, header.toString))

  /** Whether the header's own lines open an include guard: `#ifndef NAME` with `#define NAME` right
    * behind it, or `#pragma once` first. An include guard says the header was written to be parsed
    * whole, whatever position it is included at.
    */
  def isGuarded(tu: IASTTranslationUnit): Boolean =
    val own = tu.getAllPreprocessorStatements.toSeq
        .filter(_.isPartOfTranslationUnitFile)
        .sortBy(s => Option(s.getFileLocation).map(_.getNodeOffset).getOrElse(Int.MaxValue))
    own match
      case Seq(first: IASTPreprocessorPragmaStatement, rest*) =>
          String.valueOf(first.getMessage).trim.equalsIgnoreCase("once") || guardedByIfndef(rest)
      case _ => guardedByIfndef(own)

  /** The classic guard: an `#ifndef` whose macro the next statement in the same file defines. */
  private def guardedByIfndef(statements: Seq[IASTPreprocessorStatement]): Boolean =
      statements match
        case Seq(
              ifndef: IASTPreprocessorIfndefStatement,
              define: IASTPreprocessorMacroDefinition,
              rest*
            ) =>
            ASTStringUtil.getSimpleName(define.getName) == String.valueOf(ifndef.getCondition).trim
        case _ => false

  /** The names the header's own parse cannot resolve, in the header's own lines: a name CDT gives a
    * problem binding, such as a type name the includer is meant to declare first.
    */
  def unresolvedNames(tu: IASTTranslationUnit): Set[String] =
    val names = mutable.Set.empty[String]
    tu.accept(new ASTVisitor:
      shouldVisitNames = true
      override def visit(name: IASTName): Int =
        if name.isPartOfTranslationUnitFile then
          name.resolveBinding() match
            case _: IProblemBinding => names += ASTStringUtil.getSimpleName(name)
            case _                  =>
        ASTVisitor.PROCESS_CONTINUE
    )
    names.toSet

  /** Whether the header is included somewhere other than file scope: a declaration of the parse
    * spans the directive's position, and that declaration is not a linkage specification wrapping a
    * file's whole content (`extern "C" { ... }` keeps file scope).
    */
  def includedInsideDeclaration(
    tu: IASTTranslationUnit,
    directive: IASTPreprocessorIncludeStatement
  ): Boolean =
      Option(directive.getFileLocation) match
        case Some(dirLoc) =>
            val dirFile = dirLoc.getFileName
            val dirOff  = dirLoc.getNodeOffset
            tu.getDeclarations.exists { decl =>
                !decl.isInstanceOf[ICPPASTLinkageSpecification] &&
                Option(decl.getFileLocation).exists { start =>
                    start.getFileName == dirFile && start.getNodeOffset < dirOff &&
                    endsAfter(tu, decl, dirFile, dirOff)
                }
            }
        case None => false
  end includedInsideDeclaration

  /** Whether the declaration's last position lies past `offset` in the same file: a declaration
    * whose positions span two files ends where its last token is, and a directive inside it counts
    * as inside only when that token is in the file the directive is written in.
    */
  private def endsAfter(
    tu: IASTTranslationUnit,
    decl: IASTDeclaration,
    file: String,
    offset: Int
  ): Boolean =
    val locations = decl.getNodeLocations
    if locations == null || locations.isEmpty then false
    else
      Option(tu.flattenLocationsToFile(Array(locations.last))).map(_.asFileLocation()).exists {
          end => end.getFileName == file && end.getNodeOffset + end.getNodeLength > offset
      }

  /** The names the parse declares in the file the directive is written in, before the directive's
    * position: the spellings of every name that appears there (a use implies an earlier
    * declaration), and the macros defined up to it.
    */
  def declaredBefore(
    tu: IASTTranslationUnit,
    directive: IASTPreprocessorIncludeStatement
  ): Set[String] =
      Option(directive.getFileLocation) match
        case Some(dirLoc) =>
            val dirFile = dirLoc.getFileName
            val dirOff  = dirLoc.getNodeOffset
            val names   = mutable.Set.empty[String]
            tu.accept(new ASTVisitor:
              shouldVisitNames = true
              override def visit(name: IASTName): Int =
                Option(name.getFileLocation).foreach { loc =>
                    if loc.getFileName == dirFile && loc.getNodeOffset < dirOff then
                      names += ASTStringUtil.getSimpleName(name)
                }
                ASTVisitor.PROCESS_CONTINUE
            )
            tu.getAllPreprocessorStatements.foreach {
                case macroDef: IASTPreprocessorMacroDefinition =>
                    Option(macroDef.getExpansionLocation).foreach { loc =>
                        if loc.getFileName == dirFile && loc.getNodeOffset < dirOff then
                          names += ASTStringUtil.getSimpleName(macroDef.getName)
                    }
                case _ =>
            }
            names.toSet
        case None => Set.empty
  end declaredBefore

  /** Whether two spellings name the same file: compared through their real paths, since the
    * preprocessor and the scanner may reach the same file through a link or a different prefix.
    */
  private def sameFile(a: String, b: String): Boolean =
    def real(p: Path): Path = Try(p.toRealPath()).getOrElse(p.toAbsolutePath.normalize)
    real(Paths.get(a)) == real(Paths.get(b))
end HeaderFromOwner
