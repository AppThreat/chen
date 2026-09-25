package io.appthreat.x2cpg.passes.linking

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Method, Modifier, StoredNode}
import io.shiftleft.codepropertygraph.generated.{ModifierTypes, NodeTypes}
import io.shiftleft.semanticcpg.language.*

import scala.jdk.CollectionConverters.*

/** Which of the METHODs sharing a full name a reference in a given file can reach.
  *
  * C gives two `static` functions in different translation units the same name - libavformat
  * defines 706 function names in more than one file - and full-name linking alone connected every
  * call to all of them, so `a.c`'s `static get_tag` answered to `b.c`'s callers. A function with
  * internal linkage (the `static` modifier c2cpg puts on a non-member function declared static - a
  * C/C++ file's method; the check is by file, since c2cpg parents every function to its own
  * TYPE_DECL) is visible only inside its own translation unit:
  *
  *   - a file that has its own internal-linkage candidate means that one, and only its own file's
  *     candidates are reachable (its prototype and its definition);
  *   - otherwise an internal-linkage candidate in ANOTHER source file is hidden. One in a header is
  *     kept - a `static inline` helper is compiled into every file that includes it - and so is
  *     every candidate when the reference sits in a header, which some source file includes.
  *
  * A source file that is itself `#include`d (a `*_template.c`) looks like a translation unit by its
  * extension, and its calls to the including file's statics are left unlinked.
  */
final class InternalLinkage(cpg: Cpg):

  private val internal: Set[Long] =
      cpg.graph.nodes(NodeTypes.MODIFIER).asScala
          .collect { case m: Modifier if m.modifierType == ModifierTypes.STATIC => m }
          .flatMap(_._astIn)
          .collect { case m: Method if InternalLinkage.isCFamily(m.filename) => m.id() }
          .toSet

  def hasInternalLinkage(m: Method): Boolean = internal.contains(m.id())

  /** The candidates a reference in `file` can reach. With no internal-linkage candidate, or no
    * file, this is every candidate - the full-name linking as it always was.
    */
  def visibleFrom(file: Option[String], candidates: Seq[Method]): Seq[Method] =
      file match
        case Some(f)
            if internal.nonEmpty && InternalLinkage.isCFamily(f) &&
                candidates.exists(hasInternalLinkage) =>
            if candidates.exists(c => c.filename == f && hasInternalLinkage(c)) then
              candidates.filter(_.filename == f)
            else
              candidates.filterNot(c =>
                  hasInternalLinkage(c) && c.filename != f &&
                      InternalLinkage.isTranslationUnit(c.filename) &&
                      InternalLinkage.isTranslationUnit(f)
              )
        case _ => candidates

  /** The same, from the referencing node itself. */
  def visibleFrom(node: StoredNode, candidates: Seq[Method]): Seq[Method] =
      if candidates.sizeIs <= 1 && !candidates.exists(hasInternalLinkage) then candidates
      else visibleFrom(InternalLinkage.fileOf(node), candidates)
end InternalLinkage

object InternalLinkage:

  private val TranslationUnitExtensions =
      Seq(".c", ".cc", ".cpp", ".cxx", ".c++", ".cp", ".m", ".mm")

  private val HeaderExtensions = Seq(".h", ".hh", ".hpp", ".hxx", ".h++", ".inc", ".inl", ".ipp")

  def isTranslationUnit(file: String): Boolean =
    val f = Option(file).getOrElse("").toLowerCase
    TranslationUnitExtensions.exists(f.endsWith)

  /** C and C++ sources and headers: the only files whose `static` means internal linkage (a Java or
    * C# static method is an ordinary class member and is never narrowed here).
    */
  def isCFamily(file: String): Boolean =
    val f = Option(file).getOrElse("").toLowerCase
    isTranslationUnit(f) || HeaderExtensions.exists(f.endsWith)

  /** The file a node belongs to, by its enclosing method. AST parents only, so this works on the
    * raw frontend graph before the Base overlay adds CONTAINS edges.
    */
  def fileOf(node: StoredNode): Option[String] = node match
    case a: AstNode =>
        a.inAst.collectFirst { case m: Method => m }.map(_.filename).filter(f =>
            f != null && f.nonEmpty
        )
    case _ => None
end InternalLinkage
