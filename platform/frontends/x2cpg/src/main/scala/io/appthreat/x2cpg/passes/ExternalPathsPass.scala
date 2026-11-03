package io.appthreat.x2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.{NewTag, StoredNode}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable
import scala.util.Try
import scala.util.matching.Regex

/** Which input paths are vendored code (`--external-paths`, decision 0001 P5), in one meaning for
  * every frontend: a regular expression matched against a file's path as the graph names it,
  * relative to the input root, with `/` as separator whatever the platform.
  *
  * A match must begin at the start of a path segment: at the beginning of the relative path or
  * right after a `/`. `third_party` therefore names `third_party/zlib/a.c` and
  * `src/third_party/zlib/a.c`, never `src/not_third_party/a.c`. The match may end anywhere; the
  * vendored directory (or file) is the path up to the end of the segment the match ends in, so
  * `third_party/` and `third_party/[^/]+` give `third_party` and `third_party/zlib`. When the
  * pattern has a capture group the group's end decides instead, so `(third_party/[^/]+)/src` names
  * `third_party/zlib`.
  */
final class ExternalPathMatcher private (private val regex: Option[Regex]):

  /** Whether the pattern is usable and non-empty: a run with no pattern marks nothing. */
  def isEmpty: Boolean = regex.isEmpty

  private val cache = mutable.HashMap.empty[String, Option[String]]

  /** The vendored directory (or file) a path lies in: `third_party/zlib/zlib.c` ->
    * `Some("third_party/zlib")` for `third_party/[^/]+`; `None` for a path the pattern does not
    * name.
    */
  def vendoredPathOf(path: String): Option[String] = this.synchronized {
      cache.getOrElseUpdate(path, compute(path))
  }

  def matches(path: String): Boolean = vendoredPathOf(path).isDefined

  private def compute(raw: String): Option[String] =
      regex.flatMap { re =>
        val path = ExternalPathMatcher.normalize(raw)
        if path.isEmpty || path.startsWith("<") then None
        else
          val matcher = re.pattern.matcher(path)
          // lookbehinds in the pattern may see the text before a segment start
          matcher.useTransparentBounds(true).useAnchoringBounds(false)
          val starts = 0 +: path.indices.filter(path.charAt(_) == '/').map(_ + 1)
          starts.iterator.filter(_ < path.length).flatMap { start =>
            matcher.region(start, path.length)
            if matcher.lookingAt() then
              val end =
                  if matcher.groupCount > 0 && matcher.start(1) >= 0 then matcher.end(1)
                  else matcher.end()
              Option.when(end > start)(ExternalPathMatcher.upToSegmentEnd(path, end))
            else None
          }.nextOption()
      }
end ExternalPathMatcher

object ExternalPathMatcher:

  /** A matcher for `pattern`; one that does not compile marks nothing and says so, rather than
    * looking like a pattern that matched nothing.
    */
  def apply(pattern: String): ExternalPathMatcher =
      new ExternalPathMatcher(
        Option(pattern).filter(_.nonEmpty).flatMap(p =>
            Try(p.r).fold(
              e =>
                org.slf4j.LoggerFactory.getLogger(getClass)
                    .warn(s"--external-paths '$p' is not a regular expression: ${e.getMessage}")
                None
              ,
              Some(_)
            )
        )
      )

  /** A path with `/` separators and no leading `./`. */
  def normalize(path: String): String =
      path.replace('\\', '/').stripPrefix("./")

  /** `path` up to the end of the segment that contains offset `end`, without a trailing `/`. */
  def upToSegmentEnd(path: String, end: Int): String =
    val segmentEnd = path.indexOf('/', math.max(end - 1, 0)) match
      case -1 => path.length
      case i  => i
    path.substring(0, math.max(segmentEnd, end)).stripSuffix("/")
end ExternalPathMatcher

/** Marks the methods and types of vendored paths external: code a project carries from someone else
  * (`third_party/`, a copied single-header library) is parsed as always, because its bodies and
  * types are needed, but it is not the project's own code, and uses of it from the project are uses
  * of a dependency. `isVendored` decides by the file name the graph gives a node, relative to the
  * input root. Run after the AST and the type declarations exist; it never marks anything internal
  * again.
  */
class ExternalPathsPass(cpg: Cpg, isVendored: String => Boolean) extends CpgPass(cpg):

  def this(cpg: Cpg, pattern: String) =
      this(
        cpg, {
            val matcher = ExternalPathMatcher(pattern)
            (path: String) => matcher.matches(path)
        }
      )

  override def run(dstGraph: overflowdb.BatchedUpdate.DiffGraphBuilder): Unit =
    // one decision per file name, however many methods and types it holds
    val decided = mutable.HashMap.empty[String, Boolean]
    def vendored(path: String): Boolean =
        path.nonEmpty && decided.getOrElseUpdate(path, isVendored(path))
    // The marked methods carry a tag, so a reader tells vendored code this pass made external from
    // code a frontend already knew was a dependency (Composer's vendor/, a venv, node_modules)
    val tag = NewTag().name(ExternalPathsPass.TagName).value("")
    var any = false
    def mark(node: StoredNode, tagged: Boolean): Unit =
      if !any then
        dstGraph.addNode(tag)
        any = true
      dstGraph.setNodeProperty(node, PropertyNames.IS_EXTERNAL, true)
      if tagged then dstGraph.addEdge(node, tag, EdgeTypes.TAGGED_BY)
    cpg.method.isExternal(false).l.foreach { m =>
        if vendored(m.filename) then mark(m, tagged = true)
    }
    cpg.typeDecl.isExternal(false).l.foreach { t =>
        if vendored(t.filename) then mark(t, tagged = false)
    }
  end run
end ExternalPathsPass

object ExternalPathsPass:

  /** The tag on every method this pass marked external (a type declaration cannot carry a tag; its
    * file holds tagged methods).
    */
  val TagName = "external-path"

  /** What every frontend calls after its AST is built: marks the config's `--external-paths`
    * vendored code external; no pattern, no change.
    */
  def applyTo(cpg: Cpg, externalPaths: String): Unit =
      if externalPaths.nonEmpty then new ExternalPathsPass(cpg, externalPaths).createAndApply()
