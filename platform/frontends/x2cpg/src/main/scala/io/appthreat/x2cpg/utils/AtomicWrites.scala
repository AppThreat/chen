package io.appthreat.x2cpg.utils

import java.nio.file.{AtomicMoveNotSupportedException, Files, LinkOption, Path, StandardCopyOption}
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** Writes cache and working files so that a symbolic link committed at a predictable name cannot
  * redirect them.
  *
  * Every cache writer names its own files (a content hash, a fingerprint), and a cache directory
  * often sits inside the analysed input, so a checkout decides those names before the run does: a
  * plain `Files.write` or `Files.copy` onto a name that is a link truncates whatever the link
  * points at. Each method here fills a fresh, unpredictable temporary in the target's own directory
  * (so the final step stays a rename on one file system) and renames it onto the final name. A
  * rename replaces a link at that name; it never writes through one. The temporary is removed again
  * whenever anything fails, so a run that dies mid-write leaves no debris at a predictable name
  * either.
  */
object AtomicWrites:

  /** Write `content` to `target` through an unpredictable temporary that is renamed onto it. */
  def bytes(target: Path, content: Array[Byte]): Unit =
      replace(target)(Files.write(_, content))

  /** Write `content` as text to `target` through an unpredictable temporary renamed onto it. */
  def text(target: Path, content: String): Unit =
      replace(target)(Files.writeString(_, content))

  /** Copy `source` to `target` through an unpredictable temporary renamed onto it, for stores that
    * build their content as a file elsewhere first.
    */
  def copy(source: Path, target: Path): Unit =
      replace(target)(Files.copy(source, _, StandardCopyOption.REPLACE_EXISTING))

  /** Write `target` with content the caller streams itself: `fill` writes into a fresh
    * unpredictable temporary beside `target`, and the completed temporary is renamed onto it with
    * the same replace semantics as the other methods, the temporary removed when anything fails.
    * The naming and the rename stay here, so a caller only produces content; one that has it in
    * memory or as a file uses `bytes`, `text` or `copy` instead.
    */
  def replace(target: Path)(fill: Path => Unit): Unit =
    val parent = requireParent(target)
    val tmp    = Files.createTempFile(parent, "." + target.getFileName, ".tmp")
    try
      fill(tmp)
      moveIntoPlace(tmp, target)
    catch
      case e: Throwable =>
          Try(Files.deleteIfExists(tmp))
          throw e

  /** Build the directory `target` through an unpredictable temporary: `fill` populates the
    * temporary, whatever already sits at the final name is removed (a link there is removed as a
    * link), and the temporary is renamed onto it.
    */
  def directory(target: Path)(fill: Path => Unit): Unit =
    val parent = requireParent(target)
    val tmp    = Files.createTempDirectory(parent, "." + target.getFileName)
    try
      fill(tmp)
      FileUtil.delete(target, swallowIoExceptions = true)
      moveIntoPlace(tmp, target)
    catch
      case e: Throwable =>
          Try(FileUtil.delete(tmp, swallowIoExceptions = true))
          throw e

  /** Why `dir` must not be used as a cache directory, or `None` when it may be, judged against an
    * `anchor` the caller trusts: the analysed input root, the directory the run was pointed at.
    * Every component of `dir` strictly below the anchor is checked without following links, whether
    * or not it exists yet, so a linked `.chen` is caught even when the directory the link points at
    * already holds the next component, and a link swapped in above a directory an earlier safe run
    * left behind is caught too.
    *
    * The anchor and everything above it, the part of the path the user spelled rather than a
    * checkout committed, is not checked. A `dir` that does not lie below the anchor (a directory of
    * the run's own, in a temporary place) falls back to the unanchored walk below.
    */
  def checkCacheDirectory(dir: Path, anchor: Path): Option[String] =
    val root   = anchor.toAbsolutePath.normalize
    val target = dir.toAbsolutePath.normalize
    val below  = root.relativize(target)
    if below.toString.isEmpty || below.startsWith("..") then checkCacheDirectory(dir)
    else
      val walk = mutable.ListBuffer.empty[Path]
      var cur  = root
      below.iterator().asScala.foreach { name =>
        cur = cur.resolve(name)
        walk += cur
      }
      walk.find(offends).map(reason)

  /** Why `dir` must not be used as a cache directory, or `None` when it may be, when the caller has
    * no anchor to judge the position against. A component of its path is a symbolic link (entries
    * written below it would land where the link points), or the final component exists and is not a
    * directory.
    *
    * The walk starts at the deepest component that already exists and checks every component down
    * to `dir` without following links, so a link anywhere on the remaining path is caught before
    * anything is created through it. A link above the deepest existing component, the part of the
    * path that was spelled by the user rather than committed by a checkout (the analysed input
    * itself, or a temporary directory behind a system link, as `/tmp` on macOS), is not part of the
    * check: the walk deliberately goes no further up than it must. This leaves a linked directory
    * whose target already holds the deeper components unexamined, which is why a caller that knows
    * the analysed input root passes it as the anchor above.
    */
  def checkCacheDirectory(dir: Path): Option[String] =
    val below = mutable.ListBuffer.empty[Path]
    var cur   = dir
    while cur != null && !Files.exists(cur, LinkOption.NOFOLLOW_LINKS) do
      below.prepend(cur)
      cur = cur.getParent
    val components = if cur == null then below.toList else cur :: below.toList
    components.find(offends).map(reason)

  /** A component offends when it is a symbolic link (wherever it points), or exists and is not a
    * directory; a component that does not exist yet is fine, it will be created below the
    * components already checked.
    */
  private def offends(component: Path): Boolean =
      Files.isSymbolicLink(component) ||
          (Files.exists(component, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(
            component,
            LinkOption.NOFOLLOW_LINKS
          ))

  private def reason(component: Path): String =
      if Files.isSymbolicLink(component) then s"$component is a symbolic link"
      else s"$component exists and is not a directory"

  /** A rename on the same file system replaces whatever sits at the final name, a link included.
    * Where the file system refuses atomic renames the same replacement is done non-atomically.
    */
  private def moveIntoPlace(tmp: Path, target: Path): Unit =
      try
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
      catch
        case _: AtomicMoveNotSupportedException =>
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)

  /** The temporary must be a sibling of the target, so the renaming move stays on one file system;
    * a target without a parent directory would silently put it elsewhere.
    */
  private def requireParent(target: Path): Path =
      Option(target.getParent)
          .getOrElse(throw new IllegalArgumentException(s"$target has no parent directory"))

end AtomicWrites
