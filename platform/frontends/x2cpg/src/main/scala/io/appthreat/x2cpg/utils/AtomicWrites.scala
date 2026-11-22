package io.appthreat.x2cpg.utils

import java.nio.file.{AtomicMoveNotSupportedException, Files, LinkOption, Path, StandardCopyOption}
import scala.collection.mutable
import scala.util.Try

/** Writes cache and working files so that a symbolic link committed at a predictable name cannot
  * redirect them.
  *
  * Every cache writer names its own files (a content hash, a fingerprint), and a cache directory
  * often sits inside the analysed input, so a checkout decides those names before the run does: a
  * plain `Files.write` or `Files.copy` onto a name that is a link truncates whatever the link
  * points at. Each method here fills a fresh, unpredictable temporary in the target's own
  * directory (so the final step stays a rename on one file system) and renames it onto the final
  * name. A rename replaces a link at that name; it never writes through one. The temporary is
  * removed again whenever anything fails, so a run that dies mid-write leaves no debris at a
  * predictable name either.
  */
object AtomicWrites:

  /** Write `content` to `target` through an unpredictable temporary that is renamed onto it. */
  def bytes(target: Path, content: Array[Byte]): Unit =
      throughTemporary(target)(Files.write(_, content))

  /** Write `content` as text to `target` through an unpredictable temporary renamed onto it. */
  def text(target: Path, content: String): Unit =
      throughTemporary(target)(Files.writeString(_, content))

  /** Copy `source` to `target` through an unpredictable temporary renamed onto it, for stores that
    * build their content as a file elsewhere first.
    */
  def copy(source: Path, target: Path): Unit =
      throughTemporary(target)(Files.copy(source, _, StandardCopyOption.REPLACE_EXISTING))

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

  /** Why `dir` must not be used as a cache directory, or `None` when it may be. A component of
    * its path is a symbolic link (entries written below it would land where the link points), or
    * the final component exists and is not a directory.
    *
    * The walk starts at the deepest component that already exists and checks every component down
    * to `dir` without following links, so a link anywhere on the remaining path is caught before
    * anything is created through it. Callers use this for directories at a default position under
    * the analysed input, which a checkout controls; a directory the user explicitly configured is
    * the user's own choice and is not checked.
    */
  def checkCacheDirectory(dir: Path): Option[String] =
      val below = mutable.ListBuffer.empty[Path]
      var cur   = dir
      while cur != null && !Files.exists(cur, LinkOption.NOFOLLOW_LINKS) do
          below.prepend(cur)
          cur = cur.getParent
      val components = if cur == null then below.toList else cur :: below.toList
      components
          .find(c =>
              Files.isSymbolicLink(c) ||
              (Files.exists(c, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(
                c,
                LinkOption.NOFOLLOW_LINKS
              ))
          )
          .map(c =>
              if Files.isSymbolicLink(c) then s"$c is a symbolic link"
              else s"$c exists and is not a directory"
          )
  end checkCacheDirectory

  /** Runs `fill` on a fresh unpredictable temporary beside `target`, then renames it onto
    * `target`, removing the temporary when anything fails.
    */
  private def throughTemporary(target: Path)(fill: Path => Unit): Unit =
      val parent = requireParent(target)
      val tmp    = Files.createTempFile(parent, "." + target.getFileName, ".tmp")
      try
        fill(tmp)
        moveIntoPlace(tmp, target)
      catch
        case e: Throwable =>
            Try(Files.deleteIfExists(tmp))
            throw e

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
