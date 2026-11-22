package io.appthreat.x2cpg.utils

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.{
    AtomicMoveNotSupportedException,
    FileAlreadyExistsException,
    Files,
    LinkOption,
    Path,
    Paths,
    StandardCopyOption,
    StandardOpenOption
}
import java.util.concurrent.ThreadLocalRandom
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.{Try, Using}

/** Writes and reads cache and working files so that a symbolic link committed at a predictable name
  * cannot redirect them.
  *
  * Every cache writer names its own files (a content hash, a fingerprint), and a cache directory
  * often sits inside the analysed input, so a checkout decides those names before the run does: a
  * plain `Files.write` or `Files.copy` onto a name that is a link truncates whatever the link
  * points at. Each method here fills a fresh, unpredictable temporary in the target's own directory
  * (so the final step stays a rename on one file system) and renames it onto the final name. A
  * rename replaces a link at that name; it never writes through one. The temporary is created
  * exclusively, so a link planted at its name makes the creation fail instead of being followed,
  * and it gets the permissions an ordinary new file gets (the process umask applies), so the final
  * file is as readable as a file written in place. The temporary is removed again whenever anything
  * fails; one left behind by a killed process carries the [[TempSuffix]] and a leading dot, and
  * [[sweepStale]] removes it once it is old.
  */
object AtomicWrites:

  /** The suffix of every temporary this object creates, files and directories alike. */
  val TempSuffix: String = ".tmp"

  /** How old a leftover temporary must be before [[sweepStale]] removes it: far longer than any
    * write takes, so a temporary another run is still filling is never touched.
    */
  private val StaleAfterMillis: Long = 24L * 60 * 60 * 1000

  /** The directories [[sweepStale]] has already swept in this process. */
  private val swept = java.util.concurrent.ConcurrentHashMap.newKeySet[String]()

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
    * unpredictable temporary beside `target`, and the completed temporary is renamed onto it, the
    * temporary removed when anything fails. A caller that has the content in memory or as a file
    * uses `bytes`, `text` or `copy` instead.
    */
  def replace(target: Path)(fill: Path => Unit): Unit =
    val tmp = createTemp(target, directory = false)
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
    val tmp = createTemp(target, directory = true)
    try
      fill(tmp)
      FileUtil.delete(target, swallowIoExceptions = true)
      moveIntoPlace(tmp, target)
    catch
      case e: Throwable =>
          Try(FileUtil.delete(tmp, swallowIoExceptions = true))
          throw e

  /** The bytes of `file` when it is a regular file, `None` when it is missing, a symbolic link or
    * anything else (a FIFO, a device, a directory). The open itself refuses a link, so a link
    * swapped in after the check is not followed either.
    */
  def readRegular(file: Path): Option[Array[Byte]] =
      if !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) then None
      else
        Try {
            Using.resource(Files.newByteChannel(
              file,
              StandardOpenOption.READ,
              LinkOption.NOFOLLOW_LINKS
            )) { channel =>
              val size = channel.size()
              if size > Int.MaxValue - 8 then throw new IOException(s"$file is too large to read")
              val buffer = ByteBuffer.allocate(size.toInt)
              while buffer.hasRemaining && channel.read(buffer) >= 0 do ()
              java.util.Arrays.copyOf(buffer.array(), buffer.position())
            }
        }.toOption

  /** Removes the temporaries a killed process left directly in `dir`: dot-prefixed entries ending
    * in [[TempSuffix]], older than a day, removed without following links. Errors are ignored; the
    * sweep only keeps a long-lived cache directory from growing, so each directory is swept once
    * per process however many stores open it.
    */
  def sweepStale(dir: Path): Unit =
      if Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) &&
        swept.add(dir.toAbsolutePath.normalize.toString)
      then
        val cutoff = System.currentTimeMillis() - StaleAfterMillis
        Try {
            Using.resource(Files.newDirectoryStream(dir)) { stream =>
                stream.iterator().asScala.foreach { entry =>
                  val name = entry.getFileName.toString
                  if name.startsWith(".") && name.endsWith(TempSuffix) then
                    Try(
                      Files.readAttributes(
                        entry,
                        classOf[BasicFileAttributes],
                        LinkOption.NOFOLLOW_LINKS
                      )
                    ).foreach { attrs =>
                        if attrs.lastModifiedTime.toMillis < cutoff then
                          FileUtil.delete(entry, swallowIoExceptions = true)
                    }
                }
            }
        }

  /** Why the cache directory `dir` must not be used, or `None` when it may be. A directory the user
    * configured (`trusted`) is taken as chosen. Any other position is checked with
    * [[checkCacheDirectory]], against `anchor` when the caller knows the analysed input root. A
    * check that cannot be completed refuses the position, so an error never turns the cache on.
    */
  def cacheDirRefusal(dir: Path, trusted: Boolean, anchor: Option[String]): Option[String] =
      if trusted then None
      else
        Try(anchor match
          case Some(root) => checkCacheDirectory(dir, Paths.get(root))
          case None       => checkCacheDirectory(dir)
        ).fold(e => Some(s"$dir could not be checked (${e.getMessage})"), identity)

  /** Why `dir` must not be used as a cache directory, or `None` when it may be, judged against an
    * `anchor` the caller trusts: the analysed input root, the directory the run was pointed at.
    * Every component of `dir` strictly below the anchor is checked without following links, whether
    * or not it exists yet, so a linked `.chen` is caught even when the directory the link points at
    * already holds the next component, and a link swapped in above a directory an earlier safe run
    * left behind is caught too.
    *
    * The anchor and everything above it, the part of the path the user spelled rather than a
    * checkout committed, is not checked. A `dir` that does not lie below the anchor (a directory of
    * the run's own, in a temporary place, or one on another drive) falls back to the unanchored
    * walk below.
    */
  def checkCacheDirectory(dir: Path, anchor: Path): Option[String] =
    val root   = anchor.toAbsolutePath.normalize
    val target = dir.toAbsolutePath.normalize
    Try(root.relativize(target)).toOption match
      case Some(below) if below.toString.nonEmpty && !below.startsWith("..") =>
          val walk = mutable.ListBuffer.empty[Path]
          var cur  = root
          below.iterator().asScala.foreach { name =>
            cur = cur.resolve(name)
            walk += cur
          }
          walk.find(offends).map(reason)
      case _ => checkCacheDirectory(dir)

  /** Why `dir` must not be used as a cache directory, or `None` when it may be, when the caller has
    * no anchor to judge the position against: a component of its path is a symbolic link (entries
    * written below it would land where the link points), or the final component exists and is not a
    * directory.
    *
    * The walk starts at the deepest component that already exists and checks every component down
    * to `dir` without following links, so a link anywhere on the remaining path is caught before
    * anything is created through it. Without an anchor a link the user spelled cannot be told from
    * one a checkout committed, so the deepest existing component is checked too, and a directory
    * still to be created under a linked one (a new directory under `/tmp` on macOS) is refused;
    * every caller in a frontend passes the analysed input root as the anchor above instead.
    * Components above the deepest existing one are not part of the check, which leaves a linked
    * directory whose target already holds the deeper components unexamined.
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

  /** A fresh temporary beside `target`, named `.<target name>.<random>.tmp` and created
    * exclusively: an existing entry at the name, a link included, makes the creation fail and a new
    * name is drawn. Created without explicit permissions, so the umask applies as it does to any
    * new file.
    */
  private def createTemp(target: Path, directory: Boolean): Path =
    val parent = Option(target.toAbsolutePath.getParent)
        .getOrElse(throw new IllegalArgumentException(s"$target has no parent directory"))
    val name                  = target.getFileName.toString
    var attempt: Option[Path] = None
    var tries                 = 0
    while attempt.isEmpty do
      val candidate = parent.resolve(
        s".$name.${java.lang.Long.toUnsignedString(ThreadLocalRandom.current().nextLong(), 36)}$TempSuffix"
      )
      try
        if directory then Files.createDirectory(candidate) else Files.createFile(candidate)
        attempt = Some(candidate)
      catch
        case e: FileAlreadyExistsException =>
            tries += 1
            if tries >= 100 then throw e
    attempt.get

  /** A rename on the same file system replaces whatever sits at the final name, a link included.
    * Where the file system refuses atomic renames the same replacement is done non-atomically.
    */
  private def moveIntoPlace(tmp: Path, target: Path): Unit =
      try
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
      catch
        case _: AtomicMoveNotSupportedException =>
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)

end AtomicWrites
