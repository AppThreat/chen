package io.appthreat.x2cpg.passes.frontend

import io.appthreat.x2cpg.utils.AtomicWrites
import org.slf4j.LoggerFactory

import java.io.OutputStream
import java.io.IOException
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.{FileVisitResult, Files, LinkOption, Path, Paths, SimpleFileVisitor, StandardCopyOption}
import java.security.{DigestInputStream, MessageDigest}
import scala.util.{Try, Using}

/** Whole-CPG caching: reuse a previously built `.atom` when the entire project (and the analysis
  * configuration) is unchanged.
  *
  * This is the coarsest cache. Unlike the per-file AST cache, it does not give partial reuse - any
  * change to any input invalidates it - but on an identical re-run (resume after a crash, a CI
  * re-scan of the same commit, or simply re-invoking the tool) it skips the entire pipeline
  * (parsing, overlays and data flow) and restores the finished graph instantly.
  *
  * Soundness depends entirely on the fingerprint being complete: it must capture everything that
  * can change the resulting CPG. [[projectFingerprint]] hashes every input file's content by
  * default; callers MUST additionally pass, via `extra`, anything else that influences the graph -
  * the frontend configuration, the chen/schema versions, and the set of overlays/semantics the
  * caller applies. An incomplete fingerprint would restore a stale graph, so when in doubt include
  * more.
  */
object CpgCacheStore:

  private val logger = LoggerFactory.getLogger(getClass)

  /** Version control metadata. No front end reads it, so it cannot change what a parser emits, and
    * it holds a large share of the files in a checkout.
    */
  val VcsDirNames: Set[String] = Set(".git", ".hg", ".svn")

  /** Directories that are never part of a fingerprint: the chen cache itself and VCS metadata. */
  val DefaultExcludeDirNames: Set[String] = VcsDirNames + AstCacheStore.CacheDirName

  /** A fingerprint over the input files plus caller-supplied `extra` identity (configuration,
    * versions, overlay set, ...). Entries are visited in sorted order of their relative path, so
    * the result does not depend on the order the file system lists them.
    *
    * Every regular file is hashed by content unless the caller says a cheaper description is
    * enough, so a caller that passes only `inputPath` and `extra` gets a key that covers every byte
    * of the project except the chen cache and VCS metadata:
    *   - a directory named in `excludeDirNames` is pruned with everything below it
    *   - a file for which `skipPath` is true is left out
    *   - a file below a directory named in `metadataOnlyDirNames`, or for which `metadataOnlyPath`
    *     is true, contributes its relative path, size and last-modified time instead of its bytes.
    *     Only use this for files that are expensive to read and are replaced as a whole when they
    *     change, for example the output of a package manager. A change that keeps both the size and
    *     the modification time goes unseen, and a rewrite of identical bytes changes the key (a
    *     cache miss, never a stale hit)
    *
    * The two predicates receive the path as the caller spelled the input plus the relative path of
    * the file, which is the form an ignore pattern configured for the front end is matched against.
    * Symbolic links are never followed into directories. A link to a regular file outside a
    * metadata-only subtree is read through, as a file the project owns. A link inside one, or to
    * anything but a regular file, contributes its target text (and, for a file, its size and time),
    * which changes when a package manager relinks it to another version.
    */
  def projectFingerprint(
    inputPath: String,
    extra: Seq[String],
    excludeDirNames: Set[String] = DefaultExcludeDirNames,
    metadataOnlyDirNames: Set[String] = Set.empty,
    skipPath: Path => Boolean = _ => false,
    metadataOnlyPath: Path => Boolean = _ => false
  ): String =
    val spelled = Paths.get(inputPath)
    val root    = spelled.toAbsolutePath
    val digest  = MessageDigest.getInstance("SHA-256")

    if Files.isRegularFile(root) then hashContent(digest, root.getFileName.toString, root)
    else if Files.isDirectory(root) then
      val entries = collectEntries(
        root,
        spelled,
        excludeDirNames,
        metadataOnlyDirNames,
        skipPath,
        metadataOnlyPath
      )
      entries.sortBy(_.rel).foreach {
          case Entry(rel, path, Mode.Content)   => hashContent(digest, rel, path)
          case Entry(rel, path, Mode.Metadata)  => hashMetadata(digest, rel, path)
          case Entry(rel, _, Mode.Stats(stats)) => hashStats(digest, rel, stats)
      }

    extra.foreach(e => digest.update(e.getBytes("UTF-8")))
    digest.digest().map("%02x".format(_)).mkString
  end projectFingerprint

  private enum Mode:
    case Content, Metadata
    // the size and time the walk already read for a plain file, so it is not asked again
    case Stats(stats: String)

  private case class Entry(rel: String, path: Path, mode: Mode)

  private def collectEntries(
    root: Path,
    spelled: Path,
    excludeDirNames: Set[String],
    metadataOnlyDirNames: Set[String],
    skipPath: Path => Boolean,
    metadataOnlyPath: Path => Boolean
  ): List[Entry] =
    val entries = List.newBuilder[Entry]
    // one flag per directory entered: whether it is itself a metadata-only directory
    val enteredMetadataOnly = scala.collection.mutable.ArrayDeque.empty[Boolean]
    var metadataDepth       = 0

    // Without FOLLOW_LINKS a symbolic link is reported as a file and never descended into
    Files.walkFileTree(
      root,
      new SimpleFileVisitor[Path]:
        override def preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult =
          val name = Option(dir.getFileName).map(_.toString).getOrElse("")
          if dir != root && excludeDirNames.contains(name) then FileVisitResult.SKIP_SUBTREE
          else
            val metadataOnly = dir != root && metadataOnlyDirNames.contains(name)
            enteredMetadataOnly.append(metadataOnly)
            if metadataOnly then metadataDepth += 1
            FileVisitResult.CONTINUE

        override def postVisitDirectory(dir: Path, e: IOException): FileVisitResult =
          if enteredMetadataOnly.removeLast() then metadataDepth -= 1
          FileVisitResult.CONTINUE

        override def visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult =
          val relPath   = root.relativize(file)
          val asSpelled = spelled.resolve(relPath)
          if skipPath(asSpelled) then ()
          else if metadataDepth > 0 || metadataOnlyPath(asSpelled) then
            val mode = if attrs.isSymbolicLink then Mode.Metadata else Mode.Stats(statsOf(attrs))
            entries += Entry(relPath.toString, file, mode)
          else if attrs.isSymbolicLink && !Files.isRegularFile(file) then
            // a link to a directory (not followed), or one that leads nowhere
            entries += Entry(relPath.toString, file, Mode.Metadata)
          else if attrs.isRegularFile || Files.isRegularFile(file) then
            entries += Entry(relPath.toString, file, Mode.Content)
          FileVisitResult.CONTINUE

        override def visitFileFailed(file: Path, e: IOException): FileVisitResult =
          logger.warn(s"Could not read $file for CPG fingerprint: ${e.getMessage}")
          FileVisitResult.CONTINUE
    )
    entries.result()
  end collectEntries

  private def hashContent(digest: MessageDigest, relPath: String, path: Path): Unit =
      Try {
          digest.update(relPath.getBytes("UTF-8"))
          digest.update(ContentTag)
          Using.resource(new DigestInputStream(Files.newInputStream(path), digest))(
            _.transferTo(OutputStream.nullOutputStream())
          )
      }.failed.foreach(e =>
          logger.warn(s"Could not hash $path for CPG fingerprint: ${e.getMessage}")
      )

  /** The relative path, then the size and last-modified time of the file the path leads to (or the
    * link's target text, for a link that leads to no file), without reading any content.
    */
  private def hashMetadata(digest: MessageDigest, relPath: String, path: Path): Unit =
      Try {
          val description =
              if Files.isSymbolicLink(path) then
                val target = Files.readSymbolicLink(path).toString
                if Files.isRegularFile(path) then s"link=$target;${fileStats(path)}"
                else s"link=$target"
              else fileStats(path)
          digest.update(relPath.getBytes("UTF-8"))
          digest.update(MetadataTag)
          digest.update(description.getBytes("UTF-8"))
      }.failed.foreach(e =>
          logger.warn(s"Could not stat $path for CPG fingerprint: ${e.getMessage}")
      )

  private def hashStats(digest: MessageDigest, relPath: String, stats: String): Unit =
    digest.update(relPath.getBytes("UTF-8"))
    digest.update(MetadataTag)
    digest.update(stats.getBytes("UTF-8"))

  private def fileStats(path: Path): String =
      statsOf(Files.readAttributes(path, classOf[BasicFileAttributes]))

  private def statsOf(attrs: BasicFileAttributes): String =
      s"size=${attrs.size};mtime=${attrs.lastModifiedTime.toMillis}"

  // They separate the path from what follows it, so that a path and a content that run together
  // cannot collide with another path.
  private val ContentTag: Array[Byte]  = Array[Byte](0, 'C'.toByte, 0)
  private val MetadataTag: Array[Byte] = Array[Byte](0, 'M'.toByte, 0)

end CpgCacheStore

/** Stores and restores whole `.atom` graphs keyed on a project fingerprint.
  *
  * @param trustedCacheDir
  *   true only when `cacheDir` was configured explicitly by the user. A directory at a default
  *   position under the analysed input may be committed as a symbolic link by the input's own
  *   checkout, so such a position is checked (see [[AtomicWrites.checkCacheDirectory]]) and the
  *   cache is switched off when the position is a link; the user's own configured directory is
  *   taken as the user chose it.
  * @param cacheDirAnchor
  *   the analysed input root, when the caller knows it; see [[AstCacheStore]]. Ignored when
  *   `trustedCacheDir` is true.
  */
class CpgCacheStore(
  cacheDir: String,
  trustedCacheDir: Boolean = false,
  cacheDirAnchor: Option[String] = None
):

  private val logger = LoggerFactory.getLogger(classOf[CpgCacheStore])

  // Only usable if the cache dir's parent exists, so a placeholder/relative path (e.g. in tests)
  // never has the cache directory materialized and left behind.
  private val cacheDirParentExists: Boolean =
      Try {
          Files.isDirectory(Option(Paths.get(cacheDir).getParent).getOrElse(Paths.get(".")))
      }.getOrElse(false)

  /** Why the cache directory position was refused, when it was; see [[AstCacheStore]] for the
    * rule (the anchor, when given, widens the walk to every component below the input root).
    * Only a default position is checked.
    */
  private val cacheDirRefusal: Option[String] =
      if trustedCacheDir then None
      else
        cacheDirAnchor
            .map(anchor =>
              Try(AtomicWrites.checkCacheDirectory(Paths.get(cacheDir), Paths.get(anchor))).toOption
            )
            .getOrElse(Try(AtomicWrites.checkCacheDirectory(Paths.get(cacheDir))).toOption)
            .flatten

  private def enabled: Boolean =
      cacheDir.nonEmpty && cacheDirParentExists && cacheDirRefusal.isEmpty &&
      CacheControl.isEnabled(CacheControl.Cpg)

  if cacheDir.nonEmpty && cacheDirParentExists && CacheControl.isEnabled(CacheControl.Cpg) then
    cacheDirRefusal.foreach { reason =>
        logger.warn(
          s"Switching the whole-CPG cache off for this run: $reason, so cache directory $cacheDir is not used"
        )
    }

  if enabled then
    Try(Files.createDirectories(Paths.get(cacheDir))).failed.foreach { e =>
        logger.warn(s"Failed to create cache directory $cacheDir: ${e.getMessage}")
    }

  private def cacheFile(fingerprint: String): Path =
      Paths.get(cacheDir, s"cpg-$fingerprint.atom")

  /** Restore a cached CPG for `fingerprint` into `outputPath`, returning true on a hit. An entry
    * that is a symbolic link is a miss: its target is never read.
    */
  def restore(fingerprint: String, outputPath: String): Boolean =
      if !enabled then false
      else
        val cached = cacheFile(fingerprint)
        if !Files.isRegularFile(cached, LinkOption.NOFOLLOW_LINKS) then
          if Files.exists(cached, LinkOption.NOFOLLOW_LINKS) then
            logger.debug(s"CPG cache entry $cached is not a regular file; treating it as a miss")
          false
        else
          Try {
              val out = Paths.get(outputPath)
              Option(out.getParent).foreach(Files.createDirectories(_))
              Files.copy(cached, out, StandardCopyOption.REPLACE_EXISTING)
          }.fold(
            e =>
              logger.warn(s"Failed to restore cached CPG: ${e.getMessage}"); false
            ,
            _ => true
          )

  /** Store the freshly built `.atom` at `atomPath` under `fingerprint`, through an unpredictable
    * temporary renamed onto the entry, so a link committed at the entry's name is replaced rather
    * than written through.
    */
  def store(fingerprint: String, atomPath: String): Unit =
      if enabled then
        val source = Paths.get(atomPath)
        if Files.isRegularFile(source) then
          Try(AtomicWrites.copy(source, cacheFile(fingerprint))).failed.foreach { e =>
            logger.warn(s"Failed to store CPG cache: ${e.getMessage}")
          }

end CpgCacheStore
