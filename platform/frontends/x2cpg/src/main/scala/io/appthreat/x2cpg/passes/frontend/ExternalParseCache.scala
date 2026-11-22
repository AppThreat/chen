package io.appthreat.x2cpg.passes.frontend

import io.appthreat.x2cpg.parse.ParseReporter
import io.appthreat.x2cpg.utils.AtomicWrites
import org.slf4j.LoggerFactory

import java.nio.file.{Files, LinkOption, Path, Paths, StandardCopyOption}
import scala.jdk.CollectionConverters.*
import scala.util.{Try, Using}

/** Caches the output directory of an external parser (e.g. astgen for JavaScript/TypeScript, which
  * shells out to a Node.js process to emit Babel JSON ASTs).
  *
  * Running such a parser is often the dominant cost for a frontend, and its output is a pure
  * function of the input sources plus the parser's version and flags. This caches that output
  * directory keyed on a project fingerprint, so an unchanged project skips the external process and
  * restores the previously generated artifacts instead.
  *
  * As with [[CpgCacheStore]], soundness depends on the fingerprint being complete: callers must
  * fold the parser version and any flags that affect its output into the fingerprint's `extra`.
  *
  * @param trustedCacheDir
  *   true only when `cacheDir` was configured explicitly by the user. A directory at a default
  *   position under the analysed input may be committed as a symbolic link by the input's own
  *   checkout, so such a position is checked (see [[AtomicWrites.checkCacheDirectory]]) and the
  *   cache is switched off when the position is a link; the user's own configured directory is
  *   taken as the user chose it.
  * @param cacheDirAnchor
  *   the analysed input root, when the caller knows it; see [[AstCacheStore]]. With it, one walk
  *   over the entry directory's path covers the cache directory and the kind directory below it,
  *   whether or not either exists. Ignored when `trustedCacheDir` is true.
  */
class ExternalParseCache(
  cacheDir: String,
  kind: String,
  trustedCacheDir: Boolean = false,
  cacheDirAnchor: Option[String] = None
):

  private val logger = LoggerFactory.getLogger(classOf[ExternalParseCache])

  // Only usable if the cache dir's parent exists, so a placeholder/relative path (e.g. in tests)
  // never has the cache directory materialized and left behind.
  private val cacheDirParentExists: Boolean =
      Try {
          Files.isDirectory(Option(Paths.get(cacheDir).getParent).getOrElse(Paths.get(".")))
      }.getOrElse(false)

  /** Why the cache's entry directory position was refused, when it was; see [[AstCacheStore]] for
    * the rule. The check runs on the entry directory `<cacheDir>/<kind>` itself, the position
    * whose predictable names this store reads and writes: a checkout can commit a real cache
    * directory with the kind subdirectory as a link, and with an anchor the walk covers the cache
    * directory above it, existing or not, so a linked `.chen` is refused even when its target
    * already holds the kind directory. Only a default position is checked.
    */
  private val cacheDirRefusal: Option[String] =
      if trustedCacheDir then None
      else
        cacheDirAnchor
            .map(anchor => Try(AtomicWrites.checkCacheDirectory(entriesDir, Paths.get(anchor))).toOption)
            .getOrElse(Try(AtomicWrites.checkCacheDirectory(entriesDir)).toOption)
            .flatten

  private def enabled: Boolean =
      cacheDir.nonEmpty && cacheDirParentExists && cacheDirRefusal.isEmpty &&
      CacheControl.isEnabled(kind)

  if cacheDir.nonEmpty && cacheDirParentExists && CacheControl.isEnabled(kind) then
    cacheDirRefusal.foreach { reason =>
        logger.warn(
          s"Switching the $kind cache off for this run: $reason, so cache directory $entriesDir is not used"
        )
    }

  if enabled then
    Try(Files.createDirectories(entriesDir)).failed.foreach { e =>
        logger.warn(s"Failed to create cache directory $entriesDir: ${e.getMessage}")
    }

  /** Whether this cache can restore or store anything right now: it has a directory it may create
    * and its kind is not switched off (`--cache none`, `--cache no-astgen`, `--no-ast-cache`,
    * `chen.cache.disabled*`). A caller asks this before it does the work that only a cache key
    * needs (a project fingerprint, a parser version probe), since [[restore]] and [[store]] do
    * nothing when it is false.
    */
  def isUsable: Boolean = enabled

  private def entriesDir: Path = Paths.get(cacheDir, kind)

  private def entryDir(fingerprint: String): Path = entriesDir.resolve(fingerprint)

  /** Restore cached artifacts for `fingerprint` into `outDir`, returning true on a hit. A run that
    * collects the parse report never restores: the parser's messages about the files it could not
    * read are not all part of its output directory, so only a fresh run can report them. An entry
    * that is a symbolic link is a miss: neither it nor anything below it is read.
    */
  def restore(fingerprint: String, outDir: Path): Boolean =
      if !enabled || ParseReporter.isEnabled then false
      else
        val entry = entryDir(fingerprint)
        if !Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS) then
          if Files.exists(entry, LinkOption.NOFOLLOW_LINKS) then
            logger.debug(s"$kind cache entry $entry is not a directory; treating it as a miss")
          false
        else
          Try {
              Files.createDirectories(outDir)
              copyTree(entry, outDir)
          }.fold(
            e =>
              logger.warn(s"Failed to restore $kind cache: ${e.getMessage}"); false
            ,
            _ => true
          )

  /** Store the artifacts under `outDir` for `fingerprint`. The entry is built in an unpredictable
    * temporary directory beside its final name and renamed onto it, so a link committed at the
    * entry's name is replaced rather than written through, and an older entry at that name is
    * removed as part of the swap.
    */
  def store(fingerprint: String, outDir: Path): Unit =
      if enabled && Files.isDirectory(outDir) then
        Try {
            AtomicWrites.directory(entryDir(fingerprint)) { tmp =>
              copyTree(outDir, tmp)
            }
        }.failed.foreach { e =>
          logger.warn(s"Failed to store $kind cache: ${e.getMessage}")
        }

  /** Copies one directory tree into another, both of them real directories. Regular files are
    * copied and directories recreated; anything else, a symbolic link above all, is skipped, so
    * the copy never reads through a link in either direction and never descends into a linked
    * directory.
    */
  private def copyTree(from: Path, to: Path): Unit =
      Using.resource(Files.walk(from)) { stream =>
          stream.iterator().asScala.foreach { src =>
              val dst = to.resolve(from.relativize(src))
              if Files.isDirectory(src, LinkOption.NOFOLLOW_LINKS) then Files.createDirectories(dst)
              else if Files.isRegularFile(src, LinkOption.NOFOLLOW_LINKS) then
                Option(dst.getParent).foreach(Files.createDirectories(_))
                Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING)
          }
      }

end ExternalParseCache
