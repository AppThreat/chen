package io.appthreat.x2cpg.passes.frontend

import org.slf4j.LoggerFactory

import java.nio.file.{Files, Path, Paths, StandardCopyOption}
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
  */
class ExternalParseCache(cacheDir: String, kind: String):

  private val logger = LoggerFactory.getLogger(classOf[ExternalParseCache])

  // Only usable if the cache dir's parent exists, so a placeholder/relative path (e.g. in tests)
  // never has the cache directory materialized and left behind.
  private val cacheDirParentExists: Boolean =
      Try {
          Files.isDirectory(Option(Paths.get(cacheDir).getParent).getOrElse(Paths.get(".")))
      }.getOrElse(false)

  private def enabled: Boolean =
      cacheDir.nonEmpty && cacheDirParentExists && CacheControl.isEnabled(kind)

  if enabled then
    Try(Files.createDirectories(entriesDir)).failed.foreach { e =>
        logger.warn(s"Failed to create cache directory $entriesDir: ${e.getMessage}")
    }

  private def entriesDir: Path = Paths.get(cacheDir, kind)

  private def entryDir(fingerprint: String): Path = entriesDir.resolve(fingerprint)

  /** Restore cached artifacts for `fingerprint` into `outDir`, returning true on a hit. */
  def restore(fingerprint: String, outDir: Path): Boolean =
      if !enabled then false
      else
        val entry = entryDir(fingerprint)
        if !Files.isDirectory(entry) then false
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

  /** Store the artifacts under `outDir` for `fingerprint`. */
  def store(fingerprint: String, outDir: Path): Unit =
      if enabled && Files.isDirectory(outDir) then
        val finalEntry = entryDir(fingerprint)
        val tmpEntry   = entriesDir.resolve(s"$fingerprint.tmp")
        Try {
            deleteTree(tmpEntry)
            Files.createDirectories(tmpEntry)
            copyTree(outDir, tmpEntry)
            deleteTree(finalEntry)
            Files.move(tmpEntry, finalEntry, StandardCopyOption.ATOMIC_MOVE)
        }.failed.foreach { e =>
          logger.warn(s"Failed to store $kind cache: ${e.getMessage}")
          Try(deleteTree(tmpEntry))
        }

  private def copyTree(from: Path, to: Path): Unit =
      Using.resource(Files.walk(from)) { stream =>
          stream.iterator().asScala.foreach { src =>
            val dst = to.resolve(from.relativize(src))
            if Files.isDirectory(src) then Files.createDirectories(dst)
            else
              Option(dst.getParent).foreach(Files.createDirectories(_))
              Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING)
          }
      }

  private def deleteTree(path: Path): Unit =
      if Files.exists(path) then
        Using.resource(Files.walk(path)) { stream =>
            stream
                .sorted(java.util.Comparator.reverseOrder())
                .iterator()
                .asScala
                .foreach(p => Try(Files.deleteIfExists(p)))
        }

end ExternalParseCache
