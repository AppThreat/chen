package io.appthreat.x2cpg.passes.frontend

import org.slf4j.LoggerFactory

import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*
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
  * can change the resulting CPG. [[projectFingerprint]] hashes every input file's content; callers
  * MUST additionally pass, via `extra`, anything else that influences the graph - the frontend
  * configuration, the chen/schema versions, and the set of overlays/semantics the caller applies.
  * An incomplete fingerprint would restore a stale graph, so when in doubt include more.
  */
object CpgCacheStore:

  private val logger = LoggerFactory.getLogger(getClass)

  /** A fingerprint over all input files plus caller-supplied `extra` identity (configuration,
    * versions, overlay set, ...). Files under `excludeDirNames` (e.g. the cache directory) are
    * skipped. Sorted by relative path for determinism.
    */
  def projectFingerprint(
    inputPath: String,
    extra: Seq[String],
    excludeDirNames: Set[String] = Set(AstCacheStore.CacheDirName)
  ): String =
    val root   = Paths.get(inputPath).toAbsolutePath
    val digest = MessageDigest.getInstance("SHA-256")

    if Files.isRegularFile(root) then hashFile(digest, root.getFileName.toString, root)
    else if Files.isDirectory(root) then
      val files =
          Using.resource(Files.walk(root)) { stream =>
              stream
                  .iterator()
                  .asScala
                  .filter(Files.isRegularFile(_))
                  .filterNot(p => isExcluded(root, p, excludeDirNames))
                  .map(p => root.relativize(p).toString -> p)
                  .toList
                  .sortBy(_._1)
          }
      files.foreach { case (rel, path) => hashFile(digest, rel, path) }

    extra.foreach(e => digest.update(e.getBytes("UTF-8")))
    digest.digest().map("%02x".format(_)).mkString
  end projectFingerprint

  private def isExcluded(root: Path, path: Path, excludeDirNames: Set[String]): Boolean =
      root.relativize(path).iterator().asScala.exists(seg => excludeDirNames.contains(seg.toString))

  private def hashFile(digest: MessageDigest, relPath: String, path: Path): Unit =
      Try {
          digest.update(relPath.getBytes("UTF-8"))
          digest.update(Files.readAllBytes(path))
      }.failed.foreach(e =>
          logger.warn(s"Could not hash $path for CPG fingerprint: ${e.getMessage}")
      )

end CpgCacheStore

/** Stores and restores whole `.atom` graphs keyed on a project fingerprint. */
class CpgCacheStore(cacheDir: String):

  private val logger = LoggerFactory.getLogger(classOf[CpgCacheStore])

  // Only usable if the cache dir's parent exists, so a placeholder/relative path (e.g. in tests)
  // never has the cache directory materialized and left behind.
  private val cacheDirParentExists: Boolean =
      Try {
          Files.isDirectory(Option(Paths.get(cacheDir).getParent).getOrElse(Paths.get(".")))
      }.getOrElse(false)

  private def enabled: Boolean =
      cacheDir.nonEmpty && cacheDirParentExists && CacheControl.isEnabled(CacheControl.Cpg)

  if enabled then
    Try(Files.createDirectories(Paths.get(cacheDir))).failed.foreach { e =>
        logger.warn(s"Failed to create cache directory $cacheDir: ${e.getMessage}")
    }

  private def cacheFile(fingerprint: String): Path =
      Paths.get(cacheDir, s"cpg-$fingerprint.atom")

  /** Restore a cached CPG for `fingerprint` into `outputPath`, returning true on a hit. */
  def restore(fingerprint: String, outputPath: String): Boolean =
      if !enabled then false
      else
        val cached = cacheFile(fingerprint)
        if !Files.exists(cached) then false
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

  /** Store the freshly built `.atom` at `atomPath` under `fingerprint`. */
  def store(fingerprint: String, atomPath: String): Unit =
      if enabled then
        val source = Paths.get(atomPath)
        if Files.exists(source) then
          val finalPath = cacheFile(fingerprint)
          val tmpPath   = Paths.get(cacheDir, s"cpg-$fingerprint.atom.tmp")
          Try {
              Files.copy(source, tmpPath, StandardCopyOption.REPLACE_EXISTING)
              Files.move(tmpPath, finalPath, StandardCopyOption.REPLACE_EXISTING)
          }.failed.foreach { e =>
            logger.warn(s"Failed to store CPG cache: ${e.getMessage}")
            Try(Files.deleteIfExists(tmpPath))
          }

end CpgCacheStore
