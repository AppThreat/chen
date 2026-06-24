package io.appthreat.x2cpg.passes.frontend

import io.appthreat.x2cpg.{AstCache, AstFragment}
import io.appthreat.x2cpg.AstCache.AstBitcode
import org.slf4j.{Logger, LoggerFactory}
import overflowdb.BatchedUpdate.DiffGraphBuilder
import upickle.default.*

import java.nio.file.{Files, Paths, StandardCopyOption}
import java.security.MessageDigest
import scala.util.Try

object AstCacheStore:

  /** Result of parsing a single part: the local diff graph plus any type names the frontend
    * registered in its global type table while parsing (so they can be re-registered on a cache
    * hit). `usedTypes` may be empty for frontends that do not use a global type table.
    */
  case class ParsedUnit(
    diffGraph: DiffGraphBuilder,
    usedTypes: Seq[String] = Nil
  )

  /** Keys a cache entry for one part. `identity` distinguishes parts (e.g. a relative path);
    * `content` is the bytes whose change must invalidate the entry (e.g. the file content).
    */
  case class CacheKey(identity: String, content: Array[Byte])

  /** Name of the per-project cache directory created in the project root, holding `<hash>.ast`
    * files. Modelled after `.git`: hidden, lives alongside the analyzed sources, and can be deleted
    * at any time to force a clean reparse.
    */
  val CacheDirName: String = ".chen"

  /** Resolve the effective cache directory: an explicitly configured directory takes precedence,
    * otherwise default to `<inputPath>/.chen` so that caching works automatically without any
    * configuration.
    */
  def resolveCacheDir(inputPath: String, configured: String): String =
      if configured != null && configured.nonEmpty then configured
      else Paths.get(inputPath, CacheDirName).toString
end AstCacheStore

/** Centralized AST caching, decoupled from any particular CPG pass base.
  *
  * A frontend keeps its own pass type (and thus its determinism and memory characteristics) and
  * simply calls [[process]] from `runOnPart`. This owns hashing, on-disk cache lookup/validation,
  * persistence and diff-graph population, so every frontend shares one implementation of the
  * hashing and cache format.
  *
  * Caching is keyed on each part's content (plus an optional project fingerprint), so an unchanged
  * part reuses its cached AST and a changed part is reparsed. Caches written by an incompatible
  * build are discarded and recomputed (see [[AstCache.isCompatible]]).
  *
  * @param enableAstCache
  *   whether to read/write the on-disk AST cache at all
  * @param cacheDir
  *   directory holding the `<hash>.ast` cache files
  * @param onlyAstCache
  *   when true, parse and populate the cache but do not write into the CPG (cache warming)
  */
class AstCacheStore(
  enableAstCacheParam: Boolean,
  cacheDir: String,
  onlyAstCache: Boolean,
  useFragmentCache: Boolean = false
):

  import AstCacheStore.{CacheKey, ParsedUnit}

  private val logger: Logger = LoggerFactory.getLogger(classOf[AstCacheStore])

  /** The cache directory is only usable if its parent (the project input path) actually exists as a
    * directory. A real scan always satisfies this; it guards against relative or non-existent input
    * paths, which would otherwise have the cache directory materialized in an unexpected location.
    */
  private val cacheDirParentExists: Boolean =
      Try {
          val parent = Option(Paths.get(cacheDir).getParent).getOrElse(Paths.get("."))
          Files.isDirectory(parent)
      }.getOrElse(false)

  /** Caching is on only if requested by the frontend, not globally disabled via [[CacheControl]],
    * and the cache directory's parent exists.
    */
  private def enableAstCache: Boolean =
      enableAstCacheParam && cacheDirParentExists && CacheControl.isEnabled(CacheControl.Ast)

  if enableAstCache then
    Try(Files.createDirectories(Paths.get(cacheDir))).failed.foreach { e =>
        logger.warn(s"Failed to create cache directory $cacheDir: ${e.getMessage}")
    }

  /** Cache-aware processing of a single part.
    *
    * @param diffGraph
    *   the pass's per-part diff graph to populate
    * @param cacheKey
    *   stable cache key inputs for the part, or `None` to skip caching it
    * @param fingerprint
    *   a fingerprint of everything outside the part that can influence its AST (empty for
    *   self-contained frontends; set by cross-file frontends to stay sound). Mixed into the key.
    * @param registerUsedTypes
    *   re-register type names into the frontend's global type table; called on both hit and miss so
    *   a cached run produces the same TYPE nodes as a fresh parse
    * @param createAst
    *   parse the part into a [[AstCacheStore.ParsedUnit]] (only called on a cache miss)
    */
  def process[T](
    diffGraph: DiffGraphBuilder,
    part: T,
    cacheKey: => Option[CacheKey],
    fingerprint: String,
    registerUsedTypes: Seq[String] => Unit,
    createAst: => Option[ParsedUnit]
  ): Unit =
    val partHash = if enableAstCache then computeEntryHash(cacheKey, fingerprint) else None
    if fragmentsActive then processFragment(diffGraph, partHash, registerUsedTypes, createAst)
    else processClassic(diffGraph, partHash, registerUsedTypes, createAst)

  /** Fragment codec active when requested explicitly by this store or enabled globally (atom
    * `--flux` / `-Dchen.cache.fragments=true`). Read at runtime so toggling needs no frontend
    * recompile.
    */
  private def fragmentsActive: Boolean = useFragmentCache || CacheControl.useFragments

  /** Classic codec path: [[AstCache]]'s upickle bitcode (`<hash>.ast`). */
  private def processClassic[T](
    diffGraph: DiffGraphBuilder,
    partHash: Option[String],
    registerUsedTypes: Seq[String] => Unit,
    createAst: => Option[ParsedUnit]
  ): Unit =
    loadFromCache(partHash) match
      case Some(bitcode) =>
          // Re-register types regardless of onlyAstCache so the global type table matches a
          // fresh parse; only the graph population is skipped in cache-warming mode.
          registerUsedTypes(bitcode.usedTypes)
          if !onlyAstCache then AstCache.storeInDiffGraph(bitcode, diffGraph)
      case None =>
          createAst.foreach { unit =>
            // On a miss the frontend already registered its types while parsing; re-registering is
            // idempotent and keeps the miss and hit paths uniform.
            registerUsedTypes(unit.usedTypes)
            partHash.foreach { hash =>
                AstCache
                    .toBitcode(unit.diffGraph)
                    .foreach(bitcode =>
                        saveToCache(bitcode.copy(usedTypes = unit.usedTypes.toList), hash)
                    )
            }
            if !onlyAstCache then diffGraph.absorb(unit.diffGraph)
          }
    end match
  end processClassic

  /** Fragment codec path: [[AstFragment]] over overflowdb2's `GraphFragmentCodec` (`<hash>.frag`).
    *
    * A hit decodes into a throwaway diff and absorbs it only on success, so a corrupt / stale
    * (schema-mismatched) entry is treated exactly like a miss - the part is reparsed and the cache
    * is rewritten - and the caller's diff graph is never left partially populated.
    */
  private def processFragment[T](
    diffGraph: DiffGraphBuilder,
    partHash: Option[String],
    registerUsedTypes: Seq[String] => Unit,
    createAst: => Option[ParsedUnit]
  ): Unit =
    val hit =
        loadFragmentBytes(partHash).exists { bytes =>
          val staging = new DiffGraphBuilder
          AstFragment.decodeIntoDiffGraph(bytes, staging) match
            case Some(usedTypes) =>
                registerUsedTypes(usedTypes)
                if !onlyAstCache then diffGraph.absorb(staging)
                true
            case None => false // corrupt / incompatible -> fall through to reparse
        }
    if !hit then
      createAst.foreach { unit =>
        registerUsedTypes(unit.usedTypes)
        partHash.foreach { hash =>
            AstFragment.encode(unit.diffGraph, unit.usedTypes).foreach(saveFragmentBytes(_, hash))
        }
        if !onlyAstCache then diffGraph.absorb(unit.diffGraph)
      }
  end processFragment

  private def computeEntryHash(cacheKey: => Option[CacheKey], fingerprint: String): Option[String] =
      cacheKey.flatMap { key =>
          Try {
              val digest = MessageDigest.getInstance("SHA-256")
              digest.update(key.identity.getBytes("UTF-8"))
              if fingerprint.nonEmpty then digest.update(fingerprint.getBytes("UTF-8"))
              digest.update(key.content)
              digest.digest().map("%02x".format(_)).mkString
          }.toOption
      }

  private def loadFromCache(partHash: Option[String]): Option[AstBitcode] =
      partHash.flatMap { hash =>
        val cacheFile = Paths.get(cacheDir, s"$hash.ast")
        if !Files.exists(cacheFile) then None
        else
          try
            val bitcode = readBinary[AstBitcode](Files.readAllBytes(cacheFile))
            // Discard and recompute caches written by an incompatible build rather than risking a
            // corrupt graph.
            if AstCache.isCompatible(bitcode) then Some(bitcode)
            else
              Try(Files.deleteIfExists(cacheFile))
              None
          catch
            case e: Exception =>
                logger.warn(
                  s"Failed to load cache $hash: ${e.getClass.getSimpleName} - ${e.getMessage}"
                )
                Try(Files.deleteIfExists(cacheFile))
                None
      }

  private def saveToCache(bitcode: AstBitcode, hash: String): Unit =
    val finalPath = Paths.get(cacheDir, s"$hash.ast")
    val tmpPath   = Paths.get(cacheDir, s"$hash.ast.tmp")
    try
      val bytes = writeBinary(bitcode)
      // Write to a temp file and atomically move into place so concurrent readers never see a
      // partially written cache entry.
      Files.write(tmpPath, bytes)
      Files.move(tmpPath, finalPath, StandardCopyOption.REPLACE_EXISTING)
    catch
      case e: Exception =>
          logger.warn(s"Failed to save AST cache for hash $hash: ${e.getMessage}")
          Try(Files.deleteIfExists(tmpPath))

  /** The cached fragment bytes for a part, or `None` if caching is off, the key is unavailable, or
    * no fragment is on disk. Used by a warm-restore build path to decide whether a whole project
    * can be reconstructed from fragments (see
    * [[io.appthreat.x2cpg.passes.linking.FragmentSplicePass]]).
    */
  def fragmentFor(cacheKey: => Option[CacheKey], fingerprint: String): Option[Array[Byte]] =
      if !enableAstCache then None
      else loadFragmentBytes(computeEntryHash(cacheKey, fingerprint))

  private def loadFragmentBytes(partHash: Option[String]): Option[Array[Byte]] =
      partHash.flatMap { hash =>
        val cacheFile = Paths.get(cacheDir, s"$hash.frag")
        if !Files.exists(cacheFile) then None
        else Try(Files.readAllBytes(cacheFile)).toOption
      }

  private def saveFragmentBytes(bytes: Array[Byte], hash: String): Unit =
    val finalPath = Paths.get(cacheDir, s"$hash.frag")
    val tmpPath   = Paths.get(cacheDir, s"$hash.frag.tmp")
    try
      Files.write(tmpPath, bytes)
      Files.move(tmpPath, finalPath, StandardCopyOption.REPLACE_EXISTING)
    catch
      case e: Exception =>
          logger.warn(s"Failed to save fragment cache for hash $hash: ${e.getMessage}")
          Try(Files.deleteIfExists(tmpPath))

end AstCacheStore
