package io.appthreat.c2cpg.parser

import org.eclipse.cdt.core.index.IIndexFileLocation
import org.eclipse.cdt.core.parser.FileContent
import org.eclipse.cdt.internal.core.parser.IMacroDictionary
import org.eclipse.cdt.internal.core.parser.scanner.{
    InternalFileContent,
    InternalFileContentProvider
}

import java.nio.file.{Path, Paths}
import java.util.concurrent.ConcurrentHashMap

object CustomFileContentProvider:

  /** Global, thread-safe cache of include-path existence checks.
    *
    * For every `#include` directive the CDT preprocessor probes *every* entry of the include search
    * path until one resolves (see `CPreprocessor.findInclusion`). For large projects the search
    * path can contain hundreds of directories (aws-sdk-cpp auto-discovers ~450), so a single
    * unresolved system header such as `<vector>` triggers hundreds of `File.exists` syscalls. The
    * very same candidate paths recur across thousands of translation units, so without caching the
    * filesystem stat storm dominates parse time and is the primary cause of the per-file 2-minute
    * timeouts. A process-wide cache collapses each repeated probe to a hash lookup.
    */
  private val existsCache = new ConcurrentHashMap[String, java.lang.Boolean]()

  /** Global, thread-safe cache of resolved inclusions, keyed by `(includee, includerDir)`.
    *
    * Resolving a single `#include` involves a `getInclusionExists` probe, an optional
    * [[HeaderFileFinder]] basename lookup, and a `toRealPath` canonicalisation syscall. The same
    * header is included from the same directory across thousands of translation units, so the
    * resolution result is stable and worth memoising. The value is the canonical path of the
    * resolved header, or `None` when it cannot be resolved.
    */
  private val resolutionCache = new ConcurrentHashMap[(String, String), Option[String]]()

  /** Global, thread-safe cache of decoded header source, keyed by canonical path.
    *
    * Without this cache every translation unit that pulls in a shared header (e.g. the deeply
    * nested aws-sdk-cpp headers) re-reads and re-UTF-8-decodes the file from disk. The decoded
    * `char[]` is treated as immutable read-only source by the CDT lexer, so a single decode can be
    * shared across all parses. A fresh lightweight [[FileContent]] wrapper is created per use.
    */
  private val contentCache = new ConcurrentHashMap[String, Array[Char]]()

  /** Clears the shared caches. Intended for tests / repeated in-process runs. */
  def clearCaches(): Unit =
    existsCache.clear()
    resolutionCache.clear()
    contentCache.clear()
end CustomFileContentProvider

class CustomFileContentProvider(headerFileFinder: HeaderFileFinder, currentFileContext: Path)
    extends InternalFileContentProvider:

  override def getInclusionExists(path: String): Boolean =
    val cached = CustomFileContentProvider.existsCache.get(path)
    if cached ne null then cached.booleanValue()
    else
      // Delegate to the base implementation so UNC paths keep their special handling.
      val result = super.getInclusionExists(path)
      CustomFileContentProvider.existsCache.put(path, java.lang.Boolean.valueOf(result))
      result

  /** Resolves an include string to the canonical path of the backing header, or `None`. */
  private def resolvePath(path: String): Option[String] =
    val maybeFullPath = if !getInclusionExists(path) then
      headerFileFinder.find(path, Option(currentFileContext))
    else
      Option(path)
    maybeFullPath.flatMap { foundPath =>
        try Option(Paths.get(foundPath).toRealPath().toString)
        catch case _: Throwable => None
    }

  private def loadContent(path: String): InternalFileContent =
    val includerDir = Option(currentFileContext.getParent).map(_.toString).getOrElse("")
    val resolved = CustomFileContentProvider.resolutionCache
        .computeIfAbsent((path, includerDir), _ => resolvePath(path))

    resolved match
      case Some(canonicalPath) =>
          try
            val chars = CustomFileContentProvider.contentCache
                .computeIfAbsent(canonicalPath, p => CdtParser.readFileChars(Paths.get(p)))
            FileContent.create(canonicalPath, true, chars).asInstanceOf[InternalFileContent]
          catch
            case e: Throwable => null
      case None => null

  override def getContentForInclusion(
    path: String,
    macroDictionary: IMacroDictionary
  ): InternalFileContent =
      loadContent(path)

  override def getContentForInclusion(
    ifl: IIndexFileLocation,
    astPath: String
  ): InternalFileContent =
      loadContent(astPath)
end CustomFileContentProvider
