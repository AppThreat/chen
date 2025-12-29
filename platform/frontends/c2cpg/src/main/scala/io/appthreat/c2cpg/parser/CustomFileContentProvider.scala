package io.appthreat.c2cpg.parser

import org.eclipse.cdt.core.index.IIndexFileLocation
import org.eclipse.cdt.internal.core.parser.IMacroDictionary
import org.eclipse.cdt.internal.core.parser.scanner.{
    InternalFileContent,
    InternalFileContentProvider
}

import java.nio.file.{Path, Paths}

class CustomFileContentProvider(headerFileFinder: HeaderFileFinder)
    extends InternalFileContentProvider:
  private val currentFileContext = new ThreadLocal[Path]()

  def setContext(path: Path): Unit = currentFileContext.set(path)
  def clearContext(): Unit         = currentFileContext.remove()
  private def loadContent(path: String): InternalFileContent =
    val maybeFullPath = if !getInclusionExists(path) then
      headerFileFinder.find(path, Option(currentFileContext.get()))
    else
      Option(path)

    maybeFullPath match
      case Some(foundPath) =>
          try
            val canonicalPath = Paths.get(foundPath).toRealPath().toString
            val raw           = CdtParser.readFileAsFileContent(Paths.get(canonicalPath))
            raw.asInstanceOf[InternalFileContent]
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
