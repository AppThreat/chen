package io.appthreat.c2cpg.parser

import org.eclipse.cdt.core.index.IIndexFileLocation
import org.eclipse.cdt.internal.core.parser.IMacroDictionary
import org.eclipse.cdt.internal.core.parser.scanner.{
    InternalFileContent,
    InternalFileContentProvider
}

import java.nio.file.{Path, Paths}

class CustomFileContentProvider(headerFileFinder: HeaderFileFinder, currentFileContext: Path)
    extends InternalFileContentProvider:

  private def loadContent(path: String): InternalFileContent =
    val maybeFullPath = if !getInclusionExists(path) then
      headerFileFinder.find(path, Option(currentFileContext))
    else
      Option(path)

    maybeFullPath match
      case Some(foundPath) =>
          try
            val canonicalPath = Paths.get(foundPath).toRealPath().toString
            CdtParser.readFileAsFileContent(Paths.get(canonicalPath)).asInstanceOf[
              InternalFileContent
            ]
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
