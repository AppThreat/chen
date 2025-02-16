package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{CdtParser, FileDefaults}
import io.appthreat.c2cpg.utils.Report
import io.appthreat.x2cpg.SourceFiles
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass

import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern
import scala.util.matching.Regex

class AstCreationPass(cpg: Cpg, config: Config, report: Report = new Report())
    extends ConcurrentWriterCpgPass[String](cpg):

  private val file2OffsetTable: ConcurrentHashMap[String, Array[Int]] = new ConcurrentHashMap()
  private val parser: CdtParser                                       = new CdtParser(config)

  private val EscapedFileSeparator = Pattern.quote(java.io.File.separator)
  private val DefaultIgnoredFolders: List[Regex] = List(
    "\\..*".r,
    s"(.*[$EscapedFileSeparator])?tests?[$EscapedFileSeparator].*".r,
    s"(.*[$EscapedFileSeparator])?CMakeFiles[$EscapedFileSeparator].*".r
  )

  override def generateParts(): Array[String] =
      SourceFiles
          .determine(
            config.inputPath,
            FileDefaults.SOURCE_FILE_EXTENSIONS ++ FileDefaults.HEADER_FILE_EXTENSIONS,
            ignoredDefaultRegex = Option(DefaultIgnoredFolders),
            ignoredFilesRegex = Option(config.ignoredFilesRegex),
            ignoredFilesPath = Option(config.ignoredFiles)
          )
          .sortWith(_.compareToIgnoreCase(_) > 0)
          .toArray

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
    val path    = Paths.get(filename).toAbsolutePath
    val relPath = SourceFiles.toRelativePath(path.toString, config.inputPath)
    try
      val parseResult = parser.parse(path)
      parseResult match
        case Some(translationUnit) =>
            val localDiff =
                new AstCreator(relPath, config, translationUnit, file2OffsetTable)(
                  config.schemaValidation
                ).createAst()
            diffGraph.absorb(localDiff)
        case None =>
    catch
      case e: Throwable =>
end AstCreationPass
