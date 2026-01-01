package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{CdtParser, FileDefaults, HeaderFileFinder}
import io.appthreat.x2cpg.SourceFiles
import org.eclipse.cdt.core.dom.ast.{
    IASTPreprocessorIfStatement,
    IASTPreprocessorIfdefStatement,
    IASTPreprocessorStatement
}

import java.nio.file.Paths
import scala.collection.parallel.CollectionConverters.ImmutableIterableIsParallelizable
import scala.collection.parallel.immutable.ParIterable

class PreprocessorPass(config: Config):

  private val headerFileFinder = new HeaderFileFinder(config.inputPath)
  private val parser           = new CdtParser(config, headerFileFinder)

  def run(): ParIterable[String] =
      SourceFiles.determine(config.inputPath, FileDefaults.SOURCE_FILE_EXTENSIONS).par.flatMap(
        runOnPart
      )

  private def preprocessorStatement2String(stmt: IASTPreprocessorStatement): Option[String] =
      stmt match
        case s: IASTPreprocessorIfStatement =>
            Option(s"${s.getCondition.mkString}${if s.taken() then "=true" else ""}")
        case s: IASTPreprocessorIfdefStatement =>
            Option(s"${s.getCondition.mkString}${if s.taken() then "=true" else ""}")
        case _ => None

  private def runOnPart(filename: String): Iterable[String] =
      parser.preprocessorStatements(Paths.get(filename)).flatMap(
        preprocessorStatement2String
      ).toSet
end PreprocessorPass
