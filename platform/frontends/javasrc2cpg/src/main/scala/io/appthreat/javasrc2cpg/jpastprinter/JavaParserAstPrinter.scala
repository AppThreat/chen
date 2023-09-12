package io.appthreat.javasrc2cpg.jpastprinter

import com.github.javaparser.printer.YamlPrinter
import com.github.javaparser.printer.DotPrinter
import io.appthreat.javasrc2cpg.{Config, util}
import io.appthreat.javasrc2cpg.util.SourceParser
import io.shiftleft.semanticcpg.language.dotextension.Shared

import java.nio.file.Path

object JavaParserAstPrinter {
  def printJpAsts(config: Config): Unit = {

    val sourceParser = util.SourceParser(config, false)
    val printer      = new YamlPrinter(true)

    SourceParser.getSourceFilenames(config).foreach { filename =>
      val relativeFilename = Path.of(config.inputPath).relativize(Path.of(filename)).toString
      sourceParser.parseAnalysisFile(relativeFilename).foreach { compilationUnit =>
        println(relativeFilename)
        println(printer.output(compilationUnit))
      }
    }
  }
}
