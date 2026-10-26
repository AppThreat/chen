package io.appthreat.jssrc2cpg.passes

import better.files.File
import io.appthreat.jssrc2cpg.Config
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.utils.{Report, TimeUtils}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.NewConfigFile
import io.shiftleft.passes.ConcurrentWriterCpgPass
import io.shiftleft.utils.IOUtils
import org.slf4j.{Logger, LoggerFactory}

class ConfigPass(cpg: Cpg, config: Config, report: Report = new Report())
    extends ConcurrentWriterCpgPass[File](cpg):

  private val logger: Logger = LoggerFactory.getLogger(getClass)

  // Single-file components (.vue, .svelte) are treated as configuration
  // artifacts alongside the usual config/script files so their content is
  // queryable via configFile nodes.
  protected val allExtensions: Set[String] =
      Set(".json", ".js", ".vue", ".svelte", ".html", ".pug")
  protected val selectedExtensions: Set[String] =
      Set(".json", ".config.js", ".conf.js", ".vue", ".svelte", ".html", ".pug")

  override def generateParts(): Array[File] =
      configFiles(config, allExtensions).toArray

  protected def fileContent(file: File): Seq[String] =
      IOUtils.readLinesInFile(file.path)

  protected def configFiles(config: Config, extensions: Set[String]): Seq[File] =
      SourceFiles
          .determine(config.inputPath, extensions)
          .filterNot(_.contains(Defines.NodeModulesFolder))
          .filter(f => selectedExtensions.exists(f.endsWith))
          .map(File(_))

  override def runOnPart(diffGraph: DiffGraphBuilder, file: File): Unit =
    val path = File(config.inputPath).path.toAbsolutePath.relativize(file.path).toString
    logger.debug(s"Adding file '$path' as config.")
    val (gotCpg, duration) = TimeUtils.time {
        val localDiff  = new DiffGraphBuilder
        val content    = fileContent(file)
        val loc        = content.size
        val configNode = NewConfigFile().name(path).content(content.mkString("\n"))
        report.addReportInfo(path, loc, parsed = true)
        localDiff.addNode(configNode)
        localDiff
    }
    diffGraph.absorb(gotCpg)
    report.updateReport(path, cpg = true, duration)
end ConfigPass
