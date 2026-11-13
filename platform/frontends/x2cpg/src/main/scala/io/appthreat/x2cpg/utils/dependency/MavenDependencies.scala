package io.appthreat.x2cpg.utils.dependency

import io.appthreat.x2cpg.utils.{ExecutableLookup, ExternalCommand}
import org.slf4j.LoggerFactory

import java.nio.file.Path

object MavenDependencies:
  private val logger = LoggerFactory.getLogger(getClass)

  /** The compile class path Maven reports for the project in `projectDir`. `mvn` is the one found
    * in the absolute `pathEnvironment` directories outside `scanRoot` (see [[ExecutableLookup]]),
    * started directly with the project as its working directory: a `mvn` or `mvn.cmd` the scanned
    * code ships is never the one run.
    */
  private[dependency] def get(
    projectDir: Path,
    scanRoot: Path,
    pathEnvironment: String = ExecutableLookup.currentPath()
  ): Option[collection.Seq[String]] =
    // we can't use -Dmdep.outputFile because that keeps overwriting its own output for each sub-project it's running for
    val args = Seq(
      "-B",
      "dependency:build-classpath",
      "-DincludeScope=compile",
      "-Dorg.slf4j.simpleLogger.defaultLogLevel=info",
      "-Dorg.slf4j.simpleLogger.logFile=System.out"
    )
    val lines = ExecutableLookup.find("mvn", Seq(scanRoot), pathEnvironment) match
      case None =>
          logger.debug("No mvn found in the PATH directories outside the project.")
          Seq.empty
      case Some(mvn) =>
          val result = ExternalCommand.runWithResult(
            ExecutableLookup.commandLine(mvn, args),
            projectDir.toString,
            mergeStdErrInStdOut = true
          )
          if result.exitCode != 0 then
            logger.debug(
              s"Retrieval of compile class path via maven return with error.\n" +
                  "The compile class path may be missing or partial.\n" +
                  "Results will suffer from poor type information.\n\n" +
                  result.stdOut.mkString(System.lineSeparator())
            )
          // the output of a failed run can still hold partial results
          result.stdOut

    var classPathNext = false
    val deps = lines
        .flatMap { line =>
          val isClassPathNow = classPathNext
          classPathNext = line.endsWith("Dependencies classpath:")

          if isClassPathNow then line.split(':') else Array.empty[String]
        }
        .distinct
        .toList

    logger.debug("got {} Maven dependencies", deps.size)
    Some(deps)
  end get
end MavenDependencies
