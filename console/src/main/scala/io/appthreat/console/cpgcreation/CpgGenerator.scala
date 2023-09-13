package io.appthreat.console.cpgcreation

import better.files.File
import io.shiftleft.codepropertygraph.Cpg

import scala.sys.process._
import scala.util.Try

/** A CpgGenerator generates Code Property Graphs from code. Each supported language implements a Generator, e.g.,
  * [[JavaCpgGenerator]] implements Java Archive to CPG conversion, while [[CSharpCpgGenerator]] translates C# projects
  * into code property graphs.
  */
abstract class CpgGenerator() {

  def isWin: Boolean = scala.util.Properties.isWin

  def isAvailable: Boolean

  /** is this a JVM based frontend? if so, we'll invoke it with -Xmx for max heap settings */
  def isJvmBased: Boolean

  /** Generate a CPG for the given input path. Returns the output path, or a Failure, if no CPG was generated.
    *
    * This method appends command line options in config.frontend.cmdLineParams to the shell command.
    */
  def generate(inputPath: String, outputPath: String = "app.atom"): Try[String]

  protected def runShellCommand(program: String, arguments: Seq[String]): Try[Unit] =
    Try {
      assert(File(program).exists, s"CPG generator does not exist at: $program")

      val cmd       = Seq(program) ++ performanceParameter ++ arguments
      val cmdString = cmd.mkString(" ")

      println(
        s"""=======================================================================================================
           |Invoking Atom generator in a separate process. Note that the new process will consume additional memory.
           |If you are importing a large codebase (and/or running into memory issues), please try the following:
           |1) exit chen
           |2) invoke the frontend: $cmdString
           |3) start chennai, import the atom: `importAtom("path/to/atom")`
           |=======================================================================================================
           |""".stripMargin
      )

      val exitValue = cmd.run().exitValue()
      assert(exitValue == 0, s"Error running shell command: exitValue=$exitValue; $cmd")
    }

  protected lazy val performanceParameter = {
    if (isJvmBased) {
      val maxValueInGigabytes = Math.floor(Runtime.getRuntime.maxMemory.toDouble / 1024 / 1024 / 1024).toInt
      val minValueInGigabytes = Math.floor(maxValueInGigabytes.toDouble / 2).toInt
      Seq(s"-J-Xms${minValueInGigabytes}G", s"-J-Xmx${maxValueInGigabytes}G", "-J-XX:+ExplicitGCInvokesConcurrent", "-J-XX:+ParallelRefProcEnabled", "-J-XX:+UnlockExperimentalVMOptions", "-J-XX:G1NewSizePercent=20", "-J-XX:+UnlockDiagnosticVMOptions", "-J-XX:G1SummarizeRSetStatsPeriod=1")
    } else Nil
  }

  /** override in specific cpg generators to make them apply post processing passes */
  def applyPostProcessingPasses(cpg: Cpg): Cpg =
    cpg

}
