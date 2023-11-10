package io.appthreat.console.cpgcreation

import better.files.File
import io.shiftleft.codepropertygraph.Cpg

import scala.sys.process.*
import scala.util.Try

/** A CpgGenerator generates Code Property Graphs from code. Each supported language implements a
  * Generator, e.g., [[JavaCpgGenerator]] implements Java Archive to CPG conversion, while
  * [[CSharpCpgGenerator]] translates C# projects into code property graphs.
  */
abstract class CpgGenerator():

    def isWin: Boolean = scala.util.Properties.isWin

    def isAvailable: Boolean

    /** is this a JVM based frontend? if so, we'll invoke it with -Xmx for max heap settings */
    def isJvmBased: Boolean

    /** Generate a CPG for the given input path. Returns the output path, or a Failure, if no CPG
      * was generated.
      *
      * This method appends command line options in config.frontend.cmdLineParams to the shell
      * command.
      */
    def generate(inputPath: String, outputPath: String = "app.atom"): Try[String]

    protected def runShellCommand(program: String, arguments: Seq[String]): Try[Unit] =
        Try {
            val cmd       = Seq(program) ++ performanceParameter ++ arguments
            val exitValue = cmd.run().exitValue()
            assert(exitValue == 0, s"Error running shell command: exitValue=$exitValue; $cmd")
        }

    protected lazy val performanceParameter =
        if isJvmBased then
            val maxValueInGigabytes =
                Math.floor(Runtime.getRuntime.maxMemory.toDouble / 1024 / 1024 / 1024).toInt
            Seq(s"-J-Xmx${maxValueInGigabytes}G")
        else Nil

    /** override in specific cpg generators to make them apply post processing passes */
    def applyPostProcessingPasses(cpg: Cpg): Cpg =
        cpg
end CpgGenerator
