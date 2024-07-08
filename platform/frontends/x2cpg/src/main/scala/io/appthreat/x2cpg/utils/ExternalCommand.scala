package io.appthreat.x2cpg.utils

import java.util.concurrent.ConcurrentLinkedQueue
import org.apache.commons.lang.StringUtils
import scala.sys.process.{Process, ProcessLogger}
import scala.util.{Failure, Success, Try}
import scala.jdk.CollectionConverters.*

object ExternalCommand:

  private val IS_WIN: Boolean =
      scala.util.Properties.isWin

  private val shellPrefix: Seq[String] =
      if IS_WIN then "cmd" :: "/c" :: Nil else "sh" :: "-c" :: Nil

  def run(command: String, cwd: String, separateStdErr: Boolean = false): Try[Seq[String]] =
    val stdOutOutput = new ConcurrentLinkedQueue[String]
    val stdErrOutput =
        if separateStdErr then new ConcurrentLinkedQueue[String] else stdOutOutput
    val processLogger = ProcessLogger(stdOutOutput.add, stdErrOutput.add)

    Process(shellPrefix :+ command, new java.io.File(cwd)).!(processLogger) match
      case 0 =>
          Success(stdOutOutput.asScala.toSeq)
      case _ =>
          Failure(new RuntimeException(stdErrOutput.asScala.mkString(System.lineSeparator())))

  private val COMMAND_AND: String = " && "

  def toOSCommand(command: String): String = if IS_WIN then command + ".cmd" else command

  def runMultiple(
    command: String,
    inDir: String = ".",
    extraEnv: Map[String, String] = Map.empty
  ): Try[String] =
    val dir           = new java.io.File(inDir)
    val stdOutOutput  = new ConcurrentLinkedQueue[String]
    val stdErrOutput  = new ConcurrentLinkedQueue[String]
    val processLogger = ProcessLogger(stdOutOutput.add, stdErrOutput.add)
    val commands      = command.split(COMMAND_AND).toSeq
    commands.map { cmd =>
      val cmdWithQuotesAroundDir = StringUtils.replace(cmd, inDir, s"'$inDir'")
      Try(Process(cmdWithQuotesAroundDir, dir, extraEnv.toList*).!(processLogger)).getOrElse(
        1
      )
    }.sum match
      case 0 =>
          Success(stdOutOutput.asScala.mkString(System.lineSeparator()))
      case _ =>
          val allOutput = stdOutOutput.asScala ++ stdErrOutput.asScala
          Failure(new RuntimeException(allOutput.mkString(System.lineSeparator())))
  end runMultiple
end ExternalCommand
