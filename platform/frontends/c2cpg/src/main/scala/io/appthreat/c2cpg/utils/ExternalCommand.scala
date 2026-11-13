package io.appthreat.c2cpg.utils

import scala.collection.mutable
import scala.sys.process.{Process, ProcessLogger}
import scala.util.{Failure, Success, Try}

object ExternalCommand:

  private val IS_WIN: Boolean =
      scala.util.Properties.isWin

  /** Runs `command` (the program, then its arguments) without a shell, with `extraEnv` added to the
    * environment: its standard output and error lines. On Windows an exit code of 1 also counts as
    * success when `acceptWindowsExitOne` is set, as a compiler asked for its search path with `.`
    * as its input exits with 1 after printing it.
    */
  def run(
    command: Seq[String],
    extraEnv: Map[String, String] = Map.empty,
    acceptWindowsExitOne: Boolean = false
  ): Try[Seq[String]] =
    val result                      = mutable.ArrayBuffer.empty[String]
    val lineHandler: String => Unit = line => result.synchronized(result.addOne(line))
    Try(Process(command, None, extraEnv.toSeq*).!(ProcessLogger(lineHandler, lineHandler))) match
      case Success(0) =>
          Success(result.toSeq)
      case Success(1) if IS_WIN && acceptWindowsExitOne =>
          Success(result.toSeq)
      case Success(_) =>
          Failure(new RuntimeException(result.mkString(System.lineSeparator())))
      case Failure(e) => Failure(e)
end ExternalCommand
