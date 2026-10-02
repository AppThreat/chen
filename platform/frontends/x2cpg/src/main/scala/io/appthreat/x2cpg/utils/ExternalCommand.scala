package io.appthreat.x2cpg.utils

import io.shiftleft.utils.IOUtils
import java.io.File
import java.nio.file.{Path, Paths}
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import scala.sys.process.{Process, ProcessLogger}
import scala.util.{Failure, Success, Try}
import scala.jdk.CollectionConverters.*
import scala.util.control.NonFatal

object ExternalCommand:

  private val IS_WIN: Boolean =
      scala.util.Properties.isWin

  private val shellPrefix: Seq[String] =
      if IS_WIN then "cmd" :: "/c" :: Nil else "sh" :: "-c" :: Nil

  case class ExternalCommandResult(
    exitCode: Int,
    stdOut: Seq[String],
    stdErr: Seq[String],
    timedOut: Boolean = false
  ):
    def successOption: Option[Seq[String]] = exitCode match
      case 0 if !timedOut => Some(stdOut)
      case _              => None

    def toTry: Try[Seq[String]] = exitCode match
      case 0 => Success(stdOut)
      case nonZeroExitCode =>
          val allOutput = stdOut ++ stdErr
          val message =
              s"""Process exited with code $nonZeroExitCode. Output:
                       |${allOutput.mkString(System.lineSeparator())}
                       |""".stripMargin
          Failure(new RuntimeException(message))

  def run(command: String, cwd: String, separateStdErr: Boolean): Try[Seq[String]] =
      run(command, cwd, Map.empty, separateStdErr)

  def run(
    command: String,
    cwd: String,
    extraEnv: Map[String, String] = Map.empty,
    separateStdErr: Boolean = false
  ): Try[Seq[String]] =
    val stdOutOutput = new ConcurrentLinkedQueue[String]
    val stdErrOutput =
        if separateStdErr then new ConcurrentLinkedQueue[String] else stdOutOutput
    val processLogger = ProcessLogger(stdOutOutput.add, stdErrOutput.add)

    Process(shellPrefix :+ command, new java.io.File(cwd), extraEnv.toList*).!(processLogger) match
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
      val cmdWithQuotesAroundDir = cmd.replace(inDir, s"'$inDir'")
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

  /** Milliseconds `waitFor` grants a process started by [[runWithResult]] past its
    * `timeoutMillis` before the exit value is read with a fallback, after it was destroyed.
    */
  private val DESTROY_SETTLE_MS = 5000L

  def runWithResult(
    command: Seq[String],
    cwd: String,
    mergeStdErrInStdOut: Boolean = false,
    extraEnv: Map[String, String] = Map.empty,
    timeoutMillis: Long = -1L
  ): ExternalCommandResult =
    val builder = new ProcessBuilder()
        .command(command.toArray*)
        .directory(new File(cwd))
        .redirectErrorStream(mergeStdErrInStdOut)
    builder.environment().putAll(extraEnv.asJava)

    val stdOutFile = File.createTempFile("x2cpg", "stdout")
    val stdErrFile = Option.when(!mergeStdErrInStdOut)(File.createTempFile("x2cpg", "stderr"))

    try
      builder.redirectOutput(stdOutFile)
      stdErrFile.foreach(f => builder.redirectError(f))

      val process = builder.start()
      // A caller that passes no timeout keeps the historic wait-forever behaviour;
      // a caller that passes one gets the process destroyed on expiry rather than
      // an abandoned thread holding a live child (a wedged generator would
      // otherwise outlive the probe that started it).
      val timedOut =
          if timeoutMillis > 0 then !process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
          else
              process.waitFor()
              false
      if timedOut then
          process.destroyForcibly()
          // Give the OS a moment to reap it before reading the exit value.
          process.waitFor(DESTROY_SETTLE_MS, TimeUnit.MILLISECONDS)
      val returnValue = Try(process.exitValue()).getOrElse(1)

      val stdOut = IOUtils.readLinesInFile(stdOutFile.toPath)
      val stdErr = stdErrFile.map(f => IOUtils.readLinesInFile(f.toPath)).getOrElse(Seq.empty)
      ExternalCommandResult(returnValue, stdOut, stdErr, timedOut)
    catch
      case NonFatal(exception) =>
          ExternalCommandResult(1, Seq.empty, stdErr = Seq(exception.getMessage))
    finally
      stdOutFile.delete()
      stdErrFile.foreach(_.delete())
  end runWithResult

  /** Finds the absolute path to the executable directory (e.g. `/path/to/javasrc2cpg/bin`). Based
    * on the package path of a loaded classfile based on some (potentially flakey?) filename
    * heuristics. Context: we want to be able to invoke the x2cpg frontends from any directory, not
    * just their install directory, and then invoke other executables, like astgen, php-parser et
    * al.
    */
  def executableDir(packagePath: Path): Path =
    val packagePathAbsolute = packagePath.toAbsolutePath
    val fixedDir =
        if packagePathAbsolute.toString.contains("lib") then
          var dir = packagePathAbsolute
          while dir.toString.contains("lib") do
            dir = dir.getParent
          dir
        else if packagePathAbsolute.toString.contains("target") then
          var dir = packagePathAbsolute
          while dir.toString.contains("target") do
            dir = dir.getParent
          dir
        else
          Paths.get(".")

    fixedDir.resolve("bin/").toAbsolutePath
end ExternalCommand
