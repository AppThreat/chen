package io.appthreat.x2cpg.utils

import java.nio.file.{Files, Path, Paths}
import scala.util.Try

/** Finds a host tool (`mvn`, `gradle`, `gcc`) by name before it is started, so the operating system
  * never searches for it.
  *
  * The tool is looked up in the absolute directories of the `PATH` only. A relative entry (`.`,
  * `bin`) depends on the working directory, which can be the project being scanned, and is skipped.
  * A tool whose path or real path lies under one of the `excluded` directories (the scan root) is
  * never returned, even when the `PATH` lists that directory.
  *
  * On Windows the names tried are `<name>.exe`, `<name>.cmd` and `<name>.bat` in each directory, in
  * that order, and a `.cmd` or `.bat` file is started through `cmd /c` with its absolute path (see
  * [[commandLine]]). Elsewhere the bare name is tried, and the file must be executable.
  */
object ExecutableLookup:

  /** Set for every process started through [[commandLine]] on Windows: `cmd` and `CreateProcess`
    * then do not search the working directory for the programs a batch file starts.
    */
  val WindowsEnvironment: Map[String, String] = Map("NoDefaultCurrentDirectoryInExePath" -> "1")

  private val WindowsSuffixes = Seq(".exe", ".cmd", ".bat")

  /** The host's `PATH`, or the variable spelled in another case (`Path` on Windows). */
  def currentPath(): String =
      sys.env.get("PATH").orElse(sys.env.collectFirst {
          case (k, v) if k.equalsIgnoreCase("PATH") => v
      }).getOrElse("")

  /** The absolute directories a `PATH` value lists, `..` segments folded. */
  def absolutePathDirectories(pathEnvironment: String): Seq[Path] =
      pathEnvironment.split(java.io.File.pathSeparator).toSeq.filter(_.nonEmpty)
          .flatMap(d => Try(Paths.get(d)).toOption).filter(_.isAbsolute).map(_.normalize)

  /** Characters `cmd.exe` interprets on a command line even inside quotes, or that end it. */
  val BatchUnsafeChars: Set[Char] = Set('"', '%', '!', '^', '&', '|', '<', '>', '\r', '\n')

  private def isBareName(name: String): Boolean =
      name.nonEmpty && !name.contains('/') && !name.contains('\\') && name != "." && name != ".."

  private def isBatchFile(executable: Path): Boolean =
    val lower = executable.getFileName.toString.toLowerCase
    lower.endsWith(".cmd") || lower.endsWith(".bat")

  /** Whether `candidate` is outside every directory of `excluded`, by its path and its real path.
    */
  private def isOutside(candidate: Path, excluded: Seq[Path]): Boolean =
    val outside = excluded.map(_.toAbsolutePath.normalize)
    val real    = Try(candidate.toRealPath()).toOption
    real.isDefined && !outside.exists(candidate.startsWith) &&
    !outside.map(p => Try(p.toRealPath()).getOrElse(p)).exists(p => real.exists(_.startsWith(p)))

  /** The absolute path of the tool `name` in the absolute `PATH` directories, outside `excluded`.
    * `name` must be a bare file name; anything with a directory part is not looked up.
    */
  def find(
    name: String,
    excluded: Seq[Path] = Nil,
    pathEnvironment: String = currentPath(),
    windows: Boolean = scala.util.Properties.isWin
  ): Option[Path] =
      if !isBareName(name) then None
      else
        val names = if windows then WindowsSuffixes.map(name + _) else Seq(name)
        absolutePathDirectories(pathEnvironment).iterator
            .flatMap(dir => names.map(dir.resolve))
            .find { candidate =>
                Files.isRegularFile(candidate) && (windows || Files.isExecutable(candidate)) &&
                isOutside(candidate, excluded)
            }

  /** The argument vector that starts `program` with `args`, or why it cannot be started.
    *
    * A bare name is looked up with [[find]]. A path is taken as the operator wrote it, made
    * absolute against this process's working directory (on Windows also with `.exe`, `.cmd` or
    * `.bat` appended), and must not lie under `excluded` either. On Windows a batch file is not
    * started with an argument holding a character of [[BatchUnsafeChars]], as `cmd.exe` would
    * interpret it.
    */
  def command(
    program: String,
    args: Seq[String],
    excluded: Seq[Path] = Nil,
    pathEnvironment: String = currentPath(),
    windows: Boolean = scala.util.Properties.isWin
  ): Either[String, Seq[String]] =
    val executable =
        if isBareName(program) then find(program, excluded, pathEnvironment, windows)
        else
          Try(Paths.get(program).toAbsolutePath.normalize).toOption.flatMap { path =>
            val names =
                if windows then path +: WindowsSuffixes.map(sfx => Paths.get(s"$path$sfx"))
                else Seq(path)
            names.find(Files.isRegularFile(_))
          }.filter(isOutside(_, excluded))
    executable match
      case None => Left(s"'$program' was not found, or lies inside the scanned project")
      case Some(exe) if windows && isBatchFile(exe) =>
          args.find(_.exists(BatchUnsafeChars.contains)) match
            case Some(arg) =>
                Left(
                  s"$exe is a batch file, and the argument '$arg' holds a character cmd.exe " +
                      "would interpret"
                )
            case None => Right(commandLine(exe, args, windows))
      case Some(exe) => Right(commandLine(exe, args, windows))
  end command

  /** The arguments that start the tool at `executable` with `args`. A Windows batch file, which
    * `CreateProcess` does not start by itself, goes through `cmd /d /c call` with its absolute
    * path: `/d` skips the AutoRun commands, and `call` keeps `cmd` from removing the quotes around
    * a path with spaces. Anything else is started directly, and no shell parses `args`.
    */
  def commandLine(
    executable: Path,
    args: Seq[String],
    windows: Boolean = scala.util.Properties.isWin
  ): Seq[String] =
      if windows && isBatchFile(executable) then
        Seq("cmd", "/d", "/c", "call", executable.toString) ++ args
      else executable.toString +: args

  /** The environment additions for a process started through [[commandLine]] on this host. */
  def environment(windows: Boolean = scala.util.Properties.isWin): Map[String, String] =
      if windows then WindowsEnvironment else Map.empty
end ExecutableLookup
