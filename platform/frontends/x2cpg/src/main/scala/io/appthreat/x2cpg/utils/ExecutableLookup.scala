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

  /** The absolute path of the tool `name` in the absolute `PATH` directories, outside `excluded`.
    * `name` must be a bare file name; anything with a directory part is not looked up.
    */
  def find(
    name: String,
    excluded: Seq[Path] = Nil,
    pathEnvironment: String = currentPath(),
    windows: Boolean = scala.util.Properties.isWin
  ): Option[Path] =
      if name.isEmpty || name.contains('/') || name.contains('\\') || name == "." || name == ".."
      then None
      else
        val outside     = excluded.map(_.toAbsolutePath.normalize)
        val realOutside = outside.map(p => Try(p.toRealPath()).getOrElse(p))
        val names       = if windows then WindowsSuffixes.map(name + _) else Seq(name)
        absolutePathDirectories(pathEnvironment).iterator
            .flatMap(dir => names.map(dir.resolve))
            .find { candidate =>
                Files.isRegularFile(candidate) && (windows || Files.isExecutable(candidate)) &&
                !outside.exists(candidate.startsWith) &&
                Try(candidate.toRealPath()).toOption.exists(real =>
                    !realOutside.exists(real.startsWith)
                )
            }

  /** The arguments that start the tool at `executable` with `args`: `cmd /c` and the absolute path
    * for a Windows batch file, which `CreateProcess` does not start by itself, otherwise the path
    * itself. No shell parses `args` on other hosts.
    */
  def commandLine(
    executable: Path,
    args: Seq[String],
    windows: Boolean = scala.util.Properties.isWin
  ): Seq[String] =
    val lower = executable.getFileName.toString.toLowerCase
    if windows && (lower.endsWith(".cmd") || lower.endsWith(".bat")) then
      Seq("cmd", "/c", executable.toString) ++ args
    else executable.toString +: args

  /** The environment additions for a process started through [[commandLine]] on this host. */
  def environment(windows: Boolean = scala.util.Properties.isWin): Map[String, String] =
      if windows then WindowsEnvironment else Map.empty
end ExecutableLookup
