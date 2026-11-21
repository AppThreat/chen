package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{
    CompileFlags,
    FileDefaults,
    MacroChange,
    ProjectSources,
    SourceLanguage,
    UnitSettings
}
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{File, NewFile, NewTag}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import scala.util.Try

/** The build-context fingerprint: what the parts of a unit's compile command that change the unit
  * as a program hash to. Two commands give the same fingerprint when they compile a unit to the
  * same preprocessing and parsing, and different ones when they do not, so a file a database
  * compiles twice with different definitions carries two contexts.
  *
  * The options that change none of that (an output path, diagnostics and debug settings, the
  * compile-only switch) are the ones [[io.appthreat.c2cpg.parser.CompileCommand.parseArguments]]
  * does not keep, so the fingerprint reads the kept fields only: the driver, the family its table
  * entry names, the language and standard, the include search path, the macro changes, the files
  * forced into the unit or read for their macros, and the target and feature options the compiler
  * is asked with. A unit no compilation database compiles has no command; its configured language,
  * standard, include paths and definitions stand in for one.
  */
object BuildContextPass:

  /** The fingerprint of a compile command, over the fields [[CompileFlags]] keeps. It does not
    * depend on where the project is checked out: the driver counts by its file name, a path under
    * `root` by its path relative to it, every path with `/` separators, and definitions of distinct
    * macros in a canonical order, since their order changes nothing. A command that defines or
    * removes one macro more than once keeps its order, which then decides the macro.
    */
  def fingerprintOf(flags: CompileFlags, root: Path): String =
    val macroLines = flags.macros.map {
        case MacroChange.Define(name, value) => (name, s"define=$name=$value")
        case MacroChange.Undefine(name)      => (name, s"undefine=$name")
    }
    val macros =
        if macroLines.map(_._1).distinct.size == macroLines.size then macroLines.map(_._2).sorted
        else macroLines.map(_._2)
    hash(
      Seq(
        s"driver=${flags.compiler.map(driverName).getOrElse("")}",
        s"family=${flags.family}",
        s"language=${flags.language.getOrElse("")}",
        s"standard=${flags.standard.getOrElse("")}"
      ) ++
          flags.includePaths.map(p => s"include=${portable(p, root)}") ++
          flags.systemIncludePaths.map(p => s"system-include=${portable(p, root)}") ++
          macros ++
          flags.includeFiles.map(p => s"include-file=${portable(p, root)}") ++
          flags.macroFiles.map(p => s"macro-file=${portable(p, root)}") ++
          flags.targetOptions.map(o => s"target=$o")
    )
  end fingerprintOf

  /** The fingerprint of the configured settings of a unit no compilation database compiles. */
  def fingerprintOf(config: Config, language: SourceLanguage): String =
    val root                    = Paths.get(config.inputPath).toAbsolutePath.normalize
    def path(p: String): String = portable(Paths.get(p), root)
    hash(
      Seq(s"language=$language", s"standard=${Option(config.cppStandard).getOrElse("")}") ++
          config.includePaths.toSeq.map(path).sorted.map(p => s"include=$p") ++
          UnitSettings.userDefines(config).toSeq.sorted.map((n, v) => s"define=$n=$v") ++
          config.includeFiles.toSeq.map(path).sorted.map(p => s"include-file=$p") ++
          config.macroFiles.toSeq.map(path).sorted.map(p => s"macro-file=$p")
    )

  /** The driver's file name, without the directory it was found in or a Windows suffix. */
  private def driverName(driver: String): String =
      Option(Paths.get(driver.replace('\\', '/')).getFileName).map(_.toString)
          .getOrElse(driver).stripSuffix(".exe")

  /** A path as the fingerprint reads it: relative to `root` when it lies under it, with `/` as the
    * separator either way.
    */
  private def portable(path: Path, root: Path): String =
    val normalized = path.normalize
    val shown =
        if normalized.isAbsolute && normalized.startsWith(root) then root.relativize(normalized)
        else normalized
    shown.toString.replace('\\', '/')

  /** SHA-256 over the fields, one per line. */
  private def hash(lines: Seq[String]): String =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(lines.mkString("\n").getBytes(StandardCharsets.UTF_8))
    digest.digest().map("%02x".format(_)).mkString
end BuildContextPass

/** The `build-context` tag on the FILE node of every file the front end parsed, both C front ends
  * register it. A translation unit's tag is the fingerprint of the compile command the graph was
  * built from (the configured settings stand in for a unit no compilation database compiles), so of
  * the entries that compile one file with different definitions it names the one whose code the
  * graph holds. A header's tag is `<owner relative path>:<fingerprint>`, the unit whose parse it
  * was read with and that unit's fingerprint.
  *
  * The tag is rebuilt on every run, fresh or from the AST cache: its inputs are the compilation
  * database and the header owners, which no cache carries, and the pass runs wherever
  * [[IncludeRecordPass]] does, on the cold and the warm pipeline alike. That is how a warm run
  * gives the same tags a cold one does.
  */
class BuildContextPass(cpg: Cpg, config: Config, sources: ProjectSources) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val existing: Map[String, File] =
        cpg.file.l.groupBy(_.name).map((name, files) => name -> files.head)
    val root = Paths.get(config.inputPath).toAbsolutePath.normalize
    cpg.namespaceBlock.l
        .flatMap(ns => Option.when(ns.filename.nonEmpty)(ns.filename))
        .distinct.sorted
        .foreach { name =>
            contextOf(root, name).foreach { value =>
              val file = existing.getOrElse(
                name, {
                    val created = NewFile().name(name).order(0)
                    dstGraph.addNode(created)
                    created
                }
              )
              dstGraph.addEdge(
                file,
                NewTag().name(X2CpgDefines.BuildContextTag).value(value),
                EdgeTypes.TAGGED_BY
              )
            }
        }
  end run

  /** The tag value for the file a namespace block names, when that name is a file of this project:
    * the synthetic namespaces of the graph (`<unknown>`, `<includes>`) name no file and stay
    * untagged.
    */
  private def contextOf(root: Path, name: String): Option[String] =
      // `<unknown>` is not a valid path on Windows, where Paths.get throws for it.
      Try(Paths.get(name)).toOption.flatMap(path => contextOf(root, name, path))

  private def contextOf(root: Path, name: String, path: Path): Option[String] =
    val absolute = if path.isAbsolute then path else root.resolve(path)
    if !Files.isRegularFile(absolute) then None
    else if FileDefaults.isHeaderFile(name) then
      ownerOf(absolute) match
        case Some(owner) => Some(s"${relative(owner)}:${unitFingerprint(owner)}")
        case None        => Some(unitFingerprint(absolute))
    else Some(unitFingerprint(absolute))

  /** The unit whose parse `header` is read with, from the front ends' owner map: keyed by real
    * paths, because a namespace names its file the way its front end relativized it, which is not
    * always the owners' own spelling.
    */
  private val owners: Map[Path, Path] =
      sources.headerOwners.map((header, unit) =>
          Paths.get(AstCreationPass.realPath(
            header.toString
          )) -> unit
      )

  private def ownerOf(header: Path): Option[Path] =
    val real = Paths.get(AstCreationPass.realPath(header.toString))
    owners.get(real).orElse(owners.get(header))

  /** The fingerprint of `unit`'s compile command; of a unit no database compiles, of the configured
    * settings it is parsed with.
    */
  private def unitFingerprint(unit: Path): String =
      sources.database.flatMap(_.commandFor(unit))
          .map(c =>
              BuildContextPass.fingerprintOf(
                c.flags,
                Paths.get(config.inputPath).toAbsolutePath.normalize
              )
          )
          .getOrElse(BuildContextPass.fingerprintOf(config, sources.settingsFor(unit).language))

  /** The path of `file` as the graph's FILE names spell it: relative to the input path. */
  private def relative(file: Path): String =
      SourceFiles.toRelativePath(file.toString, config.inputPath)
end BuildContextPass
