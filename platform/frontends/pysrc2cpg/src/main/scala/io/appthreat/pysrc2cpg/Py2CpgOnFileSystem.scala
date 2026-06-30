package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.passes.frontend.TypeRecoveryParserConfig
import io.appthreat.x2cpg.{SourceFiles, X2Cpg, X2CpgConfig, X2CpgFrontend}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.utils.IOUtils

import java.nio.file.*
import scala.util.Try
import scala.jdk.CollectionConverters.*

case class Py2CpgOnFileSystemConfig(
  venvDir: Path = Paths.get(".venv"),
  ignoreVenvDir: Boolean = true,
  ignorePaths: Seq[Path] = Nil,
  ignoreDirNames: Seq[String] = Nil,
  requirementsTxt: String = "requirements.txt"
) extends X2CpgConfig[Py2CpgOnFileSystemConfig]
    with TypeRecoveryParserConfig[Py2CpgOnFileSystemConfig]:
  def withVenvDir(venvDir: Path): Py2CpgOnFileSystemConfig =
      copy(venvDir = venvDir).withInheritedFields(this)

  def withIgnoreVenvDir(value: Boolean): Py2CpgOnFileSystemConfig =
      copy(ignoreVenvDir = value).withInheritedFields(this)

  def withIgnorePaths(value: Seq[Path]): Py2CpgOnFileSystemConfig =
      copy(ignorePaths = value).withInheritedFields(this)

  def withIgnoreDirNames(value: Seq[String]): Py2CpgOnFileSystemConfig =
      copy(ignoreDirNames = value).withInheritedFields(this)

  def withRequirementsTxt(text: String): Py2CpgOnFileSystemConfig =
      copy(requirementsTxt = text).withInheritedFields(this)
end Py2CpgOnFileSystemConfig

object Py2CpgOnFileSystem:
  /** Leading path prefixes that mark build/packaging output. A `.py` file under one of these is a
    * *shadow* copy ONLY when the same logical module path also exists outside any build dir — see
    * [[Py2CpgOnFileSystem.dropShadowedBuildCopies]]. We deliberately do NOT ignore these dirs
    * outright, so analysing an unzipped `.egg`/`.tar.gz` (whose sources live entirely under `dist/`
    * or `build/`) still works.
    */
  private val BuildPrefixDirs: Set[String] = Set("build", "dist")

  /** A leading `src` segment (src-layout) is stripped when comparing logical paths, so
    * `src/pkg/x.py` and `build/lib/pkg/x.py` are recognised as the same module.
    */
  private val SrcLayoutDir = "src"

  /** Reduce a relative path to its logical module path: strip a leading build/dist prefix (and an
    * optional `lib` segment, as in `build/lib/...`), then a leading `src`. Returns the remaining
    * path, or `None` if nothing is left.
    */
  private def logicalModulePath(rel: Path): Option[Path] =
    var parts = (0 until rel.getNameCount).map(i => rel.getName(i).toString).toList
    if parts.headOption.exists(BuildPrefixDirs.contains) then
      parts = parts.tail
      if parts.headOption.contains("lib") then parts = parts.tail
    if parts.headOption.contains(SrcLayoutDir) then parts = parts.tail
    parts match
      case Nil          => None
      case head :: tail => Some(tail.foldLeft(Path.of(head))((p, s) => p.resolve(s)))

  private def isUnderBuildDir(rel: Path): Boolean =
      rel.getNameCount > 0 && BuildPrefixDirs.contains(rel.getName(0).toString)

  /** Drop `.py` files under a build/dist dir whose logical module path is ALSO provided by a
    * non-build file. Files that exist only under build/dist (e.g. an unzipped sdist) are kept.
    * `files` are absolute; compared relative to `inputPath`.
    */
  private[pysrc2cpg] def dropShadowedBuildCopies(
    files: Seq[Path],
    inputPath: Path
  ): Seq[Path] =
    val rels = files.map(f => f -> inputPath.relativize(f))
    // Logical module paths contributed by files NOT under a build dir.
    val nonBuildLogical: Set[Path] = rels.iterator
        .filterNot { case (_, rel) => isUnderBuildDir(rel) }
        .flatMap { case (_, rel) => logicalModulePath(rel) }
        .toSet
    rels.collect {
        case (abs, rel)
            if !isUnderBuildDir(rel) ||
                !logicalModulePath(rel).exists(nonBuildLogical.contains) =>
            abs
    }
end Py2CpgOnFileSystem

class Py2CpgOnFileSystem extends X2CpgFrontend[Py2CpgOnFileSystemConfig]:

  /** Entry point for files system based cpg generation from python code.
    * @param config
    *   Configuration for cpg generation.
    */
  override def createCpg(config: Py2CpgOnFileSystemConfig): Try[Cpg] =
      X2Cpg.withNewEmptyCpg(config.outputPath, config) { (cpg, _) =>
        val venvIgnorePath =
            if config.ignoreVenvDir then
              config.venvDir :: Nil
            else
              Nil
        val inputPath         = Path.of(config.inputPath)
        val ignoreDirNamesSet = config.ignoreDirNames.toSet
        val absoluteIgnorePaths = (config.ignorePaths ++ venvIgnorePath).map { path =>
            inputPath.resolve(path)
        }

        val inputFiles = SourceFiles
            .determine(
              config.inputPath,
              Set(".py"),
              ignoredFilesRegex = Option(config.ignoredFilesRegex),
              ignoredFilesPath = Option(config.ignoredFiles)
            )
            .map(x => Path.of(x))
            .filter { file => filterIgnoreDirNames(file, inputPath, ignoreDirNamesSet) }
            .filter { file =>
                !absoluteIgnorePaths.exists(ignorePath => file.startsWith(ignorePath))
            }

        // Remove build/dist shadow copies that merely duplicate real sources; keep
        // build/dist files that are the only copy (e.g. an unzipped sdist/egg).
        val dedupedFiles = Py2CpgOnFileSystem.dropShadowedBuildCopies(inputFiles, inputPath)

        val inputProviders = dedupedFiles.map { inputFile => () =>
          val content = IOUtils.readLinesInFile(inputFile).mkString("\n")
          Py2Cpg.InputPair(content, inputPath.relativize(inputFile).toString)
        }
        val py2Cpg = new Py2Cpg(
          inputProviders,
          cpg,
          config.inputPath,
          config.requirementsTxt,
          config.schemaValidation
        )
        py2Cpg.buildCpg()
      }
  end createCpg

  private def filterIgnoreDirNames(
    file: Path,
    inputPath: Path,
    ignoreDirNamesSet: Set[String]
  ): Boolean =
    var parts = inputPath.relativize(file).iterator().asScala.toList

    if !Files.isDirectory(file) then
      // we're only interested in the directories - drop the file part
      parts = parts.dropRight(1)

    val aPartIsInIgnoreSet = parts.exists(part => ignoreDirNamesSet.contains(part.toString))
    !aPartIsInIgnoreSet

end Py2CpgOnFileSystem
