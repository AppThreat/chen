package io.appthreat.php2atom.passes

import better.files.File
import io.appthreat.x2cpg.passes.frontend.XConfigFileCreationPass
import io.shiftleft.codepropertygraph.Cpg

class ConfigFileCreationPass(cpg: Cpg) extends XConfigFileCreationPass(cpg):

  override val configFileFilters: List[File => Boolean] = List(
    // TOML files
    extensionFilter(".toml"),
    // INI files
    extensionFilter(".ini"),
    // YAML files
    extensionFilter(".yaml"),
    extensionFilter(".lock"),
    pathEndFilter("composer.json"),
    pathEndFilter("bom.json"),
    pathEndFilter("cdx.json"),
    pathEndFilter("chennai.json"),
    // Composer's record of the installed packages and its autoload maps: the only way to say
    // which package declares a class once `vendor/` itself is not parsed
    composerFile(ConfigFileCreationPass.ComposerFiles)
  )

  private def composerFile(names: Set[String])(file: File): Boolean =
      names.contains(file.name) && file.parent.name == "composer"
end ConfigFileCreationPass

object ConfigFileCreationPass:
  /** The files of `vendor/composer` the callsites slice reads to map a class to its package. */
  val ComposerFiles: Set[String] =
      Set("installed.json", "autoload_classmap.php", "autoload_psr4.php", "autoload_namespaces.php")
