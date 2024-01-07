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
      pathEndFilter(".cdx.json"),
      pathEndFilter("chennai.json")
    )
