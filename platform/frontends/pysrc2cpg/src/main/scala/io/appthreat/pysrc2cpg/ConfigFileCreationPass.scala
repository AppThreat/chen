package io.appthreat.pysrc2cpg

import better.files.File
import io.appthreat.x2cpg.passes.frontend.XConfigFileCreationPass
import io.shiftleft.codepropertygraph.Cpg

class ConfigFileCreationPass(cpg: Cpg, requirementsTxt: String = "requirements.txt")
    extends XConfigFileCreationPass(cpg):

    override val configFileFilters: List[File => Boolean] = List(
      // TOML files
      extensionFilter(".toml"),
      // INI files
      extensionFilter(".ini"),
      // YAML files
      extensionFilter(".yaml"),
      extensionFilter(".lock"),
      pathEndFilter("bom.json"),
      pathEndFilter(".cdx.json"),
      pathEndFilter("chennai.json"),
      pathEndFilter("setup.cfg"),
      // Requirements.txt
      pathEndFilter(requirementsTxt)
    )
