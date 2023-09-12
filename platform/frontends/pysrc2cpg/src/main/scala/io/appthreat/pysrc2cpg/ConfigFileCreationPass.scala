package io.appthreat.pysrc2cpg

import better.files.File
import io.appthreat.x2cpg.passes.frontend.XConfigFileCreationPass
import io.shiftleft.codepropertygraph.Cpg

class ConfigFileCreationPass(cpg: Cpg, requirementsTxt: String = "requirement.txt")
    extends XConfigFileCreationPass(cpg) {

  override val configFileFilters: List[File => Boolean] = List(
    // TOML files
    extensionFilter(".toml"),
    // INI files
    extensionFilter(".ini"),
    // YAML files
    extensionFilter(".yaml"),
    // Requirements.txt
    pathEndFilter(requirementsTxt)
  )

}
