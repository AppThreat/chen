package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The CycloneDX documents in a graph that the tag passes read components from: the project's own
  * (`bom.json`, `*.cdx.json`, which the frontends store as config files) or the ones atom was given
  * with `--bom-file`/`--bom-dir`, which it stores in their place. A VDR (`*.vdr.json`) is a BOM
  * with vulnerabilities and carries the same components.
  */
object BomFiles:

  private val BomName = ".*bom.*\\.json|.*cdx\\.json|.*vdr\\.json".r

  def isBom(path: String): Boolean =
    val name = path.substring(math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1)
    BomName.matches(name) && !path.contains("node_modules")

  /** The content of every BOM in the graph. */
  def contents(cpg: Cpg): List[String] = cpg.configFile.filter(f => isBom(f.name)).content.l
