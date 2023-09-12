package io.appthreat.chencli

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.x2cpg.X2Cpg.applyDefaultOverlays
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.layers.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

object DefaultOverlays {

  val DEFAULT_CPG_IN_FILE           = "cpg.bin"
  val defaultMaxNumberOfDefinitions = 4000

  /** Load the CPG at `storeFilename` and add enhancements, turning the CPG into an SCPG.
    *
    * @param storeFilename
    *   the filename of the cpg
    */
  def create(storeFilename: String, maxNumberOfDefinitions: Int = defaultMaxNumberOfDefinitions): Cpg = {
    val cpg = CpgBasedTool.loadFromOdb(storeFilename)
    applyDefaultOverlays(cpg)
    val context = new LayerCreatorContext(cpg)
    val options = new OssDataFlowOptions(maxNumberOfDefinitions)
    new OssDataFlow(options).run(context)
    cpg
  }

}
