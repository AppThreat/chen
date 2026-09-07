package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.passes.frontend.ImportStringHandling
import io.appthreat.x2cpg.passes.frontend.XInheritanceFullNamePass
import io.shiftleft.codepropertygraph.Cpg

/** Using some basic heuristics, will try to resolve type full names from types found within the
  * CPG. Requires ImportPass as a pre-requisite.
  */
class PythonInheritanceNamePass(cpg: Cpg) extends XInheritanceFullNamePass(cpg):

  override val moduleName: String = "<module>"
  override val fileExt: String    = ".py"

  /** The combined import path already IS the dotted full name (`foo.bar.Baz`), so the base pass's
    * path-to-file rewrite is skipped and stubs land at names the graph can match.
    */
  override protected def xTypeFullName(
    importedType: String,
    importedPath: String
  ): (String, String) =
    val combinedPath = ImportStringHandling.combinedPath(importedType, importedPath)
    combinedPath.split('.').lastOption match
      case Some(tName) => (tName, combinedPath)
      case None        => (combinedPath, combinedPath)
