package io.appthreat.chencli.console

import io.appthreat.console.workspacehandling.{Project, ProjectFile}
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.Cpg

import java.nio.file.Path

class ChenProject(
  projectFile: ProjectFile,
  path: Path,
  cpg: Option[Cpg] = None,
  var context: EngineContext = EngineContext(Semantics.empty)
) extends Project(projectFile, path, cpg) {}
