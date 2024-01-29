package io.appthreat.chencli.console

import better.files.*
import io.appthreat.console.workspacehandling.{ProjectFile, WorkspaceLoader}
import io.appthreat.console.{Console, ConsoleConfig, InstallConfig}
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.Cpg

import java.nio.file.Path

object ChenWorkspaceLoader {}

class ChenWorkspaceLoader extends WorkspaceLoader[ChenProject]:
    override def createProject(projectFile: ProjectFile, path: Path): ChenProject =
        val project = new ChenProject(projectFile, path)
        project.context = EngineContext()
        project

class ChenConsole extends Console[ChenProject](new ChenWorkspaceLoader):

    override val config: ConsoleConfig = ChenConsole.defaultConfig

    implicit var semantics: Semantics = context.semantics

    // this is set to be `opts.ossdataflow` on initialization of the shell
    var ossDataFlowOptions: OssDataFlowOptions = new OssDataFlowOptions()

    implicit def context: EngineContext =
        workspace.getActiveProject
            .map(x => x.asInstanceOf[ChenProject].context)
            .getOrElse(EngineContext())

    def loadCpg(inputPath: String): Option[Cpg] =
        report("Deprecated. Please use `importAtom` instead")
        importCpg(inputPath)

    override def applyDefaultOverlays(cpg: Cpg): Cpg =
        super.applyDefaultOverlays(cpg)
        _runAnalyzer(new OssDataFlow(ossDataFlowOptions))
end ChenConsole

object ChenConsole:

    def banner(): String =
        s"""
        | _                          _   _   _   _  __
        |/  |_   _  ._  ._   _. o   |_  / \\ / \\ / \\  / |_|_
        |\\_ | | (/_ | | | | (_| |   |_) \\_/ \\_/ \\_/ /    |
        |
        |Version: $version
      """.stripMargin

    def version: String =
        getClass.getPackage.getImplementationVersion

    def defaultConfig: ConsoleConfig = new ConsoleConfig()
