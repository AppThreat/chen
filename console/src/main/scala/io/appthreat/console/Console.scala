package io.appthreat.console

import better.files.File
import io.appthreat.console.cpgcreation.{CpgGeneratorFactory, ImportCode}
import io.appthreat.console.workspacehandling.{Project, WorkspaceLoader, WorkspaceManager}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.appthreat.x2cpg.X2Cpg.defaultOverlayCreators
import io.shiftleft.codepropertygraph.cpgloading.CpgLoader
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.Overlays
import io.shiftleft.semanticcpg.language.types.structure.MethodTraversal
import io.shiftleft.semanticcpg.language.dotextension.ImageViewer
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}
import io.shiftleft.semanticcpg.utils.Torch
import overflowdb.traversal.help.Doc
import me.shadaj.scalapy.py
import me.shadaj.scalapy.py.SeqConverters
import py.PyQuote
import me.shadaj.scalapy.interpreter.CPythonInterpreter

import scala.collection.mutable
import scala.sys.process.Process
import scala.util.control.NoStackTrace
import scala.util.{Failure, Success, Try}
import scala.collection.mutable.ListBuffer

class Console[T <: Project](loader: WorkspaceLoader[T], baseDir: File = File.currentWorkingDirectory)
    extends Reporting {

  import Console._

  private val _config       = new ConsoleConfig()
  def config: ConsoleConfig = _config
  def console: Console[T]   = this

  protected var workspaceManager: WorkspaceManager[T] = _
  switchWorkspace(baseDir.path.resolve("workspace").toString)
  protected def workspacePathName: String = workspaceManager.getPath

  private val nameOfCpgInProject           = "cpg.bin"
  implicit val resolver: ICallResolver     = NoResolve
  implicit val finder: NodeExtensionFinder = DefaultNodeExtensionFinder

  implicit val pyGlobal: me.shadaj.scalapy.py.Dynamic.global.type = py.Dynamic.global
  var richTableLib: me.shadaj.scalapy.py.Dynamic                  = py.module("logging")
  var richTreeLib: me.shadaj.scalapy.py.Dynamic                   = py.module("logging")
  var richProgressLib: me.shadaj.scalapy.py.Dynamic               = py.module("logging")
  var richConsole: me.shadaj.scalapy.py.Dynamic                   = py.module("logging")
  var richAvailable                                               = true
  try {
    richTableLib = py.module("rich.table")
    richTreeLib = py.module("rich.tree")
    richProgressLib = py.module("rich.progress")
    richConsole = py.module("chenpy.logger").console
  } catch {
    case _: Exception => richAvailable = false
  }

  implicit object ConsoleImageViewer extends ImageViewer {
    def view(imagePathStr: String): Try[String] = {
      // We need to copy the file as the original one is only temporary
      // and gets removed immediately after running this viewer instance asynchronously via .run().
      val tmpFile = File(imagePathStr).copyTo(File.newTemporaryFile(suffix = ".svg"), overwrite = true)
      tmpFile.deleteOnExit(swallowIOExceptions = true)
      Try {
        val command = if (scala.util.Properties.isWin) { Seq("cmd.exe", "/C", config.tools.imageViewer) }
        else { Seq(config.tools.imageViewer) }
        Process(command :+ tmpFile.path.toAbsolutePath.toString).run()
      } match {
        case Success(_) =>
          // We never handle the actual result anywhere.
          // Hence, we just pass a success message.
          Success(s"Running viewer for '$tmpFile' finished.")
        case Failure(exc) =>
          System.err.println("Executing image viewer failed. Is it installed? ")
          System.err.println(exc)
          Failure(exc)
      }
    }
  }

  @Doc(
    info = "Access to the workspace directory",
    longInfo = """
                 |All auditing projects are stored in a workspace directory, and `workspace`
                 |provides programmatic access to this directory. Entering `workspace` provides
                 |a list of all projects, indicating which code the project makes accessible,
                 |whether the project is open, and which analyzers have been run to produce it.
                 |Multiple projects can be open at any given time, however, only one project
                 |can be active. Queries and edit-operations are executed on the active project
                 |only.
                 |
                 |Operations
                 |
                 |----------
                 |
                 |`workspace` provides low-level access to the workspace directory. In most cases,
                 |it is a better idea to use higher-level operations such as `importCode`, `open`,
                 |`close`, and `delete`, which make use of workspace operations internally.
                 |
                 |* workspace.open([name]): open project by name and make it the active project.
                 | If `name` is omitted, the last project in the workspace list is opened. If
                 | the project is already open, this has the same effect as `workspace.setActiveProject([name])`
                 |
                 |* workspace.close([name]): close project by name. Does not remove the project.
                 |
                 |* workspace.remove([name]): close and remove project by name.
                 |
                 |* workspace.reset: create a fresh workspace directory, deleting the current
                 |workspace directory
                 |
                 |""",
    example = "workspace"
  )
  def workspace: WorkspaceManager[T] = workspaceManager

  @Doc(
    info = "Close current workspace and open a different one",
    longInfo = """ | By default, the workspace in $INSTALL_DIR/workspace is used.
                 | This method allows specifying a different workspace directory
                 | via the `pathName` parameter.
                 | Before changing the workspace, the current workspace will be
                 | closed, saving any unsaved changes.
                 | If `pathName` points to a non-existing directory, then a new
                 | workspace is first created.
                 |"""
  )
  def switchWorkspace(pathName: String): Unit = {
    if (workspaceManager != null) {
      report("Saving current workspace before changing workspace")
      workspaceManager.projects.foreach { p =>
        p.close
      }
    }
    workspaceManager = new WorkspaceManager[T](pathName, loader)
  }

  @Doc(info = "Currently active project", example = "project")
  def project: T =
    workspace.projectByCpg(cpg).getOrElse(throw new RuntimeException("No active project"))

  @Doc(
    info = "CPG of the active project",
    longInfo = """
                 |Upon importing code, a project is created that holds
                 |an intermediate representation called `Code Property Graph`. This
                 |graph is a composition of low-level program representations such
                 |as abstract syntax trees and control flow graphs, but it can be arbitrarily
                 |extended to hold any information relevant in your audit, information
                 |about HTTP entry points, IO routines, information flows, or locations
                 |of vulnerable code. Think of Ocular and Joern as a CPG editors.
                 |
                 |In practice, `cpg` is the root object of the query language, that is, all
                 |query language constructs can be invoked starting from `cpg`. For example,
                 |`cpg.method.l` lists all methods, while `cpg.finding.l` lists all findings
                 |of potentially vulnerable code.
                 |""",
    example = "cpg.method.l"
  )
  implicit def cpg: Cpg = workspace.cpg
  def atom: Cpg         = workspace.cpg

  /** All cpgs loaded in the workspace
    */
  def cpgs: Iterator[Cpg] = {
    if (workspace.projects.lastOption.isEmpty) {
      Iterator()
    } else {
      val activeProjectName = project.name
      (workspace.projects.filter(_.cpg.isDefined).iterator.flatMap { project =>
        open(project.name)
        Some(project.cpg)
      } ++ Iterator({ open(activeProjectName); None })).flatten
    }
  }

  // Provide `.l` on iterators, specifically so
  // that `cpgs.flatMap($query).l` is possible
  implicit class ItExtend[X](it: Iterator[X]) {
    def l: List[X] = it.toList
  }

  @Doc(
    info = "Open project by name",
    longInfo = """
                 |open([projectName])
                 |
                 |Opens the project named `name` and make it the active project.
                 |If `name` is not provided, the active project is opened. If `name`
                 |is a path, the project name is derived from and a deprecation
                 |warning is printed.
                 |
                 |Upon completion of this operation, the CPG stored in this project
                 |can be queried via `cpg`. Returns an optional reference to the
                 |project, which is empty on error.
                 |""",
    example = """open("projectName")"""
  )
  def open(name: String): Option[Project] = {
    val projectName = fixProjectNameAndComplainOnFix(name)
    workspace.openProject(projectName).map { project =>
      project
    }
  }

  @Doc(
    info = "Open project for input path",
    longInfo = """
                 |openForInputPath([input-path])
                 |
                 |Opens the project of the CPG generated for the input path `input-path`.
                 |
                 |Upon completion of this operation, the CPG stored in this project
                 |can be queried via `cpg`. Returns an optional reference to the
                 |project, which is empty on error.
                 |"""
  )
  def openForInputPath(inputPath: String): Option[Project] = {
    val absInputPath = File(inputPath).path.toAbsolutePath.toString
    workspace.projects
      .filter(x => x.inputPath == absInputPath)
      .map(_.name)
      .map(open)
      .headOption
      .flatten
  }

  /** Open the active project
    */
  def open: Option[Project] = {
    workspace.projects.lastOption.flatMap { p =>
      open(p.name)
    }
  }

  /** Delete project from disk and remove it from the workspace manager. Returns the (now invalid) project.
    * @param name
    *   the name of the project
    */
  @Doc(info = "Close and remove project from disk", example = "delete(projectName)")
  def delete(name: String): Option[Unit] = {
    workspaceManager.getActiveProject.foreach(_.cpg.foreach(_.close()))
    defaultProjectNameIfEmpty(name).flatMap(workspace.deleteProject)
  }

  @Doc(info = "Exit the REPL")
  def exit: Unit = {
    workspace.projects.foreach(_.close)
    System.exit(0)
  }

  /** Delete the active project
    */
  def delete: Option[Unit] = delete("")

  protected def defaultProjectNameIfEmpty(name: String): Option[String] = {
    if (name.isEmpty) {
      val projectNameOpt = workspace.projectByCpg(cpg).map(_.name)
      if (projectNameOpt.isEmpty) {
        report("Fatal: cannot find project for active CPG")
      }
      projectNameOpt
    } else {
      Some(fixProjectNameAndComplainOnFix(name))
    }
  }

  @Doc(
    info = "Write all changes to disk",
    longInfo = """
                 |Close and reopen all loaded CPGs. This ensures
                 |that changes have been flushed to disk.
                 |
                 |Returns list of affected projects
                 |""",
    example = "save"
  )
  def save: List[Project] = {
    report("Saving graphs on disk. This may take a while.")
    workspace.projects.collect {
      case p: Project if p.cpg.isDefined =>
        p.close
        workspace.openProject(p.name)
    }.flatten
  }

  @Doc(
    info = "Create new project from code",
    longInfo = """
                 |importCode(<inputPath>, [projectName], [namespaces], [language])
                 |
                 |Type `importCode` alone to get a list of all supported languages
                 |
                 |Import code at `inputPath`. Creates a new project, generates a CPG,
                 |and opens the project. Upon success, the CPG can be queried via the `cpg`
                 |object. Default overlays are already applied to the newly created CPG.
                 |Returns new CPG and ensures that `cpg` now refers to this new CPG.
                 |
                 |By default, `importCode` attempts to guess the source language of
                 |the code you provide. You can also specify the source language
                 |manually, by running `importCode.<language>`. For example, `importCode.c`
                 |runs the C/C++ frontend.
                 |
                 |Type `importCode` alone to get an overview of all available language modules.
                 |
                 |Parameters:
                 |
                 |-----------
                 |
                 |inputPath: http or git url, CVE or GHSA id, location on disk of the code to analyze. e.g., a directory
                 |containing source code or a Java archive (JAR) or Android apk file.
                 |
                 |projectName: a unique name used for project management. If this parameter
                 |is omitted, the name will be derived from `inputPath`
                 |
                 |namespaces: the whitelist of namespaces to analyse. Specifying this
                 |parameter is only effective if the language frontend supports it.
                 |If the list is omitted or empty, namespace selection is performed
                 |automatically via heuristics.
                 |
                 |language: the programming language which the code at `inputPath` is written in.
                 |If `language` is empty, the language used is guessed by inspecting
                 |the filename found and possibly by looking into the file/directory.
                 |
                 |""",
    example = """importCode("git url or path")"""
  )
  def importCode = new ImportCode(this)

  @Doc(
    info = "Create new project from existing atom",
    longInfo = """
        |importAtom(<inputPath>, [projectName])
        |
        |Import an existing atom.
        |
        |Parameters:
        |
        |inputPath: path where the existing atom (in overflowdb format)
        |is stored
        |
        |projectName: name of the new project. If this parameter
        |is omitted, the path is derived from `inputPath`
        |
        |""",
    example = """importAtom("app.atom")"""
  )
  def importAtom(inputPath: String, projectName: String = ""): Unit = {
    importCpg(inputPath, projectName, false)
    summary
  }
  @Doc(
    info = "Create new project from existing CPG",
    longInfo = """
                 |importCpg(<inputPath>, [projectName], [enhance])
                 |
                 |Import an existing CPG. The CPG is stored as part
                 |of a new project and blanks are filled in by analyzing the CPG.
                 |If we find that default overlays have not been applied, these
                 |are applied to the CPG after loading it.
                 |
                 |Parameters:
                 |
                 |inputPath: path where the existing CPG (in overflowdb format)
                 |is stored
                 |
                 |projectName: name of the new project. If this parameter
                 |is omitted, the path is derived from `inputPath`
                 |
                 |enhance: run default overlays and post-processing passes. Defaults to `true`.
                 |Pass `enhance=false` to disable the enhancements.
                 |""",
    example = """importCpg("app.atom")"""
  )
  def importCpg(inputPath: String, projectName: String = "", enhance: Boolean = true): Option[Cpg] = {
    val name =
      Option(projectName).filter(_.nonEmpty).getOrElse(deriveNameFromInputPath(inputPath, workspace))
    val cpgFile = File(inputPath)

    if (!cpgFile.exists) {
      report(s"CPG at $inputPath does not exist. Bailing out.")
      return None
    }

    val pathToProject         = workspace.createProject(inputPath, name)
    val cpgDestinationPathOpt = pathToProject.map(_.resolve(nameOfCpgInProject))

    if (cpgDestinationPathOpt.isEmpty) {
      report(s"Error creating project for input path: `$inputPath`")
      return None
    }

    val cpgDestinationPath = cpgDestinationPathOpt.get

    if (CpgLoader.isLegacyCpg(cpgFile)) {
      report("You have provided a legacy proto CPG. Attempting conversion.")
      try {
        CpgConverter.convertProtoCpgToOverflowDb(cpgFile.path.toString, cpgDestinationPath.toString)
      } catch {
        case exc: Exception =>
          report("Error converting legacy CPG: " + exc.getMessage)
          return None
      }
    } else {
      cpgFile.copyTo(cpgDestinationPath, overwrite = true)
    }

    val cpgOpt = open(name).flatMap(_.cpg)

    if (cpgOpt.isEmpty) {
      workspace.deleteProject(name)
    }

    if (enhance) {
      cpgOpt
        .filter(_.metaData.hasNext)
        .foreach { cpg =>
          applyDefaultOverlays(cpg)
          applyPostProcessingPasses(cpg)
        }
    }
    cpgOpt
  }

  @Doc(
    info = "Close project by name",
    longInfo = """|Close project. Resources are freed but the project remains on disk.
                  |The project remains active, that is, calling `cpg` now raises an
                  |exception. A different project can now be activated using `open`.
                  |""",
    example = "close(projectName)"
  )
  def close(name: String): Option[Project] = defaultProjectNameIfEmpty(name).flatMap(workspace.closeProject)

  def close: Option[Project] = close("")

  /** Close the project and open it again.
    *
    * @param name
    *   the name of the project
    */
  def reload(name: String): Option[Project] = {
    close(name).flatMap(p => open(p.name))
  }

  @Doc(
    info = "Display summary information",
    longInfo = """|Displays summary about the loaded atom such as the number of files, methods, annotations etc.
         |Requires the python modules to be installed.
         |""",
    example = "summary"
  )
  def summary: Unit = {
    try {
      val table = richTableLib.Table(title = "Atom Summary")
      table.add_column("Node Type")
      table.add_column("Count")
      table.add_row("Files", "" + atom.file.size)
      table.add_row("Methods", "" + atom.method.size)
      table.add_row("Annotations", "" + atom.annotation.size)
      table.add_row("Imports", "" + atom.imports.size)
      table.add_row("Literals", "" + atom.literal.size)
      table.add_row("Config Files", "" + atom.configFile.size)
      val appliedOverlays = Overlays.appliedOverlays(atom)
      if (appliedOverlays.nonEmpty) table.add_row("Overlays", "" + appliedOverlays.size)
      richConsole.print(table)
    } catch {
      case exc: Exception => report(exc.getMessage)
    }
  }

  @Doc(
    info = "List files",
    longInfo = """|Lists the files from the loaded atom.
         |Requires the python modules to be installed.
         |""",
    example = "files"
  )
  def files(title: String = "Files"): Unit = {
    try {
      val table = richTableLib.Table(title = title, highlight = true)
      table.add_column("File Name")
      table.add_column("Method Count")
      atom.file.whereNot(_.name("<unknown>")).foreach { f => table.add_row(f.name, "" + f.method.size) }
      richConsole.print(table)
    } catch {
      case exc: Exception => report(exc.getMessage)
    }
  }
  def files: Unit = files("Files")

  @Doc(
    info = "List methods",
    longInfo = """|Lists the methods by files from the loaded atom.
         |Requires the python modules to be installed.
         |
         |Parameters:
         |
         |title: Title for the table. Default Methods.
         |tree: Display as a tree instead of table
         |""",
    example = "methods('Methods', includeCalls=true, tree=true)"
  )
  def methods(title: String = "Methods", includeCalls: Boolean = false, tree: Boolean = false): Unit = {
    try {
      if (tree) {
        val rootTree = richTreeLib.Tree(title, highlight = true)
        atom.file.whereNot(_.name("<unknown>")).foreach { f =>
          val childTree = richTreeLib.Tree(f.name, highlight = true)
          f.method.foreach(m => {
            val mtree = childTree.add(m.fullName)
            if (includeCalls)
              m.call
                .filterNot(_.name.startsWith("<operator"))
                .toSet
                .foreach(c =>
                  mtree
                    .add(
                      c.methodFullName + (if (c.callee(NoResolve).head.isExternal) " :right_arrow_curving_up:" else "")
                    )
                )
          })
          rootTree.add(childTree)
        }
        richConsole.print(rootTree)
      } else {
        val table = richTableLib.Table(title = title, highlight = true, show_lines = true)
        table.add_column("File Name")
        table.add_column("Methods")
        atom.file.whereNot(_.name("<unknown>")).foreach { f =>
          table.add_row(f.name, f.method.fullName.l.mkString("\n"))
        }
        richConsole.print(table)
      }
    } catch {
      case exc: Exception => report(exc.getMessage)
    }
  }
  def methods: Unit = methods("Methods")

  @Doc(
    info = "List annotations",
    longInfo = """|Lists the method annotations by files from the loaded atom.
         |Requires the python modules to be installed.
         |""",
    example = "annotations"
  )
  def annotations(title: String = "Annotations"): Unit = {
    try {
      val table = richTableLib.Table(title = title, highlight = true, show_lines = true)
      table.add_column("File Name")
      table.add_column("Methods")
      table.add_column("Annotations")
      atom.file.whereNot(_.name("<unknown>")).method.filter(_.annotation.nonEmpty).foreach { m =>
        table.add_row(m.location.filename, m.fullName, m.annotation.fullName.l.mkString("\n"))
      }
      richConsole.print(table)
    } catch {
      case exc: Exception => report(exc.getMessage)
    }
  }

  def annotations: Unit = annotations("Annotations")

  @Doc(
    info = "List imports",
    longInfo = """|Lists the imports by files from the loaded atom.
         |Requires the python modules to be installed.
         |""",
    example = "imports"
  )
  def imports(title: String = "Imports"): Unit = {
    try {
      val table = richTableLib.Table(title = title, highlight = true, show_lines = true)
      table.add_column("File Name")
      table.add_column("Import")
      atom.imports.foreach { i =>
        table.add_row(i.file.name.l.mkString("\n"), i.importedEntity.getOrElse(""))
      }
      richConsole.print(table)
    } catch {
      case exc: Exception => report(exc.getMessage)
    }
  }

  def imports: Unit = imports("Imports")

  @Doc(
    info = "List declarations",
    longInfo = """|Lists the declarations by files from the loaded atom.
         |Requires the python modules to be installed.
         |""",
    example = "declarations"
  )
  def declarations(title: String = "Declarations"): Unit = {
    try {
      val table = richTableLib.Table(title = title, highlight = true, show_lines = true)
      table.add_column("File Name")
      table.add_column("Declarations")
      atom.file.whereNot(_.name("<unknown>")).foreach { f =>
        val dec: Set[Declaration] =
          (f.assignment.argument(1).filterNot(_.code == "this").isIdentifier.refsTo ++ f.method.parameter
            .filterNot(_.code == "this")
            .filter(_.typeFullName != "ANY")).toSet
        table.add_row(f.name, dec.name.toSet.mkString("\n"))
      }
      richConsole.print(table)
    } catch {
      case exc: Exception => report(exc.getMessage)
    }
  }

  def declarations: Unit = declarations("Declarations")

  @Doc(
    info = "List sensitive literals",
    longInfo = """|Lists the sensitive literals by files from the loaded atom.
         |Requires the python modules to be installed.
         |""",
    example = "sensitive"
  )
  def sensitive(
    title: String = "Sensitive Literals",
    pattern: String = "(secret|password|token|key|admin|root)"
  ): Unit = {
    try {
      val table = richTableLib.Table(title = title, highlight = true, show_lines = true)
      table.add_column("File Name")
      table.add_column("Sensitive Literals")
      atom.file.whereNot(_.name("<unknown>")).foreach { f =>
        val slits: Set[Literal] =
          f.assignment.where(_.argument.order(1).code(s"(?i).*${pattern}.*")).argument.order(2).isLiteral.toSet
        table.add_row(f.name, if (slits.nonEmpty) slits.code.mkString("\n") else "N/A")
      }
      richConsole.print(table)
    } catch {
      case exc: Exception => report(exc.getMessage)
    }
  }

  def sensitive: Unit = sensitive("Sensitive Literals")

  @Doc(
    info = "Show graph edit distance from the source method to the comparison methods",
    longInfo = """|Compute graph edit distance from the source method to the comparison methods.
         |""",
    example = "distance(source method iterator, comparison method iterators)"
  )
  def distance(sourceTrav: Iterator[Method], sourceTravs: Iterator[Method]*): Seq[Double] = {
    val first_method = new MethodTraversal(sourceTrav.iterator).gml
    sourceTravs.map { compareTrav =>
      val second_method = new MethodTraversal(compareTrav.iterator).gml
      Torch.edit_distance(first_method, second_method)
    }
  }

  case class MethodDistance(filename: String, fullName: String, editDistance: Double)

  @Doc(
    info = "Show methods similar to the given method",
    longInfo = """|List methods to similar to the one based on graph edit distance.
         |""",
    example = "showSimilar(method full name)"
  )
  def showSimilar(
    methodFullName: String,
    comparePattern: String = "",
    upper_bound: Int = 500,
    timeout: Int = 5
  ): Unit = {
    val table =
      richTableLib.Table(title = s"Similarity analysis for `${methodFullName}`", highlight = true, show_lines = true)
    val progress     = richProgressLib.Progress(transient = true)
    val first_method = atom.method.fullNameExact(methodFullName).gml
    table.add_column("File Name")
    table.add_column("Method Name")
    table.add_column("Edit Distance")
    val methodDistances = mutable.ArrayBuffer[MethodDistance]()
    val base = if (comparePattern.nonEmpty) atom.method.fullName(s".*${comparePattern}.*") else atom.method.internal
    base.whereNot(_.fullNameExact(methodFullName)).foreach { method =>
      py.`with`(progress) { mprogress =>
        val task = mprogress.add_task(s"Analyzing ${method.fullName}", start = false)
        val edit_distance =
          Torch.edit_distance(first_method, method.iterator.gml, upper_bound = upper_bound, timeout = timeout)
        if (edit_distance != -1) {
          methodDistances += MethodDistance(method.location.filename, method.fullName, edit_distance)
        }
        mprogress.update(task, advance = 100)
      }
    }
    methodDistances.sortInPlaceBy[Double](x => x.editDistance)
    methodDistances.foreach(row => table.add_row(row.filename, row.fullName, "" + row.editDistance))
    richConsole.print(table)
  }

  def printDashes(count: Int) = {
    var tabStr = "+--- "
    var i      = 0
    while (i < count) {
      tabStr = "|    " + tabStr
      i += 1
    }
    tabStr
  }

  @Doc(
    info = "Show call tree for the given method",
    longInfo = """|Show the call tree for the given method.
         |""",
    example = "callTree(method full name)"
  )
  def callTree(callerFullName: String, tree: ListBuffer[String] = new ListBuffer[String](), depth: Int = 3)(implicit
    atom: Cpg
  ): ListBuffer[String] = {
    var dashCount        = 0
    var lastCallerMethod = callerFullName
    var lastDashCount    = 0
    tree += callerFullName

    def findCallee(methodName: String, tree: ListBuffer[String]): ListBuffer[String] = {
      val calleeList     = atom.method.fullNameExact(methodName).callee.whereNot(_.name(".*<operator.*")).l
      val callerNameList = atom.method.fullNameExact(methodName).caller.fullName.l
      if (callerNameList.contains(lastCallerMethod) || callerNameList.isEmpty) {
        dashCount = lastDashCount
      } else {
        lastDashCount = dashCount
        lastCallerMethod = methodName
        dashCount += 1
      }
      if (dashCount < depth) {
        calleeList foreach { c =>
          tree += s"${printDashes(dashCount)}${c.fullName}~~${c.location.filename}#${c.lineNumber.getOrElse(0)}"
          findCallee(c.fullName, tree)
        }
      }
      tree
    }

    findCallee(lastCallerMethod, tree)
  }

  def applyPostProcessingPasses(cpg: Cpg): Cpg = {
    new CpgGeneratorFactory(_config).forLanguage(cpg.metaData.language.l.head) match {
      case Some(frontend) => frontend.applyPostProcessingPasses(cpg)
      case None           => cpg
    }
  }

  def applyDefaultOverlays(cpg: Cpg): Cpg = {
    val appliedOverlays = Overlays.appliedOverlays(cpg)
    if (appliedOverlays.isEmpty) {
      report("Adding default overlays to base CPG")
      _runAnalyzer(defaultOverlayCreators(): _*)
    }
    cpg
  }

  def _runAnalyzer(overlayCreators: LayerCreator*): Cpg = {

    overlayCreators.foreach { creator =>
      val overlayDirName =
        workspace.getNextOverlayDirName(cpg, creator.overlayName)

      val projectOpt = workspace.projectByCpg(cpg)
      if (projectOpt.isEmpty) {
        throw new RuntimeException("No record for CPG. Please use `importCode`/`importCpg/open`")
      }

      if (projectOpt.get.appliedOverlays.contains(creator.overlayName)) {
        report(s"Overlay ${creator.overlayName} already exists - skipping")
      } else {
        File(overlayDirName).createDirectories()
        runCreator(creator, Some(overlayDirName))
      }
    }
    report(
      "The graph has been modified. You may want to use the `save` command to persist changes to disk.  All changes will also be saved collectively on exit"
    )
    cpg
  }

  protected def runCreator(creator: LayerCreator, overlayDirName: Option[String]): Unit = {
    val context = new LayerCreatorContext(cpg, overlayDirName)
    creator.run(context, storeUndoInfo = true)
  }

  // We still tie the project name to the input path here
  // if no project name has been provided.

  def fixProjectNameAndComplainOnFix(name: String): String = {
    val projectName = Some(name)
      .filter(_.contains(java.io.File.separator))
      .map(x => deriveNameFromInputPath(x, workspace))
      .getOrElse(name)
    if (name != projectName) {
      System.err.println("Passing paths to `loadCpg` is deprecated, please use a project name")
    }
    projectName
  }

}

object Console {
  val nameOfLegacyCpgInProject = "app.atom"

  def deriveNameFromInputPath[T <: Project](inputPath: String, workspace: WorkspaceManager[T]): String = {
    val name    = File(inputPath).name
    val project = workspace.project(name)
    if (project.isDefined && project.exists(_.inputPath != inputPath)) {
      var i = 1
      while (workspace.project(name + i).isDefined) {
        i += 1
      }
      name + i
    } else {
      name
    }
  }
}

class ConsoleException(message: String, cause: Option[Throwable])
    extends RuntimeException(message, cause.orNull)
    with NoStackTrace {
  def this(message: String) = this(message, None)
  def this(message: String, cause: Throwable) = this(message, Option(cause))
}
