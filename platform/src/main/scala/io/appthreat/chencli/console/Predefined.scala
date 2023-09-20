package io.appthreat.chencli.console

import io.appthreat.console.{Help, Run}

object Predefined {

  val shared: Seq[String] =
    Seq(
      "import scala.collection.mutable.ListBuffer",
      "import _root_.io.appthreat.console._",
      "import _root_.io.appthreat.chencli.console.ChenConsole._",
      "import _root_.io.shiftleft.codepropertygraph.Cpg",
      "import _root_.io.shiftleft.codepropertygraph.Cpg.docSearchPackages",
      "import _root_.io.shiftleft.codepropertygraph.cpgloading._",
      "import _root_.io.shiftleft.codepropertygraph.generated._",
      "import _root_.io.shiftleft.codepropertygraph.generated.nodes._",
      "import _root_.io.shiftleft.codepropertygraph.generated.edges._",
      "import _root_.io.appthreat.dataflowengineoss.language._",
      "import _root_.io.shiftleft.semanticcpg.language._",
      "import overflowdb._",
      "import overflowdb.traversal.{`package` => _, help => _, _}",
      "import scala.jdk.CollectionConverters._",
      "implicit val resolver: ICallResolver = NoResolve",
      "implicit val finder: NodeExtensionFinder = DefaultNodeExtensionFinder",
      "import me.shadaj.scalapy.py",
      "import me.shadaj.scalapy.py.SeqConverters",
      "import py.PyQuote",
      "import me.shadaj.scalapy.interpreter.CPythonInterpreter",
      "implicit val pyGlobal: me.shadaj.scalapy.py.Dynamic.global.type = py.Dynamic.global",
      """
        |
        |  def printDashes(count: Int) = {
        |    var tabStr = "+--- "
        |    var i = 0
        |    while (i < count) {
        |      tabStr = "|    " + tabStr
        |      i += 1
        |    }
        |    tabStr
        |  }
        |
        |  def callTree(callerFullName: String, tree: ListBuffer[String] = new ListBuffer[String](), depth: Int = 3)(implicit atom: Cpg): ListBuffer[String] = {
        |    var dashCount = 0
        |    var lastCallerMethod = callerFullName
        |    var lastDashCount = 0
        |    tree += callerFullName
        |
        |    def findCallee(methodName: String, tree: ListBuffer[String]): ListBuffer[String] = {
        |      val calleeList = atom.method.fullNameExact(methodName).callee.whereNot(_.name(".*<operator.*")).l
        |      val callerNameList = atom.method.fullNameExact(methodName).caller.fullName.l
        |      if (callerNameList.contains(lastCallerMethod) || callerNameList.isEmpty) {
        |        dashCount = lastDashCount
        |      } else {
        |        lastDashCount = dashCount
        |        lastCallerMethod = methodName
        |        dashCount += 1
        |      }
        |      if (dashCount < depth) {
        |        calleeList foreach { c =>
        |          tree += s"${printDashes(dashCount)}${c.fullName}~~${c.location.filename}#${c.lineNumber.getOrElse(0)}"
        |          findCallee(c.fullName, tree)
        |        }
        |      }
        |      tree
        |    }
        |
        |    findCallee(lastCallerMethod, tree)
        |  }
        |""".stripMargin,
      """
        |import overflowdb.formats.ExportResult
        |import overflowdb.formats.graphml.GraphMLExporter
        |import java.nio.file.{Path, Paths}
        |
        |case class MethodSubGraph(methodName: String, nodes: Set[Node]) {
        |  def edges: Set[Edge] = {
        |    for {
        |      node <- nodes
        |      edge <- node.bothE.asScala
        |      if nodes.contains(edge.inNode) && nodes.contains(edge.outNode)
        |    } yield edge
        |  }
        |}
        |
        |def plus(resultA: ExportResult, resultB: ExportResult): ExportResult = {
        |  ExportResult(
        |    nodeCount = resultA.nodeCount + resultB.nodeCount,
        |    edgeCount = resultA.edgeCount + resultB.edgeCount,
        |    files = resultA.files ++ resultB.files,
        |    additionalInfo = resultA.additionalInfo
        |  )
        |}
        |
        |def splitByMethod(atom: Cpg): IterableOnce[MethodSubGraph] = {
        |  atom.method.map { method =>
        |    MethodSubGraph(methodName = method.name, nodes = method.ast.toSet)
        |  }
        |}
        |
        |def toGraphML(methodFullName: String, gmlFileName: String)(implicit atom: Cpg) = {
        | splitByMethod(atom).iterator
        |  .map { case subGraph @ MethodSubGraph(methodName, nodes) =>
        |    GraphMLExporter.runExport(nodes, subGraph.edges, Paths.get(gmlFileName))
        |  }
        |  .reduce(plus)
        |}
        |""".stripMargin
    )

  val forInteractiveShell: Seq[String] = {
    shared ++
      Seq("import _root_.io.appthreat.chencli.console.Chen._") ++
      Run.codeForRunCommand().linesIterator ++
      Help.codeForHelpCommand(classOf[ChenConsole]).linesIterator ++
      Seq("ossDataFlowOptions = opts.ossdataflow")
  }

}
