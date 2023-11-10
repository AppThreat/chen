package io.appthreat.chencli.console

import io.appthreat.console.{Help, Run}

object Predefined:

    val shared: Seq[String] =
        Seq(
          "import _root_.io.appthreat.console._",
          "import _root_.io.appthreat.chencli.console.ChenConsole._",
          "import _root_.io.appthreat.chencli.console.Chen.context",
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
          """
        |def reachables(sinkTag: String, sourceTag: String, sourceTags: Array[String])(implicit atom: Cpg): Unit = {
        |  try {
        |    def source=atom.tag.name(sourceTag).parameter
        |    def sources=sourceTags.map(t => atom.tag.name(t).parameter)
        |    def sink=atom.ret.where(_.tag.name(sinkTag))
        |    sink.df(source, sources).t
        |  } catch {
        |    case exc: Exception =>
        |  }
        |}
        |
        |def reachables(implicit atom: Cpg): Unit = reachables("framework-output", "framework-input", Array("api"))
        |
        |""".stripMargin
        )

    val forInteractiveShell: Seq[String] =
        shared ++
            Seq("import _root_.io.appthreat.chencli.console.Chen._") ++
            Run.codeForRunCommand().linesIterator ++
            Help.codeForHelpCommand(classOf[ChenConsole]).linesIterator ++
            Seq("ossDataFlowOptions = opts.ossdataflow")
end Predefined
