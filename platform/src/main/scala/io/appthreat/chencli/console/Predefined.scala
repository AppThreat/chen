package io.appthreat.chencli.console

import io.appthreat.console.{Help, Run}

object Predefined {

  val shared: Seq[String] =
    Seq(
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
      "implicit val finder: NodeExtensionFinder = DefaultNodeExtensionFinder"
    )

  val forInteractiveShell: Seq[String] = {
    shared ++
      Seq("import _root_.io.appthreat.chencli.console.Chen._") ++
      Run.codeForRunCommand().linesIterator ++
      Help.codeForHelpCommand(classOf[ChenConsole]).linesIterator ++
      Seq("ossDataFlowOptions = opts.ossdataflow")
  }

}
