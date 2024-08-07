package io.appthreat.chencli.console

import io.appthreat.console.{Help, Run}

object Predefined:

  val shared: Seq[String] =
      Seq(
        "import _root_.io.appthreat.console.*",
        "import _root_.io.appthreat.chencli.console.ChenConsole.*",
        "import _root_.io.appthreat.chencli.console.Chen.context",
        "import _root_.io.shiftleft.codepropertygraph.Cpg",
        "import _root_.io.shiftleft.codepropertygraph.Cpg.docSearchPackages",
        "import _root_.io.shiftleft.codepropertygraph.cpgloading.*",
        "import _root_.io.shiftleft.codepropertygraph.generated.*",
        "import _root_.io.shiftleft.codepropertygraph.generated.nodes.*",
        "import _root_.io.shiftleft.codepropertygraph.generated.edges.*",
        "import _root_.io.appthreat.dataflowengineoss.language.*",
        "import _root_.io.shiftleft.semanticcpg.language.*",
        "import overflowdb.*",
        "import overflowdb.traversal.{`package` => _, help => _, _}",
        "import overflowdb.traversal.help.Doc",
        "import scala.jdk.CollectionConverters.*",
        """
        |@Doc(info = "Show reachable flows from a source to sink. Default source: framework-input and sink: framework-output", example = "reachables")
        |def reachables(sinkTag: String, sourceTag: String, sourceTags: Array[String])(implicit atom: Cpg): Unit = {
        |  try {
        |    val language = atom.metaData.language.l.head
        |    def sources=sourceTags.map(t => atom.tag.name(t).parameter)
        |    if language == Languages.JSSRC || language == Languages.JAVASCRIPT || language == Languages.PYTHON || language == Languages.PYTHONSRC
        |    then
        |      def source = atom.tag.name(sourceTag).call.argument
        |      def sink = atom.tag.name(sinkTag).call.argument
        |      sink.df(source, sources).t
        |    else
        |       def source=atom.tag.name(sourceTag).parameter
        |       def sink=atom.ret.where(_.tag.name(sinkTag))
        |       sink.df(source, sources).t
        |    end if
        |  } catch {
        |    case exc: Exception =>
        |  }
        |}
        |
        |@Doc(info = "Show reachable flows from a source to sink. Default source: framework-input and sink: framework-output", example = "reachables")
        |def reachables(implicit atom: Cpg): Unit = reachables("framework-output", "framework-input", Array("api", "framework", "http", "cli-source", "library-call"))
        |
        |@Doc(info = "Show reachable flows from a source to sink. Default source: crypto-algorithm and sink: crypto-generate", example = "cryptos")
        |def cryptos(sinkTag: String, sourceTag: String, sourceTags: Array[String])(implicit atom: Cpg): Unit = {
        |  try {
        |    val language = atom.metaData.language.l.head
        |    def sources=sourceTags.map(t => atom.tag.name(t).parameter)
        |    if language == Languages.JSSRC || language == Languages.JAVASCRIPT
        |    then
        |      def source = atom.tag.name(sourceTag).call.argument
        |      def sink = atom.tag.name(sinkTag).call.argument
        |      sink.df(source, sources).t
        |    else if  language == Languages.PYTHON || language == Languages.PYTHONSRC
        |    then
        |      def source = atom.tag.name(sourceTag).call
        |      def sink = atom.tag.name(sinkTag).call
        |      sink.df(source).t
        |    else
        |       def source=atom.tag.name(sourceTag).literal
        |       def sink=atom.tag.name(sinkTag).call
        |       sink.df(source, sources).t
        |    end if
        |  } catch {
        |    case exc: Exception =>
        |  }
        |}
        |
        |@Doc(info = "Show reachable flows from a source to sink. Default source: crypto-algorithm and sink: crypto-generate", example = "cryptos")
        |def cryptos(implicit atom: Cpg): Unit = cryptos("crypto-generate", "crypto-algorithm", Array("api", "framework", "http", "cli-source", "library-call"))
        |""".stripMargin
      )

  val forInteractiveShell: Seq[String] =
      shared ++
          Seq("import _root_.io.appthreat.chencli.console.Chen._") ++
          Run.codeForRunCommand().linesIterator ++
          Help.codeForHelpCommand(classOf[ChenConsole]).linesIterator ++
          Seq("ossDataFlowOptions = opts.ossdataflow")
end Predefined
