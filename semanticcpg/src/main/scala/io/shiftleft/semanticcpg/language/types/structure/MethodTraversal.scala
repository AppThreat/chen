package io.shiftleft.semanticcpg.language.types.structure

import better.files.File
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.Fingerprinting
import overflowdb.*
import overflowdb.formats.{ExportResult, Exporter}
import overflowdb.traversal.help
import overflowdb.traversal.help.Doc
import java.io.BufferedWriter
import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.atomic.AtomicInteger
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.Using

case class MethodSubGraph(
  methodName: String,
  methodFullName: String,
  filename: String,
  nodes: Set[Node]
):
  def edges: Set[Edge] =
      for
        node <- nodes
        edge <- node.bothE.asScala
        if nodes.contains(edge.inNode) && nodes.contains(edge.outNode)
      yield edge

def plus(resultA: ExportResult, resultB: ExportResult): ExportResult =
    ExportResult(
      nodeCount = resultA.nodeCount + resultB.nodeCount,
      edgeCount = resultA.edgeCount + resultB.edgeCount,
      files = resultA.files ++ resultB.files,
      additionalInfo = resultA.additionalInfo
    )

object SubgraphGraphMLExporter extends Exporter:
  override def defaultFileExtension = "xml"

  private val KeyForNodeLabel = "labelV"
  private val KeyForEdgeLabel = "labelE"

  override def runExport(
    nodes: IterableOnce[Node],
    edges: IterableOnce[Edge],
    outputFile: Path
  ): ExportResult =
    val outFile                    = resolveOutputFile(outputFile, defaultFileExtension)
    val nodePropertyContextById    = mutable.Map.empty[String, PropertyContext]
    val edgePropertyContextById    = mutable.Map.empty[String, PropertyContext]
    val discardedListPropertyCount = new AtomicInteger(0)

    val nodeList = nodes.iterator.toSeq
    val edgeList = edges.iterator.toSeq

    nodeList.foreach(collectKeys(_, "node", nodePropertyContextById, discardedListPropertyCount))
    edgeList.foreach(collectKeys(_, "edge", edgePropertyContextById, discardedListPropertyCount))

    var nodeCount = 0
    var edgeCount = 0

    Using.resource(Files.newBufferedWriter(outFile)) { writer =>
      writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
      writer.newLine()
      writer.write(
        "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\">"
      )
      writer.newLine()

      writeKeyDefs(writer, "node", nodePropertyContextById)
      writeKeyDefs(writer, "edge", edgePropertyContextById)

      writer.write("    <graph id=\"G\" edgedefault=\"directed\">")
      writer.newLine()

      nodeList.foreach { node =>
        nodeCount += 1
        writeNode(writer, node, nodePropertyContextById)
      }

      edgeList.foreach { edge =>
        edgeCount += 1
        writeEdge(writer, edge, edgePropertyContextById)
      }

      writer.write("    </graph>")
      writer.newLine()
      writer.write("</graphml>")
    }

    val additionalInfo =
        Some(discardedListPropertyCount.get).filter(_ > 0).map { count =>
            s"warning: discarded $count list properties (because they are not supported by the graphml spec)"
        }

    ExportResult(nodeCount, edgeCount, Seq(outFile), additionalInfo)
  end runExport

  private def resolveOutputFile(path: Path, ext: String): Path =
      if path.toString.endsWith(s".$ext") then path else Paths.get(path.toString + s".$ext")

  private def isList(clazz: Class[?]): Boolean =
      classOf[java.util.List[?]].isAssignableFrom(clazz) || clazz.isArray

  private case class PropertyContext(name: String, tpe: String)

  private object Type:
    def fromRuntimeClass(clazz: Class[?]): String =
        if clazz == classOf[Boolean] || clazz == classOf[java.lang.Boolean] then "boolean"
        else if clazz == classOf[Int] || clazz == classOf[java.lang.Integer] then "int"
        else if clazz == classOf[Long] || clazz == classOf[java.lang.Long] then "long"
        else if clazz == classOf[Float] || clazz == classOf[java.lang.Float] then "float"
        else if clazz == classOf[Double] || clazz == classOf[java.lang.Double] then "double"
        else "string"

  private def collectKeys(
    element: Element,
    prefix: String,
    context: mutable.Map[String, PropertyContext],
    discarded: AtomicInteger
  ): Unit =
    val it = element.propertiesMap.entrySet().iterator()
    while it.hasNext do
      val entry = it.next()
      if isList(entry.getValue.getClass) then
        discarded.incrementAndGet()
      else
        val encodedName = s"${prefix}__${element.label}__${entry.getKey}"
        if !context.contains(encodedName) then
          context.put(
            encodedName,
            PropertyContext(entry.getKey, Type.fromRuntimeClass(entry.getValue.getClass))
          )

  private def writeKeyDefs(
    writer: java.io.BufferedWriter,
    forAttr: String,
    context: mutable.Map[String, PropertyContext]
  ): Unit =
    writer.write(
      s"""    <key id="$KeyForNodeLabel" for="node" attr.name="$KeyForNodeLabel" attr.type="string"></key>"""
    )
    writer.newLine()
    writer.write(
      s"""    <key id="$KeyForEdgeLabel" for="edge" attr.name="$KeyForEdgeLabel" attr.type="string"></key>"""
    )
    writer.newLine()

    context.foreach { case (key, PropertyContext(name, tpe)) =>
        writer.write(
          s"""    <key id="$key" for="$forAttr" attr.name="$name" attr.type="$tpe"></key>"""
        )
        writer.newLine()
    }
  end writeKeyDefs

  private def writeNode(
    writer: java.io.BufferedWriter,
    node: Node,
    context: mutable.Map[String, PropertyContext]
  ): Unit =
    writer.write(s"""        <node id="${node.id}">""")
    writer.newLine()
    writer.write(s"""            <data key="$KeyForNodeLabel">${node.label}</data>""")
    writer.newLine()
    writeDataEntries(writer, "node", node, context)
    writer.write("        </node>")
    writer.newLine()

  private def writeEdge(
    writer: java.io.BufferedWriter,
    edge: Edge,
    context: mutable.Map[String, PropertyContext]
  ): Unit =
    writer.write(s"""        <edge source="${edge.outNode.id}" target="${edge.inNode.id}">""")
    writer.newLine()
    writer.write(s"""            <data key="$KeyForEdgeLabel">${edge.label}</data>""")
    writer.newLine()
    writeDataEntries(writer, "edge", edge, context)
    writer.write("        </edge>")
    writer.newLine()

  private def writeDataEntries(
    writer: java.io.BufferedWriter,
    prefix: String,
    element: Element,
    context: mutable.Map[String, PropertyContext]
  ): Unit =
    val it = element.propertiesMap.entrySet().iterator()
    while it.hasNext do
      val entry = it.next()
      if !isList(entry.getValue.getClass) then
        val encodedName = s"${prefix}__${element.label}__${entry.getKey}"
        val xmlEncoded  = escapeXml(entry.getValue.toString)
        writer.write(s"""            <data key="$encodedName">$xmlEncoded</data>""")
        writer.newLine()

  private def escapeXml(s: String): String =
    val sb = new StringBuilder(s.length)
    var i  = 0
    while i < s.length do
      s.charAt(i) match
        case '<'  => sb.append("&lt;")
        case '>'  => sb.append("&gt;")
        case '&'  => sb.append("&amp;")
        case '"'  => sb.append("&quot;")
        case '\'' => sb.append("&apos;")
        case c    => sb.append(c)
      i += 1
    sb.toString
end SubgraphGraphMLExporter

object SubgraphDotExporter extends Exporter:
  override def defaultFileExtension = "dot"

  override def runExport(
    nodes: IterableOnce[Node],
    edges: IterableOnce[Edge],
    outputFile: Path
  ): ExportResult =
    val outFile   = resolveOutputFile(outputFile, defaultFileExtension)
    var nodeCount = 0
    var edgeCount = 0

    Using.resource(Files.newBufferedWriter(outFile)) { writer =>
      writer.write("digraph {"); writer.newLine()

      nodes.iterator.foreach { node =>
        nodeCount += 1
        writeNode(writer, node)
      }

      edges.iterator.foreach { edge =>
        edgeCount += 1
        writeEdge(writer, edge)
      }

      writer.write("}")
      writer.newLine()
    }
    ExportResult(nodeCount, edgeCount, Seq(outFile), None)
  end runExport

  private def resolveOutputFile(path: Path, ext: String): Path =
      if path.toString.endsWith(s".$ext") then path else Paths.get(path.toString + s".$ext")

  private def writeNode(writer: BufferedWriter, node: Node): Unit =
    writer.write(s"  ${node.id} [label=${node.label}")
    writeProperties(writer, node.propertiesMap)
    writer.write("]")
    writer.newLine()

  private def writeEdge(writer: BufferedWriter, edge: Edge): Unit =
    writer.write(s"  ${edge.outNode.id} -> ${edge.inNode.id} [label=${edge.label}")
    writeProperties(writer, edge.propertiesMap)
    writer.write("]")
    writer.newLine()

  private def writeProperties(
    writer: BufferedWriter,
    properties: java.util.Map[String, Object]
  ): Unit =
      if !properties.isEmpty then
        properties.forEach { (key, value) =>
          writer.write(" ")
          writer.write(key)
          writer.write("=")
          writer.write(encodePropertyValue(value))
        }

  private def encodePropertyValue(value: Object): String =
      value match
        case s: String =>
            escapeString(s)
        case l: java.lang.Iterable[?] =>
            val sb = new StringBuilder()
            sb.append('"')
            val it    = l.iterator()
            var first = true
            while it.hasNext do
              if !first then sb.append(';')
              sb.append(it.next().toString)
              first = false
            sb.append('"')
            sb.toString
        case arr: Array[?] =>
            val sb = new StringBuilder()
            sb.append('"')
            var first = true
            for item <- arr do
              if !first then sb.append(';')
              sb.append(item.toString)
              first = false
            sb.append('"')
            sb.toString
        case _ => value.toString

  private def escapeString(s: String): String =
    val sb = new StringBuilder(s.length + 2)
    sb.append('"')
    var i = 0
    while i < s.length do
      val c = s.charAt(i)
      if c == '"' then sb.append("\\\"")
      else if c == '\\' then sb.append("\\\\")
      else sb.append(c)
      i += 1
    sb.append('"')
    sb.toString
end SubgraphDotExporter

/** A method, function, or procedure
  */
@help.Traversal(elementType = classOf[Method])
class MethodTraversal(val traversal: Iterator[Method]) extends AnyVal:

  /** Traverse to annotations of method
    */
  def annotation: Iterator[nodes.Annotation] =
      traversal.flatMap(_._annotationViaAstOut)

  /** All control structures of this method
    */
  @Doc(info = "Control structures (source frontends only)")
  def controlStructure: Iterator[ControlStructure] =
      traversal.ast.isControlStructure

  /** Shorthand to traverse to control structures where condition matches `regex`
    */
  def controlStructure(regex: String): Iterator[ControlStructure] =
      traversal.ast.isControlStructure.code(regex)

  @Doc(info = "All try blocks (`ControlStructure` nodes)")
  def tryBlock: Iterator[ControlStructure] =
      controlStructure.isTry

  @Doc(info = "All if blocks (`ControlStructure` nodes)")
  def ifBlock: Iterator[ControlStructure] =
      controlStructure.isIf

  @Doc(info = "All else blocks (`ControlStructure` nodes)")
  def elseBlock: Iterator[ControlStructure] =
      controlStructure.isElse

  @Doc(info = "All switch blocks (`ControlStructure` nodes)")
  def switchBlock: Iterator[ControlStructure] =
      controlStructure.isSwitch

  @Doc(info = "All do blocks (`ControlStructure` nodes)")
  def doBlock: Iterator[ControlStructure] =
      controlStructure.isDo

  @Doc(info = "All for blocks (`ControlStructure` nodes)")
  def forBlock: Iterator[ControlStructure] =
      controlStructure.isFor

  @Doc(info = "All while blocks (`ControlStructure` nodes)")
  def whileBlock: Iterator[ControlStructure] =
      controlStructure.isWhile

  @Doc(info = "All gotos (`ControlStructure` nodes)")
  def goto: Iterator[ControlStructure] =
      controlStructure.isGoto

  @Doc(info = "All breaks (`ControlStructure` nodes)")
  def break: Iterator[ControlStructure] =
      controlStructure.isBreak

  @Doc(info = "All continues (`ControlStructure` nodes)")
  def continue: Iterator[ControlStructure] =
      controlStructure.isContinue

  @Doc(info = "All throws (`ControlStructure` nodes)")
  def throws: Iterator[ControlStructure] =
      controlStructure.isThrow

  /** The type declaration associated with this method, e.g., the class it is defined in.
    */
  @Doc(info = "Type this method is defined in")
  def definingTypeDecl: Iterator[TypeDecl] =
      traversal
          .repeat(_._astIn)(using _.until(_.collectAll[TypeDecl]))
          .cast[TypeDecl]

  /** The type declaration associated with this method, e.g., the class it is defined in. Alias for
    * 'definingTypeDecl'
    */
  @Doc(info = "Type this method is defined in - alias for 'definingTypeDecl'")
  def typeDecl: Iterator[TypeDecl] = definingTypeDecl

  /** The method in which this method is defined
    */
  @Doc(info = "Method this method is defined in")
  def definingMethod: Iterator[Method] =
      traversal
          .repeat(_._astIn)(using _.until(_.collectAll[Method]))
          .cast[Method]

  /** Traverse only to methods that are stubs, e.g., their code is not available or the method body
    * is empty.
    */
  def isStub: Iterator[Method] =
      traversal.where(_.not(_._cfgOut.not(_.collectAll[MethodReturn])))

  /** Traverse only to methods that are not stubs.
    */
  def isNotStub: Iterator[Method] =
      traversal.where(_._cfgOut.not(_.collectAll[MethodReturn]))

  /** Traverse only to methods that accept variadic arguments.
    */
  def isVariadic: Iterator[Method] =
      traversal.filter(_.isVariadic)

  /** Traverse to external methods, that is, methods not present but only referenced in the CPG.
    */
  @Doc(info = "External methods (called, but no body available)")
  def external: Iterator[Method] =
      traversal.isExternal(true)

  /** Traverse to internal methods, that is, methods for which code is included in this CPG.
    */
  @Doc(info = "Internal methods, i.e., a body is available")
  def internal: Iterator[Method] =
      traversal.isExternal(false)

  /** Traverse to the methods local variables
    */
  @Doc(info = "Local variables declared in the method")
  def local: Iterator[Local] =
      traversal.block.ast.isLocal

  @Doc(info = "Top level expressions (\"Statements\")")
  def topLevelExpressions: Iterator[Expression] =
      traversal._astOut
          .collectAll[Block]
          ._astOut
          .not(_.collectAll[Local])
          .cast[Expression]

  @Doc(info = "Control flow graph nodes")
  def cfgNode: Iterator[CfgNode] =
      traversal.flatMap(_.cfgNode)

  /** Traverse to last expression in CFG.
    */
  @Doc(info = "Last control flow graph node")
  def cfgLast: Iterator[CfgNode] =
      traversal.methodReturn.cfgLast

  /** Traverse to method body (alias for `block`) */
  @Doc(info = "Alias for `block`")
  def body: Iterator[Block] =
      traversal.block

  /** Traverse to namespace */
  @Doc(info = "Namespace this method is declared in")
  def namespace: Iterator[Namespace] =
      traversal.namespaceBlock.namespace

  /** Traverse to namespace block */
  @Doc(info = "Namespace block this method is declared in")
  def namespaceBlock: Iterator[NamespaceBlock] =
      traversal.flatMap { m =>
          m.astIn.headOption match
            // some language frontends don't have a TYPE_DECL for a METHOD
            case Some(namespaceBlock: NamespaceBlock) => namespaceBlock.start
            // other language frontends always embed their method in a TYPE_DECL
            case _ => m.definingTypeDecl.namespaceBlock
      }

  def numberOfLines: Iterator[Int] = traversal.map(_.numberOfLines)

  def sanitizeFilename(filename: String): String =
      Paths.get(filename).getFileName.toString.replaceAll("[^a-zA-Z0-9-_.]", "_")

  def getOrCreateExportPath(pathToUse: String): String =
      try
        if pathToUse == null then
          Files.createTempDirectory("graph-export").toAbsolutePath.toString
        else
          Paths.get(pathToUse).toFile.mkdirs()
          pathToUse
      catch
        case exc: Exception => pathToUse

  @Doc(info = "Export the methods to graphml")
  def gml(gmlDir: String = null): ExportResult =
    val pathToUse = getOrCreateExportPath(gmlDir)
    traversal
        .map { method =>
            MethodSubGraph(
              methodName = method.name,
              methodFullName = method.fullName,
              filename = method.location.filename,
              nodes = method.ast.toSet
            )
        }
        .map { case subGraph @ MethodSubGraph(methodName, methodFullName, filename, nodes) =>
            val methodHash = Fingerprinting.calculate_hash(methodFullName)
            SubgraphGraphMLExporter.runExport(
              nodes,
              subGraph.edges,
              Paths.get(
                pathToUse,
                s"$methodName-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}.graphml"
              )
            )
        }
        .reduceOption(plus)
        .getOrElse(ExportResult(0, 0, Seq.empty, None))
  end gml

  def gml: ExportResult = gml(null)

  def dot(dotDir: String = null): ExportResult =
    val pathToUse = getOrCreateExportPath(dotDir)
    traversal
        .map { method =>
            MethodSubGraph(
              methodName = method.name,
              methodFullName = method.fullName,
              filename = method.location.filename,
              nodes = method.ast.toSet
            )
        }
        .map { case subGraph @ MethodSubGraph(methodName, methodFullName, filename, nodes) =>
            val methodHash = Fingerprinting.calculate_hash(methodFullName)
            SubgraphDotExporter.runExport(
              nodes,
              subGraph.edges,
              Paths.get(
                pathToUse,
                s"$methodName-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}.dot"
              )
            )
        }
        .reduceOption(plus)
        .getOrElse(ExportResult(0, 0, Seq.empty, None))
  end dot

  def dot: ExportResult = dot(null)

  def exportAllRepr(dotCfgDir: String = null): Unit =
    val pathToUse = getOrCreateExportPath(dotCfgDir)
    traversal
        .foreach { method =>
          val methodName     = method.name
          val methodFullName = method.fullName
          val filename       = method.location.filename
          val methodHash     = Fingerprinting.calculate_hash(methodFullName)
          File(
            pathToUse,
            s"$methodName-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}-ast.dot"
          ).write(method.dotAst.head)
          File(
            pathToUse,
            s"$methodName-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}-cdg.dot"
          ).write(method.dotCdg.head)
          File(
            pathToUse,
            s"$methodName-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}-cfg.dot"
          ).write(method.dotCfg.head)
        }
  end exportAllRepr

  def exportAllRepr(): Unit = exportAllRepr(null)

end MethodTraversal
