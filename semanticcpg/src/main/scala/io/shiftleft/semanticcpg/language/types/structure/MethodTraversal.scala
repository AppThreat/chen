package io.shiftleft.semanticcpg.language.types.structure

import better.files.File
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.Fingerprinting
import overflowdb.*
import overflowdb.formats.ExportResult
import overflowdb.formats.dot.DotExporter
import overflowdb.formats.graphml.GraphMLExporter
import overflowdb.traversal.help
import overflowdb.traversal.help.Doc

import java.nio.file.{Files, Paths}
import scala.jdk.CollectionConverters.*

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
          .repeat(_._astIn)(_.until(_.collectAll[TypeDecl]))
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
          .repeat(_._astIn)(_.until(_.collectAll[Method]))
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

  def sanitizeFilename(filename: String) =
      Paths.get(filename).getFileName.toString.replaceAll("[^a-zA-Z0-9-_\\.]", "_")

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
    var pathToUse = getOrCreateExportPath(gmlDir)
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
            GraphMLExporter.runExport(
              nodes,
              subGraph.edges,
              Paths.get(
                pathToUse,
                s"${methodName}-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}.graphml"
              )
            )
        }
        .reduce(plus)
  end gml

  def gml: ExportResult = gml(null)

  def dot(dotDir: String = null): ExportResult =
    var pathToUse = getOrCreateExportPath(dotDir)
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
            DotExporter.runExport(
              nodes,
              subGraph.edges,
              Paths.get(
                pathToUse,
                s"${methodName}-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}.dot"
              )
            )
        }
        .reduce(plus)
  end dot

  def dot: ExportResult = dot(null)

  def exportAllRepr(dotCfgDir: String = null): Unit =
    var pathToUse = getOrCreateExportPath(dotCfgDir)
    traversal
        .foreach { method =>
          val methodName     = method.name
          val methodFullName = method.fullName
          val filename       = method.location.filename
          val methodHash     = Fingerprinting.calculate_hash(methodFullName)
          File(
            pathToUse,
            s"${methodName}-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}-ast.dot"
          ).write(method.dotAst.head)
          File(
            pathToUse,
            s"${methodName}-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}-cdg.dot"
          ).write(method.dotCdg.head)
          File(
            pathToUse,
            s"${methodName}-${sanitizeFilename(filename)}-${methodHash.slice(0, 8)}-cfg.dot"
          ).write(method.dotCfg.head)
        }
  end exportAllRepr

  def exportAllRepr: Unit = exportAllRepr(null)

end MethodTraversal
