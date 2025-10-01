package io.appthreat.dataflowengineoss.language

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import me.shadaj.scalapy.py
import io.appthreat.x2cpg.utils.StringUtils

import scala.collection.mutable
import scala.collection.mutable.{ArrayBuffer, Set}

case class Path(elements: List[AstNode]):
  def resultPairs(): List[(String, Option[Integer])] =
    val pairs = elements.map {
        case point: MethodParameterIn =>
            val method      = point.method
            val method_name = method.name
            val code =
                s"$method_name(${method.parameter.l.sortBy(_.order).map(_.code).mkString(", ")})"
            (code, point.lineNumber)
        case point => (point.statement.repr, point.lineNumber)
    }
    pairs.headOption
        .map(x =>
            x :: pairs.sliding(2).collect {
                case Seq(a, b) if a._1 != b._1 && a._2 != b._2 => b
            }.toList
        )
        .getOrElse(List())

object Path:

  private val DefaultMaxTrackedWidth = 128
  // TODO replace with dynamic rendering based on the terminal's width, e.g. in scala-repl-pp
  private lazy val maxTrackedWidth =
      sys.env.get("CHEN_DATAFLOW_TRACKED_WIDTH").map(_.toInt).getOrElse(DefaultMaxTrackedWidth)

  private def tagAsString(tag: Iterator[Tag]) =
      if tag.nonEmpty then tag.name.mkString(", ") else ""

  implicit val show: Show[Path] = path =>
    val pathInfo = PathInfoExtractor.extract(path)
    val tableRows = path.elements.foldLeft(ArrayBuffer[TableRow]()) { (acc, astNode) =>
      val row = PathRowBuilder.build(astNode, acc.nonEmpty, maxTrackedWidth)
      if row.isDefined then acc += row.get
      acc
    }

    val hasCheckLike  = tableRows.exists(row => isCheckLike(row.tags))
    val caption       = buildCaption(pathInfo, hasCheckLike)
    val richTableRows = tableRows.map(_.toRichTableRow)

    printFlows(richTableRows, caption)
    caption

  private def buildCaption(pathInfo: PathInfo, hasCheckLike: Boolean): String =
    val baseCaption = if pathInfo.hasValidElements then
      val srcCaption =
          if pathInfo.srcNode.code != "this" then s"Source: ${pathInfo.srcNode.code}" else ""
      val srcTags = if pathInfo.srcTags.nonEmpty then s"\nSource Tags: ${pathInfo.srcTags}" else ""
      val sinkCode = pathInfo.sinkNode match
        case cfgNode: CfgNode => cfgNode.method.fullName
        case _                => pathInfo.sinkNode.code
      val sinkTags = if pathInfo.sinkTags.nonEmpty then s"Sink Tags: ${pathInfo.sinkTags}\n" else ""
      s"$srcCaption$srcTags\nSink: $sinkCode\n$sinkTags"
    else ""

    if hasCheckLike then s"This flow has mitigations in place.\n$baseCaption" else baseCaption

  private def isCheckLike(tagsStr: String): Boolean =
      tagsStr.toLowerCase.contains("valid") ||
          tagsStr.toLowerCase.contains("encrypt") ||
          tagsStr.toLowerCase.contains("encode") ||
          tagsStr.toLowerCase.contains("transform") ||
          tagsStr.toLowerCase.contains("check")

  private def printFlows(tableRows: ArrayBuffer[RichTableRow], caption: String): Unit =
      try
        val richTableLib = py.module("rich.table")
        val richConsole  = py.module("chenpy.logger").console
        val table        = richTableLib.Table(highlight = true, expand = true, caption = caption)
        Seq("Location", "Method", "Parameter", "Tracked").foreach(c => table.add_column(c))
        tableRows.foreach { row =>
          val tagsStr    = if row.tags.nonEmpty then s"Tags: ${row.tags}" else ""
          val methodStr  = s"${row.method}\n$tagsStr"
          val endSection = row.nodeType == "call"

          table.add_row(
            simplifyFilePath(row.location),
            methodStr.stripMargin,
            addEmphasis(row.parameter, isCheckLike(tagsStr)),
            addEmphasis(row.tracked.takeWhile(_ != '\n'), isCheckLike(tagsStr)),
            end_section = endSection
          )
        }
        richConsole.print(table)
      catch
        case _: Exception =>

  private def addEmphasis(str: String, isCheckLike: Boolean): String =
      if isCheckLike then s"[green]$str[/green]" else str

  private def simplifyFilePath(str: String): String =
      str.replace("src/main/java/", "").replace("src/main/scala/", "")

end Path

private case class PathInfo(
  hasValidElements: Boolean,
  srcNode: AstNode,
  srcTags: String,
  sinkNode: AstNode,
  sinkTags: String
)

private case class TableRow(
  nodeType: String,
  location: String,
  method: String,
  parameter: String,
  tracked: String,
  tags: String
):
  def toRichTableRow: RichTableRow = RichTableRow(
    nodeType = nodeType,
    location = location,
    method = method,
    parameter = parameter,
    tracked = tracked,
    tags = tags
  )

private case class RichTableRow(
  nodeType: String,
  location: String,
  method: String,
  parameter: String,
  tracked: String,
  tags: String
)

private object PathInfoExtractor:
  def extract(path: Path): PathInfo =
      if path.elements.size > 2 then
        val srcNode  = path.elements.head
        val sinkNode = path.elements.last
        val srcTags  = tagAsString(srcNode.tag)
        val sinkTags = tagAsString(sinkNode.tag)

        PathInfo(
          hasValidElements = true,
          srcNode = srcNode,
          srcTags = srcTags,
          sinkNode = sinkNode,
          sinkTags = sinkTags
        )
      else
        PathInfo(
          hasValidElements = false,
          srcNode = null,
          srcTags = "",
          sinkNode = null,
          sinkTags = ""
        )

  private def tagAsString(tag: Iterator[Tag]) =
      if tag.nonEmpty then tag.name.mkString(", ") else ""
end PathInfoExtractor

private object PathRowBuilder:
  private val addedPaths = mutable.Set[String]()

  def build(astNode: AstNode, hasPreviousRows: Boolean, maxTrackedWidth: Int): Option[TableRow] =
    val nodeType     = astNode.getClass.getSimpleName
    val lineNumber   = astNode.lineNumber.getOrElse("").toString
    val fileName     = astNode.file.name.headOption.getOrElse("").replace("<unknown>", "")
    var fileLocation = s"$fileName#$lineNumber"
    var tags         = tagAsString(astNode.tag)
    if fileLocation == "#" then fileLocation = "N/A"
    val methodName = astNode match
      case m: Method            => m.name
      case m: MethodParameterIn => m.method.name
      case m: Return            => m.method.name
      case m: Identifier        => m.method.name
      case m: Call              => m.method.name
      case m: CfgNode           => m.method.name
      case _ =>
          val methodOpt = astNode.inAst.isMethod.headOption
          methodOpt.map(_.name).getOrElse("<no-method>")
    val shouldAdd = if hasPreviousRows then !addedPaths.contains(fileLocation) else true
    if shouldAdd then addedPaths += fileLocation
    val row = astNode match
      case _: MethodReturn => None
      case methodParameterIn: MethodParameterIn =>
          if tags.isEmpty && methodParameterIn.method.tag.nonEmpty then
            tags = tagAsString(methodParameterIn.method.tag)
          if tags.isEmpty && methodParameterIn.tag.nonEmpty then
            tags = tagAsString(methodParameterIn.tag)
          Some(TableRow(
            nodeType = "methodParameterIn",
            location = fileLocation,
            method = methodParameterIn.method.name,
            parameter = s"[bold red]${methodParameterIn.name}[/bold red]",
            tracked = methodParameterIn.method.fullName + (if methodParameterIn.method.isExternal
                                                           then " :right_arrow_curving_up:"
                                                           else ""),
            tags = tags
          ))
      case ret: Return =>
          Some(TableRow(
            nodeType = "return",
            location = fileLocation,
            method = ret.method.name,
            parameter = ret.argumentName.getOrElse(""),
            tracked = ret.code,
            tags = tags
          ))
      case identifier: Identifier =>
          if !addedPaths.contains(fileLocation) && identifier.inCall.nonEmpty then
            if tags.isEmpty && identifier.inCall.nonEmpty && identifier.inCall.head.tag.nonEmpty
            then
              tags = tagAsString(identifier.inCall.head.tag)
            Some(TableRow(
              nodeType = "identifier",
              location = fileLocation,
              method = identifier.method.name,
              parameter = identifier.name,
              tracked = if identifier.inCall.nonEmpty then identifier.inCall.head.code
              else identifier.code,
              tags = tags
            ))
          else None
      case member: Member =>
          Some(TableRow(
            nodeType = "member",
            location = fileLocation,
            method = "<not-in-method>",
            parameter = nodeType,
            tracked = member.name,
            tags = member.code
          ))
      case call: Call =>
          if !call.code.startsWith("<operator") && !call.methodFullName.startsWith("<operator") then
            if tags.isEmpty && call.callee(using NoResolve).nonEmpty &&
              call.callee(using NoResolve).head.isExternal &&
              !call.methodFullName.startsWith("new ") &&
              !call.name.startsWith("<operator")
            then
              tags = tagAsString(call.callee(using NoResolve).head.tag)

            val callIcon =
                if call.callee(using NoResolve).nonEmpty &&
                  call.callee(using NoResolve).head.isExternal &&
                  !call.name.startsWith("<operator") &&
                  !call.methodFullName.startsWith("new ")
                then
                  " :right_arrow_curving_up:"
                else if call.methodFullName.startsWith("<operator") then
                  " :curly_loop:"
                else ""

            Some(TableRow(
              nodeType = "call",
              location = fileLocation,
              method = call.method.name,
              parameter = call.code,
              tracked = call.methodFullName + callIcon,
              tags = tags
            ))
          else None
      case cfgNode: CfgNode =>
          val method = cfgNode.method
          if tags.isEmpty && method.tag.nonEmpty then
            tags = tagAsString(method.tag)
          val statement = cfgNode match
            case _: MethodParameterIn =>
                if tags.isEmpty && method.parameter.tag.nonEmpty then
                  tags = tagAsString(method.parameter.tag)
                val paramsPretty =
                    method.parameter.toList.sortBy(_.index).map(_.code).mkString(", ")
                s"$method.name($paramsPretty)"
            case _ =>
                if tags.isEmpty && cfgNode.statement.tag.nonEmpty then
                  tags = tagAsString(cfgNode.statement.tag)
                cfgNode.statement.repr
          val tracked =
              StringUtils.normalizeSpace(StringUtils.abbreviate(statement, maxTrackedWidth))
          Some(TableRow(
            nodeType = "cfgNode",
            location = fileLocation,
            method = method.name,
            parameter = "",
            tracked = tracked,
            tags = tags
          ))
      case _ =>
          Some(TableRow(
            nodeType = nodeType,
            location = fileLocation,
            method = methodName,
            parameter = astNode.code,
            tracked = astNode.code,
            tags = tags
          ))
    if shouldAdd then row else None
  end build

  private def tagAsString(tag: Iterator[Tag]) =
      if tag.nonEmpty then tag.name.mkString(", ") else ""
end PathRowBuilder
