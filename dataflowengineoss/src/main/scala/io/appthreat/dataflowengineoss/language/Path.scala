package io.appthreat.dataflowengineoss.language

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import me.shadaj.scalapy.py
import org.apache.commons.lang.StringUtils

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
    var caption = ""
    if path.elements.size > 2 then
      val srcNode  = path.elements.head
      val srcTags  = tagAsString(srcNode.tag)
      val sinkNode = path.elements.last
      var sinkCode = sinkNode.code
      val sinkTags = tagAsString(sinkNode.tag)
      sinkNode match
        case cfgNode: CfgNode =>
            val method = cfgNode.method
            sinkCode = method.fullName
      caption = if srcNode.code != "this" then s"Source: ${srcNode.code}" else ""
      if srcTags.nonEmpty then caption += s"\nSource Tags: $srcTags"
      caption += s"\nSink: $sinkCode\n"
      if sinkTags.nonEmpty then caption += s"Sink Tags: $sinkTags\n"
    var hasCheckLike: Boolean = false
    val tableRows             = ArrayBuffer[Array[String]]()
    val addedPaths            = Set[String]()
    path.elements.foreach { astNode =>
      val nodeType     = astNode.getClass.getSimpleName
      val lineNumber   = astNode.lineNumber.getOrElse("").toString
      val fileName     = astNode.file.name.headOption.getOrElse("").replace("<unknown>", "")
      var fileLocation = s"$fileName#$lineNumber"
      var tags: String = tagAsString(astNode.tag)
      if fileLocation == "#" then fileLocation = "N/A"
      astNode match
        case _: MethodReturn =>
        case methodParameterIn: MethodParameterIn =>
            val methodName = methodParameterIn.method.name
            if tags.isEmpty && methodParameterIn.method.tag.nonEmpty then
              tags = tagAsString(methodParameterIn.method.tag)
            if tags.isEmpty && methodParameterIn.tag.nonEmpty then
              tags = tagAsString(methodParameterIn.tag)
            tableRows += Array[String](
              "methodParameterIn",
              fileLocation,
              methodName,
              s"[bold red]${methodParameterIn.name}[/bold red]",
              methodParameterIn.method.fullName + (if methodParameterIn.method.isExternal
                                                   then " :right_arrow_curving_up:"
                                                   else ""),
              tags
            )
        case ret: Return =>
            val methodName = ret.method.name
            tableRows += Array[String](
              "return",
              fileLocation,
              methodName,
              ret.argumentName.getOrElse(""),
              ret.code,
              tags
            )
        case identifier: Identifier =>
            val methodName = identifier.method.name
            if tags.isEmpty && identifier.inCall.nonEmpty && identifier.inCall.head.tag.nonEmpty
            then
              tags = tagAsString(identifier.inCall.head.tag)
            if !addedPaths.contains(
                s"$fileName#$lineNumber"
              ) && identifier.inCall.nonEmpty
            then
              tableRows += Array[String](
                "identifier",
                fileLocation,
                methodName,
                identifier.name,
                if identifier.inCall.nonEmpty then
                  identifier.inCall.head.code
                else identifier.code,
                tags
              )
        case member: Member =>
            val methodName = "<not-in-method>"
            tableRows += Array[String](
              "member",
              fileLocation,
              methodName,
              nodeType,
              member.name,
              member.code,
              tags
            )
        case call: Call =>
            if !call.code.startsWith("<operator") || !call.methodFullName.startsWith(
                "<operator"
              )
            then
              if
                tags.isEmpty && call.callee(NoResolve).nonEmpty && call
                    .callee(NoResolve)
                    .head
                    .isExternal && !call.methodFullName.startsWith(
                  "<operator"
                ) && !call.name
                    .startsWith("<operator") && !call.methodFullName.startsWith("new ")
              then
                tags = tagAsString(call.callee(NoResolve).head.tag)
              var callIcon =
                  if
                    call.callee(NoResolve).nonEmpty && call.callee(
                      NoResolve
                    ).head.isExternal && !call.name
                        .startsWith("<operator") && !call.methodFullName.startsWith(
                      "new "
                    )
                  then " :right_arrow_curving_up:"
                  else ""
              if call.methodFullName.startsWith("<operator") then
                callIcon = " :curly_loop:"
              tableRows += Array[String](
                "call",
                fileLocation,
                call.method.name,
                call.code,
                call.methodFullName + callIcon,
                tags
              )
        case cfgNode: CfgNode =>
            val method = cfgNode.method
            if tags.isEmpty && method.tag.nonEmpty then
              tags = tagAsString(method.tag)
            val methodName = method.name
            val statement = cfgNode match
              case _: MethodParameterIn =>
                  if tags.isEmpty && method.parameter.tag.nonEmpty then
                    tags = tagAsString(method.parameter.tag)
                  val paramsPretty =
                      method.parameter.toList.sortBy(_.index).map(_.code).mkString(", ")
                  s"$methodName($paramsPretty)"
              case _ =>
                  if tags.isEmpty && cfgNode.statement.tag.nonEmpty then
                    tags = tagAsString(cfgNode.statement.tag)
                  cfgNode.statement.repr
            val tracked = StringUtils.normalizeSpace(StringUtils.abbreviate(
              statement,
              maxTrackedWidth
            ))
            tableRows += Array[String](
              "cfgNode",
              fileLocation,
              methodName,
              "",
              tracked,
              tags
            )
      end match
      if isCheckLike(tags) then hasCheckLike = true
      addedPaths += s"$fileName#$lineNumber"
    }
    try
      if hasCheckLike then caption = s"This flow has mitigations in place.\n$caption"
      printFlows(tableRows, caption)
    catch
      case _: Exception =>
    caption

  private def addEmphasis(str: String, isCheckLike: Boolean): String =
      if isCheckLike then s"[green]$str[/green]" else str

  private def simplifyFilePath(str: String): String =
      str.replace("src/main/java/", "").replace("src/main/scala/", "")

  private def isCheckLike(tagsStr: String): Boolean =
      tagsStr.contains("valid") || tagsStr.contains("encrypt") || tagsStr.contains(
        "encode"
      ) || tagsStr.contains(
        "transform"
      ) || tagsStr.contains("check")

  private def printFlows(tableRows: ArrayBuffer[Array[String]], caption: String): Unit =
    val richTableLib = py.module("rich.table")
    val richConsole  = py.module("chenpy.logger").console
    val table        = richTableLib.Table(highlight = true, expand = true, caption = caption)
    Array("Location", "Method", "Parameter", "Tracked").foreach(c => table.add_column(c))
    tableRows.foreach { row =>
      val end_section         = row.head == "call"
      val trow: Array[String] = row.tail
      if !trow(3).startsWith("<operator") && trow(3) != "<empty>" && trow(3) != "RET" then
        val tagsStr: String = if trow(4).nonEmpty then s"Tags: ${trow(4)}" else ""
        val methodStr       = s"${trow(1)}\n$tagsStr"
        table.add_row(
          simplifyFilePath(trow(0)),
          methodStr.stripMargin,
          addEmphasis(trow(2), isCheckLike(tagsStr)),
          addEmphasis(trow(3).takeWhile(_ != '\n'), isCheckLike(tagsStr)),
          end_section = end_section
        )
    }
    richConsole.print(table)
  end printFlows
end Path
