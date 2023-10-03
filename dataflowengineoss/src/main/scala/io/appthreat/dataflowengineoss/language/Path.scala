package io.appthreat.dataflowengineoss.language

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.Show
import org.apache.commons.lang.StringUtils

import scala.collection.mutable.{ArrayBuffer, Set}

import me.shadaj.scalapy.py
import me.shadaj.scalapy.py.SeqConverters
import py.PyQuote
import me.shadaj.scalapy.interpreter.CPythonInterpreter

case class Path(elements: List[AstNode]) {
  def resultPairs(): List[(String, Option[Integer])] = {
    val pairs = elements.map {
      case point: MethodParameterIn =>
        val method      = point.method
        val method_name = method.name
        val code        = s"$method_name(${method.parameter.l.sortBy(_.order).map(_.code).mkString(", ")})"
        (code, point.lineNumber)
      case point => (point.statement.repr, point.lineNumber)
    }
    pairs.headOption
      .map(x => x :: pairs.sliding(2).collect { case Seq(a, b) if a._1 != b._1 && a._2 != b._2 => b }.toList)
      .getOrElse(List())
  }
}

object Path {

  val DefaultMaxTrackedWidth = 128
  // TODO replace with dynamic rendering based on the terminal's width, e.g. in scala-repl-pp
  lazy val maxTrackedWidth = sys.env.get("CHEN_DATAFLOW_TRACKED_WIDTH").map(_.toInt).getOrElse(DefaultMaxTrackedWidth)

  implicit val show: Show[Path] = { path =>
    var caption = ""
    if (path.elements.size > 2) {
      val srcNode  = path.elements.head
      val srcTags  = if (srcNode.tag.nonEmpty) srcNode.tag.filterNot(_.name == "purl").mkString(", ") else ""
      val sinkNode = path.elements.last
      var sinkCode = sinkNode.code
      val sinkTags = if (sinkNode.tag.nonEmpty) sinkNode.tag.filterNot(_.name == "purl").mkString(", ") else ""
      sinkNode match {
        case cfgNode: CfgNode =>
          val method = cfgNode.method
          sinkCode = method.fullName
      }
      caption = s"Source: ${srcNode.code}"
      if (srcTags.nonEmpty) caption += s"\nSource Tags: ${srcTags}"
      caption += s"\nSink: ${sinkCode}\n"
      if (sinkTags.nonEmpty) caption += s"Sink Tags: ${sinkTags}\n"
    }
    val tableRows  = ArrayBuffer[Array[String]]()
    val addedPaths = Set[String]()
    path.elements.foreach { astNode =>
      val nodeType     = astNode.getClass.getSimpleName
      val lineNumber   = astNode.lineNumber.getOrElse("").toString
      val fileName     = astNode.file.name.headOption.getOrElse("").replace("<unknown>", "")
      var fileLocation = s"${fileName}#${lineNumber}"
      var tags: String = if (astNode.tag.nonEmpty) astNode.tag.filterNot(_.name == "purl").name.mkString(", ") else ""
      if (fileLocation == "#") fileLocation = "N/A"
      astNode match {
        case methodParameterIn: MethodParameterIn =>
          val methodName = methodParameterIn.method.name
          if (tags.isEmpty && methodParameterIn.method.tag.nonEmpty) {
            tags = methodParameterIn.method.tag.filterNot(_.name == "purl").name.mkString(", ")
          }
          if (tags.isEmpty && methodParameterIn.tag.nonEmpty) {
            tags = methodParameterIn.tag.filterNot(_.name == "purl").name.mkString(", ")
          }
          tableRows += Array[String](
            "methodParameterIn",
            fileLocation,
            methodName,
            s"[bold red]${methodParameterIn.name}[/bold red]",
            methodParameterIn.method.fullName + (if (methodParameterIn.method.isExternal) " :right_arrow_curving_up:"
                                                 else ""),
            tags
          )
        case identifier: Identifier =>
          val methodName = identifier.method.name
          if (tags.isEmpty && identifier.inCall.nonEmpty && identifier.inCall.head.tag.nonEmpty) {
            tags = identifier.inCall.head.tag.filterNot(_.name == "purl").name.mkString(", ")
          }
          if (!addedPaths.contains(s"${fileName}#${lineNumber}")) {
            tableRows += Array[String](
              "identifier",
              fileLocation,
              methodName,
              identifier.name,
              if (identifier.inCall.nonEmpty)
                identifier.inCall.head.code
              else identifier.code,
              tags
            )
          }
        case member: Member =>
          val methodName = "<not-in-method>"
          tableRows += Array[String]("member", fileLocation, methodName, nodeType, member.name, member.code, tags)
        case call: Call =>
          if (!call.code.startsWith("<operator") || !call.methodFullName.startsWith("<operator")) {
            if (
              tags.isEmpty && call.callee(NoResolve).head.isExternal && !call.methodFullName.startsWith(
                "<operator"
              ) && !call.name
                .startsWith("<operator") && !call.methodFullName.startsWith("new ")
            ) {
              tags = call.callee(NoResolve).head.tag.filterNot(_.name == "purl").name.mkString(", ")
            }
            var callIcon =
              if (
                call.callee(NoResolve).head.isExternal && !call.name
                  .startsWith("<operator") && !call.methodFullName.startsWith("new ")
              ) " :right_arrow_curving_up:"
              else ""
            if (call.methodFullName.startsWith("<operator")) callIcon = " :curly_loop:"
            tableRows += Array[String](
              "call",
              fileLocation,
              call.method.name,
              call.code,
              call.methodFullName + callIcon,
              tags
            )
          }
        case cfgNode: CfgNode =>
          val method = cfgNode.method
          if (tags.isEmpty && method.tag.nonEmpty) {
            tags = method.tag.filterNot(_.name == "purl").name.mkString(", ")
          }
          val methodName = method.name
          val statement = cfgNode match {
            case _: MethodParameterIn =>
              if (tags.isEmpty && method.parameter.tag.nonEmpty) {
                tags = method.parameter.tag.filterNot(_.name == "purl").name.mkString(", ")
              }
              val paramsPretty = method.parameter.toList.sortBy(_.index).map(_.code).mkString(", ")
              s"$methodName($paramsPretty)"
            case _ =>
              if (tags.isEmpty && cfgNode.statement.tag.nonEmpty) {
                tags = cfgNode.statement.tag.filterNot(_.name == "purl").name.mkString(", ")
              }
              cfgNode.statement.repr
          }
          val tracked = StringUtils.normalizeSpace(StringUtils.abbreviate(statement, maxTrackedWidth))
          tableRows += Array[String]("cfgNode", fileLocation, methodName, "", tracked, tags)
      }
      addedPaths += s"${fileName}#${lineNumber}"
    }
    try {
      printFlows(tableRows, caption)
    } catch {
      case exc: Exception =>
    }
    caption
  }

  def printFlows(tableRows: ArrayBuffer[Array[String]], caption: String): Unit = {
    val richTableLib = py.module("rich.table")
    val richConsole  = py.module("chenpy.logger").console
    val table        = richTableLib.Table(highlight = true, expand = true, caption = caption)
    Array("Location", "Method", "Parameter", "Tracked").foreach(c => table.add_column(c))
    tableRows.foreach { row =>
      {
        val end_section         = row.head == "call"
        val trow: Array[String] = row.tail
        val tagsStr: String     = if (trow(4).nonEmpty) s"Tags: ${trow(4)}" else ""
        val methodStr           = s"${trow(1)}\n${tagsStr}"
        table.add_row(trow(0), methodStr.stripMargin, trow(2), trow(3), end_section = end_section)
      }
    }
    richConsole.print(table)
  }
}
