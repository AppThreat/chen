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
      val sinkNode = path.elements.last
      var sinkCode = sinkNode.code
      sinkNode match {
        case cfgNode: CfgNode =>
          val method = cfgNode.method
          sinkCode = method.fullName
      }
      caption = s"Source: ${srcNode.code}\nSink: ${sinkCode}\n"
    }
    val tableRows  = ArrayBuffer[Array[String]]()
    val addedPaths = Set[String]()
    path.elements.foreach { astNode =>
      val nodeType     = astNode.getClass.getSimpleName
      val lineNumber   = astNode.lineNumber.getOrElse("").toString
      val fileName     = astNode.file.name.headOption.getOrElse("").replace("<unknown>", "")
      var fileLocation = s"${fileName}#${lineNumber}"
      if (fileLocation == "#") fileLocation = "N/A"
      astNode match {
        case methodParameterIn: MethodParameterIn =>
          val methodName = methodParameterIn.method.name
          tableRows += Array[String](
            "methodParameterIn",
            fileLocation,
            methodName,
            s"[bold red]${methodParameterIn.name}[/bold red]",
            methodParameterIn.method.fullName + (if (methodParameterIn.method.isExternal) " :right_arrow_curving_up:"
                                                 else "")
          )
        case identifier: Identifier =>
          val methodName = identifier.method.name
          if (!addedPaths.contains(s"${fileName}#${lineNumber}")) {
            tableRows += Array[String](
              "identifier",
              fileLocation,
              methodName,
              identifier.name,
              if (identifier.inCall.nonEmpty)
                identifier.inCall.head.code
              else identifier.code
            )
          }
        case member: Member =>
          val methodName = "<not-in-method>"
          tableRows += Array[String]("member", fileLocation, methodName, nodeType, member.name, member.code)
        case call: Call =>
          if (!call.code.startsWith("<operator") || !call.methodFullName.startsWith("<operator")) {
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
              call.methodFullName + callIcon
            )
          }
        case cfgNode: CfgNode =>
          val method     = cfgNode.method
          val methodName = method.name
          val statement = cfgNode match {
            case _: MethodParameterIn =>
              val paramsPretty = method.parameter.toList.sortBy(_.index).map(_.code).mkString(", ")
              s"$methodName($paramsPretty)"
            case _ => cfgNode.statement.repr
          }
          val tracked = StringUtils.normalizeSpace(StringUtils.abbreviate(statement, maxTrackedWidth))
          tableRows += Array[String]("cfgNode", fileLocation, methodName, "", tracked)
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
        table.add_row(trow(0), trow(1), trow(2), trow(3), end_section = end_section)
      }
    }
    richConsole.print(table)
  }
}
