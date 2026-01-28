package io.appthreat.dataflowengineoss.language

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
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
