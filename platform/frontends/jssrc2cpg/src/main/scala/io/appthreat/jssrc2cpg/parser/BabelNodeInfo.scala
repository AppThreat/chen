package io.appthreat.jssrc2cpg.parser

import io.appthreat.jssrc2cpg.parser.BabelAst.BabelNode
import BabelAst.BabelNode
import ujson.Value

case class BabelNodeInfo(
  node: BabelNode,
  json: Value,
  code: String,
  lineNumber: Option[Integer],
  columnNumber: Option[Integer],
  lineNumberEnd: Option[Integer],
  columnNumberEnd: Option[Integer]
)
