package io.appthreat.pysrc2cpg

import io.appthreat.pythonparser.ast

class NodeToCode(content: String) {
  def getCode(node: ast.iattributes): String = {
    content.substring(node.input_offset, node.end_input_offset)
  }
}
