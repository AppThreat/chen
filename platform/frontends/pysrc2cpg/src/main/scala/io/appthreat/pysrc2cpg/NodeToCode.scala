package io.appthreat.pysrc2cpg

import io.appthreat.pythonparser.ast

class NodeToCode(content: String):
  // A compound statement that ends the file also spans the NEWLINE/DEDENT tokens the lexer
  // synthesises there, which can end one character past the content: clamp to it.
  def getCode(node: ast.iattributes): String =
    val end   = math.min(node.end_input_offset, content.length)
    val start = math.min(math.max(node.input_offset, 0), end)
    content.substring(start, end)
