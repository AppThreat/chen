package io.appthreat.x2cpg.utils

object WordUtils:
  def wrap(str: String, wrapLength: Int): String =
      wrap(str, wrapLength, System.lineSeparator(), false)

  def wrap(str: String, wrapLength: Int, newLineStr: String, wrapLongWords: Boolean): String =
    if str == null then
      return null

    val actualNewLineStr = if newLineStr == null then System.lineSeparator() else newLineStr
    val actualWrapLength = if wrapLength < 1 then 1 else wrapLength
    val inputLineLength  = str.length
    var offset           = 0
    val wrappedLine      = new StringBuilder(inputLineLength + 32)

    while inputLineLength - offset > actualWrapLength do
      if str.charAt(offset) == ' ' then
        offset += 1
      else
        val spaceToWrapAt = str.lastIndexOf(' ', actualWrapLength + offset)
        if spaceToWrapAt >= offset then
          wrappedLine.append(str.substring(offset, spaceToWrapAt)).append(actualNewLineStr)
          offset = spaceToWrapAt + 1
        else if wrapLongWords then
          wrappedLine.append(str.substring(offset, actualWrapLength + offset)).append(
            actualNewLineStr
          )
          offset += actualWrapLength
        else
          val nextSpace = str.indexOf(' ', actualWrapLength + offset)
          if nextSpace >= 0 then
            wrappedLine.append(str.substring(offset, nextSpace)).append(actualNewLineStr)
            offset = nextSpace + 1
          else
            wrappedLine.append(str.substring(offset))
            offset = inputLineLength
    end while

    wrappedLine.append(str.substring(offset)).toString
  end wrap
end WordUtils
