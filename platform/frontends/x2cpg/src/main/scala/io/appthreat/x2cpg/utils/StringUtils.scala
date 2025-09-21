package io.appthreat.x2cpg.utils

import scala.annotation.tailrec

object StringUtils:

  private def strip(str: String): String =
      if str == null then null else str.strip()

  /** Normalizes whitespace in a string.
    *
    * This method removes leading and trailing whitespace and replaces sequences of whitespace
    * characters with a single space.
    *
    * @param str
    *   The string to normalize, may be null.
    * @return
    *   The normalized string or null if the input was null.
    */
  def normalizeSpace(str: String): String =
    val stripped = strip(str)
    if stripped != null && stripped.length > 2 then
      val builder      = new StringBuilder(stripped.length)
      var i            = 0
      var lastWasSpace = false

      while i < stripped.length do
        val c = stripped.charAt(i)
        if Character.isWhitespace(c) then
          if !lastWasSpace && builder.nonEmpty then
            builder.append(' ')
          lastWasSpace = true
        else
          builder.append(c)
          lastWasSpace = false
        i += 1
      builder.toString
    else
      stripped
  end normalizeSpace

  private val ELLIPSIS = "..."

  /** Abbreviates a string using ellipses.
    *
    * This method will check if the specified string is longer than the maximum width. If so, it
    * will abbreviate the string, placing the ellipsis (`...`) at the end.
    *
    * @param str
    *   The string to abbreviate, may be null.
    * @param maxWidth
    *   Maximum length of the resulting string, including the ellipsis. Must be at least 4.
    * @return
    *   The abbreviated string or the original string if it's short enough or null.
    * @throws IllegalArgumentException
    *   if maxWidth is less than 4.
    */
  def abbreviate(str: String, maxWidth: Int): String =
      abbreviate(str, 0, maxWidth)

  /** Abbreviates a string using ellipses, with an offset.
    *
    * This method will check if the specified string is longer than the maximum width. If so, it
    * will abbreviate the string. The abbreviation will attempt to display characters from the
    * offset position, placing the ellipsis (`...`) at the beginning.
    *
    * @param str
    *   The string to abbreviate, may be null.
    * @param offset
    *   Left edge of source string to start omitting characters from. Must be less than or equal to
    *   the string length.
    * @param maxWidth
    *   Maximum length of the resulting string, including the ellipsis. Must be at least 4.
    * @return
    *   The abbreviated string or the original string if it's short enough or null.
    * @throws IllegalArgumentException
    *   if maxWidth is less than 4, or less than 7 if offset > 0.
    */
  def abbreviate(str: String, offset: Int, maxWidth: Int): String =
    if str == null then
      return null
    if maxWidth < 4 then
      throw new IllegalArgumentException("Minimum abbreviation width is 4")
    if str.length <= maxWidth then
      return str

    val actualOffset = if offset > str.length then str.length else offset
    if str.length - actualOffset < maxWidth - 3 then
      val adjustedOffset = str.length - (maxWidth - 3)
      if adjustedOffset <= 4 then
        str.substring(0, maxWidth - 3) + ELLIPSIS
      else
        // Need to recurse or handle complex case
        if maxWidth < 7 then
          throw new IllegalArgumentException("Minimum abbreviation width with offset is 7")
        ELLIPSIS + abbreviate(str.substring(adjustedOffset), maxWidth - 3)
    else if actualOffset <= 4 then
      str.substring(0, maxWidth - 3) + ELLIPSIS
    else
      if maxWidth < 7 then
        throw new IllegalArgumentException("Minimum abbreviation width with offset is 7")
      val availableLength = maxWidth - 3 // Space for "..."
      val halfLength      = availableLength / 2
      val startLength     = halfLength + (availableLength % 2) // Favor the start slightly
      val endLength       = halfLength

      val startPart = str.substring(0, startLength)
      val endPart   = str.substring(str.length - endLength)
      startPart + ELLIPSIS + endPart
    end if
  end abbreviate
end StringUtils
