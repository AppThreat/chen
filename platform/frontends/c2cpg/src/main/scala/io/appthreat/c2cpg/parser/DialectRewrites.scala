package io.appthreat.c2cpg.parser

/** What the CDT parser cannot read of the dialect the file is written in, rewritten to what it can,
  * the way the frontends already bridge dialect gaps: the same text with characters the parser
  * rejects blanked to spaces, so every position after the gap keeps its column. Only constructs
  * that never parsed appear here - what CDT already accepts is left alone.
  *
  * C: a C23 `[[...]]` attribute sequence becomes spaces (CDT's C grammar has no attribute
  * position), and a digit separator `'` inside a numeric literal becomes a space (the number's
  * value is the digits without it). C++: the `this` of an explicit object parameter (`int f(this S&
  * self)`) becomes spaces, leaving the parameter itself, so the member function parses with its
  * object parameter as an ordinary one.
  */
object DialectRewrites:

  /** The C rewrites; the text is unchanged unless it holds one of the gaps. */
  def forC(chars: Array[Char]): Array[Char] =
    val out     = chars.clone()
    var i       = 0
    var state   = 0 // 0 code, 1 line comment, 2 block comment, 3 string, 4 char literal
    var escaped = false
    while i < out.length do
      val c = out(i)
      state match
        case 0 =>
            c match
              case '/' if i + 1 < out.length =>
                  out(i + 1) match
                    case '/' => state = 1; i += 1
                    case '*' => state = 2; i += 1
                    case _   =>
              case '"'  => state = 3
              case '\'' =>
                  // a digit separator sits between hex digits of a number; a char literal's
                  // quotes do not (the closing one is followed by an operator, the opening
                  // preceded by one)
                  if isDigitIsh(out, i - 1) && isDigitIsh(out, i + 1) then
                    i = blankSeparators(out, i)
                  else state = 4
              case '[' if i + 1 < out.length && out(i + 1) == '[' =>
                  blankAttribute(out, i) match
                    case end => i = end // past the closing `]]`, or unchanged at `i`
              case _ =>
        case 1 => if c == '\n' then state = 0
        case 2 =>
            if c == '*' && i + 1 < out.length && out(i + 1) == '/' then
              state = 0; i += 1
        case 3 =>
            if escaped then escaped = false
            else if c == '\\' then escaped = true
            else if c == '"' then state = 0
        case 4 =>
            if escaped then escaped = false
            else if c == '\\' then escaped = true
            else if c == '\'' then state = 0
      end match
      i += 1
    end while
    out
  end forC

  /** Rewrites the number around the separator at `at` without its separators, padded with trailing
    * spaces to the number's original length, so nothing after it moves: `1'000` becomes `1000 `,
    * one token of the same value. Returns the index to continue at.
    */
  private def blankSeparators(out: Array[Char], at: Int): Int =
    def numberChar(c: Char): Boolean = c.isLetterOrDigit || c == '.' || c == '\''
    var start                        = at
    while start > 0 && numberChar(out(start - 1)) do start -= 1
    var end = at
    while end + 1 < out.length &&
      (numberChar(out(end + 1)) ||
          ((out(end + 1) == '+' || out(end + 1) == '-') && "eEpP".indexOf(out(end)) >= 0))
    do end += 1
    val digits = (start to end).map(out).filterNot(_ == '\'')
    (start to end).zipAll(digits, -1, ' ').foreach((at2, d) => out(at2) = d)
    end

  private def isDigitIsh(chars: Array[Char], at: Int): Boolean =
      // a hexadecimal digit on both sides: decimal separators sit between digits, hex ones
      // between hex digits (`0xF'F`), and nothing else in code has a quote between two of them
      at >= 0 && at < chars.length &&
          (chars(at).isDigit || "abcdefABCDEF".indexOf(chars(at)) >= 0)

  /** Blanks `[[...]]` from `open` through its matching `]]`, returning the index to continue at;
    * `open` itself when there is no match (the text stays as it was, and the parse fails as it
    * would have).
    */
  private def blankAttribute(out: Array[Char], open: Int): Int =
    var i       = open + 2
    var depth   = 1
    var state   = 0 // inside the attribute: 0 code, 3 string, 4 char literal
    var escaped = false
    while i < out.length && depth > 0 do
      val c = out(i)
      state match
        case 0 =>
            c match
              case '[' if i + 1 < out.length && out(i + 1) == '[' => depth += 1; i += 1
              case ']' if i + 1 < out.length && out(i + 1) == ']' =>
                  depth -= 1
                  if depth == 0 then
                    var j = open
                    while j <= i + 1 do
                      out(j) = ' '; j += 1
                    return i + 1
                  i += 1
              case '"'                                            => state = 3
              case '\''                                           => state = 4
              case '/' if i + 1 < out.length && out(i + 1) == '/' =>
                  // a line comment ends the line; blank it too, it is inside the attribute
                  while i < out.length && out(i) != '\n' do
                    out(i) = ' '; i += 1
                  i -= 1
              case '/' if i + 1 < out.length && out(i + 1) == '*' =>
                  var j = i + 2
                  while j + 1 < out.length && !(out(j) == '*' && out(j + 1) == '/') do j += 1
                  val end = math.min(j + 1, out.length - 1)
                  var k   = i
                  while k <= end do
                    out(k) = ' '; k += 1
                  i = end
              case _ =>
        case 3 =>
            if escaped then escaped = false
            else if c == '\\' then escaped = true
            else if c == '"' then state = 0
        case 4 =>
            if escaped then escaped = false
            else if c == '\\' then escaped = true
            else if c == '\'' then state = 0
      end match
      i += 1
    end while
    open
  end blankAttribute

  /** The C++ rewrites; the text is unchanged unless it holds one of the gaps. */
  def forCpp(chars: Array[Char]): Array[Char] =
    val out     = chars.clone()
    var i       = 0
    var state   = 0
    var escaped = false
    while i < out.length do
      val c = out(i)
      state match
        case 0 =>
            c match
              case '/' if i + 1 < out.length =>
                  out(i + 1) match
                    case '/' => state = 1; i += 1
                    case '*' => state = 2; i += 1
                    case _   =>
              case '"'  => state = 3
              case '\'' => state = 4
              case _    =>
                  // `this` starting a parameter is the explicit object parameter; `this` in an
                  // expression is followed by `)`, `,` or `->`
                  if (c == 't' || c == 'T') && startsThis(out, i) &&
                    previousTokenChar(out, i).exists(ch => ch == '(' || ch == ',') &&
                    nextNonSpace(out, i + 4).exists(ch =>
                        ch.isLetter || ch == '_' || ch == '&'
                    )
                  then
                    var j = i
                    while j < out.length && (out(j) == 't' || out(j) == 'h' || out(j) == 'i' ||
                          out(j) == 's' || out(j).isWhitespace) && j < i + 8
                    do
                      out(j) = ' '; j += 1
                    i = j - 1
        case 1 => if c == '\n' then state = 0
        case 2 =>
            if c == '*' && i + 1 < out.length && out(i + 1) == '/' then
              state = 0; i += 1
        case 3 =>
            if escaped then escaped = false
            else if c == '\\' then escaped = true
            else if c == '"' then state = 0
        case 4 =>
            if escaped then escaped = false
            else if c == '\\' then escaped = true
            else if c == '\'' then state = 0
      end match
      i += 1
    end while
    out
  end forCpp

  private def startsThis(out: Array[Char], at: Int): Boolean =
      at + 4 <= out.length && new String(out, at, 4) == "this" &&
          (at + 4 == out.length || !out(at + 4).isLetterOrDigit) &&
          (at == 0 || !out(at - 1).isLetterOrDigit)

  private def previousTokenChar(out: Array[Char], at: Int): Option[Char] =
    var j = at - 1
    while j >= 0 && (out(j).isWhitespace || out(j) == '\n') do j -= 1
    if j >= 0 then Some(out(j)) else None

  private def nextNonSpace(out: Array[Char], at: Int): Option[Char] =
    var j = at
    while j < out.length && out(j).isWhitespace do j += 1
    if j < out.length then Some(out(j)) else None
end DialectRewrites
