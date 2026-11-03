package io.appthreat.jssrc2cpg.utils

/** Canonical form of a type string written by the TypeScript 7 checker (the native astgen type
  * map).
  *
  * TypeScript 7 orders union members and the property members of object types by a stable key, and
  * keeps the quote style of a literal type from the source, where TypeScript 6 ordered by type id
  * and always wrote double quotes. The same type therefore prints in more than one way. This
  * rewrites a string so that those differences disappear:
  *
  *   - string literal types use double quotes,
  *   - the members of a union are sorted, at any depth, and
  *   - the property members of an object type are sorted, while call, construct and index
  *     signatures keep their order (overload order is meaningful).
  *
  * The string is edited in place: it is split into spans at its own brackets, only the spans that
  * are reordered move and only the quote characters of string literals change, and every other
  * character is kept as written. It is the same algorithm as lib/typemap/canon.mjs in
  * atom-parsetools, and both are tested against one table
  * (src/test/resources/typemap-normalization.json). It only applies to native type maps: TypeScript
  * 6 strings are used as they are.
  */
object TypeStringNormalizer:

  private val Openers = Map('(' -> ')', '<' -> '>', '[' -> ']', '{' -> '}')
  private val Closers = Set(')', '>', ']', '}')

  private def literalEnd(s: String, i: Int): Int =
    val q = s(i)
    var j = i + 1
    while j < s.length && s(j) != q do
      if s(j) == '\\' then j += 1
      j += 1
    math.min(j, s.length - 1)

  private def unquote(raw: String): String =
    val body = raw.substring(1, raw.length - 1)
    val sb   = new StringBuilder
    var i    = 0
    while i < body.length do
      if body(i) == '\\' && i + 1 < body.length then
        i += 1
        sb.append(body(i))
      else sb.append(body(i))
      i += 1
    sb.toString

  /** 'a' as "a", keeping the value; double quoted and template literals are returned as they are.
    */
  private def requote(raw: String): String =
      if raw.isEmpty || raw.head != '\'' then raw
      else
        val q = new StringBuilder("\"")
        unquote(raw).foreach {
            case '"'  => q.append("\\\"")
            case '\\' => q.append("\\\\")
            case '\n' => q.append("\\n")
            case '\r' => q.append("\\r")
            case '\t' => q.append("\\t")
            case ch   => q.append(ch)
        }
        q.append('"').toString

  private final case class Split(parts: Vector[String], between: Vector[Char])

  /** Splits at the top level (outside brackets and literals) at the given characters, as written.
    */
  private def splitTop(s: String, seps: Set[Char]): Split =
    val parts   = Vector.newBuilder[String]
    val between = Vector.newBuilder[Char]
    var depth   = 0
    var start   = 0
    var i       = 0
    while i < s.length do
      val c = s(i)
      if c == '"' || c == '\'' || c == '`' then i = literalEnd(s, i)
      else if c == '=' && i + 1 < s.length && s(i + 1) == '>' then i += 1
      else if Openers.contains(c) then depth += 1
      else if Closers.contains(c) then depth = math.max(0, depth - 1)
      else if depth == 0 && seps.contains(c) then
        parts += s.substring(start, i)
        between += c
        start = i + 1
      i += 1
    parts += s.substring(start)
    Split(parts.result(), between.result())

  /** The `=>` of a function type at the top level, or -1. */
  private def topArrow(s: String): Int =
    var depth = 0
    var i     = 0
    while i < s.length do
      val c = s(i)
      if c == '"' || c == '\'' || c == '`' then i = literalEnd(s, i)
      else if c == '=' && i + 1 < s.length && s(i + 1) == '>' then
        if depth == 0 then return i
        i += 1
      else if Openers.contains(c) then depth += 1
      else if Closers.contains(c) then depth = math.max(0, depth - 1)
      i += 1
    -1

  private final case class Opts(unionOrder: Boolean, objectOrder: Boolean, quotes: Boolean)

  /** Rewrites the bracketed spans and string literals inside s. */
  private def rewriteInner(s: String, o: Opts): String =
    val out = new StringBuilder
    var i   = 0
    while i < s.length do
      val c = s(i)
      if c == '"' || c == '\'' || c == '`' then
        val e   = literalEnd(s, i)
        val raw = s.substring(i, e + 1)
        out.append(if o.quotes && c == '\'' then requote(raw) else raw)
        i = e + 1
      else if c == '=' && i + 1 < s.length && s(i + 1) == '>' then
        out.append("=>")
        i += 2
      else if Openers.contains(c) then
        var depth = 1
        var j     = i + 1
        while j < s.length && depth > 0 do
          val d = s(j)
          if d == '"' || d == '\'' || d == '`' then j = literalEnd(s, j)
          else if d == '=' && j + 1 < s.length && s(j + 1) == '>' then j += 1
          else if Openers.contains(d) then depth += 1
          else if Closers.contains(d) then depth -= 1
          j += 1
        val innerEnd = if depth == 0 then j - 1 else j
        val inner    = s.substring(i + 1, innerEnd)
        out.append(c).append(rewriteGroup(c, inner, o))
        if depth == 0 then out.append(s(j - 1))
        i = j
      else
        out.append(c)
        i += 1
      end if
    end while
    out.toString
  end rewriteInner

  private def trimParts(p: String): (String, String, String) =
    val lead  = p.takeWhile(_.isWhitespace)
    val rest  = p.drop(lead.length)
    val trail = rest.reverse.takeWhile(_.isWhitespace).reverse
    (lead, rest.dropRight(trail.length), trail)

  private def join(pieces: Seq[String], between: Seq[Char]): String =
    val sb = new StringBuilder
    pieces.indices.foreach { i =>
      sb.append(pieces(i))
      if i < between.size then sb.append(between(i))
    }
    sb.toString

  private def sortPieces(pieces: Vector[String], between: Vector[Char]): String =
    val cores  = pieces.map(p => trimParts(p)._2)
    val sorted = cores.sorted
    val moved = pieces.indices.map { i =>
      val (lead, _, trail) = trimParts(pieces(i))
      lead + sorted(i) + trail
    }
    join(moved, between)

  private def rewriteGroup(open: Char, inner: String, o: Opts): String =
      if open == '{' then rewriteObjectBody(inner, o)
      else
        val Split(parts, between) = splitTop(inner, Set(','))
        // a parameter is `name: type`; type arguments and tuple elements are plain types
        val pieces = parts.map(p => if open == '(' then rewriteMember(p, o) else rewriteType(p, o))
        join(pieces, between)

  private def isSignature(member: String): Boolean =
      trimParts(member)._2.matches("(?s)^(\\(|<|new\\s*[(<]).*")

  private def rewriteObjectBody(inner: String, o: Opts): String =
    val Split(parts, between) = splitTop(inner, Set(';', ','))
    val members               = parts.map(p => rewriteMember(p, o))
    if !o.objectOrder then join(members, between)
    else
      val present = members.filter(m => trimParts(m)._2.nonEmpty)
      val ordered = present.filter(isSignature) ++ present.filterNot(isSignature).sortBy(m =>
          trimParts(m)._2
      )
      var k = 0
      val moved = members.map { m =>
          if trimParts(m)._2.isEmpty then m
          else
            val (lead, _, trail) = trimParts(m)
            val core             = trimParts(ordered(k))._2
            k += 1
            lead + core + trail
      }
      join(moved, between)

  private def isConditional(head: String): Boolean = "\\s\\?(\\s|$)".r.findFirstIn(head).isDefined

  /** `name: type`: the colon after the name is not a union boundary; the type behind it can be a
    * union.
    */
  private def rewriteMember(member: String, o: Opts): String =
    val Split(parts, between) = splitTop(member, Set(':'))
    if between.isEmpty || isConditional(parts.head) then rewriteType(member, o)
    else
      val head = rewriteInner(parts.head, o)
      val rest = member.substring(parts.head.length + 1)
      head + ":" + rewriteType(rest, o)

  private def rewriteType(t: String, o: Opts): String =
    val arrow = topArrow(t)
    if arrow >= 0 then
      rewriteType(t.substring(0, arrow), o) + "=>" + rewriteType(t.substring(arrow + 2), o)
    else
      val Split(parts, between) = splitTop(t, Set('|'))
      val pieces                = parts.map(p => rewriteIntersection(p, o))
      if parts.size > 1 && o.unionOrder then sortPieces(pieces, between) else join(pieces, between)

  private def rewriteIntersection(t: String, o: Opts): String =
    val Split(parts, between) = splitTop(t, Set('&'))
    join(parts.map(p => rewriteInner(p, o)), between)

  /** The canonical form of `s` (union order, object member order and quote style). */
  def normalize(s: String): String =
      normalize(s, unionOrder = true, objectOrder = true, quotes = true)

  /** The form of `s` with the chosen normalizations; all off leaves the string as written. */
  def normalize(s: String, unionOrder: Boolean, objectOrder: Boolean, quotes: Boolean): String =
      if s.isEmpty then s
      else rewriteType(s, Opts(unionOrder, objectOrder, quotes)).replaceAll("\\s+", " ").trim
end TypeStringNormalizer
