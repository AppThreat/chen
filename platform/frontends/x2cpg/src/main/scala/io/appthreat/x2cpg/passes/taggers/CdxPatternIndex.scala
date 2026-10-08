package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.generated.nodes.Misc

import java.util.regex.Pattern
import scala.collection.mutable

/** A compiled name pattern with the exact semantics of the generated property steps
  * (`.typeFullName(p)`, `.fullName(p)`, ...): a string without regex characters is an exact match,
  * anything else is a full `(?s)` regex match.
  */
sealed trait CdxPatternMatcher:
  def matches(value: String): Boolean

object CdxPatternMatcher:
  final case class Exact(value: String) extends CdxPatternMatcher:
    def matches(v: String): Boolean = v == value

  /** `literal.*` - under `(?s)` that is precisely `startsWith(literal)`. */
  final case class Prefix(prefix: String) extends CdxPatternMatcher:
    def matches(v: String): Boolean = v.startsWith(prefix)

  final case class Regex(pattern: String) extends CdxPatternMatcher:
    private val compiled            = Pattern.compile(s"(?s)$pattern")
    def matches(v: String): Boolean = compiled.matcher(v).matches()

  def apply(pattern: String): CdxPatternMatcher =
      if !Misc.isRegex(pattern) then Exact(pattern)
      else literalPrefixOf(pattern).map(Prefix(_)).getOrElse(Regex(pattern))

  /** The literal `P` of a pattern of the form `P.*`, where `P` contains no regex syntax other than
    * the escaped dot `\.`. `None` for anything else, which then stays a real regex.
    */
  private[taggers] def literalPrefixOf(pattern: String): Option[String] =
    if !pattern.endsWith(".*") then return None
    val stem = pattern.dropRight(2)
    val sb   = new StringBuilder(stem.length)
    var i    = 0
    while i < stem.length do
      val c = stem.charAt(i)
      if c == '\\' then
        if i + 1 < stem.length && stem.charAt(i + 1) == '.' then
          sb.append('.')
          i += 2
        else return None
      else if MetaChars.indexOf(c) >= 0 then return None
      else
        sb.append(c)
        i += 1
    Some(sb.toString)

  private val MetaChars = "[](){}*+?.^$|\\"
end CdxPatternMatcher

/** Answers "which of these patterns match `value`" without trying every pattern: exact and
  * literal-prefix patterns are hash lookups, only genuine regexes are tried one by one.
  *
  * @param entries
  *   (matcher, id) pairs; [[matching]] returns the ids of matching entries in ascending order.
  */
final class CdxPatternIndex(entries: Seq[(CdxPatternMatcher, Int)]):
  import CdxPatternMatcher.*

  private val exact    = mutable.HashMap.empty[String, mutable.ArrayBuffer[Int]]
  private val prefixes = mutable.HashMap.empty[String, mutable.ArrayBuffer[Int]]
  private val regexes  = mutable.ArrayBuffer.empty[(Regex, Int)]

  entries.foreach {
      case (Exact(v), id)  => exact.getOrElseUpdate(v, mutable.ArrayBuffer.empty) += id
      case (Prefix(p), id) => prefixes.getOrElseUpdate(p, mutable.ArrayBuffer.empty) += id
      case (r: Regex, id)  => regexes += (r -> id)
  }

  private val prefixLengths: Array[Int] =
      prefixes.keysIterator.map(_.length).toArray.distinct.sorted

  val isEmpty: Boolean = entries.isEmpty

  def matching(value: String): IndexedSeq[Int] =
    if isEmpty || value == null then return IndexedSeq.empty
    var out: mutable.ArrayBuffer[Int] = null
    def add(ids: Iterable[Int]): Unit =
      if out == null then out = mutable.ArrayBuffer.empty
      out ++= ids
    exact.get(value).foreach(add)
    var k = 0
    while k < prefixLengths.length && prefixLengths(k) <= value.length do
      prefixes.get(value.substring(0, prefixLengths(k))).foreach(add)
      k += 1
    regexes.foreach { (r, id) => if r.matches(value) then add(id :: Nil) }
    if out == null then IndexedSeq.empty
    else if out.length == 1 then out.toIndexedSeq
    else out.distinct.sorted.toIndexedSeq
end CdxPatternIndex
