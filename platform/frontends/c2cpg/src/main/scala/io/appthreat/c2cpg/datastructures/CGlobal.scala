package io.appthreat.c2cpg.datastructures

import io.appthreat.c2cpg.astcreation.Defines
import io.appthreat.x2cpg.datastructures.Global

import scala.jdk.CollectionConverters.*

object CGlobal extends Global:

  /** Member layouts ride the used-types channel (so the AST cache replays them) as records under
    * this prefix: a struct or class defined in a header is otherwise only an `<includes>` stub
    * without members.
    */
  val MemberRecordPrefix = "\u0000member\u0000"

  def memberRecord(owner: String, file: String, order: Int, name: String, tpe: String): String =
      s"$MemberRecordPrefix$owner\u0000$file\u0000$order\u0000$name\u0000$tpe"

  /** The member layouts the last [[typesSeen]] drained: owner -> its layouts, each with the header
    * that defines it - (file, [(order, name, type)]). Headers that define the same layout give one
    * entry; same-named structs with different layouts give one each, and a reader sees the one its
    * includes bring in.
    */
  @volatile var lastMembers: Map[String, List[(String, List[(Int, String, String)])]] = Map.empty

  /** Constant values ride the same channel: `\u0000const\u0000<name>\u0000<value>`. */
  val ConstRecordPrefix = "\u0000const\u0000"

  def constRecord(name: String, value: Long): String = s"$ConstRecordPrefix$name\u0000$value"

  /** The header constants the last [[typesSeen]] drained, by simple name. A name two constants
    * share with different values is left out.
    */
  @volatile var lastConstants: Map[String, Long] = Map.empty

  /** Type names that are arrays behind a typedef (`jmp_buf`), on the same channel: such a variable
    * decays to a pointer when it is passed, as a spelled array does.
    */
  val ArrayTypedefPrefix = "\u0000arraytypedef\u0000"

  def arrayTypedefRecord(name: String): String = s"$ArrayTypedefPrefix$name"

  /** The array typedef names the last [[typesSeen]] drained. */
  @volatile var lastArrayTypedefs: Set[String] = Set.empty

  /** Forget what an earlier frontend run in this process registered and did not drain: a run that
    * stopped early, or an AST pass used on its own, would otherwise lend its types, member layouts
    * and constants to the next graph.
    */
  def reset(): Unit =
    usedTypes.clear()
    lastMembers = Map.empty
    lastConstants = Map.empty
    lastArrayTypedefs = Set.empty

  def typesSeen(): List[String] =
    val (constants, rest) =
        usedTypes.keys().asScala.toList.partition(_.startsWith(ConstRecordPrefix))
    lastConstants = constants.flatMap { r =>
        r.stripPrefix(ConstRecordPrefix).split('\u0000') match
          case Array(name, value) => value.toLongOption.map(name -> _)
          case _                  => None
    }.groupMap(_._1)(_._2).collect { case (n, vs) if vs.distinct.size == 1 => n -> vs.head }
    val (arrayTypedefs, others) = rest.partition(_.startsWith(ArrayTypedefPrefix))
    lastArrayTypedefs = arrayTypedefs.map(_.stripPrefix(ArrayTypedefPrefix)).toSet
    val (records, types) = others.partition(_.startsWith(MemberRecordPrefix))
    lastMembers = records.flatMap { r =>
        r.stripPrefix(MemberRecordPrefix).split('\u0000') match
          case Array(owner, file, order, name, tpe) =>
              order.toIntOption.map(o => (owner, file, (o, name, tpe)))
          case _ => None
    }.groupBy(_._1).view.mapValues { rows =>
      val byFile = rows.groupMap(_._2)(_._3).view.mapValues(_.distinct.sortBy(_._1)).toList
          // a layout with two members at one position is not one layout
          .filter((_, ms) => ms.map(_._1).distinct.size == ms.size)
          .sortBy(_._1)
      // headers that agree are one layout
      byFile.groupBy(_._2).values.map(_.head).toList.sortBy(_._1)
    }.toMap.filter(_._2.nonEmpty)
    usedTypes.clear()
    types.filterNot(_ == Defines.anyTypeName)
  end typesSeen
end CGlobal
