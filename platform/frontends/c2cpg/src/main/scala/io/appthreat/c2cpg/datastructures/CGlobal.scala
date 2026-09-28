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

  def memberRecord(owner: String, order: Int, name: String, tpe: String): String =
      s"$MemberRecordPrefix$owner\u0000$order\u0000$name\u0000$tpe"

  /** The member layouts the last [[typesSeen]] drained: owner -> (order, name, type). An owner two
    * files spell with different layouts (same-named structs) is left out: which one a read sees is
    * not known here.
    */
  @volatile var lastMembers: Map[String, List[(Int, String, String)]] = Map.empty

  /** Constant values ride the same channel: `\u0000const\u0000<name>\u0000<value>`. */
  val ConstRecordPrefix = "\u0000const\u0000"

  def constRecord(name: String, value: Long): String = s"$ConstRecordPrefix$name\u0000$value"

  /** The header constants the last [[typesSeen]] drained, by simple name. A name two constants
    * share with different values is left out.
    */
  @volatile var lastConstants: Map[String, Long] = Map.empty

  def typesSeen(): List[String] =
    val (constants, rest) =
        usedTypes.keys().asScala.toList.partition(_.startsWith(ConstRecordPrefix))
    lastConstants = constants.flatMap { r =>
        r.stripPrefix(ConstRecordPrefix).split('\u0000') match
          case Array(name, value) => value.toLongOption.map(name -> _)
          case _                  => None
    }.groupMap(_._1)(_._2).collect { case (n, vs) if vs.distinct.size == 1 => n -> vs.head }
    val (records, types) = rest.partition(_.startsWith(MemberRecordPrefix))
    lastMembers = records.flatMap { r =>
        r.stripPrefix(MemberRecordPrefix).split('\u0000') match
          case Array(owner, order, name, tpe) => order.toIntOption.map(o => (owner, (o, name, tpe)))
          case _                              => None
    }.groupMap(_._1)(_._2).view.mapValues(_.distinct.sortBy(_._1)).toMap
        .filter((_, ms) => ms.map(_._1).distinct.size == ms.size)
    usedTypes.clear()
    types.filterNot(_ == Defines.anyTypeName)
end CGlobal
