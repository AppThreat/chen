package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.parser.EdgaUnit
import io.appthreat.edg2atom.parser.EdgaUnit.*
import ujson.Value

import scala.collection.mutable

/** The names of the records the program declares without a tag. The front end calls every one of
  * them `<unnamed>`, so the records of a unit cannot be told apart by name, and a typedef of one
  * (`typedef struct { ... } MonRec;`) aliases the same `<unnamed>` as every other. The CDT frontend
  * names such a record after the first declarator of the declaration that holds it, and so does
  * this class:
  *
  *   - `typedef struct { ... } MonRec, *MonPtr;` is `MonRec`, the `typedefName` edga (0.4.1 and
  *     later) records for it: the earliest typedef in its scope that names the record itself;
  *   - `struct { ... } v;` at file scope is `v`, and in a function `f` it is `f.v`;
  *   - `struct outer { struct { ... } x; };` is `outer.x`, and an unnamed member of `outer` is
  *     `outer.anonymous_composite_type_N`, where N counts the unnamed members of `outer`;
  *   - any other record is `anonymous_composite_type_N` with N counting the remaining ones of the
  *     unit.
  *
  * A C++ class that takes a typedef name for linkage already carries that name from the front end.
  */
final class AnonymousRecordNames(unit: EdgaUnit, ownerName: Long => String):

  val Prefix = "anonymous_composite_type"

  def isUnnamed(t: Value): Boolean =
      t.string("kind").exists(k => k == "struct" || k == "union" || k == "class") &&
          !t.flag("closure") && !t.flag("incomplete") &&
          t.string("tag").forall(_.isEmpty) &&
          t.string("qualifiedName").forall(q => q.isEmpty || q.endsWith("<unnamed>"))

  /** The name of the unnamed record `id`, dotted, as the rest of the frontend spells a type. */
  def nameOf(id: Long): Option[String] = names.get(id).map(_())

  private lazy val names: Map[Long, () => String] =
    val unnamed = unit.types.values.toSeq.sortBy(_("id").num).filter(isUnnamed)
    val ids     = unnamed.map(_("id").num.toLong).toSet
    val found   = mutable.HashMap.empty[Long, () => String]

    // an unnamed record the type table reaches through pointers and arrays, from a declaration
    def target(typeId: Option[Long]): Option[Long] =
      var cur   = typeId
      var guard = 0
      while guard < 32 do
        guard += 1
        cur.flatMap(unit.types.get) match
          case Some(t) if t.string("kind").contains("pointer") => cur = t.long("to")
          case Some(t) if t.string("kind").contains("array")   => cur = t.long("of")
          case Some(t)
              if t.string("kind").contains("typeref") && !t.string("typedef").exists(_.nonEmpty) =>
              cur = t.long("of")
          case _ => guard = 64
      cur.filter(ids)

    // members: a named member declares its record, an unnamed one is numbered among its siblings
    unit.types.values.toSeq.sortBy(_("id").num).filter(t =>
        t.string("kind").exists(k => k == "struct" || k == "union" || k == "class") &&
            !t.flag("closure")
    ).foreach { owner =>
      val ownerId   = owner("id").num.toLong
      var anonymous = 0
      owner.list("fields").foreach { f =>
        val fieldName = f.string("name").getOrElse("")
        if fieldName.isEmpty then
          f.long("type").filter(ids).foreach { rec =>
            val n = anonymous
            if !found.contains(rec) then found(rec) = () => s"${ownerName(ownerId)}.${Prefix}_$n"
          }
          if f.long("type").exists(ids) then anonymous += 1
        else
          target(f.long("type")).foreach { rec =>
              if !found.contains(rec) then found(rec) = () => s"${ownerName(ownerId)}.$fieldName"
          }
      }
    }

    // a variable declared with the record in a function body: the first one after its marker
    unit.routines.foreach { r =>
      val routine = r.string("qualifiedName").orElse(r.string("name")).getOrElse("")
          .replace("::", ".")
      r.field("body").foreach(declMarkers(_, routine, ids, found))
    }

    // a global variable
    unit.globals.sortBy(g => g.position.map(p => (p.file, p.line, p.column)).getOrElse((0L, 0, 0)))
        .foreach { g =>
          val name = g.string("name").getOrElse("")
          if name.nonEmpty then
            target(g.long("type")).foreach { rec =>
                if !found.contains(rec) then found(rec) = () => name
            }
        }

    // the typedef edga names it by, and the rest by their count
    var counted = 0
    unnamed.foreach { t =>
      val id = t("id").num.toLong
      if !found.contains(id) then
        t.string("typedefName").filter(_.nonEmpty) match
          case Some(name) => found(id) = () => name
          case None =>
              val n = counted
              counted += 1
              found(id) = () => s"${Prefix}_$n"
    }
    found.toMap
  end names

  private def declMarkers(
    node: Value,
    routine: String,
    ids: Set[Long],
    found: mutable.HashMap[Long, () => String]
  ): Unit =
      node match
        case ujson.Obj(o) =>
            o.get("decls").foreach {
                case ujson.Arr(entries) =>
                    entries.toSeq.zipWithIndex.foreach { case (entry, i) =>
                        entry.long("typeDecl").filter(ids).foreach { rec =>
                          val declared =
                              entries.toSeq.drop(i + 1).takeWhile(_.long("typeDecl").isEmpty)
                                  .find(e =>
                                      e.string("name").exists(_.nonEmpty) && e.field("storage").isDefined
                                  )
                          declared.flatMap(_.string("name")).foreach { n =>
                              if !found.contains(rec) then found(rec) = () => s"$routine.$n"
                          }
                        }
                    }
                case _ =>
            }
            o.values.foreach(declMarkers(_, routine, ids, found))
        case ujson.Arr(items) => items.foreach(declMarkers(_, routine, ids, found))
        case _                =>

end AnonymousRecordNames
