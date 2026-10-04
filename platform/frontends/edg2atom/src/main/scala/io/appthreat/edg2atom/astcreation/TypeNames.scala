package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.parser.EdgaUnit
import io.appthreat.edg2atom.parser.EdgaUnit.*
import io.appthreat.x2cpg.Defines as X2CpgDefines
import ujson.Value

import scala.collection.mutable

/** Type names as the C/C++ frontend spells them, so the graphs of both frontends agree: a struct by
  * its tag (`pkt`), a pointer `char*`, an array `char[16]`, a typedef by its name (`size_t`), a
  * function type `int(int,char*)`, qualifiers dropped, C++ scopes joined with `.`.
  */
final class TypeNames(unit: EdgaUnit):

  private val cache = mutable.HashMap.empty[Long, String]

  def apply(id: Long): String =
      if id < 0 then X2CpgDefines.Any
      else
        cache.getOrElseUpdate(id, unit.types.get(id).map(nameOf(_, 0)).getOrElse(X2CpgDefines.Any))

  def apply(id: Option[Long]): String = id.map(apply).getOrElse(X2CpgDefines.Any)

  /** A function's return type as its declaration spells it, qualifiers and a reference kept (`const
    * char*`, `const int&`), as the CDT frontend writes return types.
    */
  def returnType(id: Option[Long]): String =
      id.flatMap(unit.types.get).flatMap(_.string("name")).map { n =>
          withoutInlineNamespaces(n).replace("struct ", "").replace("union ", "").replace(
            "enum ",
            ""
          ).replace(" *", "*").replace(" &", "&").replace("::", ".").trim
      }.filter(_.nonEmpty).getOrElse(apply(id))

  /** The type a typedef or a qualifier wraps, followed to the type itself. */
  def resolved(id: Long, depth: Int = 0): Option[Value] =
      unit.types.get(id).flatMap { t =>
          if t.string("kind").contains("typeref") && depth < 32 then
            t.long("of").flatMap(resolved(_, depth + 1))
          else Some(t)
      }

  def isPointer(id: Long): Boolean = resolved(id).exists(_.string("kind").contains("pointer"))
  def isArray(id: Long): Boolean   = resolved(id).exists(_.string("kind").contains("array"))

  def isUnsignedInteger(id: Long): Boolean =
      resolved(id).exists(t => t.string("kind").contains("integer") && !t.flag("signed"))

  /** The type a pointer or array refers to. */
  def target(id: Long): Option[Long] =
      resolved(id).flatMap(t => t.long("to").orElse(t.long("of")))

  private def nameOf(t: Value, depth: Int): String =
    if depth > 32 then return X2CpgDefines.Any
    def sub(id: Option[Long]): String =
        id.flatMap(unit.types.get).map(nameOf(_, depth + 1)).getOrElse(X2CpgDefines.Any)
    t.string("kind").getOrElse("") match
      case "pointer" =>
          val to = sub(t.long("to"))
          if t.flag("reference") || t.flag("rvalueReference") then to else s"$to*"
      case "array" =>
          val of = sub(t.long("of"))
          t.long("count") match
            case Some(n) if n > 0 => s"$of[$n]"
            case _                => s"$of[]"
      case "typeref" =>
          t.string("typedef") match
            case Some(name) if name.nonEmpty => scoped(name, t)
            case _                           => sub(t.long("of"))
      case "routine" =>
          val params = t.list("params").map(p => sub(Some(p.num.toLong)))
          val all    = if t.flag("variadic") then params :+ "..." else params
          s"${sub(t.long("returns"))}(${all.mkString(",")})"
      // a lambda's closure has no name the program can spell
      case "class" | "struct" | "union" if t.flag("closure") => X2CpgDefines.Any
      case "class" | "struct" | "union" =>
          t.string("qualifiedName").filter(_.nonEmpty).orElse(t.string("tag")).map(dotted)
              .getOrElse(X2CpgDefines.Any)
      case "integer" if t.flag("enum") =>
          t.string("tag").filter(_.nonEmpty).map(dotted).getOrElse(cleaned(t.string("name")))
      case _ => cleaned(t.string("name"))
    end match
  end nameOf

  /** A type as a C++ function's full name spells it, as the CDT frontend does: a pointer `T *`, a
    * reference `T &`, qualifiers dropped; the spaces before `*` and `&` are kept only for a
    * qualified name (`geo.Point &`, but `int&`).
    */
  def signatureType(id: Option[Long]): String =
    val spelled = id.map(spelledForSignature(_, 0)).getOrElse(X2CpgDefines.Any)
    val base    = spelled.takeWhile(c => c != ' ' && c != '*' && c != '&')
    if base.contains('.') then spelled else spelled.replace(" *", "*").replace(" &", "&")

  private def spelledForSignature(id: Long, depth: Int): String =
      unit.types.get(id) match
        case Some(t) if depth < 32 && t.string("kind").contains("pointer") =>
            val to = t.long("to").map(spelledForSignature(_, depth + 1)).getOrElse(X2CpgDefines.Any)
            if t.flag("rvalueReference") then s"$to &&"
            else if t.flag("reference") then s"$to &"
            else s"$to *"
        case Some(t)
            if depth < 32 && t.string("kind").contains("typeref") &&
                !t.string("typedef").exists(_.nonEmpty) =>
            t.long("of").map(spelledForSignature(_, depth + 1)).getOrElse(X2CpgDefines.Any)
        case _ => apply(id)

  /** A typedef by the name its scope gives it (`std::string` is `std.string`). */
  private def scoped(name: String, t: Value): String =
      t.string("name").filter(_.endsWith(s"::$name")).map(dotted).getOrElse(dotted(name))

  /** `a::b::C` as `a.b.C`, without the inline namespaces a program names their members without
    * (`std::__1::vector` is `std.vector`).
    */
  def dotted(name: String): String =
      withoutInlineNamespaces(name).replace("::", ".").stripPrefix(".")

  private val inlineQualifiers = unit.inlineNamespaces.map { ns =>
    val parent = ns.lastIndexOf("::") match
      case -1 => ""
      case at => ns.substring(0, at + 2)
    (s"(?<![A-Za-z0-9_])${java.util.regex.Pattern.quote(ns + "::")}".r, parent)
  }

  private def withoutInlineNamespaces(name: String): String =
      inlineQualifiers.foldLeft(name) { case (n, (qualifier, parent)) =>
          if n.contains("::") then
            qualifier.replaceAllIn(n, java.util.regex.Matcher.quoteReplacement(parent))
          else n
      }

  private def cleaned(name: Option[String]): String =
      name.map { n =>
          withoutInlineNamespaces(n).split("\\s+").filterNot(w =>
              w == "const" || w == "volatile" || w == "restrict"
          ).mkString(" ").replace(" *", "*").replace("struct ", "").replace("union ", "")
              .replace("enum ", "").trim
      }.filter(_.nonEmpty).getOrElse(X2CpgDefines.Any)
end TypeNames
