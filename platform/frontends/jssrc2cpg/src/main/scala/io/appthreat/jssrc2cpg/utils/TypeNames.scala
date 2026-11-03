package io.appthreat.jssrc2cpg.utils

import io.appthreat.jssrc2cpg.passes.Defines

/** The name chen gives a type that is written as a TypeScript type expression: the string of the
  * checker's type map, or the text of a type annotation. `TYPE_FULL_NAME` holds the name of a type,
  * not its display text, so a type expression is reduced to one name:
  *
  *   - a generic reference is its class (`Promise<User>` is `Promise`); recovery then looks the
  *     class up in the imports of the file, as it does for any name,
  *   - a class named through an import type is `package:Class` for a package (as recovery names
  *     imported classes) and `Class` for a file of the project,
  *   - `typeof import("x")` and `import("x")` are the module (`moduleOf`),
  *   - an array or tuple type is the built-in array, and an object literal type is `object`,
  *   - `typeof Foo` is `Foo`, the name of the value, which recovery resolves like any name,
  *   - a function or constructor type, a signature, `keyof`, `typeof` of anything but a name, an
  *     indexed access, a conditional or a template literal type is `ANY`,
  *   - an intersection is `ANY`, and a union without its `null` and `undefined` members is its
  *     member when it has only one, and `ANY` when it has more (a fixed rule: no member is
  *     preferred).
  */
object TypeNames:

  private val NameChars = "^[A-Za-z_$@~./][\\w$@~#./:\\-]*$".r
  private val ImportClass =
      "^import\\([\"']([^\"']+)[\"']\\)\\.([A-Za-z_$][\\w$.]*)(<.*>)?$".r
  private val Generic       = "^([A-Za-z_$][\\w$.]*)<.*>$".r
  private val NumberLiteral = "^-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?$".r
  private val TypeofName    = "^typeof ([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*)$".r

  def isName(t: String): Boolean = NameChars.matches(t)

  /** The parts of `t` that are separated by `sep` outside every bracket and quote. */
  private def splitTop(t: String, sep: Char): List[String] =
    val parts = List.newBuilder[String]
    var depth = 0
    var start = 0
    var i     = 0
    while i < t.length do
      t(i) match
        case '"' | '\'' | '`' =>
            val q = t(i)
            i += 1
            while i < t.length && t(i) != q do
              if t(i) == '\\' then i += 1
              i += 1
        case '(' | '<' | '[' | '{'           => depth += 1
        case ')' | ']' | '}'                 => depth -= 1
        case '>' if i > 0 && t(i - 1) == '=' => // the arrow of a function type
        case '>'                             => depth -= 1
        case c if c == sep && depth == 0 =>
            parts += t.substring(start, i)
            start = i + 1
        case _ =>
      i += 1
    parts += t.substring(start)
    parts.result().map(_.trim)
  end splitTop

  /** Whether `t` has `=>` outside every bracket: a function type. */
  private def hasTopArrow(t: String): Boolean = topArrow(t) >= 0

  private def topArrow(t: String): Int =
    var depth = 0
    var i     = 0
    while i < t.length do
      t(i) match
        case '"' | '\'' | '`' =>
            val q = t(i)
            i += 1
            while i < t.length && t(i) != q do
              if t(i) == '\\' then i += 1
              i += 1
        case '(' | '<' | '[' | '{'                                    => depth += 1
        case ')' | ']' | '}'                                          => depth -= 1
        case '>' if i > 0 && t(i - 1) == '='                          =>
        case '>'                                                      => depth -= 1
        case '=' if depth == 0 && i + 1 < t.length && t(i + 1) == '>' => return i
        case _                                                        =>
      i += 1
    -1

  private def wrapped(t: String): Boolean =
      t.startsWith("(") && t.endsWith(")") && {
          var depth = 0
          var ok    = true
          var i     = 0
          while i < t.length && ok do
            if t(i) == '(' then depth += 1
            else if t(i) == ')' then
              depth -= 1
              if depth == 0 && i < t.length - 1 then ok = false
            i += 1
          ok
      }

  private def closesAtEnd(t: String, open: Int): Boolean =
    var depth = 0
    var i     = open
    while i < t.length do
      t(i) match
        case '<'                             => depth += 1
        case '>' if i > 0 && t(i - 1) == '=' =>
        case '>' =>
            depth -= 1
            if depth == 0 then return i == t.length - 1
        case _ =>
      i += 1
    false

  /** The name of the value a function typed `raw` returns, where a value type is expected of a
    * function (the return of a method): `(a: A) => R` is `R`, any other type is as in [[clean]].
    */
  def cleanReturn(raw: String, moduleOf: String => String): String =
    val t     = raw.trim
    val inner = if wrapped(t) then t.substring(1, t.length - 1).trim else t
    val arrow = topArrow(inner)
    if arrow >= 0 && !inner.startsWith("new ") then clean(inner.substring(arrow + 2), moduleOf)
    else clean(raw, moduleOf)

  /** The name of the type `raw`; `moduleOf` names the module of `typeof import("x")`. */
  def clean(raw: String, moduleOf: String => String): String =
    val t = raw.trim
    t match
      case "" | "ANY" | "any" | "error"                                  => Defines.Any
      case "string"                                                      => Defines.String
      case "number"                                                      => Defines.Number
      case "boolean" | "true" | "false"                                  => Defines.Boolean
      case "null"                                                        => Defines.Null
      case "undefined"                                                   => Defines.Undefined
      case "bigint"                                                      => Defines.BigInt
      case "symbol"                                                      => Defines.Symbol
      case "unknown"                                                     => Defines.Unknown
      case "void"                                                        => Defines.Void
      case "never"                                                       => Defines.Never
      case "object"                                                      => Defines.Object
      case _ if t.head == '"' || t.head == '\'' || t.head == '`'         => Defines.String
      case _ if NumberLiteral.matches(t)                                 => Defines.Number
      case _ if t.endsWith("n") && NumberLiteral.matches(t.dropRight(1)) => Defines.BigInt
      case _ if wrapped(t)                     => clean(t.substring(1, t.length - 1), moduleOf)
      case _ if t.startsWith("readonly ")      => clean(t.stripPrefix("readonly "), moduleOf)
      case _ if t.startsWith("typeof import(") => moduleOf(t)
      case _ if t.startsWith("import(") && t.endsWith(")") => moduleOf(t)
      case ImportClass(pkg, name, _) =>
          val simple = name.split('.').last
          if pkg.startsWith(".") || pkg.startsWith("/") || pkg.startsWith("~") then simple
          else s"$pkg:$simple"
      case _ if splitTop(t, '|').sizeIs > 1 =>
          val members = splitTop(t, '|').filterNot(m => m == "null" || m == "undefined")
              .map(clean(_, moduleOf)).distinct
          members match
            case single :: Nil => single
            case _             => Defines.Any
      case _ if splitTop(t, '&').sizeIs > 1 => Defines.Any
      case _ if hasTopArrow(t) || t.startsWith("new ") || t.startsWith("abstract new ") =>
          Defines.Any
      // `typeof Foo` is the type of the value `Foo`: as chen did before, the name, which recovery
      // looks up like any other (an imported class, or the variable's own types)
      case TypeofName(name) => name
      case _ if t.startsWith("keyof ") || t.startsWith("typeof ") || t.startsWith("unique ") =>
          Defines.Any
      case _ if t.startsWith("[") => "__ecma.Array"
      case _ if t.endsWith("[]") =>
          "__ecma.Array"
      case _ if t.startsWith("{") =>
          // an object type with a call or construct signature is a function type
          val inner = t.drop(1).trim
          if inner.startsWith("(") || inner.startsWith("<") || inner.startsWith("new ") then
            Defines.Any
          else Defines.Object
      case Generic(name) if closesAtEnd(t, name.length) =>
          if name == "Array" || name == "ReadonlyArray" then "__ecma.Array" else name
      case _ if isName(t) => t
      case _              => Defines.Any
    end match
  end clean
end TypeNames
