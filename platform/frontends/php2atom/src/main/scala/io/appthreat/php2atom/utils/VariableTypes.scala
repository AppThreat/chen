package io.appthreat.php2atom.utils

import io.appthreat.php2atom.parser.Domain.*
import io.shiftleft.codepropertygraph.generated.Operators

import scala.collection.mutable

/** The static types of a function body's variables, recovered from declarations alone.
  *
  * A variable has a type when PHP declares it: a parameter with a single class type, or a local
  * that is assigned `new Foo` and never written again. Any other write (a second assignment, a
  * `foreach`, `list()`, `catch`, `global`, `static`, `unset` or `++` target, a `use (&$x)` of a
  * closure) leaves the variable untyped, and so does a body that can write variables by name
  * (`$$v`, `extract()`, `eval`, `include`).
  */
object VariableTypes:

  /** The class names a type writes when it is exactly one class (`Foo`, `?Foo`, `Foo|null`), else
    * none: a union or intersection of classes holds no single static type.
    */
  def singleClass(typ: Option[PhpNameExpr]): Option[String] =
      typ.flatMap { t =>
          t.members match
            case single :: Nil
                if !t.name.contains("&") && onlyNullAlternative(t.name, single.name) =>
                Some(single.name)
            case _ => None
      }

  private def onlyNullAlternative(rendered: String, cls: String): Boolean =
      rendered == cls || rendered == s"?$cls" ||
          rendered.split('|').toList.map(_.trim).sorted == List(cls, "null").sorted

  /** What a function body writes: how often each variable, and whether names can be written
    * dynamically.
    */
  final class Writes(
    val counts: Map[String, Int],
    val onlyNew: Map[String, String],
    val dynamic: Boolean
  ):
    def written(name: String): Boolean = counts.getOrElse(name, 0) > 0

  def writesOf(stmts: Seq[PhpNode]): Writes =
    val counts  = scala.collection.mutable.HashMap.empty[String, Int]
    val news    = scala.collection.mutable.HashMap.empty[String, String]
    var dynamic = false

    def write(name: String): Unit = counts.update(name, counts.getOrElse(name, 0) + 1)

    def targets(expr: PhpExpr): Unit = expr match
      case PhpVariable(PhpNameExpr(name, _, _), _) => write(name)
      case PhpVariable(_, _)                       => dynamic = true
      case PhpListExpr(items, _)                   => items.flatten.foreach(i => targets(i.value))
      case PhpArrayExpr(items, _)                  => items.flatten.foreach(i => targets(i.value))
      case _                                       => ()

    def walk(value: Any): Unit = value match
      case assign: PhpAssignment =>
          targets(assign.target)
          assign.target match
            case PhpVariable(PhpNameExpr(name, _, _), _)
                if assign.assignOp == Operators.assignment && !assign.isRefAssign =>
                assign.source match
                  case PhpNewExpr(PhpNameExpr(cls, _, _), _, _) if !special(cls) =>
                      news.update(name, cls)
                  case _ => ()
            case _ => ()
          walk(assign.target)
          walk(assign.source)
      case unary: PhpUnaryOp if IncDec.contains(unary.operator) =>
          targets(unary.expr)
          walk(unary.expr)
      case foreach: PhpForeachStmt =>
          foreach.keyVar.foreach(targets)
          targets(foreach.valueVar)
          foreach.productIterator.foreach(walk)
      case catchStmt: PhpCatchStmt =>
          catchStmt.variable.foreach(targets)
          catchStmt.stmts.foreach(walk)
      case global: PhpGlobalStmt =>
          global.vars.foreach(targets)
      case unset: PhpUnsetStmt =>
          unset.vars.foreach(targets)
          unset.vars.foreach(walk)
      case static: PhpStaticStmt =>
          static.vars.foreach { v =>
            targets(v.variable)
            v.defaultValue.foreach(walk)
          }
      case closure: PhpClosureExpr =>
          // the body is its own scope; only a by-reference capture writes the enclosing variable
          closure.uses.filter(_.byRef).foreach(u => targets(u.variable))
      case _: PhpMethodDecl | _: PhpClassLikeStmt => ()
      case PhpVariable(_: PhpNameExpr, _)         => ()
      case PhpVariable(inner, _) =>
          dynamic = true
          walk(inner)
      case _: PhpEvalExpr | _: PhpIncludeExpr => dynamic = true
      case call: PhpCallExpr =>
          call.methodName match
            case PhpNameExpr(name, _, _) if call.target.isEmpty && DynamicWriters.contains(name) =>
                dynamic = true
            case _ => ()
          call.productIterator.foreach(walk)
      case nameExpr: PhpNameExpr => ()
      case p: Product            => p.productIterator.foreach(walk)
      case it: Iterable[?]       => it.foreach(walk)
      case _                     => ()

    stmts.foreach(walk)
    val only = news.toMap.filter((name, _) => counts.getOrElse(name, 0) == 1)
    Writes(counts.toMap, only, dynamic)
  end writesOf

  /** The classes an expression names in the shapes a constant expression can hold (a parameter's
    * default value), as (name node, kind, member): `Foo::BAR` and `Foo::class` (kind `ref`, with
    * the member) and `new Foo` (kind `new`), each with the name node's own position.
    */
  def classReferencesIn(expr: PhpNode): List[(PhpNameExpr, String, String)] =
    val found = mutable.ListBuffer.empty[(PhpNameExpr, String, String)]
    def walk(value: Any): Unit = value match
      case PhpClassConstFetchExpr(name: PhpNameExpr, member, _) =>
          found += ((name, "ref", member.map(_.name).getOrElse("")))
      case PhpNewExpr(name: PhpNameExpr, args, _) =>
          found += ((name, "new", ""))
          args.foreach(walk)
      case _: PhpClosureExpr | _: PhpNameExpr => ()
      case p: Product                         => p.productIterator.foreach(walk)
      case it: Iterable[?]                    => it.foreach(walk)
      case _                                  => ()
    walk(expr)
    found.toList

  private val IncDec =
      Set(
        Operators.postIncrement,
        Operators.postDecrement,
        Operators.preIncrement,
        Operators.preDecrement
      )

  private val DynamicWriters = Set("extract", "parse_str", "eval")

  def special(cls: String): Boolean = SpecialNames.contains(cls.toLowerCase)

  private val SpecialNames = Set("self", "static", "parent")
end VariableTypes
