package io.appthreat.pysrc2cpg

import io.appthreat.pythonparser.ast

import java.util

/** PEP 810 (Python 3.15) explicit lazy imports, as the frontend sees them.
  *
  * A lazy import binds a proxy and loads the module on the first use of the bound name. Two source
  * forms make an import lazy, and both are reported on the import call node with the [[Tag]] TAG
  * (and on the IMPORT node the imports pass derives from it):
  *
  *   - the `lazy` soft keyword (`lazy import json`, `lazy from os import path`) - the AST's
  *     `is_lazy` flag, tag value [[Keyword]];
  *   - the `__lazy_modules__` compatibility list (`__lazy_modules__ = ["json"]` then `import json`)
  *     \- tag value [[LazyModules]].
  *
  * `__lazy_modules__` semantics, verified against CPython 3.15.0 at runtime: the list is consulted
  * when an import statement EXECUTES, so only imports after the assignment are affected; the
  * looked-up name is the fully qualified module (`import a.b` looks up `a.b`; `from .sub import f`
  * in package `pkg` looks up `pkg.sub`); star imports stay eager; only module-scope imports qualify
  *   - inside `if`/`for`/`while`/`with`/`match` and a `try`'s `else`/`finally` they are lazy,
  *     inside a function, a class body, a `try` body or an `except` handler they are eager. The
  *     analysis is flow-insensitive within that scope: statements are visited in source order, and
  *     an assignment whose value is not a literal display of strings makes the list unknown, so
  *     nothing after it is claimed lazy (unknown is never reported as lazy).
  *
  * The keyword form is reported wherever it parses, like CPython's `ast.parse` does - the "lazy
  * import not allowed inside functions" class of errors comes from CPython's compiler, not its
  * parser, and the AST still carries `is_lazy`.
  */
object PythonLazyImports:
  val Tag         = "lazy-import"
  val Keyword     = "keyword"
  val LazyModules = "__lazy_modules__"

  /** For each import statement of `module` made lazy by `__lazy_modules__`, the names of its
    * aliases that are lazy (identity-keyed: two textually identical statements stay distinct).
    *
    * @param packageName
    *   the dotted package relative imports resolve against (`pkg` for `pkg/mod.py` and for
    *   `pkg/__init__.py`); `None` when unknown, in which case relative imports are never claimed.
    */
  def lazyModuleAliases(
    module: ast.Module,
    packageName: Option[String]
  ): util.IdentityHashMap[ast.istmt, Set[String]] =
    val result = new util.IdentityHashMap[ast.istmt, Set[String]]()
    // None: `__lazy_modules__` is unknown (unassigned, or assigned something we cannot read)
    var lazyModules: Option[Set[String]] = None

    def string(expr: ast.iexpr): Option[String] = expr match
      // a plain (non-bytes, non-f) string literal; `u"x"` and `r"x"` are the same str
      case ast.Constant(s: ast.StringConstant, _) if !s.prefix.exists(c => c == 'b' || c == 'B') =>
          Some(s.value)
      case _ => None

    def strings(expr: ast.iexpr): Option[Set[String]] =
      val elements = expr match
        case l: ast.List  => Some(l.elts)
        case t: ast.Tuple => Some(t.elts)
        case s: ast.Set   => Some(s.elts)
        case _            => None
      elements.flatMap { elts =>
        val values = elts.map(string)
        Option.when(values.forall(_.isDefined))(values.flatten.toSet)
      }

    def isLazyModulesName(expr: ast.iexpr): Boolean = expr match
      case ast.Name(id, _) => id == LazyModules
      case _               => false

    def assign(value: Option[ast.iexpr]): Unit =
        lazyModules = value.flatMap(strings)

    def extend(more: Option[Set[String]]): Unit =
        lazyModules =
            for
              known <- lazyModules
              extra <- more
            yield known ++ extra

    def absoluteFrom(importFrom: ast.ImportFrom): Option[String] =
        if importFrom.level == 0 then importFrom.module
        else
          packageName.flatMap { pkg =>
            val parts = pkg.split('.').toSeq.filter(_.nonEmpty)
            val up    = importFrom.level - 1
            Option.when(up <= parts.size) {
                (parts.dropRight(up) ++ importFrom.module.toSeq).mkString(".")
            }.filter(_.nonEmpty)
          }

    def visit(stmts: Iterable[ast.istmt], importsEligible: Boolean): Unit =
        stmts.foreach {
            case a: ast.Assign =>
                if a.targets.exists(isLazyModulesName) then assign(Some(a.value))
            case a: ast.AnnAssign =>
                // a bare annotation (`__lazy_modules__: list[str]`) binds nothing
                if isLazyModulesName(a.target) && a.value.isDefined then assign(a.value)
            case a: ast.AugAssign =>
                if isLazyModulesName(a.target) then
                  // `+=` / `|=` add; any other operator leaves a value we do not model
                  if a.op == ast.Add || a.op == ast.BitOr then extend(strings(a.value))
                  else lazyModules = None
            case ast.Expr(call: ast.Call, _) =>
                call.func match
                  case ast.Attribute(receiver, method, _) if isLazyModulesName(receiver) =>
                      method match
                        case "append" | "add" =>
                            extend(call.args.headOption.flatMap(string).map(Set(_)))
                        case "extend" | "update" =>
                            extend(call.args.headOption.flatMap(strings))
                        case _ => ()
                  case _ => ()
            case i: ast.Import if importsEligible && !i.is_lazy =>
                lazyModules.foreach { known =>
                  val names = i.names.map(_.name).filter(known.contains).toSet
                  if names.nonEmpty then result.put(i, names)
                }
            case i: ast.ImportFrom if importsEligible && !i.is_lazy =>
                val isStar = i.names.exists(_.name == "*")
                if !isStar && !i.module.contains("__future__") then
                  for
                    known <- lazyModules
                    name  <- absoluteFrom(i)
                    if known.contains(name)
                  do result.put(i, i.names.map(_.name).toSet)
            case s: ast.If =>
                visit(s.body, importsEligible); visit(s.orelse, importsEligible)
            case s: ast.For =>
                visit(s.body, importsEligible); visit(s.orelse, importsEligible)
            case s: ast.AsyncFor =>
                visit(s.body, importsEligible); visit(s.orelse, importsEligible)
            case s: ast.While =>
                visit(s.body, importsEligible); visit(s.orelse, importsEligible)
            case s: ast.With      => visit(s.body, importsEligible)
            case s: ast.AsyncWith => visit(s.body, importsEligible)
            case s: ast.Match     => s.cases.foreach(c => visit(c.body, importsEligible))
            case s: ast.TryStar   =>
                // assignments in any clause still bind the module-level list
                visit(s.body, importsEligible = false)
                s.handlers.foreach(h => visit(h.body, importsEligible = false))
                visit(s.orelse, importsEligible)
                visit(s.finalbody, importsEligible)
            case _ => () // def / class bodies have their own scope
        }

    visit(module.stmts, importsEligible = true)
    result
  end lazyModuleAliases

  /** The package relative imports of `relFileName` resolve against, from its dotted module name. */
  def packageOf(relFileName: String, dottedModuleName: Option[String]): Option[String] =
      dottedModuleName.map { module =>
        val isInit = relFileName.endsWith("__init__.py") || relFileName.endsWith("__init__.pyi")
        if isInit then module else module.split('.').dropRight(1).mkString(".")
      }
end PythonLazyImports
