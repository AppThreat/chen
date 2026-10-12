package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*

/** A template's component element, lowered to a call of the component, resolved to the function
  * that implements it.
  *
  * jssrc2cpg lowers `<RichText html={bio} />` to a call of `RichText` whose one argument is the
  * props object (`<operator>.jsxProps(bio)`), with the element itself as a child of the call. The
  * CALL edge to the component is added here, from the import that bound the name - the module's
  * default export for a default import, the export of that name for a named one - or, absent an
  * import (components registered globally), from the one project function of that name. With the
  * edge the dataflow engine carries a parent's values into the component's props parameter.
  *
  * The engine holds an object as one value: a component reached by a tainted prop is tainted in all
  * of its props.
  *
  * Only function components are resolved. A single-file component (`.vue`, `.svelte`, `.astro`) is
  * a file, not a function, and has no parameter to receive the props.
  */
object ComponentCallBridge:

  /** Extensions a script module's specifier may omit. */
  private val ScriptExtensions = Seq(".tsx", ".jsx", ".ts", ".js", ".mjs", ".mts")

  def run(ctx: JsContext): Unit =
    lazy val byName = uniqueFunctions(ctx)
    ctx.cpg.call.filter(isComponentElementCall).foreach { call =>
      val file = call.method.filename
      val target = ctx.modules.resolve(file, call.name) match
        case Some(imp) => importedComponent(ctx, file, imp)
        case None      => byName.get(call.name)
      target.foreach(m => ctx.tagger.resolveCall(call, m))
    }

  /** The lowered call of a component element: the call has the element's template DOM as a child.
    */
  def isComponentElementCall(c: Call): Boolean =
      c.name.headOption.exists(_.isUpper) &&
          c.astChildren.collectAll[TemplateDom].exists(_.name == "JSXElement")

  /** Functions of the project's script files, by name, where the name is unambiguous. */
  private def uniqueFunctions(ctx: JsContext): Map[String, Method] =
      ctx.cpg.method.internal
          .filter(m => m.name.headOption.exists(_.isUpper) && isScriptFile(m.filename))
          .l
          .groupBy(_.name)
          .collect { case (name, m :: Nil) => name -> m }

  private def isScriptFile(file: String): Boolean =
      ScriptExtensions.exists(file.endsWith)

  /** The component an import names: the module's default export for a default import, the function
    * of the imported name for a named one. Only relative specifiers name a project file.
    */
  private def importedComponent(ctx: JsContext, fromFile: String, imp: JsImport): Option[Method] =
    if !imp.module.startsWith(".") then return None
    val base = JsModules.resolveRelative(fromFile, imp.module)
    // `./Comment.tsx` names the file; `./Comment` one of its extensions or a directory index
    val file = ((if isScriptFile(base) then Seq(base) else Nil) ++
        ScriptExtensions.map(base + _) ++ ScriptExtensions.map(s"$base/index" + _))
        .find(f => ctx.cpg.file.nameExact(f).nonEmpty)
    file.flatMap { f =>
        imp.kind match
          case ImportKind.Default => defaultExport(ctx, f)
          case ImportKind.Named =>
              ctx.cpg.file.nameExact(f).method.internal.nameExact(imp.imported).headOption
          case _ => None
    }

  private def defaultExport(ctx: JsContext, file: String): Option[Method] =
      defaultExportValue(ctx, file).flatMap(callbackMethod)
end ComponentCallBridge
