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
  * a file, not a function, and has no parameter to receive the props: where an element passes one a
  * value a source reaches, the component's props entry (`defineProps()`, `$props()`, `Astro.props`)
  * is tagged that source's kind, with where the value came from.
  */
object ComponentCallBridge:

  /** Extensions a script module's specifier may omit. */
  private val ScriptExtensions = Seq(".tsx", ".jsx", ".ts", ".js", ".mjs", ".mts")

  /** Single-file component extensions. */
  private val ComponentFileExtensions = Seq(".vue", ".svelte", ".astro")

  /** Resolves function component elements; returns the single-file component each other element
    * names, for [[bridgeProps]], which runs with the other bridges.
    */
  def run(ctx: JsContext): List[(Call, String)] =
    lazy val byName    = uniqueFunctions(ctx)
    lazy val sfcByName = singleFileComponents(ctx)
    ctx.cpg.call.filter(isComponentElementCall).l.flatMap { call =>
      val file     = call.method.filename
      val imported = ctx.modules.resolve(file, call.name)
      val target = imported match
        case Some(imp) => importedComponent(ctx, file, imp)
        case None      => byName.get(call.name)
      target.foreach(m => ctx.tagger.resolveCall(call, m))
      if target.nonEmpty then None
      else
        val sfc = imported match
          case Some(imp) if imp.module.startsWith(".") =>
              Some(JsModules.resolveRelative(file, imp.module)).filter(f =>
                  ComponentFileExtensions.exists(f.endsWith) && ctx.cpg.file.nameExact(f).nonEmpty
              )
          // registered globally (Nuxt's components/ directory): the one file of that name
          case None => sfcByName.get(call.name)
          case _    => None
        sfc.map(call -> _)
    }
  end run

  /** Single-file components by their file's base name, where it is unambiguous. */
  private def singleFileComponents(ctx: JsContext): Map[String, String] =
      ctx.cpg.file.name.l
          .filter(f => ComponentFileExtensions.exists(f.endsWith))
          .groupBy(f => f.substring(f.lastIndexOf('/') + 1).takeWhile(_ != '.'))
          .collect { case (name, f :: Nil) => name -> f }

  /** A single-file component's props entry takes what the element passes. */
  def bridgeProps(ctx: JsContext, element: Call, componentFile: String): Unit =
    val passed = element.argument.isCall.nameExact("<operator>.jsxProps").argument.l
    passed.iterator.flatMap(v => MemberTaintBridge.sourceOf(ctx, v).map(_ -> v)).nextOption()
        .foreach { (found, value) =>
          val methods = ctx.cpg.file.nameExact(componentFile).method.l
          val entries =
              methods.flatMap(_.call.nameExact("defineProps", "withDefaults", "$props")) ++
                  methods.flatMap(_.call.nameExact(Operators.fieldAccess).codeExact("Astro.props"))
          ctx.tagger.tagVia(entries, found.tag, found.places(value)*)
          if componentFile.endsWith(".vue") then
            ctx.tagger.tagVia(
              VueRecognizer.templatePropReads(ctx, componentFile),
              found.tag,
              found.places(value)*
            )
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
