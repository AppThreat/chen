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
  * a file, not a function, and has no parameter to receive the props: its reads of a prop are
  * tagged with the source behind what the elements pass under that prop's name, with where the
  * value came from (see [[bridgeProps]]).
  *
  * A component some element renders gets its props from its parents and nowhere else, so the
  * recognizers do not make such props sources of their own: see [[Elements]].
  */
object ComponentCallBridge:

  /** Extensions a script module's specifier may omit. */
  private val ScriptExtensions = Seq(".tsx", ".jsx", ".ts", ".js", ".mjs", ".mts")

  /** Single-file component extensions. */
  private val ComponentFileExtensions = Seq(".vue", ".svelte", ".astro")

  /** Elements resolved to the function component they render, and elements naming a single-file
    * component, by file.
    */
  final case class Elements(functions: List[(Call, Method)], files: List[(Call, String)]):
    lazy val renderedFunctions: Set[Long] = functions.map(_._2.id()).toSet
    lazy val renderedFiles: Set[String]   = files.map(_._2).toSet

  /** Resolves every component element of the project; see [[JsContext.elements]]. */
  def resolve(ctx: JsContext): Elements =
    lazy val byName    = uniqueFunctions(ctx)
    lazy val sfcByName = singleFileComponents(ctx)
    val resolved = ctx.cpg.call.filter(isComponentElementCall).l.map { call =>
      val file     = call.method.filename
      val imported = ctx.modules.resolve(file, call.name)
      val target = imported match
        case Some(imp) => importedComponent(ctx, file, imp)
        case None      => byName.get(call.name)
      val sfc =
          if target.nonEmpty then None
          else
            imported match
              case Some(imp)
                  if imp.module.startsWith(".") || imp.module.startsWith("$lib") ||
                      imp.module.startsWith("@/") || imp.module.startsWith("~/") =>
                  componentFile(ctx, file, imp.module)
              // registered globally (Nuxt's components/ directory): the one file of that name
              case None => sfcByName.get(call.name)
              case _    => None
      (call, target, sfc)
    }
    Elements(
      resolved.collect { case (call, Some(m), _) => call -> m },
      resolved.collect { case (call, None, Some(f)) => call -> f }
    )
  end resolve

  /** The single-file component a specifier names: relative, or under one of the project's usual
    * aliases (`$lib` for `src/lib`, `@` and `~` for `src`).
    */
  private def componentFile(ctx: JsContext, from: String, module: String): Option[String] =
    val candidates =
        if module.startsWith(".") then List(JsModules.resolveRelative(from, module))
        else
          val (alias, rest) = module.span(_ != '/')
          val roots = alias match
            case "$lib" => List("src/lib")
            case _      => List("src", "app", "")
          roots.map(r => (if r.isEmpty then "" else r) + rest).map(_.stripPrefix("/"))
    candidates.find(f =>
        ComponentFileExtensions.exists(f.endsWith) && ctx.cpg.file.nameExact(f).nonEmpty
    ).orElse(
      // the file name of an alias is relative to some project root: match on the path's tail
      if module.startsWith(".") then None
      else
        val tail = module.dropWhile(_ != '/')
        ctx.cpg.file.name.l.filter(f =>
            ComponentFileExtensions.exists(f.endsWith) && f.endsWith(tail)
        ) match
          case only :: Nil => Some(only)
          case _           => None
    )
  end componentFile

  /** Adds the CALL edge from each function component element to its component. */
  def run(ctx: JsContext): Unit =
      ctx.elements.functions.foreach((call, m) => ctx.tagger.resolveCall(call, m))

  /** Single-file components by their file's base name, where it is unambiguous. */
  private def singleFileComponents(ctx: JsContext): Map[String, String] =
      ctx.cpg.file.name.l
          .filter(f => ComponentFileExtensions.exists(f.endsWith))
          .groupBy(f => f.substring(f.lastIndexOf('/') + 1).takeWhile(_ != '.'))
          .collect { case (name, f :: Nil) => name -> f }

  /** The calls that hand a single-file component its props: Svelte's `$props()`, Vue's
    * `defineProps()` and `withDefaults()`.
    */
  private val PropsEntries = Set("$props", "defineProps", "withDefaults")

  /** A single-file component's prop reads take what the elements rendering it pass under that prop:
    * `html` - from `let { html } = $props()`, `props.html`, `Astro.props.html`, or a Vue template's
    * bare `html` - is tagged with the source behind the `html={...}` values, with where they came
    * from. A spread (`{...rest}`) may pass any prop.
    */
  def bridgeProps(ctx: JsContext): Unit =
      ctx.elements.files.groupMap(_._2)(_._1).foreach { (file, elements) =>
        val passed = elements.flatMap(_.argument.isCall.nameExact(JsxPropsOperator).argument.l)
        val (named, spread) = passed.partition(_.argumentName.nonEmpty)
        def values(key: Option[String]): List[Expression] =
            key match
              case Some(k) => named.filter(_.argumentName.contains(k)) ++ spread
              case None    => passed
        val methods = ctx.cpg.file.nameExact(file).method.l
        // props a read names bare: a Vue template's declared props, a Svelte 4 `export let`
        val bareProps =
            if file.endsWith(".vue") then VueRecognizer.declaredPropNames(ctx, file)
            else if file.endsWith(".svelte") then SvelteRecognizer.exportedProps(methods)
            else Set.empty
        DataLinkBridge.bridgeReads(
          ctx,
          methods,
          (root, path) =>
              root match
                case c: Call if PropsEntries.contains(c.name) =>
                    Some(DataLinkBridge.Link.Values(values(path.headOption), path.drop(1)))
                // `defineModel()` is the `v-model` binding; `defineModel('title')` `v-model:title`
                case c: Call if c.name == "defineModel" =>
                    val model = c.argument.filter(_.argumentIndex == 1).headOption
                        .flatMap(literalValue)
                    val bound = model match
                      case Some(name) => values(Some(name)) ++ values(Some(s"v-model:$name"))
                      case None       => values(Some("v-model")) ++ values(Some("modelValue"))
                    Some(DataLinkBridge.Link.Values(bound.distinctBy(_.id()), path))
                case id: Identifier if id.name == "Astro" && path.headOption.contains("props") =>
                    Some(DataLinkBridge.Link.Values(values(path.lift(1)), path.drop(2)))
                case id: Identifier if bareProps.contains(id.name) =>
                    Some(DataLinkBridge.Link.Values(values(Some(id.name)), path))
                case _ => None,
          id => bareProps.contains(id.name) && id.method.parameter.nameExact(id.name).isEmpty
        )
      }

  private val JsxPropsOperator = "<operator>.jsxProps"

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
