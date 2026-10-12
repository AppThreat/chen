package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Ember Octane / Polaris (https://guides.emberjs.com).
  *
  * Sources: a route's `model(params)` and `beforeModel(transition)` hooks receive the URL; the
  * router service's `currentRoute.queryParams`/`params`; a controller's declared `queryParams` are
  * bound to its fields (`queryParams = ['q']` makes `this.q` the `?q=` value).
  *
  * Sinks: `htmlSafe(x)` and its `trustHTML` alias (`@ember/template`), which mark a string as safe
  * markup for the template to render unescaped. Templates (`.hbs`, and the `<template>` blocks of
  * `.gjs`/`.gts`) come from astgen as functions `__glimmer_template` returning JSX - `{{{x}}}` as
  * `<ember-raw innerHTML={x} />`, which DomRecognizer takes for the sink it is.
  *
  * Links ([[bridge]]): a route template's `@model` is what the route's `model()` returns, and its
  * `this` the route's controller; a component's getter read (`this.term`) is what the getter
  * returns; a modifier invoked in a template (`{{innerHtml this.snippet}}`) is the function
  * `modifier(...)` wraps. Component arguments (`@slug={{...}}` -> `this.args.slug`) are
  * ComponentCallBridge's.
  */
object EmberRecognizer extends JsFrameworkRecognizer:

  val name: String = "ember"

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("@ember", "ember-source", "@glimmer") || ctx.project.dependsOn(
        "ember-source"
      )

  private val RouteHooks = Set("model", "beforeModel", "afterModel", "redirect")

  def run(ctx: JsContext): Unit =
    val routeFiles = ctx.modules.filesImporting("@ember/routing")
    val hooks = ctx.cpg.method.internal.nameExact(RouteHooks.toSeq*)
        .filter(m => routeFiles.contains(m.filename))
    ctx.tagger.tag(hooks.flatMap(firstParam), INPUT)

    val routerReads = ctx.fieldAccesses.filter(fa =>
        fieldName(fa).exists(f => f == "queryParams" || f == "params") &&
            fieldBase(fa).flatMap(memberPath).exists(_.contains("currentRoute"))
    )
    ctx.tagger.tag(readChains(routerReads), INPUT)

    // controller `queryParams = ['q', 'page']`
    val controllerFiles = ctx.modules.filesImporting("@ember/controller")
    ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a => controllerFiles.contains(a.method.filename))
        .filter(_.argumentOption(1).exists {
            case id: Identifier => id.name == "queryParams"
            case fa: Call       => fieldName(fa).contains("queryParams")
            case _              => false
        })
        .l.foreach { a =>
          val names = a.argumentOption(2).toList.flatMap(_.ast.isLiteral.flatMap(literalValue).l)
          a.method.typeDecl.orElse(enclosingTypeDecl(a.method)).foreach { td =>
              names.foreach { n =>
                val reads = classMethods(td).iterator.flatMap(_.ast.isCall)
                    .nameExact(Operators.fieldAccess).codeExact(s"this.$n")
                    .filterNot(isAssignmentTarget)
                ctx.tagger.tag(readChains(reads), INPUT)
              }
          }
          // the route template renders with the controller as `this`; a read there comes from the
          // entry naming it (a class field's initialiser has no line of its own)
          val entries = a.argumentOption(2).toList.flatMap(_.ast.isLiteral.l)
          val templateReads = templateMethods(ctx, counterpart(a.method.filename, "controllers"))
              .flatMap(_.ast.isCall.nameExact(Operators.fieldAccess).l)
              .filterNot(isAssignmentTarget)
          entries.foreach { entry =>
              literalValue(entry).foreach { n =>
                  ctx.tagger.tagVia(templateReads.filter(_.code == s"this.$n"), INPUT, entry)
              }
          }
        }

    val trusted = ctx.cpg.call.nameExact("htmlSafe", "trustHTML").filter(c =>
        c.argument.filter(_.argumentIndex == 1).exists(!_.isInstanceOf[Literal])
    )
    ctx.tagger.tag(trusted, HtmlSink*)
    modifiers.clear()
    resolveModifiers(ctx)
  end run

  /** Modifier calls in templates and the functions they resolved to. */
  private val modifiers = scala.collection.mutable.ListBuffer.empty[(Call, Method)]

  private val TemplateExtensions = Seq(".hbs", ".gjs", ".gts")

  /** The template files of the route a route or controller file is for: `app/routes/post.js` and
    * `app/controllers/post.js` render `app/templates/post.hbs` (or `.gjs`, `.gts`).
    */
  private def counterpart(file: String, kind: String): List[String] =
    val marker = s"/$kind/"
    val at     = file.lastIndexOf(marker)
    if at < 0 && !file.startsWith(s"$kind/") then Nil
    else
      val (root, rest) =
          if at < 0 then ("", file.drop(kind.length + 1))
          else (file.take(at + 1), file.drop(at + marker.length))
      val name = rest.take(rest.lastIndexOf('.').max(0))
      TemplateExtensions.toList.map(e => s"${root}templates/$name$e")

  /** The functions of the template files (the lowered templates and what nests in them). */
  private def templateMethods(ctx: JsContext, files: List[String]): List[Method] =
      files.flatMap(f => ctx.cpg.file.nameExact(f).method.l)

  /** Bridges that run with the others, as the tags they read appear. */
  def bridge(ctx: JsContext): Unit =
    bridgeRouteModels(ctx)
    bridgeGetters(ctx)
    bridgeModifierArguments(ctx)

  /** A route template's `@model` (`this.args.model`), and the controller's `this.model`, are what
    * the route's `model()` hook returns, member by member.
    */
  private def bridgeRouteModels(ctx: JsContext): Unit =
      ctx.cpg.method.internal.nameExact("model").l
          .filter(m => m.filename.contains("routes/"))
          .foreach { model =>
            val templates = templateMethods(ctx, counterpart(model.filename, "routes"))
            if templates.nonEmpty then
              DataLinkBridge.bridgeReads(
                ctx,
                templates,
                (root, path) =>
                    root match
                      case id: Identifier if id.name == "this" =>
                          path match
                            case "args" :: "model" :: rest =>
                                Some(DataLinkBridge.produced(List(model), rest))
                            case "model" :: rest => Some(DataLinkBridge.produced(List(model), rest))
                            case _               => None
                      case _ => None,
                _.name == "this"
              )
          }

  /** A getter read (`this.term`, in another getter or the class's template) is what the getter
    * returns.
    */
  private def bridgeGetters(ctx: JsContext): Unit =
    val classFiles =
        ctx.modules.filesImporting("@glimmer/component", "@ember/component", "@ember/controller")
    // a class's file is the head of its full name: `app/components/x.gjs::program:X`
    def fileOf(td: TypeDecl) = td.fullName.takeWhile(_ != ':')
    ctx.cpg.typeDecl.filter(td =>
        TemplateExtensions.exists(fileOf(td).endsWith) || classFiles.contains(fileOf(td))
    ).l.foreach { td =>
      val methods = classMethods(td)
      val getters = methods.filter(m =>
          m.fullName == s"${td.fullName}:${m.name}" &&
              m.parameter.size == 1 && m.name != "__glimmer_template"
      ).groupBy(_.name)
      if getters.nonEmpty then
        methods.flatMap(_.ast.isCall.nameExact(Operators.fieldAccess).l)
            .filter(fa => fieldBase(fa).exists(_.code == "this"))
            .filterNot(fa => isAssignmentTarget(fa) || fa._receiverIn.nonEmpty)
            .foreach { read =>
                fieldName(read).flatMap(getters.get).foreach { gs =>
                    DataLinkBridge.sourceAt(ctx, gs.flatMap(DataLinkBridge.returnedValues), Nil)
                        .foreach((found, value) =>
                            ctx.tagger.tagVia(Iterator(read), found.tag, found.places(value)*)
                        )
                }
            }
    }
  end bridgeGetters

  /** A modifier function takes `(element, positional, named)`, and destructures the arrays and
    * objects - `(element, [markup])` - which the engine does not follow from the array a template
    * passes: the parameter is tagged with the source behind what is passed in its place.
    */
  private def bridgeModifierArguments(ctx: JsContext): Unit =
      modifiers.foreach { (call, fn) =>
          call.argument.filter(a => a.argumentIndex == 2 || a.argumentIndex == 3).l.foreach { arg =>
              fn.parameter.indexFrom(1).find(_.index == arg.argumentIndex).foreach { p =>
                  MemberTaintBridge.sourceOf(ctx, arg).foreach(found =>
                      ctx.tagger.tagVia(Iterator(p), found.tag, found.places(arg)*)
                  )
              }
          }
      }

  /** A modifier a template invokes - lowered to `innerHtml(undefined, [positional], {named})` - is
    * the function its module's default export wraps: `export default modifier((element, [markup])
    * \=> ...)`.
    */
  private def resolveModifiers(ctx: JsContext): Unit =
      ctx.cpg.call.filter(c =>
          c.method.name == "__glimmer_template" || c.method.fullName.contains(":__glimmer_template")
      ).filter(_.argument.filter(_.argumentIndex == 1).code.headOption.contains("undefined"))
          .l.foreach { call =>
            val file = call.method.filename
            ctx.modules.resolve(file, call.name).filter(_.module.startsWith(".")).foreach { imp =>
              val base = JsModules.resolveRelative(file, imp.module)
              val target = (Seq(".js", ".ts", ".gjs", ".gts").map(base + _) :+ base)
                  .find(f => ctx.cpg.file.nameExact(f).nonEmpty)
              // `export default modifier(fn)`: the default export, or - as the export of a call
              // is lowered to the callee's name - the one `modifier(fn)` call of the file
              val wrapped = target.toList.flatMap { f =>
                  defaultExportValue(ctx, f).map(v => JsValues.origin(v)).toList ++
                      ctx.cpg.file.nameExact(f).method.nameExact(":program").call
                          .nameExact("modifier").l
              }.collect { case c: Call if c.name == "modifier" => c }.distinctBy(_.id())
              wrapped match
                case wrap :: Nil =>
                    wrap.argument.filter(_.argumentIndex == 1).headOption.flatMap(callbackMethod)
                        .foreach { fn =>
                          ctx.tagger.resolveCall(call, fn)
                          modifiers += call -> fn
                        }
                case _ =>
            }
          }
end EmberRecognizer
