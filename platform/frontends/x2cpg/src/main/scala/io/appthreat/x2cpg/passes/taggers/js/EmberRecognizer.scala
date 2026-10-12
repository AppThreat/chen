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
            fieldBase(fa).flatMap(memberPath).exists(_.contains("currentRoute")) ||
            // the router service's `currentURL`, query string and all
            fieldName(fa).contains("currentURL") &&
            fieldBase(fa).flatMap(memberPath).exists(_.lastOption.contains("router"))
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
    resolveHelpers(ctx)
    resolveServiceCalls(ctx)
  end run

  /** Modifier calls in templates and the functions they resolved to. */
  private val modifiers = scala.collection.mutable.ListBuffer.empty[(Call, Method)]

  private def dasherize(name: String): String =
      name.replaceAll("([a-z0-9])([A-Z])", "$1-$2").replace('_', '-').toLowerCase

  /** Files under `app/<kind>/` by the name Ember resolves them with: `services/embed-bridge.ts` is
    * the `embed-bridge` service.
    */
  private def byResolverName(ctx: JsContext, kind: String): Map[String, String] =
      ctx.cpg.file.name.l.filter(f => f.contains(s"$kind/") && !f.contains("node_modules"))
          .flatMap { f =>
            val rest = f.substring(f.lastIndexOf(s"$kind/") + kind.length + 1)
            Option.when(rest.contains('.'))(rest.take(rest.lastIndexOf('.')) -> f)
          }.toMap

  /** The class a service file defines: of its top-level declarations (interfaces too), the one with
    * methods.
    */
  private def serviceClass(ctx: JsContext, file: String): Option[TypeDecl] =
      ctx.cpg.typeDecl.filter(td =>
          td.fullName.takeWhile(_ != ':') == file && td.fullName.count(_ == ':') == 3
      ).l.map(td => td -> classMethods(td).count(m => !m.name.startsWith("<")))
          .filter(_._2 > 0).sortBy(-_._2).headOption.map(_._1)

  /** The service an injected member names - `@service declare catalog`, `@service('embed-bridge')
    * declare bridge` - found by the member's name, or else as the one service declaring `member`.
    */
  private def serviceFor(
    ctx: JsContext,
    services: Map[String, String],
    field: String,
    member: String
  ): Option[TypeDecl] =
      services.get(dasherize(field)).orElse(services.get(field)).flatMap(serviceClass(ctx, _))
          .orElse {
              services.values.toList.flatMap(serviceClass(ctx, _)).filter(td =>
                  classMethods(td).exists(m =>
                      m.name == member || m.ast.isCall.nameExact(Operators.fieldAccess)
                          .codeExact(s"this.$member").exists(isAssignmentTarget)
                  )
              ) match
                case only :: Nil => Some(only)
                case _           => None
          }

  /** `this.catalog.loadArticle(id)`: a call into an injected service is its method. */
  private def resolveServiceCalls(ctx: JsContext): Unit =
    val services = byResolverName(ctx, "services")
    if services.isEmpty then return
    ctx.cpg.call.filter(c => !c.name.startsWith("<")).l.foreach { call =>
        receiverOf(call).flatMap(memberPath).foreach {
            case List("this", field) =>
                serviceFor(ctx, services, field, call.name).foreach { td =>
                    classMethods(td).find(_.fullName == s"${td.fullName}:${call.name}")
                        .foreach(ctx.tagger.resolveCall(call, _))
                }
            case _ =>
        }
    }

  /** `{{markdown-lite @model.note}}`, lowered to `markdown_lite(...)`: the default export of
    * `helpers/markdown-lite`.
    */
  private def resolveHelpers(ctx: JsContext): Unit =
    val helpers = byResolverName(ctx, "helpers")
    if helpers.isEmpty then return
    ctx.cpg.call.filter(c => c.method.fullName.contains("__glimmer_template")).l.foreach { call =>
        helpers.get(call.name.replace('_', '-'))
            .filter(_ => ctx.modules.resolve(call.method.filename, call.name).isEmpty)
            .flatMap(defaultExport(ctx, _)).foreach(ctx.tagger.resolveCall(call, _))
    }

  private def defaultExport(ctx: JsContext, file: String): Option[Method] =
      defaultExportValue(ctx, file).flatMap(v => callbackMethod(v)).orElse(
        ctx.cpg.file.nameExact(file).method.internal.filter(m =>
            !m.name.startsWith(":") && m.fullName.count(_ == ':') == 3
        ).l match
          case only :: Nil => Some(only)
          case _           => None
      )

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
    bridgeEachItems(ctx)
    bridgeServiceFields(ctx)

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

  /** `{{#each xs as |x|}}`, lowered to `xs.map((x) => ...)`: the block param is an element of `xs`.
    */
  private def bridgeEachItems(ctx: JsContext): Unit =
      ctx.cpg.call.nameExact("map").filter(_.method.fullName.contains("__glimmer_template")).l
          .foreach { each =>
              for
                items <- receiverOf(each)
                fn <- each.argument.filter(_.argumentIndex == 1).headOption.flatMap(callbackMethod)
                item  <- fn.parameter.find(_.index == 1)
                found <- MemberTaintBridge.sourceOf(ctx, items)
              do ctx.tagger.tagVia(Iterator(item), found.tag, found.places(items)*)
          }

  /** `this.bridge.lastSnippet` in a component: what the injected service assigns to its field. */
  private def bridgeServiceFields(ctx: JsContext): Unit =
    val services = byResolverName(ctx, "services")
    if services.isEmpty then return
    ctx.fieldAccesses.filter(fa => fa._receiverIn.isEmpty && !isAssignmentTarget(fa)).foreach {
        read =>
            fieldBase(read).flatMap(memberPath).zip(fieldName(read)).foreach {
                case (List("this", field), member) =>
                    serviceFor(ctx, services, field, member).filterNot(td =>
                        read.method.fullName.startsWith(td.fullName + ":")
                    ).foreach { td =>
                      val assigned = classMethods(td).flatMap(
                        _.ast.isCall.nameExact(Operators.assignment).l
                      ).filter(_.argumentOption(1).exists(_.code == s"this.$member"))
                          .flatMap(_.argumentOption(2))
                      DataLinkBridge.sourceAt(ctx, assigned, Nil).foreach((found, value) =>
                          ctx.tagger.tagVia(Iterator(read), found.tag, found.places(value)*)
                      )
                    }
                case _ =>
            }
    }
  end bridgeServiceFields

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
      // a controller's route template reads its getters too
      val templates = templateMethods(ctx, counterpart(fileOf(td), "controllers"))
      if getters.nonEmpty then
        (methods ++ templates).flatMap(_.ast.isCall.nameExact(Operators.fieldAccess).l)
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
