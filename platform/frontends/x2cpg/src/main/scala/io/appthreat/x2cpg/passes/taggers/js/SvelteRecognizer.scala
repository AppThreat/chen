package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Svelte 5 and SvelteKit 2 (https://svelte.dev/docs).
  *
  * SvelteKit identifies route handlers by FILE name, not by a registration call: a `load` exported
  * from `+page.server.ts` is the route's data loader, the verbs exported from `+server.ts` are its
  * endpoint, and `hooks.server.ts` sits in front of every request. Their parameters are the request
  * (`{ params, url, request, cookies, fetch }`). Anonymous methods in a server file - the form
  * `actions` object (`default: async ({ request }) => ...`) - are handlers too.
  *
  * Components receive data through props: `$props()` (Svelte 5) or `export let` (Svelte 4, lowered
  * to `exports.x = x`, so the prop's reads are tagged); a route component's `data` prop is what its
  * `load` returned. The URL is also read from `page` (`$app/state`) or the legacy `$page` store
  * (`$app/stores`). An action used as `use:tooltip={value}` receives `value` as its second
  * parameter - a source where the bound value is one ([[bridgeActions]]).
  *
  * Sinks: `{@html}` (EasyTagsPass) and `bind:innerHTML` (DomRecognizer), `redirect(status, url)`
  * from `@sveltejs/kit` and `goto(url)` from `$app/navigation` with a target the code does not
  * anchor.
  */
object SvelteRecognizer extends JsFrameworkRecognizer:

  val name: String = "svelte"

  /** The file conventions are evidence on their own: a `+page.server.ts` is a SvelteKit route
    * whatever it imports.
    */
  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("svelte", "@sveltejs/kit", "$app") ||
          ctx.project.dependsOn("svelte", "@sveltejs/kit") ||
          ctx.project.hasFile(
            s"$Component|$DataFile|$EndpointFile|.*hooks\\.(server|client)\\.(js|ts|mjs|mts)"
          )

  private val DataFile     = ".*\\+(page|layout)(\\.server)?\\.(js|ts|mjs|mts)"
  private val EndpointFile = ".*\\+server\\.(js|ts|mjs|mts)"
  private val HooksFile    = ".*hooks(\\.server|\\.client)?\\.(js|ts|mjs|mts)"
  private val Component    = ".*\\.svelte"

  private val DataEntrypoints = Set("load")
  private val HttpEntrypoints =
      Set("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "fallback")
  private val HookEntrypoints =
      Set(
        "handle",
        "handleError",
        "handleFetch",
        "handleValidationError",
        "init",
        "reroute",
        "transport"
      )

  /** URL and route data on SvelteKit's page object. */
  private val PageFields = Set("url", "params", "data", "form", "state")

  def run(ctx: JsContext): Unit =
    // `load` and form actions hand their result to the page; endpoints and hooks answer the request
    tagEntrypoints(ctx, DataFile, DataEntrypoints, data = true)
    tagEntrypoints(ctx, EndpointFile, HttpEntrypoints, data = false)
    tagEntrypoints(ctx, HooksFile, HookEntrypoints, data = false)
    tagComponentProps(ctx)
    tagPage(ctx)
    tagNavigation(ctx)
    tagTransformedChunks(ctx)

  private val RouteComponent = ".*\\+(page|layout|error)\\.svelte"

  /** The `load` functions whose data a route component receives: its own route's (`+page.server`
    * and `+page`, or `+layout.server` and `+layout` for a layout), then every enclosing layout's.
    */
  private def loadsFor(ctx: JsContext, component: String): List[Method] =
    val loads = allLoads(ctx)
    val dir   = component.substring(0, component.lastIndexOf('/') + 1)
    val own =
        if component.contains("+layout.") then
          loads.filter(l => l.filename.startsWith(dir + "+layout."))
        else loads.filter(l => l.filename.startsWith(dir + "+page."))
    val layouts = loads.filter { l =>
      val ldir = l.filename.substring(0, l.filename.lastIndexOf('/') + 1)
      l.filename.substring(ldir.length).startsWith("+layout.") && dir.startsWith(ldir) &&
      !own.exists(_.id() == l.id())
    }.sortBy(l => -l.filename.length)
    own ++ layouts

  /** Every `load` of the data modules: `export function load()` and `export const load = (...) =>
    * ...`, whose function is anonymous.
    */
  private def allLoads(ctx: JsContext): List[Method] =
      (ctx.cpg.file.name(DataFile).method.internal.nameExact("load").l ++
          exportedFunctions(ctx, Set("load")).map(_._2).filter(_.filename.matches(DataFile)))
          .distinctBy(_.id())

  /** The form actions of a page: the functions of `export const actions = { ... }` in its
    * `+page.server` module.
    */
  private def actionsFor(ctx: JsContext, component: String): List[Method] =
    val dir   = component.substring(0, component.lastIndexOf('/') + 1)
    val loads = allLoads(ctx).map(_.id()).toSet
    ctx.cpg.file.name(DataFile).filter(_.name.startsWith(dir + "+page.server.")).method.internal
        .filterNot(m => m.name == ":program" || m.name == "load" || loads.contains(m.id())).l

  /** A route component receives `{ data, form, params }`: `data` is what its `load` functions
    * returned, `form` what the form action that ran returned, `params` the URL's. Each read below
    * them is tagged with the source behind that member of the returned data. Runs with the bridges.
    */
  def bridgeRouteProps(ctx: JsContext): Unit =
      ctx.cpg.file.name(RouteComponent).name.l.foreach { component =>
        lazy val loads   = loadsFor(ctx, component)
        lazy val actions = actionsFor(ctx, component)
        def link(path: List[String]): Option[DataLinkBridge.Link] =
            path match
              case "data" :: rest   => Some(DataLinkBridge.produced(loads, rest))
              case "form" :: rest   => Some(DataLinkBridge.produced(actions, rest))
              case "params" :: rest => Some(DataLinkBridge.Link.Source(INPUT))
              case _                => None
        val methods  = ctx.cpg.file.nameExact(component).method.l
        val exported = exportedProps(methods).intersect(Set("data", "form"))
        DataLinkBridge.bridgeReads(
          ctx,
          methods,
          (root, path) =>
              root match
                case c: Call if c.name == "$props" => link(path)
                // Svelte 4: `export let data`
                case id: Identifier if exported.contains(id.name) => link(id.name :: path)
                case _                                            => None,
          id => exported.contains(id.name)
        )
      }

  /** `event.locals.user = ...` in a server hook is what every `load`, action and endpoint of the
    * request reads as `locals.user`: each such read is tagged with the source behind what the hooks
    * write under that name. Runs with the bridges.
    */
  def bridgeLocals(ctx: JsContext): Unit =
    val hooks = ctx.cpg.file.name(HooksFile).method.internal.l
    if hooks.isEmpty then return
    val written = hooks.flatMap(_.ast.isCall.nameExact(Operators.assignment).l).flatMap { a =>
        (a.argumentOption(1), a.argumentOption(2)) match
          case (Some(target: Call), Some(v)) =>
              DataLinkBridge.accessPath(target).map(_._2).collect {
                  case path if path.contains("locals") =>
                      path.dropWhile(_ != "locals").drop(1) -> v
              }.filter(_._1.nonEmpty)
          case _ => None
    }
    if written.isEmpty then return
    val handlers = ctx.cpg.file.name(s"$DataFile|$EndpointFile").method.internal.l
    DataLinkBridge.bridgeReads(
      ctx,
      handlers,
      (root, path) =>
          (root, path.dropWhile(_ != "locals")) match
            case (_: MethodParameterIn, "locals" :: key :: rest) =>
                written.collect { case (k :: more, v) if k == key => (more, v) } match
                  case Nil => None
                  case vs  =>
                      // `locals.user.name` from `locals.user = { name }` - or from a write of
                      // `locals.user.name` itself
                      Some(DataLinkBridge.Link.Values(
                        vs.flatMap((more, v) =>
                            if more.isEmpty then DataLinkBridge.valueAt(v, rest)
                            else if rest.startsWith(more) then
                              DataLinkBridge.valueAt(v, rest.drop(more.size))
                            else Nil
                        ),
                        Nil
                      ))
            case _ => None
    )
  end bridgeLocals

  /** `resolve(event, { transformPageChunk: ({ html }) => html.replace(marker, data) })`: the chunk
    * the callback returns is written into the page the server sends, so its return value is an HTML
    * sink - reflected markup with whatever the callback spliced in.
    */
  private def tagTransformedChunks(ctx: JsContext): Unit =
    val chunks = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(_.argumentOption(1).exists {
            case fa: Call => fieldName(fa).contains("transformPageChunk")
            case _        => false
        })
        .flatMap(_.argumentOption(2)).l
        .flatMap(callbacksIn(_))
    val returned = chunks.flatMap { m =>
      val explicit = m.ast.isReturn.astChildren
          .collect { case e: Expression if e.method.id() == m.id() => e }.l
      val implicitBody =
          if explicit.nonEmpty then Nil
          else
            m.block.astChildren.collectFirst {
                case e: Expression if e.method.id() == m.id() => e
            }.toList
      explicit ++ implicitBody
    }
    ctx.tagger.tag(returned.iterator, HtmlSink*)
  end tagTransformedChunks

  /** Members of a request event that are not the request: what the server's own hooks put there,
    * the platform, the parent layout's data, and helpers.
    */
  private val NonRequestMembers = Set(
    "locals",
    "platform",
    "parent",
    "depends",
    "untrack",
    "setHeaders",
    "fetch",
    "isDataRequest",
    "isSubRequest",
    "resolve",
    "route",
    "data"
  )

  /** Handlers by file convention: routes, whose parameters are the request. An endpoint's return
    * value is the response; a `data` function's goes to the page and is no sink.
    *
    * The request is what an event's members hold - `url`, `params`, `request`, `cookies` - and not
    * its `locals` (bridged from the hooks that write them, [[bridgeLocals]]), `parent()` or
    * `fetch`. Where the handler reads the event member by member, those reads are the sources;
    * where it hands the event on whole, the event is. `handleFetch` sees the app's own outgoing
    * requests.
    */
  private def tagEntrypoints(
    ctx: JsContext,
    fileRegex: String,
    names: Set[String],
    data: Boolean
  ): Unit =
    // Anonymous handlers are numbered when a file has more than one (`anonymous`, `anonymous1`).
    val handlers = ctx.cpg.file.name(fileRegex).method.internal
        .filter(m => names.contains(m.name) || m.name.startsWith("anonymous"))
        .l
    ctx.tagger.tag(handlers.iterator, ROUTE)
    if data then ctx.tagger.tag(handlers.iterator, DATA)
    handlers.filterNot(_.name == "handleFetch").foreach { h =>
        params(h).foreach { p =>
          val scope = h :: nestedMethods(h)
          // member reads of the event, destructured (`{ url }` lowers to `url = param.url`) or not
          val memberReads = scope.flatMap(_.ast.isCall.nameExact(Operators.fieldAccess).l)
              .filter(fa =>
                  fieldBase(fa).flatMap(b => DataLinkBridge.accessPath(b)).exists {
                      case (root, Nil | ("event" :: Nil)) => root.id() == p.id()
                      case _                              => false
                  }
              )
          // the event used other than by reading a member of it, or through a temporary that is
          val readWhole = scope.flatMap(_.ast.isIdentifier.nameExact(p.name).l).exists { id =>
              id.astParent match
                case c: Call if c.name == Operators.fieldAccess =>
                    !c.argumentOption(1).exists(_.id() == id.id())
                case c: Call if c.name == Operators.assignment =>
                    !c.argumentOption(1).exists(_.code.startsWith("_tmp_"))
                case _ => true
          }
          if readWhole then ctx.tagger.tag(Iterator(p), INPUT)
          else
            ctx.tagger.tag(
              readChains(memberReads.filterNot(fa =>
                  fieldName(fa).exists(n => NonRequestMembers.contains(n) || n == "event")
              )),
              INPUT
            )
        }
    }
  end tagEntrypoints

  /** A component's props are a source where nothing in the code feeds them: not for a component an
    * element renders (its parents' values are bridged to it, ComponentCallBridge) nor for a route
    * component (its data is bridged from `load`, [[bridgeRouteProps]]).
    */
  private def tagComponentProps(ctx: JsContext): Unit =
    val fed = ctx.elements.renderedFiles
    val componentMethods = ctx.cpg.file.name(Component).method.internal.l
        .filterNot(m => fed.contains(m.filename) || m.filename.matches(RouteComponent))
    if componentMethods.isEmpty then return
    // Svelte 5: props arrive from `$props()`; taint flows from it into each destructured prop
    ctx.tagger.tag(componentMethods.iterator.flatMap(_.call.nameExact("$props")), INPUT)
    // Svelte 4: `export let data` lowers to `exports.data = data`; the parent assigns the binding,
    // so there is no producing call, and the prop's reads are tagged instead. Keyed on the exported
    // name: the right-hand identifier carries no REF edge to the local.
    val exported = exportedProps(componentMethods)
    if exported.nonEmpty then
      ctx.tagger.tag(
        componentMethods.iterator.flatMap(_.local)
            .filter(l => exported.contains(l.name))
            .flatMap(_.referencingIdentifiers),
        INPUT
      )

  /** The props a Svelte 4 component declares with `export let`, lowered to `exports.x = x`. */
  def exportedProps(componentMethods: List[Method]): Set[String] =
      componentMethods.iterator.flatMap(_.call.nameExact(Operators.assignment))
          .flatMap(_.argumentOption(1))
          .map(_.code)
          .filter(_.startsWith("exports."))
          .map(_.stripPrefix("exports."))
          .toSet

  /** `page.url.searchParams` (`page` from `$app/state`) and `$page.url...` (the `$app/stores`
    * store, auto-subscribed with `$` in a component).
    */
  private def tagPage(ctx: JsContext): Unit =
    val pageReads = ctx.fieldAccesses.filterNot(isAssignmentTarget).filter { fa =>
        fieldName(fa).exists(PageFields.contains) && fieldBase(fa).exists {
            case id: Identifier =>
                id.name == "$page" ||
                (id.name == "page" || ctx.modules.localNamesOf(id.method.filename, "$app", "page")
                    .contains(id.name)) &&
                ctx.modules.importsOf(id.method.filename).exists(i =>
                    i.module == "$app/state" || i.module == "$app/stores"
                )
            case _ => false
        }
    }
    ctx.tagger.tag(readChains(pageReads), INPUT)

  /** `use:tooltip={value}`: the action `tooltip(node, value)` receives the bound value. Where a
    * template binds an action to a value a source reaches, the action's parameter is that source's
    * kind, with where the value came from. The action is the function the name is bound to: by
    * import, else the one project function of that name. Runs with the bridges.
    */
  def bridgeActions(ctx: JsContext): Unit =
    if !applies(ctx) then return
    val uses = ctx.cpg.templateDom.nameExact("JSXAttribute").code("use:.*").l
    if uses.isEmpty then return
    lazy val byName = ctx.cpg.method.internal.l.groupBy(_.name)
    uses.foreach { attr =>
      val name =
          attr.code.stripPrefix("use:").takeWhile(c => c.isLetterOrDigit || c == '_' || c == '$')
      val file       = attr.file.name.headOption.getOrElse("")
      val candidates = byName.getOrElse(name, Nil)
      // a relative import names the file; an alias (`$lib/actions/tooltip`) or none, the name
      val action = ctx.modules.resolve(file, name) match
        case Some(imp) if imp.module.startsWith(".") =>
            val base = JsModules.resolveRelative(file, imp.module)
            candidates.filter(_.filename.startsWith(base))
        case _ => if candidates.size == 1 then candidates else Nil
      if action.nonEmpty then
        attr.ast.isCall.filterNot(_.astParent.isInstanceOf[Call]).l.iterator
            .flatMap(v => MemberTaintBridge.sourceOf(ctx, v).map(_ -> v)).nextOption()
            .foreach { (found, value) =>
                ctx.tagger.tagVia(
                  action.flatMap(m => params(m).lift(1)),
                  found.tag,
                  found.places(value)*
                )
            }
    }
  end bridgeActions

  private def tagNavigation(ctx: JsContext): Unit =
    def unanchored(e: Expression): Boolean = !isObjectLiteral(e) && !hasFixedOrigin(e)
    // redirect(303, location) from @sveltejs/kit
    val redirects = ctx.modules.namedImportCalls(Seq("@sveltejs/kit"), Set("redirect")).filter(c =>
        c.argument.filter(_.argumentIndex == 2).exists(unanchored)
    )
    ctx.tagger.tag(redirects, NavigationSink*)
    // goto(url) from $app/navigation
    val gotos = ctx.modules.namedImportCalls(Seq("$app"), Set("goto")).filter(c =>
        ctx.modules.resolve(c.method.filename, c.name).exists(_.module == "$app/navigation") &&
            c.argument.filter(_.argumentIndex == 1).exists(unanchored)
    )
    ctx.tagger.tag(gotos, NavigationSink*)
end SvelteRecognizer
