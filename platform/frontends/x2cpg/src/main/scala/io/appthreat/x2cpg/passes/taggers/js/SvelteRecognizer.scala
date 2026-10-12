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
  * parameter.
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
    tagActions(ctx)
    tagNavigation(ctx)
    linkLoadToData(ctx)
    tagTransformedChunks(ctx)

  /** A route component's `data` prop is what the sibling `load` (`+page.server.ts`, or the
    * universal `+page.ts`) returned. The hook `$props()` is resolved to that load function, so the
    * engine carries the loader's return value - and the taint inside it - into `data.<field>`
    * reads.
    */
  private def linkLoadToData(ctx: JsContext): Unit =
    val loads = ctx.cpg.file.name(DataFile).method.internal.nameExact("load").l
    if loads.isEmpty then return
    ctx.cpg.file.name(Component).foreach { file =>
      val name = file.name
      val dir  = name.substring(0, name.lastIndexOf('/') + 1)
      val stem = if name.contains("+page.") then "+page."
      else if name.contains("+layout.")
      then "+layout."
      else ""
      val loader =
          loads.find(m => m.filename.startsWith(dir) && m.filename.contains(s"$stem.server."))
              .orElse(loads.find(m => m.filename.startsWith(dir) && m.filename.contains(stem)))
      loader.foreach { loader =>
          ctx.cpg.file.nameExact(name).method.internal
              .flatMap(_.call.nameExact("$props"))
              .foreach(props => ctx.tagger.resolveCall(props, loader))
      }
    }
  end linkLoadToData

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

  /** Handlers by file convention: routes, whose parameters are the request. An endpoint's return
    * value is the response; a `data` function's goes to the page and is no sink.
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
    ctx.tagger.tag(handlers.iterator.flatMap(params), INPUT)

  private def tagComponentProps(ctx: JsContext): Unit =
    val componentMethods = ctx.cpg.file.name(Component).method.internal.l
    if componentMethods.isEmpty then return
    // Svelte 5: props arrive from `$props()`; taint flows from it into each destructured prop
    ctx.tagger.tag(componentMethods.iterator.flatMap(_.call.nameExact("$props")), INPUT)
    // Svelte 4: `export let data` lowers to `exports.data = data`; the parent assigns the binding,
    // so there is no producing call, and the prop's reads are tagged instead. Keyed on the exported
    // name: the right-hand identifier carries no REF edge to the local.
    val exported = componentMethods.iterator.flatMap(_.call.nameExact(Operators.assignment))
        .flatMap(_.argumentOption(1))
        .map(_.code)
        .filter(_.startsWith("exports."))
        .map(_.stripPrefix("exports."))
        .toSet
    if exported.nonEmpty then
      ctx.tagger.tag(
        componentMethods.iterator.flatMap(_.local)
            .filter(l => exported.contains(l.name))
            .flatMap(_.referencingIdentifiers),
        INPUT
      )
  end tagComponentProps

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

  /** `use:tooltip={value}`: the action `tooltip(node, value)` receives the bound value. */
  private def tagActions(ctx: JsContext): Unit =
    val actionNames = ctx.cpg.templateDom.nameExact("JSXAttribute").code("use:.*").l
        .map(_.code.stripPrefix("use:").takeWhile(c => c.isLetterOrDigit || c == '_' || c == '$'))
        .toSet
    if actionNames.isEmpty then return
    val actions = ctx.cpg.method.internal.nameExact(actionNames.toSeq*)
    ctx.tagger.tag(actions.flatMap(m => params(m).lift(1)), INPUT)

  private def tagNavigation(ctx: JsContext): Unit =
    def unanchored(e: Expression): Boolean = !isObjectLiteral(e) && !hasFixedOrigin(e)
    // redirect(303, location) from @sveltejs/kit
    val redirects = ctx.cpg.call.nameExact("redirect").filter(c =>
        ctx.modules.localNamesOf(c.method.filename, "@sveltejs/kit", "redirect").contains(c.name) &&
            c.argument.filter(_.argumentIndex == 2).exists(unanchored)
    )
    ctx.tagger.tag(redirects, NavigationSink*)
    // goto(url) from $app/navigation
    val gotos = ctx.cpg.call.nameExact("goto").filter(c =>
        ctx.modules.importsOf(c.method.filename).exists(i =>
            i.module == "$app/navigation" && i.local == c.name
        ) && c.argument.filter(_.argumentIndex == 1).exists(unanchored)
    )
    ctx.tagger.tag(gotos, NavigationSink*)
end SvelteRecognizer
