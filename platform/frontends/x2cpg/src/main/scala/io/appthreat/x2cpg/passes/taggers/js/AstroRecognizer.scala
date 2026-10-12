package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Astro (https://docs.astro.build). Components (`.astro`, which astgen lowers to the frontmatter's
  * statements plus the template as JSX) read the request through the `Astro` global - `Astro.url`,
  * `Astro.params`, `Astro.request`, `Astro.cookies` - and their parent's `Astro.props`;
  * `Astro.locals` holds what middleware put there, a source only where middleware wrote one into it
  * (see [[bridgeLocals]]); `set:html={x}` is a markup sink (DomRecognizer's template attributes).
  * The server code is API endpoints (`.ts` files under `src/pages` exporting `GET`/`POST`/... or
  * `ALL`), middleware (`onRequest`, `defineMiddleware`) and actions (`defineAction({ handler })`).
  * Each receives the request context (`{ params, url, request, cookies, locals }`) or, for an
  * action, the client's input. `context.redirect(url)` and `Astro.redirect(url)` are redirects;
  * `context.rewrite(url)` fetches another URL.
  */
object AstroRecognizer extends JsFrameworkRecognizer:

  val name: String = "astro"

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("astro", "@astrojs") || ctx.project.dependsOn("astro") ||
          ctx.project.hasFile(".*\\.astro$")

  /** What a component reads of the request through the `Astro` global, and the props its parent
    * passed (`Astro.props`).
    */
  private val AstroGlobalReads =
      Set("url", "params", "request", "cookies", "props", "clientAddress", "originPathname")

  private val EndpointFile = "(?:.*[/\\\\])?src[/\\\\]pages[/\\\\].*\\.(js|ts|mjs|mts)$"
  private val Middleware   = "(?:.*[/\\\\])?src[/\\\\]middleware(\\.|[/\\\\]).*(js|ts|mjs|mts)$"
  private val Verbs        = Set("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ALL")

  def run(ctx: JsContext): Unit =
    // `Astro.url.searchParams.get('q')`, `Astro.params.slug`, `Astro.cookies.get('motd')`; the
    // props of a component that elements render are what they pass (ComponentCallBridge)
    val fed = ctx.elements.renderedFiles
    val globalReads = ctx.fieldAccesses.filterNot(isAssignmentTarget).filter(fa =>
        fieldName(fa).exists(AstroGlobalReads.contains) &&
            !(fieldName(fa).contains("props") && fed.contains(fa.method.filename)) &&
            fieldBase(fa).exists {
                case id: Identifier => id.name == "Astro"
                case _              => false
            }
    )
    ctx.tagger.tag(readChains(globalReads), INPUT)
    val endpoints = ctx.cpg.file.name(EndpointFile).method.internal
        .filter(m => Verbs.contains(m.name) || m.name.startsWith("anonymous"))
        .l
    val middleware = ctx.cpg.file.name(Middleware).method.internal
        .filter(m => m.name == "onRequest" || m.name.startsWith("anonymous"))
        .l
    val actions = ctx.cpg.call.nameExact("defineAction").l
        .flatMap(_.argument.filter(_.argumentIndex == 1).l)
        .flatMap(callbacksIn(_, Set("handler")))
    (endpoints ++ middleware ++ actions).foreach { h =>
      ctx.tagger.tag(Iterator(h), ROUTE)
      ctx.tagger.tag(params(h).iterator, INPUT)
    }

    val serverFiles = (endpoints ++ middleware).map(_.filename).toSet ++
        ctx.cpg.file.name(".*\\.astro$").name.toSet
    def unanchored(c: Call) =
        c.argument.filter(_.argumentIndex == 1).headOption.exists(t =>
            !isObjectLiteral(t) && !hasFixedOrigin(t)
        )
    val redirects = ctx.cpg.call.nameExact("redirect")
        .filter(c => serverFiles.contains(c.method.filename) && unanchored(c))
    ctx.tagger.tag(redirects, NavigationSink*)
    val rewrites = ctx.cpg.call.nameExact("rewrite")
        .filter(c => serverFiles.contains(c.method.filename) && unanchored(c))
    ctx.tagger.tag(rewrites, (RequestSink :+ SSRF)*)
    bridgeLocals(ctx, middleware.map(_.filename).toSet)
  end run

  /** Middleware fills `context.locals` for the request; pages read it back as `Astro.locals.<x>`
    * and endpoints as `context.locals.<x>`. No code path joins the write and the read, so a field
    * middleware wrote from a source makes those reads sources of the same kind, carrying where the
    * value entered.
    */
  private def bridgeLocals(ctx: JsContext, middlewareFiles: Set[String]): Unit =
    def localsField(fa: Call): Option[String] =
        memberPath(fa).collect { case _ :: "locals" :: field :: Nil => field }
    val writes =
        ctx.cpg.call.nameExact(io.shiftleft.codepropertygraph.generated.Operators.assignment)
            .filter(w => middlewareFiles.contains(w.method.filename)).l
            .flatMap { w =>
                (w.argumentOption(1), assignedValue(w)) match
                  case (Some(fa: Call), Some(v)) => localsField(fa).map(_ -> v)
                  case _                         => None
            }
    if writes.isEmpty then return
    val reads = ctx.fieldAccesses.filterNot(isAssignmentTarget)
        .filterNot(fa => middlewareFiles.contains(fa.method.filename)).l
        .flatMap(fa => localsField(fa).map(_ -> fa))
    writes.foreach { (field, value) =>
        MemberTaintBridge.sourceOf(ctx, value).foreach { found =>
            ctx.tagger.tagVia(
              readChains(reads.collect { case (`field`, fa) => fa }),
              found.tag,
              found.places(value)*
            )
        }
    }
  end bridgeLocals
end AstroRecognizer
