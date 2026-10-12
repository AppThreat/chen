package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Astro (https://docs.astro.build). Components (`.astro`, which astgen lowers to the frontmatter's
  * statements plus the template as JSX) read the request through the `Astro` global - `Astro.url`,
  * `Astro.params`, `Astro.request`, `Astro.cookies`, `Astro.locals` - and their parent's
  * `Astro.props`; `set:html={x}` is a markup sink (DomRecognizer's template attributes). The server
  * code is API endpoints (`.ts` files under `src/pages` exporting `GET`/`POST`/... or `ALL`),
  * middleware (`onRequest`, `defineMiddleware`) and actions (`defineAction({ handler })`). Each
  * receives the request context (`{ params, url, request, cookies, locals }`) or, for an action,
  * the client's input. `context.redirect(url)` and `Astro.redirect(url)` are redirects;
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
      Set(
        "url",
        "params",
        "request",
        "cookies",
        "locals",
        "props",
        "clientAddress",
        "originPathname"
      )

  private val EndpointFile = "(?:.*[/\\\\])?src[/\\\\]pages[/\\\\].*\\.(js|ts|mjs|mts)$"
  private val Middleware   = "(?:.*[/\\\\])?src[/\\\\]middleware(\\.|[/\\\\]).*(js|ts|mjs|mts)$"
  private val Verbs        = Set("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ALL")

  def run(ctx: JsContext): Unit =
    // `Astro.url.searchParams.get('q')`, `Astro.params.slug`, `Astro.cookies.get('motd')`
    val globalReads = ctx.fieldAccesses.filterNot(isAssignmentTarget).filter(fa =>
        fieldName(fa).exists(AstroGlobalReads.contains) &&
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
  end run
end AstroRecognizer
