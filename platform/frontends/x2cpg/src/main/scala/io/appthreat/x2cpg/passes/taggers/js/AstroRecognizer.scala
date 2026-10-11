package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Astro's server code (https://docs.astro.build): API endpoints (`.ts` files under `src/pages` exporting
  * `GET`/`POST`/... or `ALL`), middleware (`onRequest`, `defineMiddleware`) and actions
  * (`defineAction({ handler })`). Each receives the request context (`{ params, url, request,
  * cookies, locals }`) or, for an action, the client's input. `context.redirect(url)` and
  * `Astro.redirect(url)` are redirects; `context.rewrite(url)` fetches another URL.
  */
object AstroRecognizer extends JsFrameworkRecognizer:

  val name: String = "astro"

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("astro", "@astrojs") || ctx.project.dependsOn("astro")

  private val EndpointFile = "(?:.*[/\\\\])?src[/\\\\]pages[/\\\\].*\\.(js|ts|mjs|mts)$"
  private val Middleware   = "(?:.*[/\\\\])?src[/\\\\]middleware(\\.|[/\\\\]).*(js|ts|mjs|mts)$"
  private val Verbs        = Set("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ALL")

  def run(ctx: JsContext): Unit =
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
