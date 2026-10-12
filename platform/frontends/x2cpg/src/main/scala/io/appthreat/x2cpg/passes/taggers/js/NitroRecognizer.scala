package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Nitro and h3, the server of Nuxt (https://nitro.build, https://h3.dev).
  *
  * Handlers are files under `server/api`, `server/routes` and `server/middleware` that export
  * `defineEventHandler(event => ...)`, and everything they use is AUTO-imported - `getQuery`,
  * `readBody`, `sendRedirect`, `useStorage`, `useDatabase` appear with no import statement. So the
  * project is recognised by its manifest (`nuxt`, `nitropack`, `h3` dependencies) or its
  * `nuxt.config`, and the h3 utilities by name in the server files.
  *
  * Sources: the handler's `event`, and the h3 request readers (`getQuery`, `readBody`,
  * `getRouterParam`, `getCookie`, `getHeader`, `getRequestURL`, ...). A Nitro task's `run({ payload
  * })` receives whatever `runTask` was given, and the dev task endpoint takes it from the request.
  *
  * Sinks: `sendRedirect`, `send`/`sendStream` and a handler returning a string built with markup
  * (h3 sends a string as `text/html`), `proxyRequest`/`sendProxy`, server-side `$fetch` (request
  * forgery), and `useStorage()` keys (`:`-separated paths across every mount).
  */
object NitroRecognizer extends JsFrameworkRecognizer:

  val name: String = "nitro"

  private[js] val ServerFileRegex =
      "(?:.*[/\\\\])?server[/\\\\](api|routes|middleware|plugins|tasks|utils)[/\\\\].*\\.(js|ts|mjs|mts|cjs)"

  def isNitroProject(ctx: JsContext): Boolean =
      ctx.modules.uses("nuxt", "h3", "nitropack", "nitro", "#imports") ||
          ctx.project.dependsOn("nuxt", "nitropack", "h3", "nitro", "nitro-nightly") ||
          ctx.project.hasFile("(?:.*[/\\\\])?nuxt\\.config\\.(ts|js|mjs)")

  def applies(ctx: JsContext): Boolean =
      isNitroProject(ctx) || ctx.cpg.file.name(ServerFileRegex).nonEmpty

  private val HandlerFactories = Set(
    "defineEventHandler",
    "eventHandler",
    "defineCachedEventHandler",
    "cachedEventHandler",
    "defineLazyEventHandler",
    "defineRouteHandler",
    "defineWebSocketHandler",
    "defineNitroPlugin"
  )

  /** h3 utilities that return request data. */
  private val Readers = Set(
    "getQuery",
    "getValidatedQuery",
    "getRouterParam",
    "getRouterParams",
    "getValidatedRouterParams",
    "readBody",
    "readRawBody",
    "readValidatedBody",
    "readFormData",
    "readMultipartFormData",
    "getCookie",
    "parseCookies",
    "getHeader",
    "getHeaders",
    "getRequestHeader",
    "getRequestHeaders",
    "getRequestURL",
    "getRequestHost",
    "getRequestPath",
    "getRequestIP",
    "toWebRequest",
    "getRequestWebStream",
    "useQuery"
  )

  def run(ctx: JsContext): Unit =
    val serverFiles = ctx.cpg.file.name(ServerFileRegex).name.toSet
    def inServer(c: CfgNode): Boolean =
        serverFiles.contains(c.method.filename) ||
            ctx.modules.importsOf(c.method.filename).exists(_.packageName.contains("h3"))

    // Handlers registered by wrapping: defineEventHandler(async (event) => ...)
    val handlers = ctx.cpg.call.nameExact(HandlerFactories.toSeq*).l.flatMap { call =>
        call.argument.filter(_.argumentIndex >= 1).l.flatMap(a => callbacksIn(a, Set("handler")))
    }.distinctBy(_.id())
    handlers.foreach { h =>
      ctx.tagger.tag(Iterator(h), ROUTE)
      ctx.tagger.tag(firstParam(h).iterator, INPUT)
    }
    // Handlers exported directly from a server/api or server/routes file. Only handler-shaped
    // exports: one taking an event, or the anonymous default export - so that a plain Node server
    // laid out the same way does not have every helper tagged.
    val routeFileHandlers = ctx.cpg.file.name(ServerFileRegex).method.internal
        .filter(m => m.filename.matches("(?:.*[/\\\\])?server[/\\\\](api|routes)[/\\\\].*"))
        .filterNot(m => m.name.contains("<") || m.name == ":program")
        .filter(m => params(m).nonEmpty || m.name.startsWith("anonymous"))
        .filterNot(m => handlers.exists(_.id() == m.id()))
        .l
    // Nested callbacks of a handler are not handlers.
    val topLevel = routeFileHandlers.filterNot(m =>
        routeFileHandlers.exists(o => o.id() != m.id() && m.fullName.startsWith(o.fullName + ":"))
    )
    ctx.tagger.tag(topLevel.iterator, ROUTE)
    ctx.tagger.tag(topLevel.iterator.flatMap(params), INPUT)

    val readers = ctx.cpg.call.nameExact(Readers.toSeq*).filter(inServer)
    ctx.tagger.tag(readers, INPUT)

    // Nitro tasks: defineTask({ run({ payload }) { ... } })
    val tasks = ctx.cpg.call.nameExact("defineTask").l
        .flatMap(_.argument.filter(_.argumentIndex == 1).l)
        .flatMap(callbacksIn(_, Set("run")))
    ctx.tagger.tag(tasks.flatMap(firstParam).iterator, INPUT)

    tagSinks(ctx, handlers ++ topLevel, inServer)
  end run

  private def argumentAt(c: Call, index: Int): Option[Expression] =
      c.argument.filter(_.argumentIndex == index).headOption

  private def tagSinks(ctx: JsContext, handlers: List[Method], inServer: CfgNode => Boolean): Unit =
    val redirects = ctx.cpg.call.nameExact("sendRedirect").filter(inServer)
        .filter(c => argumentAt(c, 2).exists(!_.isInstanceOf[Literal]))
    ctx.tagger.tag(redirects, NavigationSink*)

    val sends = ctx.cpg.call.nameExact("send", "sendStream").filter(inServer)
        .filter(c => argumentAt(c, 1).exists(_.code.matches("(?s)^(event|e|evt)$")))
    ctx.tagger.tag(sends, HtmlSink*)

    val proxies = ctx.cpg.call.nameExact("proxyRequest", "sendProxy").filter(inServer)
        .flatMap(c => argumentAt(c, 2).toList.flatMap(requestSinksFor(c, _)))
    ctx.tagger.tag(proxies, (RequestSink :+ SSRF)*)

    // useStorage().getItem(key): keys are `:`-separated paths across every mount
    val storage = ctx.cpg.call
        .nameExact(
          "getItem",
          "getItemRaw",
          "setItem",
          "setItemRaw",
          "removeItem",
          "hasItem",
          "getMeta"
        )
        .filter(c =>
            receiverOf(c).exists(r =>
                JsValues.origin(r) match
                  case s: Call => s.name == "useStorage"
                  case _       => false
            ) && argumentAt(c, 1).exists(!_.isInstanceOf[Literal])
        )
    ctx.tagger.tag(storage, "file-io")

    // A string returned by a handler is sent as text/html: markup built from data is reflected.
    val markupReturns = handlers.iterator.flatMap(_.ast.isReturn).filter { ret =>
        ret.astChildren.collectAll[Call].exists(c =>
            (c.name == Operators.formatString || c.name == Operators.addition) &&
                c.ast.isLiteral.exists(_.code.contains("<"))
        )
    }
    ctx.tagger.tag(markupReturns, HtmlSink*)
  end tagSinks
end NitroRecognizer
