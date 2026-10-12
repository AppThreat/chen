package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** React and the frameworks that share its component model: React Router / Remix, Next.js, TanStack
  * Router, Preact, SolidJS / SolidStart and Qwik City.
  *
  * Sources:
  *   - component props: a capitalised function that renders JSX receives its props as its first
  *     parameter - the only input boundary a function component has;
  *   - router hooks: `useParams`, `useSearchParams`, `useLocation`, `useLoaderData`,
  *     `useActionData`, `useFetcher`, Next's `useSearchParams`/`useParams`/`usePathname` and the
  *     pages router's `useRouter().query`, TanStack's `Route.useParams()`/`useSearch()`, Solid's,
  *     Preact's and Qwik's equivalents;
  *   - server entry points: route `loader`/`action`/`clientLoader`/`clientAction` (React Router,
  *     Remix, TanStack `loader`/`beforeLoad`), Next.js route handlers, pages API handlers,
  *     `middleware`/`proxy`, `getServerSideProps`, page `params`/`searchParams` props, every
  *     parameter of a `'use server'` function (Next.js, SolidStart), Qwik's `routeLoader$`,
  *     `routeAction$` and `server$`;
  *   - `cookies()` and `headers()` from `next/headers`.
  *
  * Sinks: `redirect()`/`permanentRedirect()`/`NextResponse.redirect()`, `NextResponse.rewrite()`
  * (request forgery), `navigate(target)` / `router.push(target)` / `<Navigate to>` with a target
  * the code does not anchor. `dangerouslySetInnerHTML` and URL attributes are template sinks.
  */
object ReactRecognizer extends JsFrameworkRecognizer:

  val name: String = "react"

  private val ReactLike = Seq(
    "react",
    "react-dom",
    "react-router",
    "react-router-dom",
    "@remix-run",
    "@react-router",
    "next",
    "@tanstack/react-router",
    "@tanstack/solid-router",
    "@tanstack/react-start",
    "@tanstack/solid-start",
    "preact",
    "preact-iso",
    "preact-router",
    "solid-js",
    "@solidjs/router",
    "@solidjs/start",
    "@builder.io/qwik",
    "@builder.io/qwik-city",
    "@qwik.dev/core",
    "@qwik.dev/router"
  )

  private val NextRouteFile = "(?:.*[/\\\\])?app([/\\\\].+)?[/\\\\]route\\.(js|jsx|ts|tsx|mjs|mts)$"
  private val NextMiddlewareFile =
      "(?:.*[/\\\\])?(src[/\\\\])?(middleware|proxy)\\.(js|ts|mjs|mts)$"
  private val NextApiFile = "(?:.*[/\\\\])?pages[/\\\\]api[/\\\\].*\\.(js|jsx|ts|tsx|mjs|mts)$"

  /** Next.js file conventions (a `route.ts` under `app`, files under `pages/api`) are evidence on
    * their own.
    */
  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses(ReactLike*) || ctx.project.dependsOn(ReactLike*) ||
          ctx.project.hasFile(s"$NextRouteFile|$NextApiFile|$NextMiddlewareFile") ||
          ctx.cpg.method.nameExact(NextEntrypoints.toSeq*).nonEmpty ||
          // a `'use server'` directive declares React server functions by itself
          ctx.cpg.literal.codeExact("\"use server\"").nonEmpty

  /** Hooks whose result is URL or route data. */
  private val RouteHooks = Set(
    "useParams",
    "useSearchParams",
    "useLocation",
    "useLoaderData",
    "useActionData",
    "useRouteLoaderData",
    "useFetcher",
    "useFetchers",
    "useMatches",
    "useAsyncValue",
    "usePathname",
    "useSelectedLayoutSegment",
    "useSelectedLayoutSegments",
    "useSearch",
    "useLoaderDeps",
    "useMatch",
    "useRoute",
    "useParam"
  )

  /** Route module exports and route-object keys whose function receives the request. */
  private val DataFunctions =
      Set("loader", "action", "clientLoader", "clientAction", "beforeLoad", "loaderDeps")

  private val NextEntrypoints =
      Set("getServerSideProps", "getStaticProps", "generateMetadata", "generateStaticParams")

  private val HttpVerbs = Set("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")

  def run(ctx: JsContext): Unit =
    tagComponentProps(ctx)
    tagHooks(ctx)
    tagDataFunctions(ctx)
    tagNext(ctx)
    tagServerFunctions(ctx)
    tagFormActions(ctx)
    tagQwik(ctx)
    tagRouteElements(ctx)
    tagNavigation(ctx)
    ValidationBridge.tagTanStackValidatedSearch(ctx)

  private def tagHandler(ctx: JsContext, handler: Method): Unit =
    ctx.tagger.tag(Iterator(handler), ROUTE)
    ctx.tagger.tag(firstParam(handler).iterator, INPUT)

  /** A capitalised function that renders a template is a component by the framework's own naming
    * rule; its first parameter is its props. Deliberately wide - presentational leaves included -
    * because props are the only input boundary a function component has.
    */
  private def tagComponentProps(ctx: JsContext): Unit =
    val components = ctx.cpg.method.internal
        .filter(m => m.name.nonEmpty && m.name.charAt(0).isUpper)
        .filter(_.ast.isTemplateDom.nonEmpty)
    ctx.tagger.tag(components.flatMap(firstParam), INPUT)

  private def tagHooks(ctx: JsContext): Unit =
    // `useParams()`, and TanStack's `Route.useParams()` / `useParams({ from })`
    val hooks = ctx.cpg.call.filter(c => RouteHooks.contains(callName(c)))
    ctx.tagger.tag(hooks, INPUT)
    // `useRouter().query` / `.asPath` (Next.js pages router); `.push` is a sink
    val routerReads = ctx.fieldAccesses.filter { fa =>
        fieldName(fa).exists(f => f == "query" || f == "asPath") &&
        fieldBase(fa).exists(b =>
            JsValues.origin(b) match
              case c: Call => c.name == "useRouter"
              case _       => false
        )
    }
    ctx.tagger.tag(readChains(routerReads), INPUT)
    // `location.state`: history state the previous page chose; `useLocation()` is the hook. The
    // read must be tagged itself - the engine stops at the hook call otherwise.
    val locationStateReads = ctx.fieldAccesses.filter { fa =>
        fieldName(fa).contains("state") && fieldBase(fa).exists(b =>
            JsValues.origin(b) match
              case c: Call => c.name == "useLocation"
              case _       => false
        )
    }
    ctx.tagger.tag(readChains(locationStateReads), INPUT)
    linkDataHooks(ctx)
  end tagHooks

  /** `useLoaderData()` returns what the route module's `loader` returned, `useActionData()` what
    * its `action` returned. The link is framework magic - no call site exists - so the consumer
    * hook is resolved to the producing data function and the dataflow engine carries the loader's
    * return value (and the taint inside it) out to the hook's result. The producer is the one the
    * hook's own type argument names (`useLoaderData<typeof articleLoader>()`), else the file's
    * single data function.
    */
  private def linkDataHooks(ctx: JsContext): Unit =
    val producers = dataFunctionMethods(ctx)
    if producers.isEmpty then return
    ctx.cpg.call
        .filter(c => callName(c) == "useLoaderData" || callName(c) == "useActionData")
        .foreach { hook =>
          val file = hook.method.filename
          val byTypeArg = "typeof\\s+([A-Za-z_$][\\w$]*)".r.findFirstMatchIn(hook.code)
              .flatMap(m =>
                  ctx.cpg.method.internal.nameExact(m.group(1)).filenameExact(file).headOption
              )
          val wanted =
              if callName(hook) == "useLoaderData" then Seq("loader", "clientLoader")
              else Seq("action", "clientAction")
          val producer = byTypeArg.orElse {
              val inFile = producers.filter(p => p.filename == file)
              inFile.filter(p => wanted.contains(p.name)) match
                case single :: Nil => Some(single)
                case _ => inFile match
                      case single :: Nil => Some(single)
                      case _             => None
          }
          producer.foreach(p => ctx.tagger.resolveCall(hook, p))
        }
  end linkDataHooks

  /** The methods that produce route data: exported `loader`/`action`/... functions of route
    * modules, and the callbacks a route object's `loader:`/`action:` keys name anywhere.
    */
  private def dataFunctionMethods(ctx: JsContext): List[Method] =
    val routerFiles = ctx.modules.filesImporting(
      "react-router",
      "react-router-dom",
      "@remix-run",
      "@react-router",
      "@tanstack/react-router",
      "@tanstack/solid-router",
      "@tanstack/react-start",
      "@solidjs/router"
    )
    val exported = ctx.cpg.method.internal.nameExact(DataFunctions.toSeq*)
        .filter(m =>
            routerFiles.contains(m.filename) || m.filename.matches("(?:.*[/\\\\])?routes?[/\\\\].*")
        ).l
    val keyed = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a =>
            a.argumentOption(1).exists {
                case fa: Call => fieldName(fa).exists(DataFunctions.contains)
                case _        => false
            } && routerFiles.contains(a.method.filename)
        )
        .flatMap(_.argumentOption(2)).l
        .flatMap(callbacksIn(_))
    (exported ++ keyed).distinctBy(_.id())
  end dataFunctionMethods

  /** `export async function loader({ params, request })` in a route module, `loader: fn` on a route
    * object or in TanStack's `createFileRoute(...)({ loader })`.
    */
  private def tagDataFunctions(ctx: JsContext): Unit =
      dataFunctionMethods(ctx).foreach(tagHandler(ctx, _))

  private def tagNext(ctx: JsContext): Unit =
    val usesNext = ctx.modules.uses("next") || ctx.project.dependsOn("next")
    // app-router route handlers: one export per HTTP verb in `route.ts`
    val routeHandlers = ctx.cpg.file.name(NextRouteFile).method.internal
        .filter(m => HttpVerbs.contains(m.name) || m.name.startsWith("anonymous"))
    routeHandlers.foreach { h =>
      ctx.tagger.tag(Iterator(h), ROUTE)
      ctx.tagger.tag(params(h).iterator, INPUT)
    }
    // pages/api: every export is a handler of `(req, res)` - the response is no input
    val apiHandlers = ctx.cpg.file.name(NextApiFile).method.internal
        .filterNot(m => m.name.contains("<") || m.name == ":program")
        .filter(m => params(m).nonEmpty)
    apiHandlers.foreach { h =>
      ctx.tagger.tag(Iterator(h), ROUTE)
      ctx.tagger.tag(firstParam(h).iterator, INPUT)
    }
    // page-data loaders, middleware (`proxy` from Next 16) - named for Next.js, but not tied to an
    // import: the loaders are found by name in any React project, as they always were
    // `params`/`searchParams` pages, `cookies()` and `headers()` below need Next itself.
    ctx.cpg.method.internal.nameExact(NextEntrypoints.toSeq*).foreach(tagHandler(ctx, _))
    ctx.cpg.method.internal.nameExact("middleware", "proxy")
        .filter(_.filename.matches(NextMiddlewareFile))
        .foreach(tagHandler(ctx, _))
    if !usesNext then return
    // app-router pages and layouts: `params` and `searchParams` props
    val pages = ctx.cpg.file
        .name(
          "(?:.*[/\\\\])?app([/\\\\].+)?[/\\\\](page|layout|default|template)\\.(js|jsx|ts|tsx)$"
        )
        .method.internal
        .filter(m =>
            m.name.nonEmpty && (m.name.charAt(0).isUpper || m.name.startsWith("anonymous"))
        )
    ctx.tagger.tag(pages.flatMap(firstParam), INPUT)
    // cookies(), headers() and draftMode() read the incoming request
    val requestReaders = ctx.cpg.call.nameExact("cookies", "headers").filter(c =>
        ctx.modules.localNamesOf(c.method.filename, "next", c.name).contains(c.name)
    )
    ctx.tagger.tag(requestReaders, INPUT)
  end tagNext

  /** `'use server'` - every parameter of a server function is a value a client can POST. A module
    * with the directive at its top makes every export a server function; a function body opening
    * with it makes that one.
    */
  private def tagServerFunctions(ctx: JsContext): Unit =
    // The directive is the first statement; the block lists the function's locals before it.
    def opensWithDirective(m: Method): Boolean =
        m.block.astChildren.filterNot(_.isInstanceOf[Local]).headOption.exists {
            case l: Literal => l.code.matches("""^['"]use server['"]$""")
            case _          => false
        }
    val moduleLevel = ctx.cpg.method.nameExact(":program").filter(opensWithDirective).l
    val serverFns = (moduleLevel.flatMap(p =>
        ctx.cpg.file.nameExact(p.filename).method.internal
            .filterNot(m => m.name.contains("<") || m.name == ":program")
            // the exported functions of the module, not callbacks nested in them
            .filter(m => !m.fullName.drop(p.fullName.length + 1).contains(":"))
            .l
    ) ++ ctx.cpg.method.internal.filter(opensWithDirective).filterNot(_.name == ":program").l)
        .distinctBy(_.id())
    serverFns.foreach { f =>
      ctx.tagger.tag(Iterator(f), ROUTE)
      ctx.tagger.tag(params(f).iterator, INPUT)
    }
    // SolidStart: action(async (formData) => ...), query(async (id) => ..., 'key')
    val solidFns = ctx.cpg.call.nameExact("action", "query", "createServerFn")
        .filter(c =>
            ctx.modules.importsOf(c.method.filename).exists(i =>
                i.packageName.exists(p => p == "@solidjs/router" || p.startsWith("@tanstack/"))
            )
        )
        .l.flatMap(_.argument.filter(_.argumentIndex == 1).l.flatMap(callbacksIn(_)))
    ctx.tagger.tag(solidFns.flatMap(params).iterator, INPUT)
  end tagServerFunctions

  /** React 19 form actions: `useActionState(fn, initial)` and `<form action={fn}>` call `fn` with
    * the submitted form (`fn(previousState, formData)` for the hook, `fn(formData)` for the form).
    */
  private def tagFormActions(ctx: JsContext): Unit =
    val viaHook = ctx.cpg.call.nameExact("useActionState", "useFormState").l
        .flatMap(_.argument.filter(_.argumentIndex == 1).l.flatMap(callbacksIn(_)))
    val viaForm = ctx.cpg.templateDom.nameExact("JSXAttribute")
        .filter(a => a.code.startsWith("action=") || a.code.startsWith("formAction="))
        .flatMap(_.ast.isIdentifier).l
        .flatMap(callbackMethod)
    ctx.tagger.tag((viaHook ++ viaForm).flatMap(params).iterator, INPUT)

  /** Qwik City: routeLoader$((requestEvent) => ...), routeAction$((data, requestEvent) => ...),
    * server$((...args) => ...).
    */
  private def tagQwik(ctx: JsContext): Unit =
    val fns = ctx.cpg.call.nameExact("routeLoader$", "routeAction$", "globalAction$", "server$")
        .l.flatMap(_.argument.filter(_.argumentIndex == 1).l.flatMap(callbacksIn(_)))
    ctx.tagger.tag(fns.flatMap(params).iterator, INPUT)
    // `throw redirect(302, url)` with the request event's `redirect`
    val redirects = fns.flatMap(_.ast.isCall.nameExact("redirect").l).filter(c =>
        c.argument.filter(_.argumentIndex == 2).headOption.exists(t =>
            !isObjectLiteral(t) && !hasFixedOrigin(t)
        )
    )
    ctx.tagger.tag(redirects.iterator, NavigationSink*)

  /** `<Route path="/profile" element={<Profile />} />`: the path is a route, the component it
    * renders a handler. Matched exactly on the tag name - a prefix would also take `<Routes>`.
    */
  private def tagRouteElements(ctx: JsContext): Unit =
      ctx.cpg.templateDom.nameExact("JSXOpeningElement")
          .filter(dom => jsxComponentName(dom.code).contains("Route"))
          .foreach { routeElem =>
              routeElem.ast.collectAll[TemplateDom].nameExact("JSXAttribute").foreach { attr =>
                  if attr.code.startsWith("path=") then
                    ctx.tagger.tag(attr.ast.isLiteral.headOption.iterator, ROUTE)
                  else if attr.code.startsWith("element=") || attr.code.startsWith("component=") ||
                    attr.code.startsWith("Component=")
                  then
                    val byIdentifier = attr.ast.isIdentifier.l.flatMap(resolveComponent(ctx, _))
                    val byElement = attr.ast.collectAll[TemplateDom].nameExact("JSXElement").l
                        .flatMap(e => jsxComponentName(e.code))
                        .flatMap(nm => ctx.cpg.method.internal.nameExact(nm).headOption)
                    (byIdentifier ++ byElement).foreach(tagHandler(ctx, _))
              }
          }

  private[js] def jsxComponentName(domCode: String): Option[String] =
    val name = domCode.drop(1).takeWhile(c => c != ' ' && c != '>' && c != '/' && c != '\n')
    Option.when(name.nonEmpty && name.charAt(0).isUpper)(name)

  private def resolveComponent(ctx: JsContext, id: Identifier): Option[Method] =
      callbackMethod(id).orElse(ctx.cpg.method.internal.nameExact(id.name).headOption)

  private def tagNavigation(ctx: JsContext): Unit =
    def target(c: Call): Option[Expression] = c.argument.filter(_.argumentIndex == 1).headOption
    def unanchored(e: Expression): Boolean  = !isObjectLiteral(e) && !hasFixedOrigin(e)

    // redirect(url) from react-router / next/navigation / @remix-run, permanentRedirect(url)
    val redirectPkgs =
        Seq("react-router", "react-router-dom", "@remix-run", "@react-router", "next", "@tanstack")
    val redirects = ctx.cpg.call
        .nameExact("redirect", "redirectDocument", "permanentRedirect", "replace")
        .filter(c =>
            c.receiver.headOption.flatMap(memberPath).exists(_.size == 1) &&
                redirectPkgs.exists(p =>
                    ctx.modules.localNamesOf(c.method.filename, p, c.name).contains(c.name)
                ) && target(c).exists(unanchored)
        )
    ctx.tagger.tag(redirects, NavigationSink*)

    // NextResponse.redirect(url) / Response.redirect(url); NextResponse.rewrite(url) proxies
    val responses = ctx.cpg.call.nameExact("redirect", "rewrite").filter(c =>
        receiverOf(c).flatMap(memberPath).exists(p =>
            p == List("NextResponse") || p == List("Response")
        ) && target(c).exists(unanchored)
    ).l
    ctx.tagger.tag(responses.iterator.filter(_.name == "redirect"), NavigationSink*)
    ctx.tagger.tag(responses.iterator.filter(_.name == "rewrite"), (RequestSink :+ SSRF)*)

    // navigate(target) where navigate = useNavigate(); router.push(target) with useRouter()
    val navigations = ctx.cpg.call.filter { c =>
      val viaHook = c.receiver.headOption.flatMap(memberPath).exists {
          case List(local) =>
              JsValues.origin(c.receiver.head) match
                case h: Call => h.name == "useNavigate"
                case _       => false
          case _ => false
      }
      val viaRouter = (c.name == "push" || c.name == "replace") && receiverOf(c).exists(r =>
          JsValues.origin(r) match
            case h: Call => h.name == "useRouter"
            case _       => false
      )
      (viaHook || viaRouter) && target(c).exists(unanchored)
    }
    ctx.tagger.tag(navigations, NavigationSink*)

    // <Navigate to={target} />
    val navigateTo = ctx.cpg.templateDom.nameExact("JSXOpeningElement")
        .filter(dom => jsxComponentName(dom.code).contains("Navigate"))
        .flatMap(
          _.ast.collectAll[TemplateDom].nameExact("JSXAttribute").filter(_.code.startsWith("to="))
        )
        .flatMap(_.ast.collectAll[Call])
    ctx.tagger.tag(navigateTo, NavigationSink*)
  end tagNavigation
end ReactRecognizer
