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
    tagTanStackStart(ctx)
    tagSolidStartApiRoutes(ctx)
    tagPageRedirects(ctx)
    tagFormActions(ctx)
    tagQwik(ctx)
    tagRouteElements(ctx)
    tagNavigation(ctx)
    ValidationBridge.tagTanStackValidatedSearch(ctx)
    linkPageProps(ctx)

  /** Next.js pages router: the page component receives what `getServerSideProps` / `getStaticProps`
    * return under `props`. Where a source reaches that object, the page's props parameter is that
    * source's kind, with where the value came from - no call site joins them.
    */
  private def linkPageProps(ctx: JsContext): Unit =
      (ctx.cpg.method.internal.nameExact("getServerSideProps", "getStaticProps").l ++
          exportedFunctions(ctx, Set("getServerSideProps", "getStaticProps")).map(_._2))
          .distinctBy(_.id()).foreach { gssp =>
            val props = gssp.ast.isCall.nameExact(Operators.assignment).l.flatMap { a =>
                (a.argumentOption(1), a.argumentOption(2)) match
                  case (Some(fa: Call), Some(v)) if fieldName(fa).contains("props") => Some(v)
                  case _                                                            => None
            }
            val page = defaultExportValue(ctx, gssp.filename).flatMap(callbackMethod)
            page.foreach { component =>
                props.iterator.flatMap(v => MemberTaintBridge.sourceOf(ctx, v).map(_ -> v))
                    .nextOption()
                    .foreach { (found, value) =>
                        ctx.tagger.tagVia(
                          firstParam(component).iterator,
                          found.tag,
                          found.places(value)*
                        )
                    }
            }
          }

  /** TanStack Start (https://tanstack.com/start).
    *
    *   - A server function, `createServerFn(...).validator(...).handler(async ({ data }) => ...)`,
    *     is an RPC endpoint: its handler's argument is what a client sends. A call of the function
    *     - `fetchPost({ data: id })`, or through `useServerFn(fetchPost)` - is the handler.
    *   - A server route's handlers, `createFileRoute(path)({ server: { handlers: { GET } } })` (and
    *     `createServerFileRoute(path).methods({ GET })`), answer a request.
    */
  private def tagTanStackStart(ctx: JsContext): Unit =
    if !ctx.modules.uses("@tanstack/react-start", "@tanstack/solid-start", "@tanstack/start")
    then return
    // the handler of each server function, by the name the function is bound to
    val serverFns = ctx.cpg.call.nameExact("handler").l.flatMap { h =>
      val chain = receiverOf(h).map(_.code).getOrElse("")
      Option.when(chain.matches("(?s)\\s*createServerFn\\b.*")) {
          h.argument.filter(_.argumentIndex == 1).headOption.flatMap(callbackMethod).map { fn =>
            // `export const fetchPost = createServerFn(...)...handler(fn)`
            val bound = h.inAssignment.argument(1).headOption.collect {
                case id: Identifier => id.name
                case fa: Call       => fieldName(fa).getOrElse("")
            }
            (bound.getOrElse(""), fn)
          }
      }.flatten
    }
    serverFns.foreach((_, fn) => tagHandler(ctx, fn))
    val byName = serverFns.filter(_._1.nonEmpty).groupMap(_._1)(_._2)
    if byName.nonEmpty then
      ctx.cpg.call.filter(c => !c.name.startsWith("<")).l.foreach { call =>
        val file = call.method.filename
        // `login(...)` after `const login = useServerFn(loginFn)`
        val wrapped = call.receiver.headOption.orElse(Option.empty).collect {
            case id: Identifier => JsValues.origin(id)
        }.collect { case c: Call if c.name == "useServerFn" => c }
            .flatMap(_.argument.filter(_.argumentIndex == 1).headOption)
            .collect { case id: Identifier => id.name }
        val name  = wrapped.getOrElse(call.name)
        val local = ctx.modules.resolve(file, name).map(_.imported).filter(_.nonEmpty)
        byName.get(local.getOrElse(name)).foreach {
            case only :: Nil
                if local.nonEmpty || wrapped.nonEmpty || only.filename == file =>
                ctx.tagger.resolveCall(call, only)
            case _ =>
        }
      }
    // server routes: `handlers: { GET: async ({ request, params }) => ... }`
    val routeHandlers = ctx.cpg.call.nameExact(Operators.assignment).filter { a =>
        a.argumentOption(1).exists {
            case fa: Call => fieldName(fa).exists(HttpVerbs.contains)
            case _        => false
        } && a.method.ast.isCall.nameExact(Operators.assignment).exists(_.argumentOption(1).exists {
            case fa: Call => fieldName(fa).exists(f => f == "handlers")
            case _        => false
        })
    }.l.flatMap(_.argumentOption(2)).flatMap(callbackMethod) ++
        ctx.cpg.call.nameExact("methods").filter(c =>
            receiverOf(c).exists(_.code.matches("(?s)\\s*createServerFileRoute\\b.*"))
        ).l.flatMap(_.argument.filter(_.argumentIndex == 1).l).flatMap(callbacksIn(_))
    routeHandlers.distinctBy(_.id()).foreach(tagHandler(ctx, _))
  end tagTanStackStart

  /** A server function's handler receives what its validator returns: a validator function whose
    * every return is a value a guard validated (`if (!SLUG.test(slug)) throw ...; return slug`)
    * hands the handler nothing to inject, and the handler's `data` reads are sanitised. Runs after
    * GuardBridge.
    */
  def tagValidatedServerFunctions(ctx: JsContext): Unit =
      ctx.cpg.call.nameExact("handler").l.foreach { h =>
        val validator = h.receiver.headOption.collect { case fa: Call => fa }.flatMap(fieldBase)
            .map(unwrap).collect {
                case v: Call if v.name == "validator" || v.name == "inputValidator" => v
            }
        for
          v <- validator
          if receiverOf(v).exists(_.code.matches("(?s)\\s*createServerFn\\b.*"))
          check   <- v.argument.filter(_.argumentIndex == 1).headOption.flatMap(callbackMethod)
          handler <- h.argument.filter(_.argumentIndex == 1).headOption.flatMap(callbackMethod)
          input   <- firstParam(handler)
          returns = DataLinkBridge.returnedValues(check)
          if returns.nonEmpty && returns.forall(r => neutralises(ctx.tagger, r))
        do
          val reads = handler.ast.isCall.nameExact(Operators.fieldAccess)
              .filter(fa =>
                  fieldBase(fa).exists(_.code == input.name) && fieldName(fa).contains("data")
              )
          ctx.tagger.tag(reads, SANITIZER)
      }

  /** TanStack Router: `loaderDeps: ({ search }) => ({ q })` reads the URL's search params, and the
    * route's `loader: ({ deps }) => ...` gets what it returns as `deps`. Runs with the bridges.
    */
  def bridgeLoaderDeps(ctx: JsContext): Unit =
      ctx.cpg.call.nameExact(Operators.assignment).l.flatMap { a =>
          a.argumentOption(1).collect { case fa: Call => fa }.flatMap(fa =>
              fieldName(fa).filter(k => k == "loaderDeps" || k == "loader")
                  .zip(fieldBase(fa).map(_.code))
          ).zip(a.argumentOption(2).flatMap(callbackMethod)).map { case ((key, obj), fn) =>
              (a.method.id(), obj, key, fn)
          }
      }.groupBy(t => (t._1, t._2)).values.foreach { keyed =>
          for
            deps   <- keyed.find(_._3 == "loaderDeps").map(_._4)
            loader <- keyed.find(_._3 == "loader").map(_._4)
            input  <- firstParam(loader)
          do
            ctx.tagger.tag(firstParam(deps).iterator, INPUT)
            val reads = loader.ast.isCall.nameExact(Operators.fieldAccess)
                .filter(fa =>
                    fieldBase(fa).exists(_.code == input.name) && fieldName(fa).contains("deps")
                )
                .l
            DataLinkBridge.sourceAt(ctx, DataLinkBridge.returnedValues(deps), Nil).foreach(
              (found, value) => ctx.tagger.tagVia(reads.iterator, found.tag, found.places(value)*)
            )
      }

  /** SolidStart API routes: a file under `src/routes` exporting `GET`/`POST`/... answers requests
    * with them, `({ request, params }: APIEvent)`.
    */
  private def tagSolidStartApiRoutes(ctx: JsContext): Unit =
    if !ctx.modules.uses("@solidjs/start") && !ctx.project.dependsOn("@solidjs/start") then return
    (ctx.cpg.method.internal.nameExact(HttpVerbs.toSeq*).l ++
        exportedFunctions(ctx, HttpVerbs).map(_._2))
        .filter(m => m.filename.matches("(?:.*[/\\\\])?src[/\\\\]routes[/\\\\].*"))
        .distinctBy(_.id()).foreach(tagHandler(ctx, _))

  /** Next.js pages router: `getServerSideProps` returning `{ redirect: { destination } }` sends the
    * browser there.
    */
  private def tagPageRedirects(ctx: JsContext): Unit =
      (ctx.cpg.method.internal.nameExact("getServerSideProps", "getStaticProps").l ++
          exportedFunctions(ctx, Set("getServerSideProps", "getStaticProps")).map(_._2))
          .distinctBy(_.id()).foreach { gssp =>
            val destinations = (gssp :: nestedMethods(gssp)).flatMap(
              _.ast.isCall.nameExact(Operators.assignment).l
            ).filter(_.argumentOption(1).exists {
                case fa: Call => fieldName(fa).contains("destination")
                case _        => false
            }).filter(inReturnedRedirect).flatMap(_.argumentOption(2)).filter {
                case _: Literal => false
                case v          => !hasFixedOrigin(v)
            }
            ctx.tagger.tag(destinations.iterator, OUTPUT, REDIRECT)
          }

  /** A write into the object a function returns under `redirect` - `return { redirect: {
    * destination } }` - not a `destination` key of some other object (`log({ destination })`).
    */
  private def inReturnedRedirect(write: Call): Boolean =
    val ancestors = Iterator.iterate[AstNode](write)(_.astParent)
        .takeWhile(n => !n.isInstanceOf[Method]).drop(1).toList
    ancestors.exists(_.isInstanceOf[Return]) &&
    ancestors.exists(_.ast.isCall.nameExact(Operators.assignment).exists(_.argumentOption(1)
        .exists {
            case fa: Call => fieldName(fa).contains("redirect")
            case _        => false
        }))

  private def tagHandler(ctx: JsContext, handler: Method): Unit =
    ctx.tagger.tag(Iterator(handler), ROUTE)
    ctx.tagger.tag(firstParam(handler).iterator, INPUT)

  /** A capitalised function that renders a template is a component by the framework's own naming
    * rule; its first parameter is its props. A component no element of the project renders - a
    * page, a component handed to a router or a library - gets its props from outside the code, so
    * they are a source. One that elements render gets them from its parents, through the resolved
    * element calls; and a route module's component gets them from its data functions, member by
    * member ([[bridgeRouteProps]]).
    */
  private def tagComponentProps(ctx: JsContext): Unit =
    val routeComponents = routeModules(ctx).map(_._2.id()).toSet
    val components = ctx.cpg.method.internal
        .filter(m => m.name.nonEmpty && m.name.charAt(0).isUpper)
        .filter(_.ast.isTemplateDom.nonEmpty)
        .filterNot(m =>
            ctx.elements.renderedFunctions.contains(m.id()) || routeComponents.contains(m.id())
        )
    ctx.tagger.tag(components.flatMap(firstParam), INPUT)

  /** Route modules (framework mode): the default-exported component of a file that exports data
    * functions, with those functions by name.
    */
  private def routeModules(ctx: JsContext): List[(String, Method, List[Method])] =
    val (exported, _) = dataFunctionsByShape(ctx)
    exported.groupBy(_.filename).toList.flatMap { (file, fns) =>
        defaultExportValue(ctx, file).flatMap(callbackMethod).map(c => (file, c, fns))
    }

  /** A route module's component receives `{ loaderData, actionData, params }`: `loaderData` is what
    * the module's `loader`/`clientLoader` returned, `actionData` what its `action`/`clientAction`
    * did. Each read below them is tagged with the source behind that member of the returned data;
    * `params` are the URL's. Runs with the bridges.
    */
  def bridgeRouteProps(ctx: JsContext): Unit =
      routeModules(ctx).foreach { (_, component, fns) =>
        val props                 = firstParam(component)
        def named(names: String*) = fns.filter(f => names.contains(f.name))
        DataLinkBridge.bridgeReads(
          ctx,
          List(component),
          (root, path) =>
              (root, path) match
                case (p: MethodParameterIn, key :: rest) if props.exists(_.id() == p.id()) =>
                    key match
                      case "loaderData" =>
                          Some(DataLinkBridge.produced(named("loader", "clientLoader"), rest))
                      case "actionData" =>
                          Some(DataLinkBridge.produced(named("action", "clientAction"), rest))
                      case "params" => Some(DataLinkBridge.Link.Source(INPUT))
                      case _        => None
                case _ => None
        )
      }

  private def tagHooks(ctx: JsContext): Unit =
    // `useParams()`, and TanStack's `Route.useParams()` / `useParams({ from })`; a data hook whose
    // producer is known carries that producer's data instead (see linkDataHooks)
    val linked = linkDataHooks(ctx)
    val hooks = ctx.cpg.call.filter(c => RouteHooks.contains(callName(c)))
        .filterNot(c => linked.contains(c.id()))
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
  end tagHooks

  /** `useLoaderData()` returns what the route module's `loader` returned, `useActionData()` what
    * its `action` returned, `useRouteLoaderData(id)` what the loader of the route `id` returned,
    * and `useFetcher()` holds what the action or loader it submitted to returned. The link is
    * framework magic - no call site exists - so the consumer hook is resolved to the producing data
    * function and the dataflow engine carries the producer's return value (and the taint inside it)
    * out to the hook's result. The producer is the one the hook's own type argument names
    * (`useLoaderData<typeof articleLoader>()`, also imported: `import type { loader as rootLoader }
    * from "../root"`), else the route the id names, else the file's single data function. Returns
    * the hooks linked.
    */
  private def linkDataHooks(ctx: JsContext): Set[Long] =
    val producers = dataFunctionMethods(ctx)
    if producers.isEmpty then return Set.empty
    val DataHooks = Set("useLoaderData", "useActionData", "useRouteLoaderData", "useFetcher")
    ctx.cpg.call
        .filter(c => DataHooks.contains(callName(c)))
        .l
        .flatMap { hook =>
          val file = hook.method.filename
          val byTypeArg = "typeof\\s+([A-Za-z_$][\\w$]*)".r.findFirstMatchIn(hook.code)
              .flatMap(m => producerNamed(ctx, file, m.group(1), producers))
          val byRouteId =
              if callName(hook) != "useRouteLoaderData" then None
              else
                hook.argument.filter(_.argumentIndex == 1).headOption.flatMap(literalValue)
                    .flatMap(id =>
                        producers.filter(p =>
                            Seq("loader", "clientLoader").contains(p.name) &&
                                p.filename.replaceAll("\\.[^./]+$", "").endsWith("/" + id)
                        ) match
                          case single :: Nil => Some(single)
                          case _             => None
                    )
          val wanted =
              if callName(hook) == "useActionData" then Seq("action", "clientAction")
              else Seq("loader", "clientLoader")
          val inFile = producers.filter(p => p.filename == file)
          val producer = byTypeArg.orElse(byRouteId).orElse(
            if callName(hook) == "useFetcher" || callName(hook) == "useRouteLoaderData" then None
            else
              inFile.filter(p => wanted.contains(p.name)) match
                case single :: Nil => Some(single)
                case _ => inFile match
                      case single :: Nil => Some(single)
                      case _             => None
          )
          producer.map { p =>
            ctx.tagger.resolveCall(hook, p)
            hook.id()
          }
        }
        .toSet
  end linkDataHooks

  /** The data function a name stands for in `file`: one of its own, or the one an import binds. */
  private def producerNamed(
    ctx: JsContext,
    file: String,
    name: String,
    producers: List[Method]
  ): Option[Method] =
      producers.find(p => p.filename == file && p.name == name).orElse(
        ctx.modules.resolve(file, name).filter(_.module.startsWith(".")).flatMap { imp =>
          val base = JsModules.resolveRelative(file, imp.module)
          producers.find(p =>
              p.name == imp.imported && (p.filename == base || p.filename.startsWith(base + "."))
          )
        }
      )

  /** The methods that produce route data: exported `loader`/`action`/... functions of route
    * modules, and the callbacks a route object's `loader:`/`action:` keys name anywhere.
    */
  private def dataFunctionMethods(ctx: JsContext): List[Method] =
    val (exported, keyed) = dataFunctionsByShape(ctx)
    (exported ++ keyed).distinctBy(_.id())

  /** Data functions a route module exports (framework mode), and those a route object's
    * `loader:`/`action:` names (data routers, TanStack).
    */
  private def dataFunctionsByShape(ctx: JsContext): (List[Method], List[Method]) =
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
    (exported, keyed)
  end dataFunctionsByShape

  /** `export async function loader({ params, request })` in a route module, `loader: fn` on a route
    * object or in TanStack's `createFileRoute(...)({ loader })`.
    */
  private def tagDataFunctions(ctx: JsContext): Unit =
    val (exported, keyed) = dataFunctionsByShape(ctx)
    // A route module that renders nothing (no default export) is a resource route: its loader
    // answers the request. Otherwise - and always for a route object's loader - the data goes to
    // the component.
    val (resources, data) =
        exported.partition(f => !hasDefaultExport(ctx, f.filename))
    resources.foreach(tagHandler(ctx, _))
    (data ++ keyed).distinctBy(_.id()).foreach { f =>
      tagHandler(ctx, f)
      ctx.tagger.tag(Iterator(f), DATA)
    }

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
    (ctx.cpg.method.internal.nameExact(NextEntrypoints.toSeq*).l ++
        exportedFunctions(ctx, NextEntrypoints).map(_._2)).distinctBy(_.id()).foreach(tagHandler(
      ctx,
      _
    ))
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
    val requestReaders = ctx.modules.namedImportCalls(Seq("next"), Set("cookies", "headers"))
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
    val wrapperNames = Set("action", "query", "createServerFn")
    val wrappers = (ctx.cpg.call.nameExact(wrapperNames.toSeq*)
        .filter(c =>
            ctx.modules.importsOf(c.method.filename).exists(i =>
                i.packageName.exists(p => p == "@solidjs/router" || p.startsWith("@tanstack/"))
            )
        ) ++ ctx.modules.namedImportCalls(Seq("@solidjs/router", "@tanstack"), wrapperNames))
        .dedup.l
    val solidFns =
        wrappers.flatMap(_.argument.filter(_.argumentIndex == 1).l.flatMap(callbacksIn(_)))
    ctx.tagger.tag(solidFns.flatMap(params).iterator, INPUT)
    linkWrappedFunctions(ctx, wrappers)
  end tagServerFunctions

  /** `const getUser = query(async (id) => ..., 'user')`: calling `getUser(id)` calls the wrapped
    * function with the same arguments. The calls - in the defining module, or where it is imported
    *   - are resolved to it, so a caller's value reaches its parameters.
    */
  private def linkWrappedFunctions(ctx: JsContext, wrappers: List[Call]): Unit =
      wrappers.foreach { w =>
          (w.astParent, w.argument.filter(_.argumentIndex == 1).l.flatMap(callbacksIn(_))) match
            case (a: Call, fn :: Nil) if a.name == Operators.assignment =>
                a.argumentOption(1).collect { case id: Identifier => id.name }.foreach { name =>
                  val defining = w.method.filename
                  JsIndexes.callsNamed(ctx.cpg.graph, name)
                      .filter { c =>
                        val file = c.method.filename
                        file == defining || ctx.modules.resolve(file, name).exists(i =>
                            i.module.startsWith(".") &&
                                defining.startsWith(JsModules.resolveRelative(file, i.module))
                        )
                      }
                      .foreach(c => ctx.tagger.resolveCall(c, fn))
                }
            case _ =>
      }

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
    linkQwikHooks(ctx)

  /** `export const useMotd = routeLoader$(...)`, used as `const motd = useMotd()`: the hook's value
    * is what the loader (or action) returns, so the hook's calls - in the file or in one importing
    * it - are resolved to the callback.
    */
  private def linkQwikHooks(ctx: JsContext): Unit =
    val hooks = ctx.cpg.call.nameExact(Operators.assignment).l.flatMap { a =>
        (a.argumentOption(1), a.argumentOption(2)) match
          case (Some(target), Some(c: Call))
              if Set("routeLoader$", "routeAction$", "globalAction$").contains(c.name) =>
              val name = target match
                case id: Identifier => Some(id.name)
                case fa: Call       => fieldName(fa)
                case _              => None
              for
                n  <- name
                cb <- c.argument.filter(_.argumentIndex == 1).headOption.flatMap(callbackMethod)
              yield (a.method.filename, n, cb)
          case _ => None
    }
    if hooks.isEmpty then return
    hooks.foreach { (file, name, cb) =>
        JsIndexes.callsNamed(ctx.cpg.graph, name).filter { c =>
          val f = c.method.filename
          f == file || ctx.modules.resolve(f, name).exists(i =>
              i.module.startsWith(".") && file.startsWith(JsModules.resolveRelative(f, i.module))
          )
        }.foreach(c => ctx.tagger.resolveCall(c, cb))
    }
  end linkQwikHooks

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
                        .flatMap(nm =>
                            JsIndexes.internalMethodsByName(ctx.cpg.graph, nm).headOption
                        )
                    (byIdentifier ++ byElement).foreach(tagHandler(ctx, _))
              }
          }

  private[js] def jsxComponentName(domCode: String): Option[String] =
    val name = domCode.drop(1).takeWhile(c => c != ' ' && c != '>' && c != '/' && c != '\n')
    Option.when(name.nonEmpty && name.charAt(0).isUpper)(name)

  private def resolveComponent(ctx: JsContext, id: Identifier): Option[Method] =
      callbackMethod(id).orElse(JsIndexes.internalMethodsByName(ctx.cpg.graph, id.name).headOption)

  private def tagNavigation(ctx: JsContext): Unit =
    def target(c: Call): Option[Expression] = c.argument.filter(_.argumentIndex == 1).headOption
    def unanchored(e: Expression): Boolean  = !isObjectLiteral(e) && !hasFixedOrigin(e)

    // redirect(url) from react-router / next/navigation / @remix-run, permanentRedirect(url)
    val redirectPkgs = Seq(
      "react-router",
      "react-router-dom",
      "@remix-run",
      "@react-router",
      "next",
      "@tanstack",
      "@solidjs/router"
    )
    // TanStack's `redirect({ href })` leaves the app; `redirect({ to, params })` stays in its routes
    def leaves(e: Expression): Boolean =
        e match
          case b: Block if isObjectLiteral(b) =>
              objectProperties(b).flatMap(_.get("href")).exists(unanchored)
          case other => unanchored(other)
    val redirects = ctx.modules
        .namedImportCalls(
          redirectPkgs,
          Set("redirect", "redirectDocument", "permanentRedirect", "replace")
        )
        .filter(c => target(c).exists(leaves))
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
