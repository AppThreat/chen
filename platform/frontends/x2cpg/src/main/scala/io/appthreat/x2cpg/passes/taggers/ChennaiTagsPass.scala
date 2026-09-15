package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{
    Call,
    Identifier,
    Literal,
    Local,
    Method,
    MethodRef
}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern
import scala.util.{Try, Using}

/** Creates tags on any node based on framework patterns and configuration.
  *
  * @param atom
  *   the graph to tag.
  * @param externalConfig
  *   optional configuration content (the same JSON as the embedded `chennai.json`). When provided,
  *   it is used in addition to any embedded config, which lets a caller pass a configuration from
  *   outside the graph - for example an atom command-line flag - without first embedding it.
  */
class ChennaiTagsPass(atom: Cpg, externalConfig: Option[String] = None) extends CpgPass(atom):

  private val FRAMEWORK_ROUTE  = "framework-route"
  private val FRAMEWORK_INPUT  = "framework-input"
  private val FRAMEWORK_OUTPUT = "framework-output"
  // A call to a declared sanitiser or validator. Flows that pass through such a call are considered
  // neutralised for the categories the sanitiser covers.
  private val SANITIZER            = "sanitizer"
  private val SANITIZER_TAG_PREFIX = "sanitizer-"
  private val EscapedFileSeparator = Pattern.quote(java.io.File.separator)
  private val RE_CHARS             = "[](){}*+&|?.,\\$"

  // Language-specific route patterns
  private val PYTHON_ROUTES_CALL_REGEXES = Array(
    s"django\\.(conf\\.)?urls\\.(path|re_path|url).*".r,
    ".*(route|web\\.|add_resource).*".r
  )

  private val PYTHON_ROUTES_DECORATORS_REGEXES = Array(
    ".*(route|endpoint|_request|require_http_methods|require_GET|require_POST|require_safe|_required|api\\.doc|api\\.response|api\\.errorhandler)\\(.*",
    ".*def\\s(get|post|put)\\(.*"
  )

  private val PHP_ROUTES_METHODS_REGEXES = Array(
    ".*(router|routes|r|app|map)->(addRoute|add|before|mount|get|post|put|delete|head|option).*",
    ".*(Router)::(scope|connect|get|post|put|delete|head|option).*"
  )

  private val JS_ROUTES_CALL_REGEX =
      ".*(?i)(app|router|route|server)\\.(get|post|put|delete|patch|head|options|all|use|registerRoute).*"
  // Precompiled once: `tagJsRoutes` tests this against every call node in the graph, twice each
  // (methodFullName + code). `String.matches` recompiles the pattern on every call, which dominated
  // the juice-shop tagging phase (jstack: ChennaiTagsPass -> String.matches -> Pattern.compile).
  private val JsRoutesCallPattern   = Pattern.compile(JS_ROUTES_CALL_REGEX)
  private val VUE_ROUTE_INPUT_REGEX = ".*\\$route\\.(params|query|body).*"

  // SvelteKit identifies route handlers by file name, not by a registration call: a
  // `load` exported from `+page.server.ts` *is* the route handler, so there is no
  // `app.get("/path", handler)` shape for the JS_ROUTES_CALL_REGEX above to match.
  // Names follow https://svelte.dev/docs/kit/routing.
  private val SVELTEKIT_DATA_FILE_REGEX     = ".*\\+(page|layout)(\\.server)?\\.(js|ts|mjs|mts)"
  private val SVELTEKIT_ENDPOINT_FILE_REGEX = ".*\\+server\\.(js|ts|mjs|mts)"
  private val SVELTEKIT_HOOKS_FILE_REGEX =
      ".*hooks(\\.server|\\.client)?\\.(js|ts|mjs|mts)"
  private val SVELTE_COMPONENT_FILE_REGEX = ".*\\.svelte"

  /** Prefix of the lowered form of an ESM export (`export let data` -> `exports.data = data`). */
  private val ExportsPrefix = "exports."

  /** `load` runs per request and receives `{ params, url, request, cookies, fetch, locals }`. */
  private val SVELTEKIT_DATA_ENTRYPOINTS = Set("load")

  /** `+server.ts` exports one function per HTTP verb, plus `fallback` for the rest. */
  private val SVELTEKIT_HTTP_ENTRYPOINTS =
      Set("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "fallback")

  /** `hooks.server.ts` / `hooks.ts` sit in front of every request. */
  private val SVELTEKIT_HOOK_ENTRYPOINTS =
      Set(
        "handle",
        "handleError",
        "handleFetch",
        "handleValidationError",
        "init",
        "reroute",
        "transport"
      )

  private val CHENNAI_CONFIG_FILE = "chennai.json"

  // ---------------------------------------------------------------------
  // Angular / React / Vue recognizers
  // ---------------------------------------------------------------------

  // React Router (and Next.js) expose the URL through hooks; the call result
  // carries the request data, so the call itself is the source.
  private val REACT_INPUT_HOOKS = Set("useParams", "useSearchParams", "useLocation")

  // `route.` and `activatedRoute.` are both idiomatic field names for an ActivatedRoute, so the
  // identifier segment is matched case-insensitively.
  private val ANGULAR_ROUTE_INPUT_REGEX =
      "(?is).*(this\\.)?route\\.(snapshot\\.)?(params|queryParams|paramMap|queryParamMap|fragment|url|data).*"

  // Angular's DomSanitizer escape hatch: the returned value is rendered as
  // raw markup by the [innerHTML]-style binding it is fed to.
  private val ANGULAR_SANITIZER_BYPASS_REGEX =
      ".*bypassSecurityTrust(HTML|Html|SCRIPT|Script|STYLE|Style|URL|Url|RESOURCE_URL|ResourceUrl).*"

  // Route tables in Vue (`createRouter({ routes })`), Angular
  // (`RouterModule.forRoot(routes)`, `provideRouter(routes)`) and React Router
  // (`createBrowserRouter([{ path, element }])`) all lower to the same shape:
  // an array of anonymous objects whose properties are assigned one by one -
  //   _tmp_1.path = "/about/:id"
  //   _tmp_1.component = About
  // A temp carrying `.path` plus one of these siblings is a route record. The whole recogniser
  // only runs when a router package is imported, which is what keeps unrelated `{ path, ... }`
  // objects out; the sibling keys are then split by how route-specific they are.
  //
  // Strong keys name a thing to render or somewhere to go, and occur on little else: a record
  // carrying one is a route whatever its path looks like (React Router and Vue child routes use
  // bare relative segments - `{ path: 'users', component: Users }`).
  private val ROUTE_RECORD_STRONG_KEYS =
      Set(
        "component",
        "components",
        "element",
        "redirect",
        "pathMatch",
        // Angular lazy routes (`loadChildren`, and `loadComponent` for standalone components)
        // and React Router's `lazy` - the handler arrives through a dynamic import, so there is
        // no identifier to resolve, but the record is unambiguously a route.
        "loadChildren",
        "loadComponent",
        "lazy"
      )

  // Weak keys are real route-record keys too - `{ path: '/admin', children: [...] }` is the
  // standard Vue Router and Angular nesting idiom, and `loader`/`action` are React Router data
  // routes - but they also occur on file trees, webpack configs and menu structures. A record
  // carrying only a weak key therefore additionally has to have a route-shaped path.
  private val ROUTE_RECORD_WEAK_KEYS = Set("children", "loader", "action")

  private val ROUTE_RECORD_SIBLING_KEYS = ROUTE_RECORD_STRONG_KEYS ++ ROUTE_RECORD_WEAK_KEYS

  private val ROUTER_PACKAGES = Seq("vue-router", "@angular", "react-router", "nuxt")

  // The HTTP verbs a Next.js app-router `route.ts` may export, the same
  // convention SvelteKit's `+server.ts` uses.
  private val NEXT_HTTP_ENTRYPOINTS =
      Set("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")

  private val NEXT_ROUTE_FILE_REGEX =
      "(.*[/\\\\])?app(/.+)?[/\\\\]route\\.(js|jsx|ts|tsx|mjs|mts)$"
  private val NEXT_API_FILE_REGEX =
      "(.*[/\\\\])?pages[/\\\\]api[/\\\\].*\\.(js|jsx|ts|tsx|mjs|mts)$"
  private val NEXT_ENTRYPOINT_NAMES =
      Set("getServerSideProps", "getStaticProps", "generateMetadata")

  private val NUXT_SERVER_FILE_REGEX =
      "(.*[/\\\\])?server[/\\\\](api|routes)[/\\\\].*\\.(js|ts|mjs|mts)$"

  /** h3/Nitro request readers: the first argument is the request event, the return value is request
    * data.
    */
  private val H3_INPUT_CALLS =
      Set("readBody", "readRawBody", "getRouterParam", "getRouterParams", "getQuery", "useQuery")

  /** True when any import comes from one of the given npm packages. ESM imports lower to
    * `<package>:<name>` and `require(...)` to the bare specifier, so the package is the text before
    * the first colon.
    */
  private def usesPackages(packagePrefixes: String*): Boolean =
      atom.imports.importedEntity.exists { e =>
        val pkg = e.takeWhile(_ != ':')
        packagePrefixes.exists(p => pkg == p || pkg.startsWith(s"$p/") || pkg.startsWith(s"$p-"))
      }

  /** Emitted-tag memo. Several recognisers in this pass reach the same boundary from different
    * angles - the controller-file heuristic and the Next.js file conventions both tag a handler's
    * parameters, and a React component's props are tagged both as a routed handler and as a
    * component - and duplicate TAG nodes with the same name surface in downstream output. Tags
    * emitted by other passes (EasyTagsPass) are not covered; this only deduplicates within this
    * pass.
    *
    * Cleared at the top of `run`: the memo is instance state, so without the reset a second
    * `createAndApply()` on the same instance would silently emit nothing at all.
    */
  private val emittedTags = scala.collection.mutable.HashSet.empty[(Long, String)]

  private def storeTag[T <: io.shiftleft.codepropertygraph.generated.nodes.StoredNode](
    nodes: Iterator[T],
    tag: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
      nodes
          .filter(n => emittedTags.add((n.id, tag)))
          .newTagNode(tag)
          .store()(using dstGraph)

  private def language: String = atom.metaData.language.headOption.getOrElse("")

  override def run(dstGraph: DiffGraphBuilder): Unit =
    emittedTags.clear()
    tagFrameworkRoutes(dstGraph)
    processChennaiConfig(dstGraph)

  private def tagFrameworkRoutes(dstGraph: DiffGraphBuilder): Unit =
      language match
        case lang if lang == Languages.PYTHON || lang == Languages.PYTHONSRC =>
            tagPythonRoutes(dstGraph)
        case lang if lang == Languages.NEWC || lang == Languages.C =>
            tagCRoutes(dstGraph)
        case lang if lang == Languages.PHP =>
            tagPhpRoutes(dstGraph)
        case lang if lang == Languages.RUBYSRC =>
            tagRubyRoutes(dstGraph)
        case lang if lang == Languages.JSSRC || lang == Languages.JAVASCRIPT =>
            tagJsRoutes(dstGraph)
        case _ => // No specific routing for this language
  private def tagJsRoutes(dstGraph: DiffGraphBuilder): Unit =
    val routeCalls = atom.call.filter { c =>
        JsRoutesCallPattern.matcher(c.methodFullName).matches() ||
        JsRoutesCallPattern.matcher(c.code).matches()
    }
    routeCalls.foreach { call =>
      call.argument
          .isLiteral
          .headOption
          .newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
      call.argument
          .lastOption
          .flatMap {
              case r: MethodRef => r._refOut.collectFirst { case m: Method => m }
              case arg          => arg._refOut.collectFirst { case m: Method => m }
          }
          .foreach { handlerMethod =>
            val params = handlerMethod.parameter.l.sortBy(_.order)
            if params.nonEmpty then
              Iterator(params.head).newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
            if params.size >= 2 then
              Iterator(params(1)).newTagNode(FRAMEWORK_OUTPUT).store()(using dstGraph)
          }
    }
    // Cheap substring prefilter before the regex: the pattern can only match code containing the
    // literal "$route", so this skips the regex engine for the vast majority of (bundled-JS) calls.
    // The Vue `$route` input tagging is only meaningful when the project actually imports Vue.
    // Checking imports once avoids scanning every call node's code on non-Vue projects, and the
    // cheap `$route` substring prefilter avoids the regex engine for the remaining calls.
    // `importedEntity` is the bare specifier for `require(...)` (e.g. "vue") and "<package>:<name>"
    // for ESM imports (e.g. "vue-router:useRoute", "@vue/composition-api:ref"), so strip the
    // ESM name suffix before matching the package.
    val usesVue = usesPackages("vue", "@vue")
    if usesVue then
      atom.call
          .filter(_.code.contains("$route"))
          .code(VUE_ROUTE_INPUT_REGEX)
          .newTagNode(FRAMEWORK_INPUT)
          .store()(using dstGraph)
    val controllerMethods = atom.file.name(".*(route|controller|api).*(js|ts|jsx|tsx)")
        .method
        .internal
        .filterNot(_.name.contains("<"))
    // Through storeTag: the Next.js/Nuxt file conventions below reach the same parameters, and
    // duplicate TAG nodes would surface in downstream output.
    storeTag(
      controllerMethods.parameter.filterNot(_.name == "this"),
      FRAMEWORK_INPUT,
      dstGraph
    )
    tagRouteTableRecords(dstGraph)
    tagReactRouter(dstGraph)
    tagVueComponentInputs(dstGraph)
    tagAngular(dstGraph)
    tagNextJsRoutes(dstGraph)
    tagNuxtServerRoutes(dstGraph)
    tagSvelteKitRoutes(dstGraph)
  end tagJsRoutes

  /** Tag a handler method (a component or function a route renders) and its first parameter as the
    * web-facing boundary: the method becomes a route entrypoint and its first parameter - the
    * component props - web-facing input.
    */
  private def tagHandlerMethod(handler: Method, dstGraph: DiffGraphBuilder): Unit =
    storeTag(Iterator(handler), FRAMEWORK_ROUTE, dstGraph)
    handler.parameter
        .filterNot(_.name == "this")
        .headOption
        .foreach(p => storeTag(Iterator(p), FRAMEWORK_INPUT, dstGraph))

  /** Resolve a route-record's `component`/`element` value to the handler method it names.
    *
    * Function components reference the method directly. Failing that, the method is looked up by
    * name in the identifier's own FILE first - component names like `Home`, `Layout`, `Index`
    * collide freely across a monorepo, and the same-file match is the one that is almost always
    * meant - before falling back to any internal method with that name.
    */
  private def resolveComponentMethod(identifier: Identifier): Option[Method] =
      identifier._refOut.collectFirst { case m: Method => m }.orElse {
          val fileMethods = identifier.file.method.internal
          fileMethods.nameExact(identifier.name).headOption
              .orElse(atom.method.internal.nameExact(identifier.name).headOption)
      }

  /** The tag name of a JSX element's code (`<Profile />` -> `Profile`), when it names a component.
    *
    * A `element={<Profile />}` value lowers to TEMPLATE_DOM nodes only - the JSXIdentifier tag
    * carries no identifier node and no reference edge - so the component can only be resolved from
    * the element's own code. Lowercase tags are host elements (`div`), not components.
    */
  private def jsxComponentName(domCode: String): Option[String] =
    val name = domCode.drop(1).takeWhile(c => c != ' ' && c != '>' && c != '/')
    Option.when(name.nonEmpty && name.charAt(0).isUpper)(name)

  /** The literal's value with its surrounding quotes removed. */
  private def literalValue(code: String): String =
      if code.length >= 2 && (code.head == '"' || code.head == '\'') && code.last == code.head then
        code.substring(1, code.length - 1)
      else code

  /** A relative filesystem path (`./src`, `../lib`) - never a route, whatever it sits next to. */
  private def isFilesystemPath(code: String): Boolean =
    val value = literalValue(code)
    value.startsWith("./") || value.startsWith("../")

  /** A route-shaped path: absolute (`/admin`), parameterised (`/users/:id`, `[slug]`) or a
    * wildcard. Required of a record that carries only a weak sibling key, where the path is the
    * only thing telling a nested route apart from a file tree or a menu structure.
    */
  private def looksLikeRoutePath(code: String): Boolean =
    val value = literalValue(code)
    !isFilesystemPath(code) &&
    (value.startsWith("/") || value.contains(":") || value.contains("*") || value.contains("["))

  /** Route-table records shared by Vue, Angular and React Router.
    *
    * `{ path: '/about/:id', component: About }` lowers to `_tmp_1.path = "/about/:id"` and
    * `_tmp_1.component = About` assignments. A temp with a `.path` assignment plus a route-record
    * sibling key is a route record; the path literal is tagged `framework-route`, and the component
    * the record renders is resolved to its method and tagged as a handler.
    *
    * Keyed on the containing method plus the base identifier's name: the synthesized `_tmp_N` names
    * are unique within a method but not across files, and they carry no REF edges to a local that
    * could be keyed on instead.
    *
    * Precision comes from three independent controls, because a bad route is not merely a noisy tag
    * - it surfaces in user-visible slice output as an application route:
    *   - a router-package import is required at all (a `{ path, children }` file tree or a `{ path,
    *     loader }` webpack config in a router-less project is never looked at);
    *   - a strong sibling key (something to render or somewhere to go) admits any path, while a
    *     weak-only record (`children`/`loader`/`action`, which also describe trees and menus) must
    *     additionally have a route-shaped path;
    *   - a relative filesystem path value (`./`, `../`) is never a route.
    *
    * The conservative edge of the middle control: an Angular parent route written with a bare
    * relative path and no component - `{ path: 'admin', children: [...] }` - is not recognised,
    * while `{ path: '/admin', children: [...] }` is. Its children, which carry components, are
    * recognised either way.
    */
  private def tagRouteTableRecords(dstGraph: DiffGraphBuilder): Unit =
    if !usesPackages(ROUTER_PACKAGES*) then return

    // (method, baseName) -> key -> assignment call, for every `_tmp.key = value` property
    // assignment whose key is `path` or a route-record sibling key. Keying on the extracted key
    // (rather than a `.path` code substring) keeps the SIBLING assignments in the collection -
    // a `component` assignment's code contains no ".path" - and drops every unrelated property
    // assignment before the grouping.
    val interestingKeys = "path" +: ROUTE_RECORD_SIBLING_KEYS.toSeq
    val propAssignments = atom.call
        .nameExact(Operators.assignment)
        .flatMap { call =>
            call.argument
                .isCall
                .nameExact(Operators.fieldAccess)
                .headOption
                .flatMap { fieldAccess =>
                  val key = fieldAccess.code.substring(fieldAccess.code.lastIndexOf('.') + 1)
                  fieldAccess.argument.isIdentifier.headOption.map { base =>
                      ((call.method, base.name), key, call)
                  }
                }
        }
        .filter((_, key, _) => interestingKeys.contains(key))
        .l

    val byTemp = propAssignments.groupBy(_._1)
    byTemp.foreach { case (_, assignments) =>
        val keys      = assignments.map(_._2).toSet
        val hasStrong = keys.exists(ROUTE_RECORD_STRONG_KEYS)
        val hasWeak   = keys.exists(ROUTE_RECORD_WEAK_KEYS)
        if keys.contains("path") && (hasStrong || hasWeak) then
          assignments.foreach {
              case (_, "path", call) =>
                  call.argument.isLiteral.headOption
                      .filter(lit =>
                          if hasStrong then !isFilesystemPath(lit.code)
                          else looksLikeRoutePath(lit.code)
                      )
                      .foreach(lit => storeTag(Iterator(lit), FRAMEWORK_ROUTE, dstGraph))
              case (_, key, call) if key == "component" || key == "element" =>
                  call.argument.isIdentifier.headOption match
                    case Some(ident) =>
                        resolveComponentMethod(ident).foreach(tagHandlerMethod(_, dstGraph))
                    case None =>
                        // `element: <App />` keeps no identifier; the component is the JSX
                        // tag named in the assigned code.
                        call.argument.l.headOption
                            .map(_.code)
                            .flatMap(jsxComponentName)
                            .orElse(jsxComponentName(call.code))
                            .flatMap(nm => atom.method.internal.nameExact(nm).headOption)
                            .foreach(tagHandlerMethod(_, dstGraph))
              case _ => // not a handler-carrying key
          }
        end if
    }
  end tagRouteTableRecords

  /** React Router JSX routes and request hooks.
    *
    * `<Route path="/profile" element={<Profile />} />` is the JSX form of a route registration: the
    * `path` attribute's literal is the route and the component the `element`/`component` attribute
    * renders is the handler. The tag name is matched exactly - a prefix match would also fire on
    * `<Routes>` and on user components like `<RouteGuard path=...>`. The URL itself reaches
    * components through the `useParams`/`useSearchParams`/`useLocation` hooks, which are tagged as
    * input.
    *
    * Function components receive their data through props: a capitalized method that renders a
    * template (contains TEMPLATE_DOM) is a React component by the framework's own naming rule, so
    * its first parameter is tagged `framework-input` - the same reasoning that makes a controller
    * method's parameters web-facing. This is deliberately wide - every React component qualifies,
    * including presentational leaves - because props are the only input boundary a function
    * component has.
    */
  private def tagReactRouter(dstGraph: DiffGraphBuilder): Unit =
    val usesReact =
        usesPackages("react", "react-dom", "react-router", "next")
    if !usesReact then return

    REACT_INPUT_HOOKS.foreach { hook =>
        storeTag(atom.call.nameExact(hook), FRAMEWORK_INPUT, dstGraph)
    }

    // The opening element carries the attributes; its code starts with the tag name.
    atom.templateDom
        .nameExact("JSXOpeningElement")
        .filter(dom => jsxComponentName(dom.code) == Some("Route"))
        .foreach { routeElem =>
            routeElem.ast
                .collectAll[io.shiftleft.codepropertygraph.generated.nodes.TemplateDom]
                .nameExact("JSXAttribute")
                .foreach { attr =>
                    attr.code match
                      case c if c.startsWith("path=") =>
                          attr.ast.isLiteral.headOption
                              .foreach(lit => storeTag(Iterator(lit), FRAMEWORK_ROUTE, dstGraph))
                      case c if c.startsWith("element=") || c.startsWith("component=") =>
                          attr.ast.isIdentifier
                              .dedup
                              .foreach { ident =>
                                  resolveComponentMethod(ident)
                                      .foreach(tagHandlerMethod(_, dstGraph))
                              }
                          // `element={<Profile />}` has no identifier - the component is the
                          // JSX element's own tag name.
                          attr.ast
                              .collectAll[io.shiftleft.codepropertygraph.generated.nodes.TemplateDom]
                              .nameExact("JSXElement")
                              .code(".*")
                              .foreach { elemDom =>
                                  jsxComponentName(elemDom.code)
                                      .flatMap(nm => atom.method.internal.nameExact(nm).headOption)
                                      .foreach(tagHandlerMethod(_, dstGraph))
                              }
                      case _ =>
                }
        }

    atom.method
        .internal
        .filter(m => m.name.nonEmpty && m.name.charAt(0).isUpper)
        .filter(_.ast.isTemplateDom.nonEmpty)
        .foreach { component =>
            component.parameter
                .filterNot(_.name == "this")
                .headOption
                .foreach(p => storeTag(Iterator(p), FRAMEWORK_INPUT, dstGraph))
        }
  end tagReactRouter

  /** Vue component props boundary.
    *
    * Composition API: `defineProps()` / `withDefaults(defineProps(), {...})` is the props
    * declaration - the call is tagged `framework-input`, the same treatment Svelte 5's `$props()`
    * gets. Options API: `setup(props)` and `data(props)` receive the props as their first
    * parameter. `useRoute()` (vue-router) returns the live route, whose `.params`/`.query` carry
    * URL data.
    */
  private def tagVueComponentInputs(dstGraph: DiffGraphBuilder): Unit =
    val usesVue = usesPackages("vue", "@vue", "vue-router")
    if !usesVue then return

    storeTag(
      atom.call.name("defineProps|withDefaults|defineModel"),
      FRAMEWORK_INPUT,
      dstGraph
    )

    storeTag(atom.call.nameExact("useRoute"), FRAMEWORK_INPUT, dstGraph)

    atom.method
        .internal
        .nameExact("setup")
        .foreach { setup =>
            setup.parameter
                .filterNot(_.name == "this")
                .headOption
                .foreach(p => storeTag(Iterator(p), FRAMEWORK_INPUT, dstGraph))
        }
  end tagVueComponentInputs

  /** Angular decorators and route-parameter reads.
    *
    * `@Input()` members are the parent-to-child data boundary: the member and its `this.x` reads
    * are tagged `framework-input`. `@Output()` members (EventEmitter) are the child-to-parent
    * boundary and are tagged `framework-output`. Classes annotated `@Component`/`@Directive`/
    * `@Pipe`/`@Injectable` are tagged `framework` for inventory. URL data arrives via
    * `ActivatedRoute` (`route.params`, `route.snapshot.queryParams`, `paramMap.get(...)`), and
    * `bypassSecurityTrust*` marks values rendered as raw markup.
    */
  private def tagAngular(dstGraph: DiffGraphBuilder): Unit =
    val usesAngular = usesPackages("@angular")
    if !usesAngular then return

    // @Input()/@Output() land as annotations on class members
    val angularMembers = atom.annotation.nameExact("Input", "Output").l
    angularMembers.foreach { annotation =>
        annotation.astParent match
          case member: io.shiftleft.codepropertygraph.generated.nodes.Member =>
              val tag = if annotation.name == "Input" then FRAMEWORK_INPUT else FRAMEWORK_OUTPUT
              storeTag(Iterator(member), tag, dstGraph)
              // `this.<member>` field-access reads inside the class are the actual taint carriers.
              // Matched by codeExact because the field access's code IS `this.<member>`: an
              // unanchored substring match would bleed an `@Input() id` onto every read of
              // `this.idx`/`this.idField`, and would also tag enclosing operator calls whose code
              // merely contains the access.
              storeTag(
                member.typeDecl.method.flatMap(_.ast.isCall).nameExact(Operators.fieldAccess)
                    .codeExact(s"this.${member.name}"),
                tag,
                dstGraph
              )
          case _ =>
    }

    // NB: class-level inventory tagging of @Component/@Injectable classes was deliberately
    // dropped - neither TYPE_DECL nor ANNOTATION nodes support TAGGED_BY edges, and the
    // @Input/@Output member tagging below is what carries the dataflow semantics.

    // Cheap case-insensitive prefilter before the regex: `route.` and `Route.` both occur
    // (`this.route.params`, `this.activatedRoute.snapshot.queryParams`), and this loop runs over
    // every call in the graph.
    storeTag(
      atom.call
          .filter(_.code.toLowerCase.contains("route."))
          .code(ANGULAR_ROUTE_INPUT_REGEX),
      FRAMEWORK_INPUT,
      dstGraph
    )

    storeTag(
      atom.call
          .filter(_.code.contains("bypassSecurityTrust"))
          .code(ANGULAR_SANITIZER_BYPASS_REGEX),
      FRAMEWORK_OUTPUT,
      dstGraph
    )
  end tagAngular

  /** Next.js file-convention routes.
    *
    * An app-router `route.ts` (e.g. `app/api/users/route.ts`) exports one function per HTTP verb
    * (the same convention as SvelteKit's `+server.ts`); every export of a `pages/api` file is a
    * handler; `middleware.ts` intercepts every request; and
    * `getServerSideProps`/`getStaticProps`/`generateMetadata` are the page-data loaders, whose
    * context parameter carries request data.
    */
  private def tagNextJsRoutes(dstGraph: DiffGraphBuilder): Unit =
    def tagExported(names: Set[String], fileRegex: String): Unit =
      val methods = atom.file.name(fileRegex).method.internal.l
      // An empty `names` (pages/api) means every export is a handler, named or anonymous.
      val handlers =
          if names.isEmpty then methods.filterNot(m => m.name.contains("<") || m.name == ":program")
          else methods.filter(m => names.contains(m.name) || m.name.startsWith("anonymous"))
      storeTag(handlers.iterator, FRAMEWORK_ROUTE, dstGraph)
      storeTag(
        handlers.iterator.parameter.filterNot(_.name == "this"),
        FRAMEWORK_INPUT,
        dstGraph
      )

    tagExported(NEXT_HTTP_ENTRYPOINTS, NEXT_ROUTE_FILE_REGEX)
    tagExported(Set.empty, NEXT_API_FILE_REGEX)

    // Page-data loaders and middleware, wherever they are defined
    atom.method
        .internal
        .name(NEXT_ENTRYPOINT_NAMES.map(n => s"^$n$$").mkString("|"))
        .foreach(tagHandlerMethod(_, dstGraph))
    atom.method
        .internal
        .nameExact("middleware")
        .where(_.filename(".*middleware\\.(js|ts|mjs|mts)$"))
        .foreach(tagHandlerMethod(_, dstGraph))
  end tagNextJsRoutes

  /** Nuxt/Nitro server routes.
    *
    * Files under `server/api` and `server/routes` export handlers directly; elsewhere handlers are
    * registered by wrapping them in `defineEventHandler(...)`/`eventHandler(...)`. The h3 request
    * readers (`readBody`, `getRouterParam`, ...) return request data and are tagged as input.
    *
    * The directory layout alone is accepted as a Nuxt signal because Nuxt AUTO-imports
    * `defineEventHandler` and friends - a real Nuxt server directory may contain no recognisable
    * import at all. To keep a plain Express/Fastify project that happens to use the same layout
    * from having every internal helper tagged, only handler-shaped exports are tagged there: a
    * method that takes at least one parameter (the event) or is the anonymous/default export.
    */
  private def tagNuxtServerRoutes(dstGraph: DiffGraphBuilder): Unit =
    val usesNuxt     = usesPackages("nuxt", "h3", "nitro")
    val hasServerDir = atom.file.name(NUXT_SERVER_FILE_REGEX).nonEmpty
    if !usesNuxt && !hasServerDir then return

    atom.call.name("defineEventHandler|eventHandler|defineRouteHandler").foreach { call =>
        call.argument
            .flatMap {
                case r: MethodRef => r._refOut.collectFirst { case m: Method => m }
                case arg          => arg._refOut.collectFirst { case m: Method => m }
            }
            .dedup
            .foreach(tagHandlerMethod(_, dstGraph))
    }

    val serverMethods = atom.file.name(NUXT_SERVER_FILE_REGEX).method.internal.l
    val handlers = serverMethods
        .filterNot(_.name.contains("<"))
        .filter(m => m.name != ":program")
        .filter(m =>
            m.parameter.filterNot(_.name == "this").nonEmpty || m.name.startsWith("anonymous")
        )
    storeTag(handlers.iterator, FRAMEWORK_ROUTE, dstGraph)
    storeTag(
      handlers.iterator.parameter.filterNot(_.name == "this"),
      FRAMEWORK_INPUT,
      dstGraph
    )

    storeTag(
      atom.call.name(H3_INPUT_CALLS.map(n => s"^$n$$").mkString("|")),
      FRAMEWORK_INPUT,
      dstGraph
    )
  end tagNuxtServerRoutes

  /** SvelteKit route semantics.
    *
    * Two halves, because SvelteKit's request path crosses a file boundary that has no edge in the
    * graph: the server's `load` return becomes the component's `data` prop by convention, not by a
    * call or an import.
    *
    * Server half: the entrypoints in `+page.server.ts`, `+server.ts` and `hooks.server.ts` are
    * tagged `framework-route`, and their parameters `framework-input`. The parameters are the
    * request (`{ params, url, request, cookies }`), so this is what makes server-side flows such as
    * `params.slug` reaching a query show up.
    *
    * Component half: `$props()` in a `.svelte` file is tagged `framework-input`. In a route
    * component the `data` prop is whatever the server `load` returned; in any component the props
    * come from outside it. Paired with the `framework-output` tag `EasyTagsPass` puts on a value
    * rendered through `{@html}`, this closes a reportable props -> raw-HTML path inside the
    * component without needing the cross-file edge.
    *
    * Anonymous methods in a server file are tagged alongside the named entrypoints: `export const
    * actions = { default: async ({ request }) => ... }` compiles to an anonymous method, and it is
    * a request handler like any other. Named helper functions in the same file are deliberately
    * left alone - only the entrypoint names and the anonymous handlers are treated as web-facing.
    *
    * Svelte 4's `export let` props are not covered; `$props()` is the Svelte 5 form.
    */
  private def tagSvelteKitRoutes(dstGraph: DiffGraphBuilder): Unit =
    def tagEntrypoints(fileRegex: String, entrypointNames: Set[String]): Unit =
      val methods = atom.file.name(fileRegex).method.internal.l
      if methods.isEmpty then return
      // Anonymous handlers are numbered when a file has more than one (`anonymous`,
      // `anonymous1`, ...), which is the normal case for an `actions` object.
      val handlers = methods
          .filter(m => entrypointNames.contains(m.name) || m.name.startsWith("anonymous"))
          .distinctBy(_.id)
      if handlers.isEmpty then return
      handlers.iterator.newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
      handlers.iterator.parameter
          .filterNot(_.name == "this")
          .newTagNode(FRAMEWORK_INPUT)
          .store()(using dstGraph)

    tagEntrypoints(SVELTEKIT_DATA_FILE_REGEX, SVELTEKIT_DATA_ENTRYPOINTS)
    tagEntrypoints(SVELTEKIT_ENDPOINT_FILE_REGEX, SVELTEKIT_HTTP_ENTRYPOINTS)
    tagEntrypoints(SVELTEKIT_HOOKS_FILE_REGEX, SVELTEKIT_HOOK_ENTRYPOINTS)

    val componentMethods = atom.file.name(SVELTE_COMPONENT_FILE_REGEX).method.internal.l
    if componentMethods.isEmpty then return

    // Svelte 5: props arrive from a `$props()` call, and taint flows from it through the
    // destructuring into each prop binding.
    componentMethods.iterator.call
        .nameExact("$props")
        .dedup
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)

    // Svelte 4: `export let data` lowers to `exports.data = data`, so the locals assigned into
    // `exports.*` are the component's props. There is no producing call to tag - the parent
    // component assigns the binding - so the prop's *reads* are tagged instead: a read of an
    // externally supplied binding is a web-facing input read, the same reasoning that makes a
    // controller method's parameters framework-input.
    //
    // When a prop is rendered directly (`{@html data.body}`) the read is both the source and
    // inside the sink; `ReachableSlicing` already drops entries whose first and last node are the
    // same, so that degenerate case needs no special handling here.
    // Keyed on the exported name rather than on the assignment's right-hand identifier: that
    // identifier carries no REF edge to the local, so a `refsTo` join finds nothing.
    val exportedPropNames = componentMethods.iterator.call
        .nameExact(Operators.assignment)
        .flatMap(_.argumentOption(1))
        .map(_.code)
        .filter(_.startsWith(ExportsPrefix))
        .map(_.stripPrefix(ExportsPrefix))
        .toSet
    if exportedPropNames.nonEmpty then
      componentMethods.iterator.local
          .filter(local => exportedPropNames.contains(local.name))
          .referencingIdentifiers
          .dedup
          .newTagNode(FRAMEWORK_INPUT)
          .store()(using dstGraph)
  end tagSvelteKitRoutes

  private def tagCRoutes(dstGraph: DiffGraphBuilder): Unit =
    val cRoutePatterns = Array(
      "Routes::(Post|Get|Delete|Head|Options|Put).*",
      "API_CALL",
      "API_CALL_ASYNC",
      "ENDPOINT",
      "ENDPOINT_ASYNC",
      "ENDPOINT_INTERCEPTOR",
      "ENDPOINT_INTERCEPTOR_ASYNC",
      "registerHandler",
      "PATH_ADD",
      "ADD_METHOD_TO",
      "ADD_METHOD_VIA_REGEX",
      "WS_PATH_ADD",
      "svr\\.(Post|Get|Delete|Head|Options|Put)"
    )

    cRoutePatterns.foreach { pattern =>
      atom.method.fullName(pattern).parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
      atom.call
          .where(_.methodFullName(pattern))
          .argument
          .isLiteral
          .newTagNode(FRAMEWORK_ROUTE)
          .store()(using dstGraph)
    }
  end tagCRoutes

  private def tagPythonRoutes(dstGraph: DiffGraphBuilder): Unit =
    // Tag route calls
    PYTHON_ROUTES_CALL_REGEXES.foreach { regex =>
        atom.call
            .where(_.methodFullName(regex.toString()))
            .argument
            .isLiteral
            .newTagNode(FRAMEWORK_ROUTE)
            .store()(using dstGraph)
    }

    // Tag decorated methods
    PYTHON_ROUTES_DECORATORS_REGEXES.foreach { pattern =>
      val decoratedMethods = atom.methodRef
          .where(_.inCall.code(pattern).argument)
          ._refOut
          .collectAll[Method]

      // NB: the request-access expression itself is tagged framework-input by
      // EasyTagsPass (step 3b). This pass used to tag the LHS identifier of an
      // assignment whose RHS was a request access, which covered only
      // `v = request.args[...]` and missed `sink(request.args[...])` entirely.
      // Tagging both would report a single source twice, so only the expression
      // tagging remains.
      decoratedMethods.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
      decoratedMethods.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
    }

    // Django views
    atom.file.name(".*views.py.*")
        .method
        .parameter
        .name("request")
        .method
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)

    // Controller methods
    val controllerMethods = atom.file.name(".*controllers.*.py.*")
        .method
        .name("get|post|put|delete|head|option")

    controllerMethods
        .parameter
        .filterNot(_.name == "self")
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)

    controllerMethods
        .methodReturn
        .newTagNode(FRAMEWORK_OUTPUT)
        .store()(using dstGraph)
  end tagPythonRoutes

  // Attribute-route matcher for PHP 8+ controllers (Symfony/Laravel modern routing). The
  // php2atom AstCreator emits each `#[Attr(...)]` as a CPG annotation whose name is the attribute
  // name rendered by Domain.readName: a simple name (e.g. "Route") or a `\`-joined fully-qualified
  // name (e.g. "Symfony\Component\Routing\Annotation\Route"). This matcher is FQN-tolerant - it
  // matches on the LAST `\`-segment - and case-insensitive. It accepts the generic `Route`
  // attribute plus Symfony 6.x method-specific route attributes (Get/Post/Put/Delete/Patch/Head/
  // Options), the `Any`/`Route`-suffixed variants, and anything whose simple name ends in "Route"
  // (e.g. a custom `ApiRoute`). It deliberately does NOT match non-routing attributes such as
  // `Deprecated`, `Override`, or `Sensitive`, so annotated-but-unrouted methods are not tagged.
  private val PHP_ROUTE_ATTRIBUTE_REGEX =
      "(?i)^(.*\\\\)?(route|get|post|put|delete|patch|head|options|any|.*route)$"

  // WordPress hook registrations. `add_action`/`add_filter` register a callable (2nd argument) as
  // the handler for a named hook; that callable is the reported entrypoint.
  private val WORDPRESS_HOOK_REGEX = "(add_action|add_filter)"

  private def tagPhpRoutes(dstGraph: DiffGraphBuilder): Unit =
    PHP_ROUTES_METHODS_REGEXES.foreach { pattern =>
      atom.method.fullName(pattern).parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
      atom.call
          .where(_.methodFullName(pattern))
          .argument
          .isLiteral
          .newTagNode(FRAMEWORK_ROUTE)
          .store()(using dstGraph)
    }

    // 1) Attribute routes: `#[Route(...)]`, `#[Get(...)]`, etc. on controller methods. The routed
    //    method surfaces as an entrypoint (framework-route) and its parameters as web-facing input
    //    (framework-input). Requirement 6.5 / design Decision 3.
    val routedMethods =
        atom.method.where(_.annotation.name(PHP_ROUTE_ATTRIBUTE_REGEX)).l
    routedMethods.iterator.newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
    routedMethods.iterator
        .parameter
        .filterNot(_.name == "this")
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)

    // 2) WordPress hooks: `add_action('hook', callable)` / `add_filter('hook', callable)`. The
    //    registered callable (2nd argument) is the reported entrypoint. Where that callable is a
    //    string literal naming a function/method that exists in the graph, its parameters are also
    //    marked framework-input so the handler's inputs are treated as web-facing. (EasyTagsPass
    //    already tags add_action/add_filter method *parameters*; here we add the missing mapping of
    //    the registration/callable itself to a framework-route entrypoint.) Requirement 6.5.
    val hookCalls = atom.call.name(WORDPRESS_HOOK_REGEX).l
    hookCalls.foreach { call =>
      val callableArgs = call.argument.argumentIndex(2).l
      callableArgs.iterator.newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
      // Resolve string-literal callables (e.g. 'my_handler') to a method by name and tag its params.
      callableArgs.iterator.isLiteral.foreach { lit =>
        val handlerName = lit.code.trim.stripPrefix("'").stripSuffix("'").stripPrefix("\"")
            .stripSuffix("\"").trim
        if handlerName.nonEmpty then
          atom.method
              .nameExact(handlerName)
              .parameter
              .filterNot(_.name == "this")
              .newTagNode(FRAMEWORK_INPUT)
              .store()(using dstGraph)
      }
    }
  end tagPhpRoutes

  private def tagRubyRoutes(dstGraph: DiffGraphBuilder): Unit =
    // Rails routes
    val railsRoutePrefix = ".*(get|post|put|delete|head|option|resources|namespace)\\s('|\").*"

    val railsRoutes = atom.method.where(
      _.filename("config/routes.rb").code(railsRoutePrefix)
    )

    railsRoutes.newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
    railsRoutes.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)

    // Rails controllers
    val railsControllers = atom.method.filename(".*controller.rb.*")
    railsControllers.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
    railsControllers.methodReturn.newTagNode(FRAMEWORK_OUTPUT).store()(using dstGraph)

    // Sinatra routes
    val sinatraRoutePrefix =
        "(app\\.namespace|app\\.)?(get|post|delete|head|options|put)\\s('|\").*"

    val sinatraRoutes = atom.method.code(sinatraRoutePrefix)
    sinatraRoutes.newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
    sinatraRoutes.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
    sinatraRoutes.methodReturn.newTagNode(FRAMEWORK_OUTPUT).store()(using dstGraph)
  end tagRubyRoutes

  private def processChennaiConfig(dstGraph: DiffGraphBuilder): Unit =
      configSources.foreach { configData =>
          parse(configData) match
            case Right(json) =>
                val cursor = json.hcursor
                cursor.downField("tags").focus.flatMap(_.asArray).getOrElse(Vector.empty)
                    .foreach(processTag(_, dstGraph))
                // A sanitiser/validator section, e.g.
                //   "sanitizers": [ { "name": "owasp-encode",
                //                     "methods": ["org\\.owasp\\.encoder\\.Encode\\..*"],
                //                     "categories": ["http"] } ]
                // `validators` is accepted as an alias and handled identically.
                (cursor.downField("sanitizers").focus.flatMap(_.asArray).getOrElse(Vector.empty) ++
                    cursor.downField("validators").focus.flatMap(_.asArray).getOrElse(Vector.empty))
                    .foreach(processSanitizer(_, dstGraph))

            case Left(error) =>
                System.err.println(s"Failed to parse Chennai config: $error")
      }

  /** Configuration content from the embedded `chennai.json` and from any externally supplied
    * config, in that order.
    */
  private def configSources: Seq[String] =
      atom.configFile(CHENNAI_CONFIG_FILE).content.toSeq ++ externalConfig.toSeq

  /** Tags every call to a declared sanitiser/validator method with the `sanitizer` tag, plus one
    * `sanitizer-<category>` tag per declared category. With no categories the sanitiser is treated
    * as covering every flow.
    */
  private def processSanitizer(sanitizerJson: Json, dstGraph: DiffGraphBuilder): Unit =
    val cursor = sanitizerJson.hcursor
    val methods =
        cursor.downField("methods").focus.flatMap(_.asArray).getOrElse(Vector.empty)
    val categories = cursor.downField("categories").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        .flatMap(_.asString).filter(_.nonEmpty)

    methods.flatMap(_.asString).filter(_.nonEmpty).foreach { methodPattern =>
      val calls =
          if containsRegex(methodPattern) then atom.call.methodFullName(methodPattern)
          else atom.call.methodFullNameExact(methodPattern)
      val callList = calls.l
      callList.iterator.newTagNode(SANITIZER).store()(using dstGraph)
      categories.foreach { category =>
          callList.iterator.newTagNode(s"$SANITIZER_TAG_PREFIX$category").store()(using dstGraph)
      }
    }

  private def processTag(tagJson: Json, dstGraph: DiffGraphBuilder): Unit =
    val cursor  = tagJson.hcursor
    val tagName = cursor.downField("name").as[String].getOrElse("")

    if tagName.nonEmpty then
      processTagParameters(cursor, tagName, dstGraph)
      processTagMethods(cursor, tagName, dstGraph)
      processTagTypes(cursor, tagName, dstGraph)
      processTagFiles(cursor, tagName, dstGraph)

  private def processTagParameters(
    cursor: HCursor,
    tagName: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
    val parameters = cursor
        .downField("parameters")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    parameters.foreach { param =>
        param.asString.foreach { paramName =>
            if paramName.nonEmpty then
              atom.method.parameter.typeFullNameExact(paramName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(paramName) then
                atom.method.parameter.typeFullName(s".*${Pattern.quote(paramName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagParameters

  private def processTagMethods(
    cursor: HCursor,
    tagName: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
    val methods = cursor
        .downField("methods")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    methods.foreach { method =>
        method.asString.foreach { methodName =>
            if methodName.nonEmpty then
              atom.method.fullNameExact(methodName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(methodName) then
                atom.method.fullName(s".*${Pattern.quote(methodName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagMethods

  private def processTagTypes(cursor: HCursor, tagName: String, dstGraph: DiffGraphBuilder): Unit =
    val types = cursor
        .downField("types")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    types.foreach { typ =>
        typ.asString.foreach { typeName =>
            if typeName.nonEmpty then
              atom.method.parameter.typeFullNameExact(typeName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(typeName) then
                atom.method.parameter.typeFullName(s".*${Pattern.quote(typeName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)

              atom.call.typeFullNameExact(typeName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !typeName.contains("[") && !typeName.contains("*") then
                atom.call.typeFullName(s".*${Pattern.quote(typeName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagTypes

  private def processTagFiles(cursor: HCursor, tagName: String, dstGraph: DiffGraphBuilder): Unit =
    val files = cursor
        .downField("files")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    files.foreach { file =>
        file.asString.foreach { fileName =>
            if fileName.nonEmpty then
              atom.file.nameExact(fileName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(fileName) then
                atom.file.name(s".*${Pattern.quote(fileName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagFiles

  private def containsRegex(str: String): Boolean =
      str.exists(RE_CHARS.contains)
end ChennaiTagsPass
