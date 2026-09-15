package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Local, Method, MethodRef}
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

  private def language: String = atom.metaData.language.headOption.getOrElse("")

  override def run(dstGraph: DiffGraphBuilder): Unit =
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
    val usesVue = atom.imports.importedEntity.exists { e =>
      val pkg = e.takeWhile(_ != ':')
      pkg == "vue" || pkg.startsWith("vue-") || pkg.startsWith("vue/") || pkg.startsWith("@vue/")
    }
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
    controllerMethods
        .parameter
        .filterNot(_.name == "this")
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)
    tagSvelteKitRoutes(dstGraph)
  end tagJsRoutes

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
