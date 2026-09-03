package io.appthreat.dataflowengineoss.semantics

/** Framework taint identifiers for PHP (Laravel, Symfony, WordPress).
  *
  * This object is the single documented home for the framework taint model described in the
  * php-support-upgrade design §2.7 (Requirements 6.2, 6.3, 6.4). It records, per framework, the
  * SOURCE / SINK / SANITIZER / ENTRYPOINT identifiers as they appear in a php2atom CPG.
  *
  * Every part of the model is consumed:
  *
  *   1. SANITIZERS drive taint clearing.
  *      [[io.appthreat.dataflowengineoss.DefaultSemantics.phpFlows]] is derived from
  *      [[allSanitizerNames]]: each sanitizer becomes a `FlowSemantic` with an empty mapping list,
  *      so taint does not pass from its argument to its return. Those flows are applied by the OSS
  *      dataflow layer (`OssDataFlow`) *only to PHP graphs* - see
  *      `DefaultSemantics.flowsForLanguage` - so a bare name like `e` cannot silently clear taint
  *      in a C/Java/JS graph.
  *
  * 2. SOURCES and SINKS drive CPG tagging. `io.appthreat.php2atom.passes.PhpFrameworkTagsPass`
  * consumes [[Sources]] / [[Sinks]] and tags matching nodes `framework-input` / `framework-output`
  * (plus `sql` for database sinks), which is the vocabulary atom's reachable slicing already
  * queries.
  *
  * 3. ENTRYPOINTS are tagged `framework-route` by `x2cpg`'s `ChennaiTagsPass.tagPhpRoutes`
  * (attribute routes and WordPress `add_action`/`add_filter` registrars).
  *
  * The `*FullName` / `*Name` shapes below reflect how php2atom actually names the constructs:
  *   - Static calls `Class::method(...)` -> methodFullName `Class::method` (call name `method`).
  *   - Instance calls `$obj->method(...)` -> methodFullName `<unresolvedNamespace>\$obj->method`
  *     (call name `method`); matching by call name plus a receiver check is the robust choice.
  *   - Free/builtin calls `foo(...)` -> methodFullName `foo` (call name `foo`).
  *   - Superglobal access `$_GET['k']` -> `<operator>.indexAccess` over identifier named `_GET`.
  */
object PhpFrameworkSemantics:

  /** Laravel (Illuminate). */
  object Laravel:
    /** Request sources. `Request::input` is a static call; `request()->input` is an instance call
      * whose call name is `input`.
      */
    val sourceFullNames: Set[String] = Set("Request::input", "Request::get", "Request::all")

    /** Bare call names. These are ambiguous on their own (`->all()`, `->query()` and `->post()` are
      * everyday collection/ORM/HTTP-client methods), so the tagging pass only accepts them when the
      * receiver looks like a request object - see [[Sources.requestReceiverRegex]].
      */
    val sourceCallNames: Set[String] = Set("input", "all", "query", "post")

    /** Raw query sink. */
    val sinkFullNames: Set[String] = Set("DB::raw", "DB::statement")

    /** Bare call names, receiver-gated against [[Sinks.databaseReceiverRegex]] (`raw` and
      * `statement` are far too common to accept unconditionally).
      */
    val sinkCallNames: Set[String] = Set("raw", "statement")

    /** HTML escaper. Enforced via DefaultSemantics.phpFlows. */
    val sanitizerNames: Set[String] = Set("e")
  end Laravel

  /** Symfony (HttpFoundation / Doctrine). */
  object Symfony:
    /** Request sources from HttpFoundation. `Request::get` is a static call. */
    val sourceFullNames: Set[String] = Set("Request::get")

    /** Bare call names, receiver-gated (a bare `get`/`query` matches almost anything). */
    val sourceCallNames: Set[String] = Set("get", "query", "request")

    /** Raw Doctrine DQL sink - `$em->createQuery(...)` (instance call, name `createQuery`). These
      * names are distinctive enough to accept without a receiver check.
      */
    val sinkCallNames: Set[String] = Set("createQuery", "createNativeQuery")

    /** Route mapping is expressed via the `#[Route]` attribute (entrypoint marker). */
    val routeAttribute: String = "Route"

    /** Symfony escaping is handled by the templating/binding layer; no free-function sanitizer is
      * modeled here.
      */
    val sanitizerNames: Set[String] = Set.empty

  /** WordPress. */
  object WordPress:
    /** Superglobal sources: access is `<operator>.indexAccess` over these identifier names.
      * `_SERVER` is included because `HTTP_REFERER`, `REQUEST_URI`, `QUERY_STRING` and friends are
      * attacker controlled and are real XSS / SQLi vectors (finding C-M2).
      */
    val sourceSuperglobals: Set[String] =
        Set("_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER")

    /** `$_SERVER` keys that are attacker controlled. `$_SERVER` as a whole is not tainted (e.g.
      * `DOCUMENT_ROOT` is not), so a literal-keyed `$_SERVER[...]` read is only a source when the
      * key is one of these. A dynamically keyed read is treated as a source conservatively.
      */
    val taintedServerKeys: Set[String] =
        Set(
          "REQUEST_URI",
          "QUERY_STRING",
          "PATH_INFO",
          "ORIG_PATH_INFO",
          "PHP_SELF",
          "REQUEST_METHOD",
          "CONTENT_TYPE",
          "argv"
        )

    /** `$_SERVER` keys carrying request headers are all attacker controlled (`HTTP_REFERER`,
      * `HTTP_USER_AGENT`, `HTTP_X_FORWARDED_FOR`, ...).
      */
    val taintedServerKeyPrefixes: Set[String] = Set("HTTP_")

    /** Output sinks. `echo`/`print` are PHP language constructs with no receiver, so they are
      * accepted unconditionally.
      */
    val outputSinkNames: Set[String] = Set("echo", "print")

    /** Database sinks - `$wpdb->query(...)`, `$wpdb->get_results(...)` (instance calls). These are
      * receiver-gated: a bare `query()` is also a Symfony/Laravel request accessor.
      */
    val databaseSinkNames: Set[String] = Set("query", "get_results")

    /** Sinks: output plus `$wpdb` database access. */
    val sinkCallNames: Set[String] = outputSinkNames ++ databaseSinkNames

    /** Output escapers and input sanitizers. Enforced via DefaultSemantics.phpFlows. */
    val sanitizerNames: Set[String] =
        Set(
          "esc_html",
          "esc_attr",
          "esc_url",
          "sanitize_text_field",
          "sanitize_email",
          "wp_kses",
          "wp_kses_post"
        )

    /** Entrypoints: `add_action('hook', callable)` / `add_filter('hook', callable)`. The callable
      * (2nd argument) is the tagged entrypoint.
      */
    val entrypointRegistrars: Set[String] = Set("add_action", "add_filter")
  end WordPress

  /** PHP language-level escapers (not framework specific). */
  object Php:
    val sanitizerNames: Set[String] = Set("htmlspecialchars", "htmlentities")

  /** Every sanitizer name across the frameworks and the language itself. Drives
    * `DefaultSemantics.phpFlows`.
    */
  val allSanitizerNames: Set[String] =
      Laravel.sanitizerNames ++ Symfony.sanitizerNames ++ WordPress.sanitizerNames ++
          Php.sanitizerNames

  /** Source matchers used by the tagging pass.
    *
    * `fullNames` are qualified (`Class::method`) and therefore unambiguous.
    * `receiverGatedCallNames` are bare method names shared with ordinary collection/ORM/HTTP-client
    * APIs, so a match also requires the receiver to look like a request object (finding C-M3).
    */
  object Sources:
    val fullNames: Set[String] = Laravel.sourceFullNames ++ Symfony.sourceFullNames

    val receiverGatedCallNames: Set[String] = Laravel.sourceCallNames ++ Symfony.sourceCallNames

    val superglobals: Set[String] = WordPress.sourceSuperglobals

    /** Matches a receiver that denotes an HTTP request: `$request`, `Request`, `request()`,
      * `$this->request`, `$httpRequest`, `$req`. Anchored on word boundaries so `$myrequests` or
      * `$requester` do not match.
      */
    val requestReceiverRegex: String =
        "(?i)(^|[^a-z0-9_])(request|req|httprequest)([^a-z0-9_]|$)"

  /** Sink matchers used by the tagging pass.
    *
    * `unambiguousCallNames` are accepted on the call name alone; `receiverGatedCallNames` require a
    * database-looking receiver.
    */
  object Sinks:
    val fullNames: Set[String] = Laravel.sinkFullNames

    val unambiguousCallNames: Set[String] =
        WordPress.outputSinkNames ++ Symfony.sinkCallNames

    val receiverGatedCallNames: Set[String] =
        Laravel.sinkCallNames ++ WordPress.databaseSinkNames

    /** Matches a receiver that denotes a database handle / query builder: `$wpdb`, `DB`, `$db`,
      * `$dbh`, `$pdo`, `$connection`, `$em`, `$entityManager`.
      */
    val databaseReceiverRegex: String =
        "(?i)(^|[^a-z0-9_])(wpdb|db|dbh|pdo|conn|connection|database|em|entitymanager|queryb(uild)?er)([^a-z0-9_]|$)"

    /** Sink names that write to a SQL store; tagged `sql` in addition to `framework-output`. */
    val sqlCallNames: Set[String] =
        Laravel.sinkCallNames ++ WordPress.databaseSinkNames ++ Symfony.sinkCallNames

    val sqlFullNames: Set[String] = Laravel.sinkFullNames
  end Sinks
end PhpFrameworkSemantics
