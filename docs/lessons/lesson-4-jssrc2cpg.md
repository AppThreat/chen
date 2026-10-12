# Lesson 4: JavaScript & TypeScript Frontend (jssrc2cpg)

## Learning Objective

Understand how `jssrc2cpg` turns JavaScript/TypeScript source into a CPG using the external
`astgen` tool, how the two-stage (parse → ingest) pipeline works, and how type recovery and
import resolution recover the dynamic bindings that the raw AST cannot express.

## Pre-requisites

- JDK 23+ (OpenJDK or GraalVM)
- SBT 1.10+
- Node.js 20+
- `@appthreat/atom-parsetools` installed globally (`npm install -g @appthreat/atom-parsetools`)
  — provides the `astgen` binary. The frontend also ships platform binaries it can fall back to.
- Local clone of [chen](https://github.com/AppThreat/chen): `sbt compile`

## Conceptual Background

JavaScript and TypeScript are dynamically typed, so most variables carry no declared type, and
calls are bound at runtime. `jssrc2cpg` therefore builds the graph in two clearly separated
stages:

1. **AST generation (out of process).** A native Node-based tool, `astgen` (Babel/Esprima under
   the hood), parses every `.js`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte` file and emits one JSON
   AST file per source file. This is driven by
   [`AstGenRunner`](https://github.com/AppThreat/chen/blob/main/platform/frontends/jssrc2cpg/src/main/scala/io/appthreat/jssrc2cpg/utils/AstGenRunner.scala).
2. **CPG ingestion (in process).** `AstCreationPass` reads the JSON and materialises `METHOD`,
   `TYPE_DECL`, `CALL`, `BLOCK`, `LOCAL`, control-flow, and AST nodes.

Because the AST alone cannot resolve `require()`/`import` targets or propagate types across
assignments, a set of **post-processing passes** runs after the base overlays to reconstruct
that semantic information.

Source:
[platform/frontends/jssrc2cpg](https://github.com/AppThreat/chen/tree/main/platform/frontends/jssrc2cpg)

## Config Fields (real names from `Main.scala`)

```scala
final case class Config(
  tsTypes: Boolean      = true,   // generate types via the TypeScript compiler (--no-tsTypes to disable)
  flow: Boolean         = false,  // enable Flow mode  (astgen -t flow)
  astGenOutDir: Option[String] = None  // permanent astgen output dir (reuse JSON between runs)
) extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]
```

The `TypeRecoveryParserConfig` mix-in adds `disableDummyTypes` and `typePropagationIterations`
(with `withDisableDummyTypes` / `withTypePropagationIterations`).

## Pass Pipeline (`JsSrc2Cpg.createCpg`)

Inside `createCpg`, after `astgen` runs:

1. **AstCreationPass** — ingests every JSON AST file; builds the structural graph.
2. **TypeNodePass** — materialises `TYPE` nodes from `astCreationPass.allUsedTypes()`.
3. **JsMetaDataPass** — writes the `MetaData` node and a SHA-256 hash of the parsed files.
4. **BuiltinTypesPass** — seeds builtin JS/TS types (`Object`, `Array`, `String`, …).
5. **ConfigPass** — creates `CONFIG_FILE` nodes (`package.json`, `tsconfig.json`, …).
6. **PrivateKeyFilePass** — flags files that look like embedded private keys.
7. **ImportsPass** — creates `IMPORT` nodes from the AST import statements.

`createCpgWithOverlays` then runs the default overlays: **Base**, **ControlFlow**,
**TypeRelations**, **CallGraph** (see `X2Cpg.scala`).

### Post-processing passes

`JsSrc2Cpg.postProcessingPasses` (run by `createCpgWithAllOverlays`, and by the `atom` CLI) adds:

1. **JavaScriptInheritanceNamePass** — resolves `extends` parent/child relationships.
2. **ConstClosurePass** — links `const`-assigned closures to their definitions.
3. **ImportResolverPass** — resolves CommonJS `require()` and ES6 `import` to their targets.
4. **JavaScriptTypeRecoveryPass** — iterative interprocedural type propagation (extends the
   shared `XTypeRecovery` framework; iteration count from `typePropagationIterations`).
5. **JavaScriptTypeHintCallLinker** — links call sites to methods once a type hint is known.

> Note: the standalone frontend and `atom` both run these. When `atom` drives the build it also
> applies `TypeHintPass` (the atom-level call linker that uses `:` as the method-name separator).

## CLI Flags (`jssrc2cpg` standalone)

| Flag                          | Config field                                     |
| ----------------------------- | ------------------------------------------------ |
| `--no-tsTypes`                | `tsTypes=false`                                  |
| `--flow`                      | `flow=true`                                      |
| `--astgen-out d`              | `astGenOutDir`                                   |
| `XTypeRecovery.parserOptions` | `disableDummyTypes`, `typePropagationIterations` |

## Real Commands and Code Examples

### atom CLI (`-l ts` / `-l js` / `-l javascript` / `-l typescript` / `-l flow`)

```bash
atom -l ts -o app.atom /path/to/typescript/project
```

### Reuse astgen output between runs

`astGenOutDir` (also honoured via the `CHEN_ASTGEN_OUT` environment variable) points astgen at a
permanent directory. If valid `.json` files already exist there, the expensive parse step is
skipped:

```bash
CHEN_ASTGEN_OUT=/tmp/astgen-cache atom -l js -o app.atom /path/to/js/project
```

### Build with the Scala API (mirrors what atom does)

```scala
import io.appthreat.jssrc2cpg.{JsSrc2Cpg, Config}
import io.appthreat.jssrc2cpg.passes.{
  ConstClosurePass, ImportResolverPass,
  JavaScriptInheritanceNamePass, JavaScriptTypeRecoveryPass
}
import io.appthreat.atom.passes.TypeHintPass
import scala.util.{Success, Failure}

val config = Config()
  .withDisableDummyTypes(true)
  .withTypePropagationIterations(2)
  .withInputPath("/path/to/javascript/source")
  .withOutputPath("/tmp/js_project.atom")

new JsSrc2Cpg().createCpgWithOverlays(config) match
  case Success(cpg) =>
    new JavaScriptInheritanceNamePass(cpg).createAndApply()
    new ConstClosurePass(cpg).createAndApply()
    new ImportResolverPass(cpg).createAndApply()
    new JavaScriptTypeRecoveryPass(cpg).createAndApply()
    new TypeHintPass(cpg).createAndApply()
    println(s"Methods: ${cpg.method.size}")
    cpg.close()
  case Failure(ex) => println(s"Failed: ${ex.getMessage}")
```

### Open and query the atom file

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/js_project.atom")

// Find DOM-based XSS sinks
cpg.call.name("innerHTML|outerHTML|insertAdjacentHTML").l

// Calls into a resolved import (e.g. the express router)
cpg.call.methodFullName(".*express.*").code.take(20).l
```

### Single-file components (`.vue`, `.svelte`)

Vue and Svelte components put script, template, and style in one document. astgen flattens each
into a normal Babel AST: script statements as top-level `Program` body, and the template as
standard **JSX** nodes. Nothing Vue- or Svelte-specific reaches chen, so `AstForTemplateDomCreator`
turns the template into `TEMPLATE_DOM` nodes with no framework-specific code.

Svelte's control flow is mapped onto the JSX equivalents, which is what makes it traversable:

| Svelte                               | Emitted as                                                 |
| ------------------------------------ | ---------------------------------------------------------- |
| `{#if c}A{:else}B{/if}`              | `ConditionalExpression` with `JSXFragment` branches        |
| `{#each xs as x, i}`                 | `xs.map((x, i) => <>…</>)` — a real `map` call and closure |
| `{#await p}…{:then v}`               | `p.then(v => <>…</>, e => <>…</>)`                         |
| `{#snippet f(a)}` / `{@render f(x)}` | assignment of an arrow function / a call                   |
| `on:click={h}`, `bind:value={q}`     | `JSXAttribute` with a `JSXNamespacedName`                  |

Query the template like any other DOM:

```scala
// every directive as written in the .svelte source
cpg.templateDom.nameExact("JSXAttribute").code.l

// the closures synthesized for {#each} bodies
cpg.call.nameExact("map").l
```

Because offsets are absolute byte positions into the component file, `code` fields read back as
the original source (`on:click={increment}`, `{#each article.tagList as tag}`) and `--code-dump`
works normally.

**Template dataflow works.** An interpolated expression is wrapped in an
`<operator>.interpolation` call, which makes it a call argument and therefore a use the data
dependence graph can see. Without that wrapper an expression sitting directly inside a
`JSXExpressionContainer` had no reaching definition at all - `DdgGenerator.uses` harvests uses from
`Return` and `Call` nodes only - so `<div>{bio}</div>` and `{@html bio}` could never be reached.
That applied to React JSX and Vue equally, and is fixed for all three.

```scala
cpg.call.nameExact("<operator>.interpolation").l
cpg.call.nameExact("<operator>.interpolation").reachableByFlows(sources)
```

An expression that is _already_ a call (`{@html data.article.body}` is a field access) carries its
own uses, so no wrapper is added and the existing call is the interpolation site.

Svelte blocks and tags all map onto `JSXExpressionContainer`, so the DOM node is named after the
construct instead - `SvelteIfBlock`, `SvelteEachBlock`, `SvelteHtmlTag`, `SvelteAwaitBlock`,
`SvelteSnippetBlock`, `SvelteRenderTag`, `SvelteConstTag`, `SvelteDebugTag`, `SvelteExpressionTag`.
Elements and attributes keep their JSX names, so Vue, React and Svelte stay uniform there:

```scala
cpg.templateDom.nameExact("SvelteHtmlTag").code.l      // every {@html} site, verbatim
cpg.templateDom.nameExact("SvelteEachBlock").code.l
```

Two things still to know. A flow whose source and sink land on the _same line_ is suppressed by
`ReachableSlicing` as zero-information, because `toSlice` renders at most one node per `file#line`.
And the template statement is emitted last in the program body on purpose: Svelte hoists the
instance script, so markup renders after it even when the `<script>` tag sits below the markup.

## SvelteKit routes

SvelteKit has no route-registration call for the Express-style patterns to match — a `load`
exported from `+page.server.ts` _is_ the handler — so `ChennaiTagsPass` keys off the file name
instead:

| File                                                         | Entrypoints tagged `framework-route`                                          |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| `+page.server.*`, `+page.*`, `+layout.server.*`, `+layout.*` | `load`, plus the `actions` handlers                                           |
| `+server.*`                                                  | `GET POST PUT PATCH DELETE OPTIONS HEAD fallback`                             |
| `hooks.server.*`, `hooks.*`, `hooks.client.*`                | `handle handleError handleFetch handleValidationError init reroute transport` |

Their parameters — the request object, `{ params, url, request, cookies }` — are tagged
`framework-input`, which is what makes server-side flows surface. `actions` handlers compile to
anonymous methods (`anonymous`, `anonymous1`, …), so those are tagged alongside the named
entrypoints; named helper functions in the same file are left alone.

The request path crosses a file boundary with no edge in the graph: the server's `load` return
becomes the component's `data` prop by SvelteKit convention, not by a call or an import. The
component side is covered instead by tagging `$props()` in a `.svelte` file `framework-input` — the
component's input boundary. Paired with the `framework-output` tag on a value rendered through
`{@html}`, that closes a reportable path inside the component:

```text
+page.svelte L2  $props()                        [framework-input]
+page.svelte L6  raw
+page.svelte L7  return '<div>' + raw + '</div>'
+page.svelte L4  decorate(data.body)
```

Note that a flow whose source and sink land on the _same line_ — `const { data } = $props()` read
straight into `{@html data.body}` — is suppressed by `ReachableSlicing` as zero-information, since
`toSlice` renders at most one node per `file#line`. The value has to pass through something on
another line to be reported. Svelte 4's `export let` props are tagged at their reads (the parent
assigns the binding, so there is no producing call); `$props()` is the Svelte 5 form. The URL is
also read from `page` (`$app/state`) or the legacy `$page` store, which are tagged too.

## Frontend framework recognizers

The JavaScript side of `ChennaiTagsPass` hands most of its work to the recognizers in
`x2cpg/passes/taggers/js` - one per framework family, registered in `JsRecognizers.all`, the same
shape as the Python recognizers. Each works from structure: the import that binds a name, the
member chain a value is read from, the parameter a framework fills, the type a dependency was
injected as. None of them needs an SBOM; where a framework auto-imports its API (Nuxt, Nitro,
SvelteKit's `$app`), the project's `package.json` dependencies and file conventions are the
evidence instead.

| Recognizer | Sources | Sinks |
| --- | --- | --- |
| `DomRecognizer` (always) | `location.*`, `document.URL`/`referrer`/`cookie`, `window.name`, `message`/`hashchange` events (not when the handler compares `event.origin` by equality); as `service-ingress`, Web Storage and `fetch`/XHR/axios/ky/ofetch responses | `innerHTML`/`outerHTML`/`srcdoc` writes, `insertAdjacentHTML`, `document.write`, URL attributes, `eval`/`Function`/string timers, `location` writes, `window.open`, `postMessage(_, '*')`, `document.cookie`, requests |
| `AngularRecognizer` | `ActivatedRoute`/`Snapshot` reads and observable callbacks, resolvers/guards, `Router.url`, `Location.path()`, `@Input()`, `input()`/`model()`, `@HostListener('window:message')` and `host: { '(window:message)': ... }`, form `valueChanges`, HttpClient responses through service methods | `bypassSecurityTrust*`, `Renderer2.setProperty/setAttribute`, HttpClient and `httpResource` request URLs, `Router.navigateByUrl` |
| `ReactRecognizer` | component props, router hooks, loaders/actions, Next.js route handlers, pages, `cookies()`/`headers()`, `'use server'` functions, React 19 form actions, Qwik `routeLoader$`/`routeAction$`/`server$` | `redirect()`, `NextResponse.redirect/rewrite`, `navigate()`/`router.push()`/`<Navigate to>` with an unanchored target |
| `VueRecognizer` | `useRoute()`, `this.$route`, props (also the Options API), guards, directive bindings, Nuxt request composables, `useFetch`/`useAsyncData` | `navigateTo(_, { external })`, `useHead` scripts, `h()` with `innerHTML`, router navigation |
| `NitroRecognizer` | `defineEventHandler` events, h3 readers, task payloads | `sendRedirect`, `send`, markup returned by a handler, `proxyRequest`, server `$fetch`, `useStorage` keys |
| `SvelteRecognizer` | `load`/endpoint/hook parameters, `$props()`, `export let`, `page`/`$page`, `use:` action values | `redirect()`, `goto()` |
| `NodeRecognizer` | server HTTP client responses | `child_process` (also through `promisify`), `fs`, `vm`, computed `require`, SQL strings (pg, mysql2, sqlite3, `@appthreat/sqlite3`, better-sqlite3, `node:sqlite`, knex, prisma, db0, ...) |
| `LitRecognizer`, `JQueryRecognizer`, `EmberRecognizer`, `AstroRecognizer` | `@property()`, ajax responses, `model(params)`, the `Astro` global, endpoint/middleware/action context | `unsafeHTML`, `.innerHTML=${}`, `$(html)`, `.html()`, `$.globalEval`, `htmlSafe`, `redirect()` |

**Vocabulary.** Sources are `framework-input` (attacker data) or `service-ingress` (remote data).
Sinks are `framework-output`, `code-execution`, `http-client` (`ssrf` on the server), `sql`,
`shell-exec` and `file-io`, and HTML/navigation sinks also carry a category - `xss` or `redirect` -
so that a sanitiser declaring it (`sanitizer-xss` on `DOMPurify.sanitize`, `sanitizer-redirect`
on `encodeURIComponent`) neutralises exactly the flows it protects. A call whose result is a
boolean or a number about its arguments (`allow.has(x)`, `url.startsWith('/')`) is a
`predicate`: a flow through its result carries nothing.

**What is not a sink.** A value that the code anchors cannot be redirected: a request to
`/search?q=${q}` or a navigation to `'/search?q=' + q` keeps its origin, and a template `href`
starting with `/` can never become `javascript:`. A variable in the *path* of a fixed URL
(`/api/items/${id}`) is client-side path traversal and is a sink; a variable base
(`${this.apiUrl}/items`) makes only the base one, and a URL that is configuration - a service's
own field (`this.http.put(this.host, body)`), a SCREAMING_CASE constant, `environment.*` - none.
The sink of a request is always that part of its URL, never the request call: what reaches its
body, options or receiver is no forgery. Angular's `[innerHTML]` and React 19's `href`
sanitise on their own and are not sinks; `@Output()` emitters are not sinks either - an emitted
value goes to the parent component.

**API chaining.** Data the application received or stored itself - a response, a WebSocket
message, Web Storage, all `service-ingress` - that reaches nothing but the URL of another request
is how an API is walked (an id from one response in the path of the next), and atom's reachables
drops such flows for JavaScript. The same data reaching markup or code is still reported.

**Service calls.** The frontend cannot type `this.products` in `this.products.feed(url)`; where the
member was injected as one of the project's own classes, the Angular recognizer resolves the call
to that class's method, so a value handed to a service reaches the request the service makes.

**Bridges.** Three things carry a value where no call does, and run after the recognizers:
`MemberTaintBridge` makes `this.x` a source in every method of a class when some method assigns
it from a source (`ngOnInit` storing a route parameter that a click handler uses);
`ReactiveBridge` does the same for reactive derivations (`computed`, `useMemo`, `createMemo`,
`useActionState`) and for the reads of a module-level variable inside functions, and makes a
derivation that returns a sanitiser's result a sanitiser itself.

**Package attribution.** Each sink the recognizers tag is also tagged with the `pkg:npm/...` purl
of the package its callee is bound to - an import, a member of a module binding, a handle made from
one (`pool = new pg.Pool()`), or for Angular the type a member was injected as - so reachable flows
carry purls with no SBOM. Versions come from `package-lock.json` or else the `package.json` range;
Node.js built-ins and modules no manifest declares (path aliases) get none. Sources are not
attributed: a purl tag is a sink tag for reachables. A request sink - the part of a URL - carries
the purl of the request it is passed to (`q` in `axios.get(q)`).

**Def-use edges.** Two JavaScript-only refinements in the reaching-definition edges matter as
much as any tag: a read of a read (`route.query.next`, `e.data.html`, `path.split('#')[1]`) is
connected to its inner read, and a captured variable is connected to every read inside the
closure, not only the first - a component's handlers and effects read what it took from the URL
at the top.

```text
go.tsx L12  searchParams.get("next")        [framework-input via useSearchParams()]
go.tsx L19  window.location.href = next     [framework-output, redirect]   (inside useEffect)
```

**Route tables** - Vue (`createRouter({ routes })`), Angular (`Routes` arrays,
`RouterModule.forRoot`/`provideRouter`) and React Router (`createBrowserRouter`) all lower to the
same object-property assignments, `_tmp_1.path = "/about/:id"` and `_tmp_1.component = About`. A
temp carrying a `.path` assignment plus a route-record sibling key is a route record: the path
literal is tagged `framework-route` and the rendered component becomes a handler whose parameters
are tagged `framework-input`. A router package must be imported; a **strong** sibling key
(`component`, `element`, `redirect`, `pathMatch`, `loadChildren`, `loadComponent`, `lazy`) admits
any path, a **weak** one (`children`, `loader`, `action`) also needs a route-shaped path, and a
relative filesystem value (`./src`) is never a route.

**Signal inputs** (`input()`, `input.required()`, `model()`, `model.required()` from
`@angular/core`) are found through the import, so a renamed import still counts and a local
function that happens to be called `input` does not. Not covered: an initialiser wrapped in
`as T`, `!` or a conditional, `this.x = input()` in the constructor body, and an `input` reached
through `import * as ng` or a re-export.

**Lowering details that matter for flows.** A directive prologue (`'use server'`, `'use client'`)
is emitted as the string-literal statement it is in the source - Babel keeps it apart from the
body. An optional member call (`form.get('next')?.toString()`) is a call on its object like any
member call; it used to be lowered as a call of the whole callee text with `this` for a receiver,
which cut the value off. Template literals map every part to the result and no part to another.

**Astro.** astgen lowers an `.astro` component to its frontmatter's statements followed by its
template as JSX (see atom-parsetools' `docs/ASTGEN.md`), so `Astro.url`/`Astro.params`/
`Astro.cookies` reads are sources and `set:html={x}` is a markup sink like any other JSX attribute.

## Notes for Security Analysts

- Without `ImportResolverPass`, calls into third-party modules keep a `methodFullName` of
  `<unknownFullName>` and cannot be matched by framework taggers — always run the
  post-processing passes (the `atom` CLI does this automatically).
- `tsTypes=true` invokes the TypeScript compiler during astgen; it produces far richer type
  information but is slower. Disable it with `--no-tsTypes` for very large pure-JS code bases.
- `PrivateKeyFilePass` is useful on its own for secret detection: it tags files whose content
  matches PEM/private-key patterns.
- `.vue` and `.svelte` files are also emitted as `CONFIG_FILE` nodes by `ConfigPass`, so
  `cpg.configFile.name(".*\\.svelte")` gives you the raw component text when the graph shape is
  not what you need.

### Producer-consumer links as resolved calls

A framework's producer-to-consumer link that no call site expresses - `useLoaderData()` returns
what the route's `loader` returned, a route component's `$props()` what the sibling `load`
returned, `inject(key)` what `provide(key, ...)` gave, `runTask('db:reindex')` the task file's
`run`, a store hook the `defineStore` setup - is closed by resolving the consumer call to the
producing METHOD (`JsTagger.resolveCall`). The dataflow engine then carries the callee's return
value, object taint included, out to the call result; tagging the consumer read alone would
start the flow too late. `JsTagger` records its resolutions because the CALL edges land in the
graph only when the pass ends - a same-run reader (`sourceTagThrough` on a resolved callee's
parameter) consults the record.

Two lowerings carry values that no call site names. A template's COMPONENT element
(`<RichText html={bio} />`) lowers to a call of the component with the element's first computed
attribute value as its argument - `ComponentCallBridge` resolves it to the component (import
binding, or the one project method of that name), so a parent's value reaches the component's
props parameter. An `.html` page (Alpine directives, Angular bindings) lowers like a Svelte
component: inline `x-data` objects become variables, `x-init` becomes statements, `x-html` and
`[prop]` bindings become JSX attributes (`x-html` -> `innerHTML`; a piped `[innerHTML]` is the
bypass marker, an unpiped one is sanitised and keeps a string value), and DOM-sink property
bindings additionally lower to the property write the framework performs. Angular's
`x.component.html` links to its component by the file convention: `[(ngModel)]="field"` makes
the field's `this.` reads sources, and bindings naming inputs read the component's inputs.

Validation is a neutraliser where it types the value: a `validateSearch` schema's non-text
fields (zod/valibot/yup `number`, `enum`, `boolean`, `literal`) make reads of those members of
`useSearch()` results `predicate` - a number or enum constant carries nothing to inject - while
`z.string()` neutralises nothing.
