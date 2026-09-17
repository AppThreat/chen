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
another line to be reported. Svelte 4's `export let` props are not tagged; `$props()` is the
Svelte 5 form.

## Angular, React and Vue routes and props

The three component frameworks are recognised by `ChennaiTagsPass` from shapes the frontend already
emits, not by pattern-matching source text.

**Route tables** — Vue (`createRouter({ routes })`), Angular (`Routes` arrays,
`RouterModule.forRoot`/`provideRouter`) and React Router (`createBrowserRouter`) all lower to the
same object-property assignments, `_tmp_1.path = "/about/:id"` and `_tmp_1.component = About`. A
temp carrying a `.path` assignment plus a route-record sibling key is a route record: the path
literal is tagged `framework-route` and the rendered component becomes a handler whose parameters
are tagged `framework-input`. An object that merely has a `path` property is not a route record.

Three independent guards keep ordinary objects out, because a bad route is not just a noisy tag —
it surfaces in slice output as an application route. A router package must be imported at all.
Sibling keys are then split by how route-specific they are: a **strong** key names something to
render or somewhere to go (`component`, `element`, `redirect`, `pathMatch`, and the lazy forms
`loadChildren`, `loadComponent`, `lazy`) and admits any path, since child routes are written with
bare relative segments; a **weak** key (`children`, `loader`, `action` — which also describe file
trees, bundler configs and menus) additionally requires a route-shaped path. And a relative
filesystem value (`./src`) is never a route. The conservative edge: an Angular parent route written
as `{ path: 'admin', children: [...] }` — bare path, no component — is missed, while
`{ path: '/admin', children: [...] }` is found; its children carry components and are found either
way.

**React** — `<Route path="/profile" element={<Profile />} />` tags the path attribute's literal and
resolves the rendered component (from the identifier, or from the JSX tag name when the value is an
element — the `JSXIdentifier` carries no reference edge). `useParams`, `useSearchParams` and
`useLocation` are tagged `framework-input` — the URL reaches a component through those hooks. And a
capitalized method that renders a template is a React component by the framework's own naming
rule, so its first (props) parameter is web-facing input:

```text
app.jsx L2  useParams()          [framework-input]
app.jsx L4  __html: bio          [framework-output]   ← dangerouslySetInnerHTML
```

**Vue** — `defineProps`/`withDefaults`/`defineModel` calls and `useRoute()` are
`framework-input`, as is the props parameter of an options-API `setup(props)` method. Since
atom-parsetools 4.3.0 a directive value like `v-html="content"` keeps a reference to the script
binding, so a props-to-raw-HTML path inside one component is reportable end to end.

**Angular** — `@Input()` members and their `this.x` reads are `framework-input` (matched
exactly, so an `@Input() id` does not taint `this.idx`), `@Output()` members are
`framework-output`, `ActivatedRoute` reads are input — whether the field is named `route` or
`activatedRoute` (`route.params`, `this.activatedRoute.snapshot.queryParams`,
`paramMap.get(...)`), and a `bypassSecurityTrust*` call — the sanitizer escape hatch that feeds
`[innerHTML]`-style bindings — is output.

**Next.js and Nuxt** file conventions are keyed off the file name, like SvelteKit: an app-router
`route.ts` tags its HTTP-verb exports, a `pages/api` handler tags every export, `middleware.ts`
and the `getServerSideProps`/`getStaticProps`/`generateMetadata` loaders are entrypoints; Nuxt
tags `defineEventHandler`/`eventHandler` lambdas and the exports of `server/api`/`server/routes`
files, with the h3 request readers (`readBody`, `getRouterParam`, `getQuery`, …) as input.

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
