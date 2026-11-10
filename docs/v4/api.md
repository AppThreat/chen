# chen 4.0 API changes and migration

This page is for code that uses chen as a library: atom, and any Scala or Java tool that builds
graphs with chen's frontends, runs its passes or queries the data-flow engine. It lists what
changed between chen 3.4.0 and 4.0.0 in the build, the semantic CPG layer (`semanticcpg`), the
data-flow engine (`dataflowengineoss`) and the shared frontend library (`x2cpg`), and what to
change when upgrading. Language-specific changes are in [the frontends document](frontends.md).

chen itself has no command line. Slicing, export and the CLI are in
[atom](https://github.com/AppThreat/atom), which uses the APIs described here.

## Upgrading in brief

1. Build with Scala 3.10.0 or later, and keep JDK 23 or newer.
2. Depend on `io.appthreat` artifacts version 4.0.0 from GitHub Packages, as before.
3. If you build `Semantics` yourself for C or C++ graphs, add the C flows
   (see [semantics](#the-default-semantics-are-language-neutral)).
4. Do not mutate `DefaultSemantics.memoised`.
5. Expect more `REACHING_DEF` and `CALL` edges on C and C++ graphs, fewer flows through
   comparison and arithmetic operators, and many new tags.
6. The data-flow layer now uses the Flux solver by default; set `useFluxEngine = false` for the
   classic one.
7. Rebuild AST caches: chen 3.4 caches are not reused.

## Build and dependencies

| | chen 3.4.0 | chen 4.0.0 |
|---|---|---|
| Scala | 3.8.4 | 3.10.0 |
| sbt | 1.x | 2.0.10 |
| JDK | 23 or newer | 23 or newer (CI builds with 25 and tests 23, 25 and 26) |
| cpg2 / overflowdb2 | 3.0.5 | 3.1.2 |

The organisation is still `io.appthreat`, and the published artifacts are `semanticcpg`,
`dataflowengineoss`, `x2cpg`, `platform` and one per frontend: `c2cpg`, `javasrc2cpg`,
`jimple2cpg`, `jssrc2cpg`, `php2atom`, `pysrc2cpg`, `ruby2atom`, and the new **`edg2atom`**. Test
jars are still published. They are hosted on GitHub Packages, so a consumer needs the resolver
and a token:

```scala
resolvers += "GitHub Package Registry" at "https://maven.pkg.github.com/appthreat/_"
credentials += Credentials(
  "GitHub Package Registry", "maven.pkg.github.com", "appthreat", sys.env.getOrElse("GITHUB_TOKEN", ""))
libraryDependencies += "io.appthreat" %% "dataflowengineoss" % "4.0.0"
```

Scala 3 artifacts compiled with 3.10 can only be read by a compiler of 3.10 or later. Scala 3.10
also drops auto-tupling, and `->` in `Predef` became an extension method, so
`node.has(Properties.CODE -> code)` no longer builds a property. Use the two-argument form,
`has(Properties.CODE, code)`, or `Properties.CODE.of(code)`; overflowdb2 3.1 restores `->` for
property keys where `overflowdb.*` is imported.

The schema of the graph is unchanged (see [cpg2](cpg2.md)), and so is the format of saved graphs
(see [overflowdb2](overflowdb2.md)).

## Data-flow engine

### Flux is the default solver

`OssDataFlowOptions.useFluxEngine` now defaults to `true`, so the `dataflowOss` layer computes
reaching definitions with `FluxReachingDefPass`, the low-allocation worklist solver, instead of
`ReachingDefPass`. Both build the same problem and produce identical `REACHING_DEF` edges; Flux
uses much less memory and garbage collection time on large methods such as bundled JavaScript.
atom already used Flux by default. To keep the classic solver:

```scala
new OssDataFlow(new OssDataFlowOptions(useFluxEngine = false)).run(new LayerCreatorContext(cpg))
```

The other defaults are unchanged: `maxNumberOfDefinitions = 4000`, `maxNumberOfCfgNodes =
50000`, and `EngineConfig(maxCallDepth = 3, useSummaries = false, ...)`. The
[engine comparison](../FLOW_ENGINE_COMPARISON.md) explains both solvers and flow summaries.

### More passes in the data-flow layer

After reaching definitions and `StaticMemberDefUsePass`, the layer now runs
`GlobalVariableDefUsePass` and `MemberDefUsePass`. They add `REACHING_DEF` edges between methods
for C and C++ globals (`VARIABLE` is the global's name) and struct members (`<owner>.<member>`),
which per-method reaching definitions cannot see. Both do nothing on graphs of other languages.
Code that relies on pass indices in `runPass` sees them shift.

### The default semantics are language neutral

`DefaultSemantics()` used to include the C library flows for every graph. A summary keyed on a
bare name then applied to a same-named function in any language, so the C flows are now added
per graph:

- `DefaultSemantics()` is `operatorFlows ++ javaFlows`.
- `DefaultSemantics.flowsForLanguage(language)` returns the flows for one language: `cFlows` for
  C and NEWC, `phpFlows` for PHP, request-reader flows for JVM languages and `javaScriptFlows`
  for JavaScript.
- `OssDataFlow` adds `flowsForLanguage` for the graph's language itself.
- `DefaultSemantics.cSemantics()` is the full C set, `operatorFlows ++ javaFlows ++ cFlows`.
  `phpSemantics()` no longer includes the C flows.

If you build an `EngineContext` with your own `Semantics` for a C or C++ graph, add the C flows:

```scala
given Semantics = DefaultSemantics.cSemantics()
// or, for any language:
given Semantics = Semantics.fromList(
  DefaultSemantics().elements ++ DefaultSemantics.flowsForLanguage(cpg.metaData.language.head))
```

`EngineContext`'s default semantics, and the default arguments of `ddgIn` and `ddgInPathElem`,
are now `DefaultSemantics.memoised`, one shared lazily built instance instead of a new one per
call. It must not be mutated, except by `loadRegexSemantics`, which the engine calls itself.

### Operator and library flows

- **Value operators** pass taint from each operand to the result only, not between operands:
  subtraction, multiplication, division, exponentiation, modulo, shifts, bitwise and logical
  operators, comparisons, `not`, `minus` and `plus`. Addition keeps its old, permissive flows, so
  string concatenation still carries taint. Queries that relied on taint moving between the
  operands of a comparison find fewer flows.
- `<operator>.pointerToMember` and `<operator>.indirectPointerToMember` pass their base to the
  result. `alignOf`, `typeId`, `parameterPackSize` and `noexcept` carry no flows.
- The C flows are much larger: the C library (copying, reading, formatting, allocation), the
  FORTIFY `__*_chk` wrappers, `__builtin_*` spellings, clamping macros such as FFmpeg's `FFMIN`,
  and resolved C++ constructors and operators.
- JavaScript template operators (`<operator>.formatString`, `interpolation`, `jsxProps`) read
  their arguments without redefining them, and a JavaScript implicit `this` receiver is not a
  definition.

### Argument binding

`io.shiftleft.semanticcpg.utils.ArgumentBinding` binds arguments to parameters the way each
language does: by position, by keyword, through `*args`/`**kwargs`, spreads, splats and
variadics. `Signature.of(method)` describes a method's parameters, `argumentsBinding(call, param)`
returns the arguments that bind to a parameter, and `parametersBound(arg, params)` the parameters
an argument binds to. Python positional-only and keyword-only parameters are tagged
`parameter-kind`.

These steps now use it instead of matching `argumentIndex` with the parameter index:
`MethodParameterTraversal.argument`, `MethodParameterOutTraversal.argument`,
`ExpressionMethods.parameter`, and the engine's argument-to-parameter task creation. Their
signatures are unchanged, but results differ for Python, PHP, Ruby, JavaScript and C variadic
calls. `MethodParameterTraversal.argument` now considers only `Call` call sites.

### Other engine changes

- `FlowSummaryComputer.computeAll` writes one summary per method full name, preferring the method
  with a body (a C or C++ definition over its prototype).
- Failures of the engine and of starting points are logged as warnings instead of being dropped.
- `reachableByFlows` uses sets for membership checks and `DdgGenerator` can share a cache across
  methods (`DdgSharedCache(sharedAcrossMethods = true)`); the flows are the same.

## Shared frontend library (x2cpg)

| Change | Notes |
|---|---|
| `X2CpgConfig.externalPaths`, `withExternalPaths(regex)`, `--external-paths` | Marks vendored code external in every source frontend. `ExternalPathsPass.applyTo(cpg, pattern)` and `ExternalPathMatcher` can be used directly. |
| `Ast` has `taggedByEdges` and `withTaggedByEdge(src, dst)` | Frontends attach tags while building the AST. The new parameter has a default, so source code compiles, but positional pattern matches on `Ast(...)` and binary compatibility break. |
| `FunctionPointerCallLinker` | Part of `CallGraph.passes`; adds `CALL` edges for C function pointers. |
| `InternalLinkage`, `RubyCallLinker` | Internal linkage for C statics and C++ unnamed namespaces; callee names for Ruby project methods. |
| `SourceDecoding`, `UnicodeSkeleton`, `SourceIntegrityPass` | Source decoding by byte-order mark, and the Unicode integrity tags. |
| `Scope.snapshot` and `restore` | Save and restore a frontend's scope stack. |
| `AstFragment.CacheRevision`, `AstFragment.NewNodeProperties` | Fragment cache key revision and the property reader for overflowdb2's fragment codec. |
| `ExternalCommand.runWithResult(..., timeoutMillis, extraEnv)` | Timeouts that kill the process tree, and extra environment for the child. |
| `DdgGenerator(semantics, sharedCache)` | New constructor parameter with a default. |

The memory-safety overlay for C and C++ is a set of library passes in
`io.appthreat.x2cpg.passes.taggers`, run in this order: `MemorySemanticsPass`, `MemoryApiPass`,
`ExtentPass`, `GuardPass`, `ValueOriginPass`, `IntegerWidthPass`, `AllocationStatePass` and
`MemorySafetyFindingPass`. They read the facts the C frontends record and the API vocabulary in
`memory-apis.json`, and report findings as `ms-finding` tags with a rule id. chen's frontends do
not run them; the caller does.

### New traversal helpers

- `TagTraversal.expression` and `TagTraversal.taggedNode`, to go from tags to what they tag.
- `TypeDeclTraversal.preferredDeclaration(decls)`, now used by `unravelAlias`, picks one
  declaration deterministically when several share a name.
- `MethodRefIndex.referencing(graph, methodFullName)` and `ImplicitReceiver` in the query engine.
- `GlobalScopeMethodNames` (`<module>`, `:package`) in `io.appthreat.dataflowengineoss`.

## Tags and properties

chen 4.0 adds no node or edge types; new facts are tags. The ones a consumer is most likely to
query:

| Tags | Written for | Meaning |
|---|---|---|
| `external-path` | methods in vendored paths | Marked external by `--external-paths` (type declarations get `IS_EXTERNAL` only). |
| `frontend` = `edg` or `cdt` | C/C++ `FILE` nodes | Which parser built the file. |
| `include-resolved-path`, `include-system` | C/C++ `IMPORT` | The header an include resolved to, and whether it is a system header. |
| `callee-declared-in`, `ref-declared-in`, `type-declared-in`, `constructs-type` | C/C++ calls, references, types | The header that declares what is used. |
| `macro-invocation`, `macro-parent`, `macro-origin`, `macro-argument-copy`, `nested-macro`, `macro-use` | C/C++ | Macro provenance. |
| `const-value`, `ptr-arith`, `ref`, `fn-attr`, `storage-class`, `object-size`, `pointee-size`, `flexible-member`, `capture`, `type-storage`, `alloc-form` | C/C++ | Facts for memory-safety analysis. |
| `implicit-conversion`, `virtual-call`, `default-argument`, `vla-size`, `compiler-generated`, `lifetime-end`, `asm-operand`, `asm-name`, `operator-call`, `template-instance` | C/C++, mostly from EDG | What the compiler resolved. |
| `unicode-confusable`, `unicode-bidi-control`, `unicode-hidden-code` | all | Unicode integrity findings. |
| `parameter-kind`, `lazy-import`, `sandbox-render`, `ai-model-artifact` | Python | Parameter kinds, PEP 810 lazy imports, template sandboxes, AI model loading. |
| `proxy-derived`, `trusted-proxy-config`, `trusted-proxy-headers`, `forwarded-header-read` | calls, five languages | Values derived from forwarded headers and the proxy trust settings. |
| `framework-data`, `predicate` and npm package URLs on sinks | JavaScript | Framework recognizers and package attribution. |
| `callsites-*` | JavaScript, Python, Java, PHP | Facts atom's callsites slice reads. |
| `memory-safety`, `ms-finding`, `ms-confidence` and `mem-*` | C/C++ | Written by the memory-safety overlay when it runs. |

The tag names are constants in `io.appthreat.x2cpg.Defines`, `io.appthreat.c2cpg.astcreation.Defines`
and the tagger objects in `io.appthreat.x2cpg.passes.taggers`.

## Caches

The AST cache key of each frontend changed (new parser options, lowering revisions, the
`astgen` engine, the fragment revision), so chen 4.0 does not replay caches written by 3.4; the
first run rebuilds them. `chen.cache.disabled`, `chen.cache.disabled.<kind>` and
`chen.cache.enabled.<kind>` still control caching, and the default cache directory is still
`<input>/.chen`.

## Removed

- c2cpg's `io.appthreat.c2cpg.parser.ParserConfig`; per-file settings now come from
  `ProjectSources`.
- The `generateScaladocs` build task and `project/SbtHelper.scala`.
- cpg2's `odb.forkjoinpass.explicitGc` system property.
