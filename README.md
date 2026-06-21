# chen

<img src="./docs/_media/chen-logo.png" width="200" height="auto" />

Code Hierarchy Exploration Net (chen) is a code analysis library that turns source code into a queryable graph and then reasons about how data moves through it. It builds a Code Property Graph (CPG) that fuses the abstract syntax tree, control flow, and data dependencies of a program into a single structure, and layers on a data-flow engine, taint reachability, and a query language for asking precise questions about a codebase.

chen exists for two audiences. If you build program analysis tooling, it gives you a stable CPG core and a set of composable passes to extend. If you analyse software for security, it lets you trace tainted data from an attacker-controlled source to a dangerous sink across functions, files, and dependency boundaries, and decide whether a reported vulnerability is actually reachable in your application.

[![SBOM](https://img.shields.io/badge/SBOM-with_%E2%9D%A4%EF%B8%8F_by_cdxgen-FF753D)](https://github.com/cdxgen/cdxgen)

## Why chen

Most static analysis stops at the boundary of a single file or a single language. chen is built for hierarchical analysis, which means it reasons across the layers a real application is made of: your code, the libraries it pulls in, the container and operating system it runs on, and the cloud context it deploys into. A vulnerability that looks exploitable in isolation is often unreachable once you account for how the surrounding code actually calls it, and chen is designed to answer that question rather than guess at it.

The result is fewer false positives. Instead of pattern matching on function names, chen follows the data. It can tell you not just that a dangerous function exists, but whether attacker input can reach it, and whether a sanitizer or validator stands in the way along that path.

## What you can do with it

- **Variant and reachability analysis.** Determine whether a known vulnerability or weakness pattern is present, and whether it is reachable from an external entry point given your code and runtime context.
- **Taint tracking across procedures.** Trace flows from sources to sinks through call chains, with interprocedural summaries so the analysis scales to large, bundled, or transpiled codebases.
- **Semantic tagging.** Attach meaning to flows: personally identifiable information, regulated data classes such as `pci-dss`, `gdpr`, and `phi-medical`, secrets, third party tracker SDKs, and network direction tags such as `service-egress`, `service-ingress`, and `on-device-ai`. This is especially developed for mobile and Android analysis.
- **Program slicing.** Extract compact, self-contained views of a program around a point of interest for data-flow, usages, or reachables.
- **Graph export and algorithms.** Run graph algorithms such as PageRank over the CPG, or export subgraphs to GraphML and other formats for downstream tooling and machine learning.

## Languages supported

- C / C++
- C / C++ headers and pre-processed `.i` files (the `H` frontend)
- Java (requires compilation) and JAR bytecode
- Android APK and split bundles (`.apkm`, `.apks`, `.xapk`); requires the Android SDK via `ANDROID_HOME` or the container image. Split bundles are unpacked and the APKs carrying Dalvik bytecode are analysed.
- JavaScript, TypeScript, and Flow
- Python (3.x through 3.13)
- PHP (7.4 and newer recommended; 7.0 to 8.4 supported, with limited 5.x support)
- Ruby (1.8 through 3.4.x syntax; built and tested against Ruby 3.4.7)

## Requirements

- Java >= 23
- Minimum 16GB RAM

## The data-flow engine

`dataflowengineoss` ships two interchangeable reaching-definitions solvers that produce identical `REACHING_DEF` edges, so you can trade memory for verifiability.

- **Flux** (`FluxSolver`, Flow-Lattice Update eXecutor) is the default. It is a low-allocation worklist solver built on arrays and in-place bitsets, with copy-on-write definition sets so unchanged nodes share state rather than each allocating a bitset. On large methods, such as bundled or transpiled JavaScript, it uses far less memory and GC time than the classic engine.
- **Classic** (`DataFlowSolver`) is the original map-based fixpoint solver, retained as the intra-procedural kernel and for A/B comparison.

Tools select the engine through `EngineConfig.useFluxEngine`. In [atom](https://github.com/AppThreat/atom) the Flux engine and per-file fragment caching are on by default, and `--legacy-dataflow` switches back to the classic engine.

### Method flow summaries

chen can compute a context-independent flow summary for each method. A `MethodFlowSummary` records which formal parameters reach the method's return value and which reach its output parameters, plus whether the return and each output parameter can be tainted by an origin internal to the method. Because these facts are expressed over parameter and return positions rather than over the nodes of one particular call, a summary is reused at every call site.

```scala
import io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryComputer

// Build summaries for every internal method, callee before caller.
val summaries = FlowSummaryComputer.computeAll(cpg)

// Or reuse a cached set, recomputing only when a method body changed.
val cached = FlowSummaryComputer.loadOrCompute(cpg, cacheDir = ".")
```

Summaries are built in callee-before-caller order over the call graph; mutually recursive methods form a strongly connected component that is iterated to a fixpoint. The set persists two ways: as CPG-native `flow-summary` tags on each `METHOD` node, so the facts serialize with the graph and reload without recomputation, and as a single JSON file keyed on a fingerprint of the method bodies and active semantics.

Flow semantics are respected. A method with a declared semantic is summarised from that semantic rather than its body, so a declared sanitizer carries nothing to its return and a pass-through semantic forwards every non-receiver argument. When `EngineConfig.useSummaries` is set, the backward query engine prunes cross-call work that a summary proves cannot carry taint. The pruning only removes provably empty work, so reported flows are identical to a run with summaries disabled.

### Filtering flows through validators and sanitizers

`reachableByFlows` returns `Path` values, and the dataflow language layer offers two node-predicate filters that are far easier to use than the older traversal combinators:

```scala
import io.appthreat.dataflowengineoss.language.*

flows.passesThrough(_.isCall)                       // keep flows touching a matching node
flows.doesNotPassThrough(n => sanitizerIds(n.id))   // drop flows touching a matching node
```

`ChennaiTagsPass` tags calls to declared sanitizers and validators so these filters have something to match. The pass reads a `sanitizers` (and `validators`) section from `chennai.json`, or from a config string passed to its constructor:

```json
{
  "sanitizers": [
    {
      "name": "owasp-encode",
      "methods": ["org\\.owasp\\.encoder\\.Encode\\..*"],
      "categories": ["http"]
    }
  ]
}
```

Each matching call is tagged `sanitizer`, plus one `sanitizer-<category>` tag per declared category. In [atom](https://github.com/AppThreat/atom) this is exposed through `reachables --validation-config`, which drops reachable flows that pass through a sanitizer covering the flow's sink category.

## Performance tuning

These runtime knobs apply to any tool built on chen and overflowdb2. Pass them as JVM `-D` flags; no rebuild is required.

- **`-Dodb.storage.compression=none|lzf|deflate`** selects the compressor for nodes spilled to disk when the graph overflows the heap. On large codebases the spill and save path is single-threaded and often dominates generation and slicing time. `deflate` (the default) produces the smallest store but is markedly slower; `lzf` is several times faster for a modest size increase; `none` skips compression. The compressor is recorded per chunk, so a store written with one mode loads fine under another. Giving the JVM more heap with `-Xmx` reduces spilling altogether.
- **`-Dchen.cache.disabled=true`** (or `-Dchen.cache.disabled.<kind>=true`) disables the AST, CPG, and summary caches for A/B comparison or troubleshooting.

## Documentation

The [documentation site](https://github.com/AppThreat/chen) includes a CLI reference, a guide to the traversal query language, a comparison of the Flux and classic engines, and a series of lessons covering each language frontend, the shared `x2cpg` core, custom taggers and traversals, the data-flow engine, reachability and semantics, flow summaries, program slicing, the on-disk atom format, and graph export and algorithms.

## Origin of chen

chen is a fork of the [joern](https://github.com/joernio/joern) project. We deviate in two deliberate ways:

- We keep the CPG implementation at version 1.0, faithful to the original paper.
- We enable broader hierarchical analysis spanning application, dependency, container, operating system, cloud, and beyond.

We do not aim for bug-to-bug compatibility and often rewrite upstream patches to suit our needs, and we do not adopt features or passes that add nothing to hierarchical analysis.

## License

Apache-2.0

## Enterprise support

Enterprise support, including custom language development and integration services, is available from AppThreat Ltd.

## Sponsors

YourKit supports open source projects with innovative and intelligent tools for monitoring and profiling Java and .NET applications. YourKit is the creator of <a href="https://www.yourkit.com/java/profiler/">YourKit Java Profiler</a>, <a href="https://www.yourkit.com/dotnet-profiler/">YourKit .NET Profiler</a>, and <a href="https://www.yourkit.com/youmonitor/">YourKit YouMonitor</a>.

![YourKit logo](./docs/yklogo.png)
</content>
</invoke>
