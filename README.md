# chen

<img src="./docs/_media/chen-logo.png" width="200" height="auto" />

Code Hierarchy Exploration Net (chen) is a code analysis library that represents a program as a graph and reasons about how data moves through it. The graph fuses the abstract syntax tree, control flow, and data dependencies of a program into one queryable structure, so that a question like "can untrusted input reach this dangerous call" becomes a graph traversal rather than a guess.

chen is the analysis core behind AppThreat's [atom](https://github.com/AppThreat/atom). It is written in Scala 3, runs on the JVM, and ships frontends for a wide range of languages.

[![SBOM](https://img.shields.io/badge/SBOM-with_%E2%9D%A4%EF%B8%8F_by_cdxgen-FF753D)](https://github.com/cdxgen/cdxgen)

## Who it is for

If you build program analysis tooling, chen gives you a stable Code Property Graph core, a library of composable passes, and a traversal language for writing your own queries. You can add taggers, frontends, and overlays without rebuilding the foundation.

If you analyse software for security, chen lets you follow tainted data from an attacker-controlled source to a sensitive sink across functions, files, and dependency boundaries, and decide whether a reported vulnerability is genuinely reachable in your application and runtime context.

## What sets it apart

chen is built for hierarchical analysis. A real application is not one layer of code but several stacked together: the code you write, the libraries it depends on, the container and operating system it runs inside, and the cloud it deploys to. chen is designed to reason across those layers rather than stop at a file or language boundary.

Because it follows data rather than matching on names and patterns, chen distinguishes a dangerous function that exists from one that is actually reachable, and it accounts for sanitizers and validators that neutralize input along the way. In practice this is what separates a finding worth acting on from noise, and it is why the analysis can keep false positives low on large codebases.

## What you can do with it

- Run variant and reachability analysis to decide whether a known weakness pattern is present and exploitable given how your code actually calls it.
- Trace taint from sources to sinks across call chains, with interprocedural summaries that keep the analysis tractable on large, bundled, or transpiled code.
- Attach semantic meaning to flows, including personally identifiable information, regulated data such as `pci-dss`, `gdpr`, and `phi-medical`, secrets, third party tracker SDKs, and network direction such as `service-egress`, `service-ingress`, and `on-device-ai`. This is developed with mobile and Android analysis in mind.
- Slice a program down to a compact, self-contained view around a point of interest for data-flow, usages, or reachables.
- Export subgraphs and run graph algorithms such as PageRank over the Code Property Graph for downstream tooling and machine learning.

## Languages supported

- C and C++, including headers and pre-processed `.i` files through the `H` frontend
- Java (requires compilation) and JAR bytecode
- Android APK and split bundles (`.apkm`, `.apks`, `.xapk`), which require the Android SDK via `ANDROID_HOME` or the container image
- JavaScript, TypeScript, and Flow
- Python, from 3.x through 3.13
- PHP, from 7.0 through 8.4 with limited 5.x support, 7.4 and newer recommended
- Ruby, supporting 1.8 through 4.0.x syntax

## Requirements

- Java 23 or newer
- At least 16GB of RAM

## How the analysis works

chen builds a graph from source and then enriches it with overlay passes. The data-flow engine computes reaching definitions to power taint queries, and the query language lets you express sources, sinks, and the conditions between them.

Two reaching-definitions solvers are available and produce identical results, so you can choose between throughput and a conservative reference implementation. The default Flux solver is a low-allocation worklist engine that uses far less memory and garbage collection time on large methods such as bundled JavaScript, while the classic solver remains for comparison. On top of this, chen computes reusable per-method flow summaries that let the engine skip cross-call work it can prove carries no taint, which keeps interprocedural analysis fast without changing the flows that are reported.

Taint queries can be refined with semantics that describe how individual functions propagate data, and with sanitizer and validator declarations that drop any flow neutralized before it reaches a sink. The result is a query that reflects how the program behaves, not just how it is shaped.

For the full picture, including the traversal query language, the engine internals, custom taggers, program slicing, the on-disk format, and graph export, see the [documentation and lessons](./docs).

## Origin of chen

chen began as a fork of the [joern](https://github.com/joernio/joern) project and has diverged deliberately. It keeps the Code Property Graph implementation at version 1.0, faithful to the original paper, and it extends analysis across the application, dependency, container, operating system, and cloud layers. chen does not aim for bug-to-bug compatibility with joern, often rewrites upstream patches to fit its needs, and leaves out features that add nothing to hierarchical analysis.

## License

Apache-2.0
