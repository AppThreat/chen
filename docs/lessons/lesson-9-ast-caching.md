# Lesson 9: AST Caching and Fragment Cache Control

### Learning Objective

Configure AST caching and fragment caching to optimize CPG construction and accelerate repeated static analysis queries.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone of [chen](https://github.com/AppThreat/chen).

### Conceptual Background

Generating Code Property Graphs for large codebases involves expensive parsing and AST structure compilation phases. To optimize repeated analyses (e.g. running multiple rules over the same project or analyzing incremental changes), the system uses caching.

Caching is managed by the **[CacheControl](https://github.com/AppThreat/chen/blob/main/platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/frontend/CacheControl.scala)** object, which handles:

- **AST Caching**: Caching raw AST parser outputs (e.g. from CDT or Soot) so that compiler frontends can skip parsing files that have not changed.
- **Mini-Graph Fragment Caching**: Storing serialized subgraphs of individual files to accelerate graph stitching.
- **Method Flow Summaries Caching**: Caching computed data-flow properties to speed up subsequent reachability queries.

Cache directory structures are managed by the command line `--ast-cache-dir` flag and environment variables like `CHEN_ASTGEN_OUT`.

### Real Commands and Code Examples

#### 1. Running Compilation with Active AST Caching

Compile a project, enabling the AST cache and pointing to a custom cache directory:

```bash
./atom.sh -l cpp -o app.atom --frontend-args "enable-ast-cache=true,ast-cache-dir=/tmp/ast_cache/" /path/to/cpp/project
```

#### 2. Configuring CacheControl Programmatically in Scala

Below is a code example showing how to enable and manage cache profiles programmatically:

```scala
import io.appthreat.x2cpg.passes.frontend.CacheControl

// Enable parsing fragment caches
CacheControl.enableFragments()

// Enable method flow summary caching (used by reachables engine)
CacheControl.enable(CacheControl.Summary)

// Check if a cache profile is active
if (CacheControl.isActive(CacheControl.Summary)) {
  println("Method-flow summary cache is active.")
}

// Clear cached items to free memory
CacheControl.clear()
```
