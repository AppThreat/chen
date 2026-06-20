# Lesson 9: AST Caching and Fragment Cache Control

### Learning Objective

Configure AST caching, CPG caching, summary caching, and fragment caching to optimize CPG construction and accelerate repeated static analysis runs, using the real `CacheControl` API.

### Pre-requisites

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen).

### Conceptual Background

Building a CPG for a large project involves expensive phases: invoking external AST generators (astgen/rbastgen), parsing, lowering to CPG nodes, and computing dataflow summaries. When the same project is analyzed repeatedly, or only a few files change, recomputing everything is wasteful. Chen centralizes these decisions in one object:

[CacheControl](https://github.com/AppThreat/chen/tree/main/platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/frontend/CacheControl.scala)
— `object CacheControl` in package `io.appthreat.x2cpg.passes.frontend`.

#### Cache kinds

Each cache is identified by a `String` constant:

```scala
object CacheControl:
  final val Ast: String     = "ast"      // parsed/lowered AST artifacts
  final val Cpg: String     = "cpg"      // serialized CPG fragments
  final val Astgen: String  = "astgen"   // external astgen output
  final val Summary: String = "summary"  // computed method-flow summaries
```

**Defaults differ per kind** and are intentionally conservative:

- `Ast` and `Astgen` are **ON** by default — reparsing/regenerating is the most common waste.
- `Cpg` and `Summary` are **OFF** by default — they are opt-in because they trade disk/memory for speed and are less universally safe.

#### API surface

The object is backed by `@volatile private var allDisabled`, a `TrieMap[String, Boolean]` of per-kind overrides, and `@volatile private var fragmentsEnabled`. The public methods are:

```scala
def isEnabled(kind: String): Boolean   // resolve final state for a kind
def disableAll(): Unit
def enableAll(): Unit
def disable(kind: String): Unit
def enable(kind: String): Unit

// Fragment caching is a separate toggle from the per-kind caches:
def useFragments: Boolean
def enableFragments(): Unit
def disableFragments(): Unit
```

> Note: there is no `isActive`, no `clear()`, and no `Profile` concept — those appeared in earlier drafts and are not part of the real API. Use `isEnabled`, `enable`, and `disable`.

#### System properties

`isEnabled(kind)` resolves in this precedence: explicit `enable`/`disable` override (the `TrieMap`) → `allDisabled` → system properties → per-kind default. The recognized properties are:

- `chen.cache.disabled` — master kill switch (maps to `disableAll`)
- `chen.cache.disabled.<kind>` — disable a specific kind, e.g. `chen.cache.disabled.summary`
- `chen.cache.enabled.<kind>` — enable a specific kind, e.g. `chen.cache.enabled.cpg`
- `chen.cache.fragments` — toggle fragment caching (`useFragments`)

So you can steer caching without code, for example:

```bash
java -Dchen.cache.enabled.summary=true -Dchen.cache.fragments=true ...
```

### Real Commands and Code Examples

#### 1. AST cache CLI flags (c2cpg)

The C frontend exposes the AST cache directly on the command line:

```bash
# Enable the AST cache and choose a cache directory.
./atom.sh -l cpp -o app.atom --frontend-args "--enable-ast-cache,--cache-dir,/tmp/ast_cache" /path/to/project
```

The corresponding `c2cpg` flags are `--enable-ast-cache` / `--no-ast-cache`, `--cache-dir <dir>`, and `--only-ast-cache` (populate the cache and stop, without producing a full atom).

#### 2. Configuring CacheControl programmatically

```scala
import io.appthreat.x2cpg.passes.frontend.CacheControl

// AST and astgen caching are already ON by default.
// Opt into the (default-off) CPG and summary caches for a heavy re-analysis run:
CacheControl.enable(CacheControl.Cpg)
CacheControl.enable(CacheControl.Summary)

// Turn on mini-graph fragment caching to speed up incremental stitching.
CacheControl.enableFragments()

// Guard expensive summary loading on the resolved state:
if CacheControl.isEnabled(CacheControl.Summary) then
  println("Method-flow summary cache is active.")

// For a clean, reproducible benchmark, disable everything:
CacheControl.disableAll()
```

#### 3. Selectively disabling one kind

```scala
import io.appthreat.x2cpg.passes.frontend.CacheControl

// Keep astgen/ast caching but force CPG fragments to be rebuilt this run.
CacheControl.disable(CacheControl.Cpg)
assert(!CacheControl.isEnabled(CacheControl.Cpg))
```

### How the caches interact with stitching

Fragment caching (`useFragments`) is what lets `StitchPass` (Lesson 8) and `FragmentSplicePass` warm-restore previously serialized mini-graphs instead of regenerating them, while the `Summary` cache stores the interprocedural `MethodFlowSummary` results so reachability/dataflow queries skip recomputation on subsequent runs.

### Summary

`CacheControl` is a small, explicit switchboard: four string-keyed cache kinds (`ast`/`astgen` ON, `cpg`/`summary` opt-in), a separate fragments toggle, and system-property overrides. Use `enable`, `disable`, `isEnabled`, `enableFragments`, and `disableAll` — not the older `isActive`/`clear`/profile API.
