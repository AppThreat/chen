# Lesson 8: Modular Mini-Graph Stitching and Incremental Linking (StitchPass)

### Learning Objective

Understand how `StitchPass` links independently-generated mini-graph fragments into a unified CPG, how the `SymbolIndex` accelerates cross-fragment lookups, and how incremental re-stitching of changed source units works.

### Pre-requisites

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen).

### Conceptual Background

In large codebases, generating a whole-program CPG in one monolithic pass is memory-intensive and slow. To scale, Chen can generate small per-unit "mini-graphs" independently, then link them. That linking step is **stitching**.

[StitchPass](https://github.com/AppThreat/chen/tree/main/platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/linking/StitchPass.scala) is the public entry point:

```scala
class StitchPass(cpg: Cpg, dirtyUnits: Option[Set[String]] = None):
  @volatile var realizedEdges: Int    = 0
  @volatile var synthesizedStubs: Int = 0
  def createAndApply(): Unit
```

The two `@volatile` counters are observable after `createAndApply()` returns and report how much work the pass did: how many `TYPE`/`REF`/`CALL`-style edges were realized, and how many external method stubs were synthesized.

#### Two modes

1. **Full stitch** — `dirtyUnits = None`. The pass scans the entire graph, synthesizes stubs for every unresolved call target, realizes all cross-fragment edges, and finally runs dynamic call resolution.
2. **Incremental stitch** — `dirtyUnits = Some(files)`. Only call sites and references that belong to, or target symbols in, the changed files are re-linked. This is the warm path for editor/CI re-analysis.

#### Phases

`StitchPass.createAndApply()` builds a `SymbolIndex` once and runs the following sub-passes in order (all defined inside `object StitchPass`):

1. **`StubSynthesisPass` (extends `CpgPass`)** — creates external `METHOD` stubs for call targets that no fragment defines. It tracks `var synthesizedStubs: Int` and records `synthesizedFullNames: mutable.LinkedHashSet[String]`, registering each new stub back into the `SymbolIndex` so the next phase can resolve against it. Candidate calls are selected by `callsToConsider(cpg, dirtyUnits)`, which narrows to dirty-unit calls in incremental mode.
2. **`EdgeRealizationPass` (extends `CpgPass with LinkingUtil`)** — realizes the actual edges. It dispatches to `linkTypeAndRefEdgesFull(...)` for a full stitch or `linkTypeAndRefEdgesDirty(...)` for the incremental case, and increments `var realizedEdges: Int`.
3. **`DynamicCallLinker`** — only in full-stitch mode, resolves dynamic dispatch targets across the now-linked graph.

Internally the pass keys stubs by a `StubKey(name, signature, fullName, dispatchType)` and resolves a node's owning unit with `unitOf(node)`.

#### SymbolIndex

`SymbolIndex.scala` is built via the factory `SymbolIndex(cpg)`. It maintains fast lookups so stitching never falls back to whole-graph traversals:

- method / typeDecl / type lookups keyed by `fullName`
- `unitExports: Map[String, Set[String]]` — filename → the FQNs that file exports, the foundation for incremental re-stitch (you can compute the closure of affected units from the changed files' exports)
- `addMethod(...)` — register a freshly synthesized stub
- internal keying via `SymbolicKey(kind, fqName, arity)`

Alongside it, `FragmentSplicePass.scala` and `FragmentBoundary.scala` (`ChenSymbolicKeys`, `SymbolIndexBoundaryResolver`, `NoBoundaryResolver`) support warm-restoring previously cached fragments into a live graph.

### Real Commands and Code Examples

#### 1. Running the stitch validation test

The C frontend ships an end-to-end check that loads a stored atom and stitches it:

```bash
sbt "c2cpg/testOnly io.appthreat.c2cpg.StitchValidation"
```

The test lives at `c2cpg/src/test/scala/io/appthreat/c2cpg/StitchValidation.scala` and uses `Cpg.withStorage` to open the atom.

#### 2. Running StitchPass programmatically

```scala
import io.appthreat.x2cpg.passes.linking.StitchPass
import io.shiftleft.codepropertygraph.Cpg

val cpg = Cpg.withStorage("/tmp/app.atom")

// Full stitch over the entire graph.
val full = new StitchPass(cpg)
full.createAndApply()
println(s"Full stitch: ${full.realizedEdges} edges, ${full.synthesizedStubs} stubs")
```

#### 3. Incremental re-stitch of changed files

```scala
import io.appthreat.x2cpg.passes.linking.StitchPass
import io.shiftleft.codepropertygraph.Cpg

val cpg = Cpg.withStorage("/tmp/app.atom")

// Only the files that changed since the last analysis.
val dirty = Set("src/service/auth.c", "src/service/session.c")
val inc   = new StitchPass(cpg, dirtyUnits = Some(dirty))
inc.createAndApply()
println(s"Incremental stitch: ${inc.realizedEdges} edges re-linked")
```

In incremental mode the pass uses `SymbolIndex.unitExports` to determine which other units depend on the changed files' exported symbols, so callers in unchanged-but-affected files still get re-linked.

### Summary

`StitchPass` turns per-file mini-graphs into a whole-program CPG in three phases — stub synthesis, edge realization, and (for full stitch) dynamic call linking — all backed by a `SymbolIndex` for O(1) cross-fragment lookups. Passing `dirtyUnits` switches it from a global rebuild to a targeted, fast incremental re-link.
