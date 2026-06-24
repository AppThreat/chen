# Lesson 17: Usage, Data-Flow & Reachable Slices

## Learning Objective

Understand the three program-slicing modes the `atom` CLI exposes — **usages**, **data-flow**,
and **reachables** — how each is configured, what shape of JSON they emit, and how downstream
SAST/AI tooling consumes them.

## Pre-requisites

- A generated atom file (see Lessons 1–6)
- The `atom` CLI on `PATH`
- Familiarity with reaching definitions / DDG (Lesson 13) and reachability (Lesson 14)

## Conceptual Background

A _slice_ is a compact projection of the CPG that retains only the nodes and edges relevant to a
question. Slicing lets you ship a small, self-contained JSON artefact (instead of the whole atom)
to a rule engine, an LLM, or a graph database. The slicers live in
[atom/.../slicing](https://github.com/AppThreat/atom/tree/main/src/main/scala/io/appthreat/atom/slicing)
and all produce a `ProgramSlice` (`toJson` / `toJsonPretty`).

| Mode         | Slicer class       | Question answered                                    |
| ------------ | ------------------ | ---------------------------------------------------- |
| `usages`     | `UsageSlicing`     | How is each local/parameter object defined and used? |
| `data-flow`  | `DataFlowSlicing`  | What backward DDG paths reach a sink?                |
| `reachables` | `ReachableSlicing` | Which tagged sources reach which tagged sinks?       |

## Data-Flow Slicing

`DataFlowSlicing.calculateDataFlowSlice(atom, config)` starts at sink nodes and walks the DDG
backwards by repeating `_.ddgIn` up to `sliceDepth`, collecting reachable nodes and the edges
between them.

```scala
case class DataFlowConfig(
  sinkPatternFilter: Option[String] = None,   // regex on the sink's code
  mustEndAtExternalMethod: Boolean = true,     // only keep slices ending in an external call
  excludeOperatorCalls: Boolean = true,        // drop <operator>.* noise
  sliceDepth: Int = 7,                         // max DDG hops backwards
  sliceNodesLimit: Int = 200,                  // cap nodes per slice
  useFluxEngine: Boolean = true                // use the low-allocation Flux reaching-def engine
) extends BaseConfig
```

The result is a `DataFlowSlice(nodes: Set[SliceNode], edges: Set[SliceEdge])`.

## Usage Slicing

`UsageSlicing` walks object definitions and the calls/arguments that flow from them. It is the
default slice emitted when you pass `-s/--slice-outfile`.

```scala
case class UsagesConfig(
  minNumCalls: Int = 1,             // ignore objects with fewer than N calls on them
  excludeOperatorCalls: Boolean = true,
  excludeMethodSource: Boolean = true,  // omit method source code (set false to include)
  extractEndpoints: Boolean = false     // also emit HTTP endpoints as OpenAPI
) extends BaseConfig
```

## Reachable Slicing

`ReachableSlicing` is the security-focused mode: it runs reachability between _tagged_ sources
and sinks (see Lesson 11/14), so it requires the tagger passes to have run first.

```scala
case class ReachablesConfig(
  sourceTag: Seq[String],            // default Seq("framework-input")
  sinkTag: Seq[String],              // default Seq("framework-output")
  sliceDepth: Int,
  includeCryptoFlows: Boolean,       // include crypto-library flows
  useFluxEngine: Boolean = true,
  useSummaries: Boolean = false      // use precomputed method flow summaries (Lesson 15)
) extends BaseConfig
```

Output is a `ReachableSlice(reachables: List[ReachableFlows])`, where each `ReachableFlows` carries
the ordered `flows: List[SliceNode]` plus the `purls` (package URLs) the flow passes through.

## The `SliceNode` shape

Every slice node is serialised with rich provenance so the consumer needs no further graph access:

```scala
case class SliceNode(
  id: Long, label: String, name: String = "", fullName: String = "",
  signature: String = "", isExternal: Boolean = false, code: String,
  typeFullName: String = "",
  parentMethodName: String = "", parentMethodSignature: String = "",
  parentFileName: String = "", parentPackageName: String = "", parentClassName: String = "",
  lineNumber: Option[Integer] = None, columnNumber: Option[Integer] = None,
  tags: String = ""
)
```

`SliceEdge(src: Long, dst: Long, label: String)` records the relationship between two slice nodes.

## Real Commands and Code Examples

### Usage slice (default, with endpoints)

```bash
atom usages -l java -o app.atom --slice-outfile usages.json \
  --min-num-calls 1 --extract-endpoints /path/to/project
```

### Backward data-flow slice toward sinks matching a pattern

```bash
atom data-flow -l java -o app.atom --slice-outfile dataflow.json \
  --slice-depth 7 --sink-filter ".*executeQuery.*" /path/to/project
```

### Reachable flows from framework input to framework output

```bash
atom reachables -l python -o app.atom --slice-outfile reachables.json \
  --source-tag framework-input --sink-tag framework-output \
  --slice-depth 7 --include-crypto /path/to/project
```

### Programmatic data-flow slice

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.appthreat.atom.slicing.{DataFlowSlicing, DataFlowConfig}

val cpg   = Cpg.withStorage("/tmp/app.atom")
val config = DataFlowConfig(sinkPatternFilter = Some(".*exec.*"), sliceDepth = 7)
new DataFlowSlicing().calculateDataFlowSlice(cpg, config).foreach { slice =>
  println(slice.toJsonPretty)
}
```

## Notes for Security Analysts

- **Reachables depend on tagging.** Run the tagger passes (or let `atom` do it) before
  `reachables`; otherwise there are no `framework-input` / `framework-output` tags to anchor on.
- `useSummaries = true` swaps full interprocedural exploration for precomputed
  `MethodFlowSummary` lookups (Lesson 15) — much faster on large graphs, at some precision cost.
- `sliceNodesLimit` (default 200) protects against pathological fan-out; raise it only when a
  legitimate flow is being truncated.
- All slices serialise to JSON via circe (`toJson` compact, `toJsonPretty` 2-space). The compact
  form is what downstream tools and the chen/atom AI pipelines ingest.
