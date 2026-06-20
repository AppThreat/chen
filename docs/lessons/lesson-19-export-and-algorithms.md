# Lesson 19: Graph Export & Algorithms

## Learning Objective

Use the `atom export` and `atom algorithms` subcommands to dump a CPG into standard graph formats
(for visualisation, graph databases, or ML) and to run call-graph algorithms (SCC, topological
sort, dominators, paths, centrality/PageRank).

## Pre-requisites

- A generated atom file
- The `atom` CLI on `PATH`
- Optional: Gephi / yEd (GEXF/GraphML), Neo4j (neo4jcsv), a GNN training pipeline (gnn JSON)

## Conceptual Background

The graph commands live in
[atom/.../GraphCommands.scala](https://github.com/AppThreat/atom/tree/main/src/main/scala/io/appthreat/atom/GraphCommands.scala).
They wrap overflowdb2's format exporters and a set of graph algorithms over the **call graph**
(method nodes connected by `CALL` edges).

### Supported export formats

```scala
private val supportedFormats =
  Set("dot", "graphml", "gexf", "graphson", "neo4jcsv", "gnn")
private val supportedScopes = Set("whole", "methods")
```

| Format     | Exporter                             | Use case                             |
| ---------- | ------------------------------------ | ------------------------------------ |
| `dot`      | `overflowdb.formats.dot.DotExporter` | Graphviz visualisation               |
| `graphml`  | `GraphMLExporter`                    | yEd, generic tooling                 |
| `gexf`     | `GexfExporter`                       | Gephi visualisation                  |
| `graphson` | `GraphSONExporter`                   | TinkerPop / Gremlin ecosystems       |
| `neo4jcsv` | `Neo4jCsvExporter`                   | Bulk import into Neo4j               |
| `gnn`      | `GnnExporter`                        | JSON feature/edge tensors for GNN ML |

**Scope** selects what is exported: `whole` dumps the entire graph into one file; `methods` writes
one file per method (handy for per-method DOT diagrams).

### Supported algorithms

```scala
private val supportedAlgorithms =
  Set("scc", "toposort", "dominators", "paths", "centrality")
```

| Algorithm    | What it computes                                                     |
| ------------ | -------------------------------------------------------------------- |
| `scc`        | Strongly connected components of the call graph (recursion clusters) |
| `toposort`   | Topological sort with SCC grouping — callee-before-caller ordering   |
| `dominators` | Per-method dominator tree over CFG edges (immediate dominators)      |
| `paths`      | Call paths between a `--source` method and a `--target` method       |
| `centrality` | PageRank + in-degree centrality over the callee call graph           |

`centrality` uses `nodes.pageRank(callees)` and `inDegreeCentrality(callees)`, emitting a ranking
of methods by `pageRank` (descending) with their `inDegree`. `dominators` computes
`node.dominatorTree(...)` over `CFG` out-edges for each internal method. `paths` resolves the first
method matching `--source`/`--target` regexes and searches up to `--max-depth` (default 10).

## Real Commands and Code Examples

### Export the whole graph to GraphML

```bash
atom export -l java -o app.atom --format graphml --scope whole --out atom-exports/ /path/to/project
```

### Per-method DOT files

```bash
atom export -l java -o app.atom --format dot --scope methods --out atom-exports/ /path/to/project
```

### Export to Neo4j CSV for bulk import

```bash
atom export -l python -o app.atom --format neo4jcsv --scope whole --out neo4j-import/ /path/to/project
# then: neo4j-admin database import full ... using the generated CSVs
```

### Export GNN tensors (for ML pipelines)

```bash
atom export -l ts -o app.atom --format gnn --scope whole --out gnn-data/ /path/to/project
```

### Run the centrality (PageRank) algorithm

```bash
atom algorithms -l java -o app.atom --type centrality /path/to/project
```

Sample output (JSON):

```json
{
  "ranking": [
    {
      "method": "com.acme.Router.dispatch:void(...)",
      "pageRank": 0.184,
      "inDegree": 42
    },
    {
      "method": "com.acme.Auth.verify:boolean(...)",
      "pageRank": 0.091,
      "inDegree": 17
    }
  ]
}
```

### Find call paths between two methods

```bash
atom algorithms -l java -o app.atom --type paths \
  --source ".*Controller.*handle.*" --target ".*Repository.*save.*" --max-depth 8 \
  /path/to/project
```

### Strongly connected components (recursion detection)

```bash
atom algorithms -l python -o app.atom --type scc /path/to/project
```

### Programmatic export

```scala
import io.shiftleft.codepropertygraph.Cpg
import overflowdb.formats.graphml.GraphMLExporter

val cpg = Cpg.withStorage("/tmp/app.atom")
GraphMLExporter.runExport(cpg.graph, "atom-exports/whole.graphml")
cpg.close()
```

## Notes

- `toposort` ordering is exactly the callee-before-caller order the flow-summary computer relies
  on (Lesson 15) — useful for sanity-checking interprocedural analysis order.
- `dominators` operates over **CFG** edges within each method, not the call graph; it answers
  intra-procedural "which statement must execute before this one" questions.
- The `gnn` exporter emits node feature vectors and edge lists as JSON, ready to feed into
  PyTorch Geometric / DGL pipelines for learned vulnerability detection.
- For very large graphs prefer `--scope methods` with `dot` to keep individual diagrams legible,
  or `neo4jcsv`/`graphson` to push the whole graph into a database for interactive querying.
