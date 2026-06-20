# Lesson 16: The atom CLI — Generation, Slicing & Subcommands

### Learning Objective

Master the full atom CLI option set: language flags, global options, per-subcommand parameters,
and the language-to-frontend routing logic inside `Atom.scala`.

### Pre-requisites

- A working `atom` installation (JVM 23+, atom jar on PATH).
- Familiarity with CPG concepts (lessons 1–8).

### Conceptual Background

`atom` is the single entry-point for the entire AppThreat pipeline. It:

1. **Generates** a `.atom` file from source code using a language-specific frontend.
2. **Enhances** the CPG with overlay passes (`OssDataFlow`, tagger passes).
3. **Slices** the CPG into a compact JSON representation (data-flow, usages, reachables).
4. Alternatively **exports** or runs **graph algorithms** on the CPG.

The CLI is parsed by `scopt` in `Atom.scala`. Every option is mapped onto a `BaseConfig`
subclass (`AtomConfig`, `AtomDataFlowConfig`, `AtomUsagesConfig`, `AtomReachablesConfig`,
`AtomExportConfig`, `AtomAlgorithmsConfig`). Subcommands (`data-flow`, `usages`, `reachables`,
`export`, `algorithms`, `parsedeps`) switch the active config subclass.

### Real Commands and Code Examples

#### 1. Global options

Source: `atom/src/main/scala/io/appthreat/atom/Atom.scala`

| CLI flag                     | Default        | Description                                     |
| ---------------------------- | -------------- | ----------------------------------------------- |
| `-o` / `--output`            | `app.atom`     | Output atom file path                           |
| `-s` / `--slice-outfile`     | `slices.json`  | Slice JSON output path                          |
| `-l` / `--language`          | _(required)_   | Source language identifier                      |
| `--frontend-args`            | —              | Key=value pairs forwarded to the frontend       |
| `--with-data-deps`           | `false`        | Generate `REACHING_DEF` edges                   |
| `--remove-atom`              | `false`        | Delete the atom after slicing                   |
| `-x` / `--export-atom`       | `false`        | Export to GraphML after build                   |
| `--reuse-atom`               | `false`        | Skip rebuilding if atom already exists          |
| `--export-dir`               | `atom-exports` | Directory for graph exports                     |
| `--export-format`            | `graphml`      | Export format for `-x` flag                     |
| `--summaries`                | `false`        | Compute & cache per-method flow summaries       |
| `--config`                   | —              | JSON config file for export/algorithms commands |
| `--validation-config`        | —              | JSON file declaring sanitizers/validators       |
| `--file-filter`              | —              | Regex filter on source file names               |
| `--method-name-filter`       | —              | Regex filter on method names for slices         |
| `--method-parameter-filter`  | —              | Regex filter on parameter types                 |
| `--method-annotation-filter` | —              | Regex filter on method annotations              |
| `--max-num-def`              | `2000`         | Max definitions per method before bail-out      |
| `--legacy-dataflow`          | `false`        | Disable Flux engine and fragment caching        |

#### 2. Language identifiers and frontend routing

The `-l` value is uppercased and matched in `createNewAtom`:

| Value(s)                                                | Frontend                                   |
| ------------------------------------------------------- | ------------------------------------------ |
| `c`, `newc`                                             | `C2Cpg` (full function bodies)             |
| `cpp`, `c++`                                            | `C2Cpg`                                    |
| `h`, `hpp`, `i`                                         | `C2Atom` (header-only, no function bodies) |
| `java`, `javasrc`                                       | `JavaSrc2Cpg`                              |
| `jar`, `jimple`, `android`, `apk`, `dex`                | `Jimple2Cpg`                               |
| `scala`, `tasty`, `sbt`                                 | `Jimple2Cpg` (via scalasem pre-pass)       |
| `jssrc`, `javascript`, `js`, `ts`, `typescript`, `flow` | `JsSrc2Cpg`                                |
| `python`, `pythonsrc`, `py`                             | `Py2CpgOnFileSystem`                       |
| `php`                                                   | `Php2Atom`                                 |
| `ruby`, `rubysrc`, `rb`, `jruby`                        | `Ruby2Atom`                                |

C/C++ accepts `--frontend-args defines=NDEBUG,cpp-standard=c++17,includes=/usr/local/include`.
Java accepts `--frontend-args` to override the Lombok delombok mode.

#### 3. The `parsedeps` subcommand

Extracts dependency information from build files and import statements without building a full CPG.

```bash
# Extract Maven/Gradle/pip/npm dependencies as a JSON slice
atom -l java parsedeps /path/to/project
cat slices.json | jq '.dependencies[]'
```

No data-deps are needed; the subcommand sets `withRemoveAtom(true)` to avoid persisting the atom.

#### 4. The `data-flow` subcommand

```bash
# Backward data-flow slice to depth 7, filtering sinks by code pattern
atom -l python --with-data-deps \
    -s df_slices.json \
    data-flow \
    --slice-depth 10 \
    --sink-filter "execute|eval" \
    /path/to/project
```

| Option          | Default | Description                                |
| --------------- | ------- | ------------------------------------------ |
| `--slice-depth` | `7`     | Max DDG traversal depth from each sink     |
| `--sink-filter` | —       | Regex applied to sink call `code` property |

The subcommand forces `withDataDependencies(true)` — data-deps are always computed.

#### 5. The `usages` subcommand

```bash
# Extract object usage slices, include method source, and convert to OpenAPI
atom -l jssrc \
    -s usage_slices.json \
    usages \
    --min-num-calls 2 \
    --include-source \
    --extract-endpoints \
    /path/to/project
```

| Option                | Default | Description                                          |
| --------------------- | ------- | ---------------------------------------------------- |
| `--min-num-calls`     | `1`     | Minimum calls on the tracked object to include slice |
| `--include-source`    | `false` | Embed raw method source code in the slice JSON       |
| `--extract-endpoints` | `false` | Run `atom-tools convert` to produce an OpenAPI JSON  |

When `--extract-endpoints` is set, atom shell-invokes `atom-tools convert` passing the usage slice
as input. The tool must be on `PATH` (e.g. via `pip install atom-tools`).

#### 6. The `reachables` subcommand

```bash
# Reachable taint flows: HTTP inputs → SQL/file-io sinks
atom -l javasrc --with-data-deps --summaries \
    -s reachables.json \
    reachables \
    --source-tag "framework-input,cli-source" \
    --sink-tag "sql,file-io,code-execution" \
    --slice-depth 10 \
    --include-crypto \
    /path/to/project
```

| Option             | Default            | Description                                        |
| ------------------ | ------------------ | -------------------------------------------------- |
| `--source-tag`     | `framework-input`  | Comma-separated source tags                        |
| `--sink-tag`       | `framework-output` | Comma-separated sink tags                          |
| `--slice-depth`    | `7`                | Max DDG depth during backward reachability         |
| `--include-crypto` | `false`            | Include `crypto-generate`/`crypto-algorithm` flows |

Default source tags include `framework-input`, `framework-route`, `cli-source`, `driver-source`,
`event`, `pii`, `sensitive-data`, and `service-ingress`. Default sink tags include `sql`,
`file-io`, `code-execution`, `reflection`, `serialization`, `http`, `network`, `cloud`,
`tracker`, `adware`, `on-device-ai`, and more. The full lists are constants in `Atom.scala`.

#### 7. The `export` subcommand

```bash
# Export the whole CPG as GNN JSON for machine-learning pipelines
atom -l python --with-data-deps \
    export \
    --format gnn \
    --scope whole \
    --out ./ml_export \
    app.atom

# Export each internal method as a separate DOT file
atom export --format dot --scope methods --out ./dot_files app.atom
```

Supported formats: `dot`, `graphml`, `gexf`, `graphson`, `neo4jcsv`, `gnn`.
Supported scopes: `whole` (entire CPG), `methods` (one file per internal method).

Note: `neo4jcsv` only supports `--scope whole` (it writes one CSV per label type).

#### 8. The `algorithms` subcommand

```bash
# Strongly connected components — detect recursive call cycles
atom algorithms --type scc --out scc.json app.atom

# Topological sort — callee-before-caller processing order
atom algorithms --type toposort --out topo.json app.atom

# PageRank centrality — most-called methods
atom algorithms --type centrality --out rank.json app.atom

# Immediate dominators for each method's CFG
atom algorithms --type dominators --out dom.json app.atom

# Interprocedural call paths between two methods
atom algorithms --type paths \
    --source "com.example.Controller.handleRequest.*" \
    --target  "java.sql.Statement.executeQuery.*" \
    --max-depth 8 \
    --out paths.json \
    app.atom
```

Supported algorithms: `scc`, `toposort`, `dominators`, `paths`, `centrality`.

The `paths` algorithm uses BFS on the call graph limited to `--max-depth` hops (default 10 when
`max-depth` is 0). Both `--source` and `--target` are regex patterns matched against method full
names.

#### 9. Frontend-args examples

```bash
# C++ with preprocessor defines and a custom include path
atom -l cpp \
    --frontend-args "defines=NDEBUG,MY_MACRO=1,includes=/usr/local/include" \
    --with-data-deps \
    /path/to/cplusplus_project

# Java: force full Lombok delombok
atom -l java \
    --frontend-args "delombok-mode=run-delombok" \
    /path/to/spring_project

# JS: only build the AST cache, skip CPG enhancement
atom -l jssrc \
    --frontend-args "enable-ast-cache=true,only-ast-cache=true" \
    /path/to/big_js_project
```

#### 10. Typical end-to-end workflow

```bash
# Step 1: Build an atom with data dependencies and flow summaries
atom -l javasrc --with-data-deps --summaries -o myapp.atom /path/to/java_project

# Step 2: Slice for reachable taint flows
atom -l javasrc --reuse-atom -o myapp.atom \
    -s reachables.json \
    reachables \
    --source-tag framework-input \
    --sink-tag sql,code-execution

# Step 3: Export for graph-DB import
atom -l javasrc --reuse-atom -o myapp.atom \
    export --format neo4jcsv --out ./neo4j_import

# Step 4: Run centrality analysis to identify hotspot methods
atom -l javasrc --reuse-atom -o myapp.atom \
    algorithms --type centrality --out centrality.json
```
