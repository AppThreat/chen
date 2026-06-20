# Lesson 14: Reachability Queries, Flow Semantics, Sanitizers & Validators

### Learning Objective

Write interprocedural taint-reachability queries using `reachableByFlows`, declare custom
`FlowSemantic` entries that control which parameters propagate taint, and filter resulting paths
through sanitizer-tagged nodes using `passesThrough` / `doesNotPassThrough`.

### Pre-requisites

- Lesson 13 completed: the atom must have `REACHING_DEF` edges present.
- Basic familiarity with the CPG query DSL (Lesson 12).
- An atom built with `--with-data-deps` (and optionally `--validation-config`).

### Conceptual Background

**Interprocedural reachability** in chen works backwards from sinks to sources over `REACHING_DEF`
edges. The `Engine` class schedules tasks in parallel via Java virtual threads, one task per sink.
Each `TaskSolver` walks `REACHING_DEF` edges in reverse (`Engine.expandIn`), crossing call
boundaries according to the active `Semantics`.

**Flow semantics** are the bridge between intra-procedural edges and interprocedural reasoning.
A `FlowSemantic` is a declaration for a named method stating which source parameters flow to which
destination parameters or the return value. When the engine crosses a call site:

- If a `FlowSemantic` exists for the callee, _only_ the declared mappings propagate taint.
  Any parameter absent from the mappings is treated as sanitized.
- If no semantic exists for an internal callee, the engine explores the callee body.
- If no semantic exists for an external callee, the call is treated as opaque (no propagation).

`PassThroughMapping` is a shorthand: every non-receiver parameter (index ≥ 1) flows both to itself
(output parameter) and to the return value — useful for wrappers that forward taint unchanged.

**Sanitizers and validators** are CPG nodes tagged by `ChennaiTagsPass` (driven by the
`--validation-config` JSON). `passesThrough` and `doesNotPassThrough` in the query DSL filter the
resulting path set without re-running the engine.

### Real Commands and Code Examples

#### 1. EngineContext and EngineConfig

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/queryengine/Engine.scala`

```scala
case class EngineContext(
  semantics: Semantics = DefaultSemantics(),
  config: EngineConfig = EngineConfig()
)

case class EngineConfig(
  var maxCallDepth: Int = 3,           // k-limit for interprocedural exploration
  initialTable: Option[...] = None,    // optional pre-seeded path cache
  shareCacheBetweenTasks: Boolean = true,
  maxArgsToAllow: Int = 100,           // prune excessively wide call sites
  maxOutputArgsExpansion: Int = 100,
  var useFluxEngine: Boolean = false,  // reserved; no cross-sink cache today
  var useSummaries: Boolean = false,   // opt-in: prune via MethodFlowSummary
  summaries: Map[String, MethodFlowSummary] = Map.empty
)
```

`maxCallDepth` is the primary tuning knob for reachability queries: higher values find deeper
interprocedural flows at the cost of exponential path explosion. The default 3 is conservative
but covers most framework → business-logic → sink paths.

#### 2. FlowSemantic and FlowMapping

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/semanticsloader/Parser.scala`

```scala
case class FlowSemantic(
  methodFullName: String,
  mappings: List[FlowPath] = List.empty,
  regex: Boolean = false               // interpret methodFullName as a regex
)

case class ParameterNode(index: Int, name: Option[String] = None) extends ParamOrRetNode
case class FlowMapping(src: FlowNode, dst: FlowNode)              extends FlowPath
object PassThroughMapping                                          extends FlowPath
```

Index conventions:

- `0` = the receiver (`this` / `self`).
- `1`, `2`, … = positional arguments.
- `-1` = the return value of the method.

```scala
import io.appthreat.dataflowengineoss.semanticsloader.{FlowSemantic, FlowMapping, PassThroughMapping}

// String.format: taint from arg-1 (format string) flows to return
val stringFormat = FlowSemantic.from("java.lang.String.format:java.lang.String(java.lang.String,java.lang.Object[])",
  List((1, -1), (2, -1)))

// A validation helper that does NOT propagate taint (empty mappings = all args sanitized)
val validator = FlowSemantic("com.example.Validator.sanitize:java.lang.String(java.lang.String)", List.empty)

// A pass-through wrapper: every arg flows to return unchanged
val wrapper = FlowSemantic("com.example.Wrapper.wrap:java.lang.Object(java.lang.Object)",
  List(PassThroughMapping))

// Regex semantic: applies to every method whose full name matches the pattern
val regexSem = FlowSemantic("^.*HttpServletRequest\\.getParameter.*$", List((0, -1)), regex = true)
```

`Semantics.loadRegexSemantics(cpg)` is called at pass construction time; it resolves all regex
entries against `cpg.method.fullName` once and caches the results so query-time lookup remains O(1).

#### 3. DefaultSemantics

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/DefaultSemantics.scala`

`DefaultSemantics()` returns a pre-populated `Semantics` covering:

- All CPG operator nodes (addition, fieldAccess, cast, indexAccess, …) — so arithmetic over tainted
  data propagates correctly.
- Common C stdlib functions (`strlen`, `memcpy`, …).
- Common Java SDK methods (`String.split` via `PassThroughMapping`, etc.).

You merge custom semantics on top:

```scala
import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.semanticsloader.Semantics

val customEntries = List(stringFormat, validator, wrapper)
implicit val semantics: Semantics =
    Semantics.fromList(DefaultSemantics().elements ++ customEntries)
```

#### 4. The `reachableByFlows` query

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.appthreat.dataflowengineoss.DefaultSemantics
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/atomdemo/app.atom")
implicit val semantics = DefaultSemantics()
implicit val context   = EngineContext(semantics, EngineConfig(maxCallDepth = 4))

val sources = cpg.call.name("getParameter").argument.l          // HTTP input
val sinks   = cpg.call.name("executeQuery").argument.index(1).l // SQL sink

// reachableByFlows returns Iterator[Path]; each Path is a sequence of PathElement
val flows = sinks.reachableByFlows(sources).l
flows.foreach { path =>
  println("=== Flow ===")
  path.elements.foreach(n => println(s"  ${n.label}  ${n.code}"))
}
println(s"Total flows: ${flows.size}")
```

The engine explores backwards from each sink, following `REACHING_DEF` edges and crossing call
boundaries up to `maxCallDepth` times. Each completed path from a sink element back to a source
element is a result.

#### 5. `passesThrough` and `doesNotPassThrough`

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/language/package.scala`

```scala
class PassesExt(traversal: Iterator[Path]):

  /** Keep flows that pass through at least one node matching predicate. */
  def passesThrough(predicate: AstNode => Boolean): Iterator[Path] =
      traversal.filter(_.elements.exists(predicate))

  /** Drop flows that pass through any node matching predicate. */
  def doesNotPassThrough(predicate: AstNode => Boolean): Iterator[Path] =
      traversal.filterNot(_.elements.exists(predicate))
```

These are post-query DSL filters — they do not re-run the engine, they simply partition the result
set. Equivalent traversal-function forms `passes` and `passesNot` also exist for complex predicates
expressed as node traversals.

#### 6. Sanitizer filtering in practice

```scala
// Collect IDs of nodes tagged with "sanitizer" by ChennaiTagsPass
val sanitizerIds: Set[Long] =
    cpg.call.where(_.tag.name("sanitizer")).id.toSet

// Full flow without filtering
val allFlows = sinks.reachableByFlows(sources).l

// Drop flows that go through any sanitizer call
val unsanitized = allFlows
    .iterator
    .doesNotPassThrough(n => sanitizerIds.contains(n.id))
    .l

// Optionally keep only flows that DO pass through a specific logging call
val loggedFlows = allFlows
    .iterator
    .passesThrough(n => n.isCall && n.asInstanceOf[Call].name == "auditLog")
    .l

println(s"All: ${allFlows.size}, Unsanitized: ${unsanitized.size}, Logged: ${loggedFlows.size}")
```

#### 7. Using --validation-config to declare sanitizers automatically

The atom CLI accepts a JSON file (chennai.json schema) via `--validation-config`:

```bash
atom -l javasrc --with-data-deps \
    --validation-config ./config/chennai.json \
    -s reachables.json \
    reachables /path/to/project
```

`ChennaiTagsPass` reads the JSON and tags every call to a declared sanitizer/validator with the
appropriate category tags. Those tags are then accessible as `n.tag.name("sanitizer")` in queries.

```json
{
  "sanitizers": [
    { "name": "escapeHtml", "category": "xss" },
    { "name": "sanitizeSQL", "category": "sqli" }
  ]
}
```

#### 8. Semantics text file format

The ANTLR-based `Parser` also reads a plain-text semantics DSL:

```
"java.lang.String.format" 1 -> -1 2 -> -1
"com.example.Validator.sanitize"
"com.example.Wrapper.wrap" PASSTHROUGH
```

Blank right-hand side = all parameters sanitized. `PASSTHROUGH` expands to every arg→return + arg→
self mapping. Load with:

```scala
import io.appthreat.dataflowengineoss.semanticsloader.Parser
val extras = new Parser().parseFile("/path/to/custom.semantics")
```
