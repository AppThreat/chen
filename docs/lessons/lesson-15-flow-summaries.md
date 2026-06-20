# Lesson 15: Interprocedural Method Flow Summaries

### Learning Objective

Understand how `MethodFlowSummary` objects are computed — callee-before-caller over call-graph
SCCs — and how they let the reachability engine prune provably-empty cross-call work without
changing analysis results.

### Pre-requisites

- Lesson 13 (reaching definitions and `REACHING_DEF` edges).
- Lesson 14 (reachability engine and `EngineConfig`).
- An atom built with `--with-data-deps`.

### Conceptual Background

The backward query engine (`Engine`) is interprocedural: when it reaches a call-site argument it
spawns a new `TaskSolver` for the matching callee. On large codebases with deep call graphs this
produces many redundant tasks — for example, the same library utility method may be visited once
per distinct call site, each time recomputing the same facts.

**Method flow summaries** solve this by precomputing, _independently of any query_, which formal
parameters of a method can reach the method's return value or any of its output parameters. These
facts are _context-independent_: they hold at every call site, so a single computed summary can be
reused across all callers without any context-sensitivity assumptions.

A `MethodFlowSummary` records:

| Field                                 | Meaning                                                                      |
| ------------------------------------- | ---------------------------------------------------------------------------- |
| `paramToReturn: Set[Int]`             | Param indices whose value can flow to the method's return.                   |
| `paramToParamOut: Map[Int, Set[Int]]` | For each param index, the output-param indices it can reach (side-effects).  |
| `returnFromInternal: Boolean`         | Return can also be tainted by a source _inside_ the body (not just a param). |
| `paramOutFromInternal: Set[Int]`      | Output params that can be tainted by internal sources.                       |

When the query engine sees that a callee's summary proves that argument `i` cannot reach the return
or any output, it skips the cross-call task entirely, reducing both task count and wall-clock time.

**Computation order** is crucial. A summary can only use callee summaries that are already
computed; therefore the call graph's strongly connected components are ordered callee-first
(reverse topological order on the condensation). Recursive components are iterated to fixpoint
(summaries only grow monotonically, so termination is guaranteed).

### Real Commands and Code Examples

#### 1. MethodFlowSummary data structure

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/queryengine/summaries/MethodFlowSummary.scala`

```scala
case class MethodFlowSummary(
  methodFullName: String,
  paramToReturn: Set[Int],
  paramToParamOut: Map[Int, Set[Int]],
  returnFromInternal: Boolean,
  paramOutFromInternal: Set[Int]
):
  /** True if tainted actual at paramIndex can reach the method's return value. */
  def reachesReturn(paramIndex: Int): Boolean = paramToReturn.contains(paramIndex)

  /** Output-parameter indices reachable from the given formal parameter index. */
  def reachedParamOuts(paramIndex: Int): Set[Int] =
      paramToParamOut.getOrElse(paramIndex, Set.empty)

  /** True if the return value can carry taint from any origin. */
  def returnTaintable: Boolean = paramToReturn.nonEmpty || returnFromInternal

  /** True if the given output parameter index can carry taint from any origin. */
  def paramOutTaintable(outIndex: Int): Boolean =
      paramOutFromInternal.contains(outIndex) ||
          paramToParamOut.values.exists(_.contains(outIndex))
```

`SummaryLookup` is a type alias `String => Option[MethodFlowSummary]` — the closure passed to
callee-aware summary computation so computed summaries can be plugged in for callee calls
discovered during the BFS over `REACHING_DEF` edges.

#### 2. FlowSummaryComputer — loading or computing

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/queryengine/summaries/FlowSummaryComputer.scala`

```scala
object FlowSummaryComputer:

  /** Restore from disk cache, or compute fresh and store. Gated by CacheControl.Summary. */
  def loadOrCompute(
    cpg: Cpg,
    cacheDir: String,
    semantics: Semantics = Semantics.empty
  ): Map[String, MethodFlowSummary] =
    val store       = new FlowSummaryStore(cacheDir)
    val fingerprint = FlowSummaryStore.fingerprint(cpg, semantics)
    store.restore(fingerprint) match
      case Some(summaries) => summaries
      case None =>
          val summaries = computeAll(cpg, semantics)
          store.store(fingerprint, summaries)
          summaries

  /** Compute summaries for all internal methods. */
  def computeAll(cpg: Cpg, semantics: Semantics = Semantics.empty): Map[String, MethodFlowSummary] =
    val methods    = cpg.method.internal.l
    val byFullName = methods.groupBy(_.fullName)
    val cache      = mutable.Map.empty[String, MethodFlowSummary]

    def summaryOf(m: Method): MethodFlowSummary =
        semantics.forMethod(m.fullName) match
          case Some(semantic) => MethodFlowSummary.fromSemantic(m, semantic) // declared wins
          case None           => MethodFlowSummary.of(m, lookup, semantics)

    val nodes      = methods.map(_.asInstanceOf[Node])
    val components = nodes.stronglyConnectedComponents(calleesOf(byFullName.keySet))

    calleeFirstOrder(components, byFullName.keySet).foreach { component =>
      val componentMethods = component.toSeq.collect { case m: Method => m }
      val recursive = component.size > 1 || componentMethods.exists(isSelfRecursive)

      if !recursive then
        componentMethods.foreach(m => cache(m.fullName) = summaryOf(m))
      else
        // Seed recursive methods with the empty summary so they can be looked up
        componentMethods.foreach(m =>
            cache.getOrElseUpdate(m.fullName, MethodFlowSummary.empty(m.fullName))
        )
        // Iterate to fixpoint (monotone growth guarantees termination)
        var changed = true
        while changed do
          changed = false
          componentMethods.foreach { m =>
            val next = summaryOf(m)
            if !cache.get(m.fullName).contains(next) then
              cache(m.fullName) = next
              changed = true
          }
    }
    cache.toMap
```

Key design points:

- `stronglyConnectedComponents` (from `CpgAlgorithms`) partitions the call graph into SCCs.
- `calleeFirstOrder` applies Kahn's algorithm on the acyclic condensation of the SCC DAG, then
  reverses the order so callee SCCs come before caller SCCs.
- A method with a declared `FlowSemantic` always uses `fromSemantic` — the declared mapping is
  authoritative and skips body analysis.

#### 3. How fromSemantic derives a summary

When a `FlowSemantic` is present for method `m`:

```scala
def fromSemantic(method: Method, semantic: FlowSemantic): MethodFlowSummary =
  val paramIndices = method.parameter.index.l
  val toReturn     = mutable.SortedSet.empty[Int]
  val toParamOut   = mutable.Map.empty[Int, mutable.SortedSet[Int]]
  semantic.mappings.foreach {
      case PassThroughMapping =>
          paramIndices.filter(_ != 0).foreach { i =>
            toReturn += i
            toParamOut.getOrElseUpdate(i, mutable.SortedSet.empty) += i
          }
      case FlowMapping(ParameterNode(srcIdx, _), ParameterNode(dstIdx, _)) =>
          if dstIdx == -1 then toReturn += srcIdx        // -1 = return
          else toParamOut.getOrElseUpdate(srcIdx, mutable.SortedSet.empty) += dstIdx
      case _ =>
  }
  // returnFromInternal = false because the semantic is authoritative (no internal sources declared)
  MethodFlowSummary(method.fullName, toReturn.toSet, toParamOut.view.mapValues(_.toSet).toMap,
    returnFromInternal = false, Set.empty)
```

Any parameter _not_ listed in a mapping is implicitly sanitized — this is the critical property
that makes declared semantics function as taint sanitizers in addition to pass-through declarations.

#### 4. Using summaries in the query engine

Enable via `EngineConfig.useSummaries = true` and pass the precomputed map:

```scala
import io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryComputer
import io.appthreat.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.appthreat.dataflowengineoss.DefaultSemantics
import io.shiftleft.codepropertygraph.Cpg

val cpg = Cpg.withStorage("/tmp/atomdemo/app.atom")
implicit val semantics = DefaultSemantics()

// Compute (or restore from cache next to the atom)
val summaries = FlowSummaryComputer.loadOrCompute(cpg, "/tmp/atomdemo", semantics)

implicit val context = EngineContext(
  semantics,
  EngineConfig(
    maxCallDepth = 5,
    useSummaries = true,
    summaries = summaries          // engine prunes tasks using these
  )
)

val sources = cpg.call.name("getParameter").argument.l
val sinks   = cpg.call.name("executeQuery").argument.l
val flows   = sinks.reachableByFlows(sources).l
println(s"Flows found: ${flows.size}")
```

#### 5. atom CLI — `--summaries` flag

```bash
# Build atom with data-deps, compute + cache summaries, use them during reachables slicing
atom -l javasrc --with-data-deps --summaries \
    -s reachables.json \
    reachables /path/to/project
```

In `Atom.scala`, `--summaries` triggers:

1. `CacheControl.enable(CacheControl.Summary)` — activates the per-atom summary cache stored next
   to the `.atom` file.
2. `FlowSummaryComputer.loadOrCompute` is called before the backward query engine runs.
3. The returned map is injected into `EngineConfig.summaries` so the engine can prune provably-
   empty cross-call tasks.

On a second run against the same unchanged atom, `loadOrCompute` detects the fingerprint match and
restores the summaries from disk in milliseconds instead of recomputing them.

#### 6. Inspecting a summary manually

```scala
val summaries = FlowSummaryComputer.computeAll(cpg)

// Which params of a specific method reach its return?
val fullName = "org.example.UserService.findById:org.example.User(java.lang.Long)"
summaries.get(fullName).foreach { s =>
  println(s"Method: ${s.methodFullName}")
  println(s"Params reaching return: ${s.paramToReturn}")
  println(s"Param-to-param-out:     ${s.paramToParamOut}")
  println(s"Return taintable:       ${s.returnTaintable}")
}
```

#### 7. Summary growth during SCC fixpoint

For a mutually recursive pair `A ↔ B`:

1. Both start with the empty summary (`paramToReturn = Set.empty`).
2. First iteration: `summaryOf(A)` uses `B`'s empty summary (no interprocedural jumps); likewise
   for `B`.
3. If the intra-procedural `REACHING_DEF` edges of `A` send param 1 to the return, `A`'s summary
   gains `paramToReturn = {1}`.
4. Second iteration: `summaryOf(B)` now sees `A`'s updated summary and may gain entries.
5. Loop continues until no summary changes — typically 2–3 iterations for simple mutual recursion.
