# Lesson 13: Reaching Definitions & the OSS Data-Flow Engine

### Learning Objective

Understand how the OSS data-flow overlay is constructed — from the `OssDataFlow` layer class
through the reaching-definitions passes (`ReachingDefPass` / `FluxReachingDefPass`) to the
`REACHING_DEF` edge set that powers every `reachableBy` query in chen.

### Pre-requisites

- Familiarity with control-flow graphs and basic data-flow lattice theory.
- A built atom file (`app.atom`) with `--with-data-deps` so `REACHING_DEF` edges are present.
- Lesson 12 (traversal methods) and the atom REPL open.

### Conceptual Background

**Reaching definitions** (a.k.a. data dependence) answer: _at program point P, which definitions
of variable V can reach P without being killed on all paths?_ This is a classic MOP (Meet-Over-all-
Paths) lattice problem on the CFG:

- **Lattice**: powerset of all definitions (assignments, parameters, …), ordered by ⊆.
- **Transfer function** per node `n`: `out(n) = gen(n) ∪ (in(n) − kill(n))`.
- **Meet**: `in(n) = ⋃ { out(p) | p ∈ pred(n) }` (set union = join in the powerset lattice).
- **Fixpoint**: iterate until no `out` set changes — guaranteed because the lattice has finite height.

The fixpoint is solved by a worklist algorithm; chen ships two implementations:

| Solver  | Class            | Allocation strategy                                                     |
| ------- | ---------------- | ----------------------------------------------------------------------- |
| Classic | `DataFlowSolver` | `Map[Node, BitSet]`, rebuilt each round                                 |
| Flux    | `FluxSolver`     | Dense `Array[BitSet]` mutated in-place; steady-state is allocation-free |

Both produce byte-for-byte identical `REACHING_DEF` edges because, for the powerset lattice with
union meet, the least fixpoint is independent of worklist visit order.

The OSS data-flow overlay ties it all together:

```
OssDataFlow (LayerCreator)
  └─ OssDataFlowOptions   – configuration knobs
       ├── maxNumberOfDefinitions (bail-out threshold)
       ├── extraFlows            (additional FlowSemantic entries)
       └── useFluxEngine         (select FluxReachingDefPass)
  └─ [Flux|Reaching]DefPass     – ForkJoinParallelCpgPass[Method]
       └─ DdgGenerator.addReachingDefEdges  → REACHING_DEF edges
```

### Real Commands and Code Examples

#### 1. The OssDataFlow layer

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/layers/dataflows/OssDataFlow.scala`

```scala
object OssDataFlow:
  val overlayName: String = "dataflowOss"
  val description: String = "Layer to support the OSS lightweight data flow tracker"

class OssDataFlowOptions(
  var maxNumberOfDefinitions: Int = 4000,
  var extraFlows: List[FlowSemantic] = List.empty[FlowSemantic],
  var useFluxEngine: Boolean = false
) extends LayerCreatorOptions

class OssDataFlow(opts: OssDataFlowOptions)(implicit
  s: Semantics = Semantics.fromList(DefaultSemantics().elements ++ opts.extraFlows)
) extends LayerCreator:

  override val overlayName: String = OssDataFlow.overlayName

  override def create(context: LayerCreatorContext, storeUndoInfo: Boolean): Unit =
    val cpg = context.cpg
    val reachingDefPass: CpgPassBase =
        if opts.useFluxEngine then new FluxReachingDefPass(cpg, opts.maxNumberOfDefinitions)
        else new ReachingDefPass(cpg, opts.maxNumberOfDefinitions)
    val enhancementExecList = Iterator(reachingDefPass)
    enhancementExecList.zipWithIndex.foreach { case (pass, index) =>
        runPass(pass, context, storeUndoInfo, index)
    }
```

The overlay is registered under the name `"dataflowOss"`. When a CPG is loaded the runtime checks
whether this overlay has already been applied; if not, `OssDataFlow.create` is called, which fires
the reaching-def pass over every method in parallel.

#### 2. Classic reaching-definitions pass

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/passes/reachingdef/ReachingDefPass.scala`

```scala
class ReachingDefPass(cpg: Cpg, maxNumberOfDefinitions: Int = 4000)(implicit s: Semantics)
    extends ForkJoinParallelCpgPass[Method](cpg):

  s.loadRegexSemantics(cpg)           // resolve regex method-name semantics up front

  override def generateParts(): Array[Method] = cpg.method.toArray

  override def runOnPart(dstGraph: DiffGraphBuilder, method: Method): Unit =
    val problem = ReachingDefProblem.create(method)
    if shouldBailOut(method, problem) then return

    val solution     = new DataFlowSolver().calculateMopSolutionForwards(problem)
    val ddgGenerator = new DdgGenerator(s)
    ddgGenerator.addReachingDefEdges(dstGraph, method, problem, solution)

  private def shouldBailOut(method: Method, problem: DataFlowProblem[StoredNode, mutable.BitSet]): Boolean =
    val transferFunction = problem.transferFunction.asInstanceOf[ReachingDefTransferFunction]
    val numberOfDefinitions = transferFunction.gen.foldLeft(0)(_ + _._2.size)
    numberOfDefinitions > maxNumberOfDefinitions
```

`shouldBailOut` sums up the sizes of all `gen` sets (one per CFG node). If the total exceeds
`maxNumberOfDefinitions` (default 4000 for the library overlay, 2000 in the atom CLI), the method
is skipped rather than running an analysis that would produce an exponential number of bit-set
operations. Users can raise the limit; for highly obfuscated or transpiled JavaScript, 8000–16 000
is common.

#### 3. Flux reaching-definitions pass

Source: `dataflowengineoss/src/main/scala/io/appthreat/dataflowengineoss/passes/reachingdef/FluxReachingDefPass.scala`

```scala
class FluxReachingDefPass(cpg: Cpg, maxNumberOfDefinitions: Int = 4000)(implicit s: Semantics)
    extends ForkJoinParallelCpgPass[Method](cpg):

  s.loadRegexSemantics(cpg)

  override def runOnPart(dstGraph: DiffGraphBuilder, method: Method): Unit =
    val problem = ReachingDefProblem.create(method)
    if shouldBailOut(method, problem) then return

    val solution     = new FluxSolver().calculateMopSolutionForwards(problem)  // <-- only difference
    val ddgGenerator = new DdgGenerator(s)
    ddgGenerator.addReachingDefEdges(dstGraph, method, problem, solution)
```

`FluxSolver` stores `out` as a dense `Array[BitSet]` indexed by node number and applies `gen`/
`kill` via in-place bitset mutation (`|=`, `&~=`). The classic solver rebuilds its `Map[Node,
BitSet]` every round and allocates a new bitset per node per visit. On a 30 000-node transpiled
JavaScript method this reduces GC pause from several seconds to under 200 ms.

#### 4. atom's DataDepsPass (atom CLI variant)

Source: `atom/src/main/scala/io/appthreat/atom/passes/DataDepsPass.scala`

```scala
class DataDepsPass(
  atom: Cpg,
  maxNumberOfDefinitions: Int = 2000,      // lower default than the library
  useFluxEngine: Boolean = false
)(implicit s: Semantics)
    extends OrderedParallelCpgPass[Method](atom):   // ordered, not ForkJoin

  override def runOnPart(dstGraph: DiffGraphBuilder, method: Method): Unit =
    val problem = ReachingDefProblem.create(method)
    if shouldBailOut(method, problem) then return

    val solution =
        if useFluxEngine then new FluxSolver().calculateMopSolutionForwards(problem)
        else new DataFlowSolver().calculateMopSolutionForwards(problem)
    val ddgGenerator = new DdgGenerator(s)
    ddgGenerator.addReachingDefEdges(dstGraph, method, problem, solution)
```

Note the switch from `ForkJoinParallelCpgPass` (library) to `OrderedParallelCpgPass` (atom CLI).
The ordered variant preserves deterministic edge ordering, which matters for reproducible slices.

#### 5. Applying the overlay programmatically

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import io.appthreat.dataflowengineoss.semanticsloader.FlowSemantic

val cpg = Cpg.withStorage("/tmp/atomdemo/app.atom")

// Add an extra semantic for a project-specific wrapper
val extraSem = FlowSemantic.from("com.example.Taint.wrap", List((1, -1)))

val opts = OssDataFlowOptions(
  maxNumberOfDefinitions = 8000,
  extraFlows = List(extraSem),
  useFluxEngine = true              // opt-in to the low-allocation Flux solver
)
new OssDataFlow(opts).run(new LayerCreatorContext(cpg))

// Now REACHING_DEF edges exist; reachableBy queries work
val sources = cpg.call.name("getParameter").argument.l
val sinks   = cpg.call.name("executeQuery").argument.l
println(s"Sources: ${sources.size}, Sinks: ${sinks.size}")
```

#### 6. Inspecting the REACHING_DEF edges

```scala
import io.shiftleft.semanticcpg.language.*
import io.appthreat.dataflowengineoss.language.*

// How many REACHING_DEF edges does the graph contain?
val edgeCount = cpg.graph.edges("REACHING_DEF").size
println(s"REACHING_DEF edges: $edgeCount")

// DDG predecessors of a specific call argument
cpg.call.name("executeQuery").argument.index(1)
   .repeat(_.ddgIn)(_.maxDepth(5).emit)
   .code.l
```

#### 7. atom CLI flags

```bash
# Classic engine (default), up to 2000 definitions per method
atom -l java --with-data-deps /path/to/project

# Flux engine with a higher limit
atom -l java --with-data-deps --max-num-def 8000 /path/to/project

# Revert to classic engine and disable fragment cache
atom -l java --with-data-deps --legacy-dataflow /path/to/project
```

`--legacy-dataflow` sets `useFluxEngine = false` and disables mini-graph fragment caching, giving
exact parity with pre-Flux behaviour for diagnostic purposes.
