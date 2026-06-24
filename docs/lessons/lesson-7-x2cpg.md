# Lesson 7: Shared Frontend Library (x2cpg) and Compiler Pass Infrastructure

### Learning Objective

Leverage the `x2cpg` shared core library to build custom compiler frontends, implement specialized AST creation logic, and design custom post-processing tagging and type-recovery passes. By the end you will know where the reusable building blocks live, which base classes to extend, and how the iterative `XTypeRecovery` framework resolves dynamically-typed code.

### Pre-requisites

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen) and run `sbt compile`.

### Conceptual Background

Writing a language frontend from scratch is time-consuming. Many tasks (mapping local variables to declarations, managing lexical scopes, building method/call/block AST subtrees, generating method signatures, and recovering types for dynamic languages) are identical across languages.

To avoid duplication, Chen ships the `x2cpg` module. Despite the historical name, in this repository it lives at:

```
platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/
```

All GitHub references below point at
`https://github.com/AppThreat/chen/tree/main/platform/frontends/x2cpg/...`.

`x2cpg` is consumed by every concrete frontend (`c2cpg`, `javasrc2cpg`, `jimple2cpg`, `jssrc2cpg`, `pysrc2cpg`, the PHP/Ruby frontends) and provides four families of components.

#### 1. Base pass classes (`io.shiftleft.passes`)

These are the units of CPG construction. A pass is created once and applied with `createAndApply()`, which builds a diff and commits it to the graph.

- `CpgPass` — single-threaded. Override `def run(dstGraph: DiffGraphBuilder): Unit`. Almost every tagger uses this.
- `ForkJoinParallelCpgPass[P]` — data-parallel. Override `def generateParts(): Array[P]` to enumerate work items and `def runOnPart(builder: DiffGraphBuilder, part: P): Unit` to process each in parallel; an optional `maxChunkSize` tunes batching.
- `ConcurrentWriterCpgPass[P]` — like the fork-join variant but serializes writes through a single concurrent writer, useful when parts contend on shared nodes.

In all cases `DiffGraphBuilder` is an alias for `overflowdb.BatchedUpdate.DiffGraphBuilder`.

#### 2. AST creation abstractions

`AstCreatorBase` (`platform/frontends/x2cpg/.../AstCreatorBase.scala`) is the shared superclass for every frontend's AST creator:

```scala
abstract class AstCreatorBase(filename: String)(implicit withSchemaValidation: ValidationMode):
  val diffGraph = new DiffGraphBuilder
  def createAst(): DiffGraphBuilder        // abstract: each frontend implements this
```

It exposes a large vocabulary of node-subtree builders so that frontends only translate language-specific syntax, never the CPG node wiring. Representative members:

- `globalNamespaceBlock(): NewNamespaceBlock`
- `methodAst(method, parameters, body, methodReturn, modifiers)` and the annotation-aware `methodAstWithAnnotations(...)`
- `methodStubAst(method, parameters, methodReturn, modifiers)` — for external/declaration-only methods
- `callAst(callNode, arguments, base, receiver)`
- `blockAst(blockNode, statements)`
- `controlStructureAst(controlStructureNode, condition, children, placeConditionLast)`, plus `whileAst`, `doWhileAst`, `forAst`, `tryCatchAst`
- `returnAst(returnNode, arguments)`
- `setArgumentIndices(arguments)` — assigns `ARGUMENT_INDEX` so dataflow/semantics align
- `withArgumentIndex` / `withArgumentName` — attach argument metadata to an `ExpressionNew`
- `staticInitMethodAst(...)`, `annotationAst(...)`, `nextClosureName()` (backed by an `IntervalKeyPool`)

#### 3. Scope management

`datastructures/Scope.scala` provides a generic lexical scope stack used during AST creation to resolve identifiers to their declaration:

```scala
class Scope[I, V, S]:
  protected var stack: List[ScopeElement[I, V, S]]
  def isEmpty: Boolean
  def pushNewScope(scopeNode: S): Unit
  def popScope(): Option[S]
  def addToScope(identifier: I, variable: V): S
  def lookupVariable(identifier: I): Option[V]
```

`I` is the identifier key (usually a `String`), `V` the variable node (e.g. a `NewLocal`), and `S` the scope node (method/block). Frontends push a scope on method/block entry, register locals via `addToScope`, resolve uses via `lookupVariable`, and `popScope` on exit.

#### 4. Generic type recovery (`passes/frontend/XTypeRecovery.scala`)

Dynamically-typed frontends (JavaScript, Python, Ruby) cannot know a value's type at parse time. `XTypeRecovery` runs an iterative interprocedural fixpoint to populate `TYPE_FULL_NAME`. Key pieces:

```scala
case class XTypeRecoveryConfig(iterations: Int = 2, enabledDummyTypes: Boolean = true)

case class XTypeRecoveryState(
  config: XTypeRecoveryConfig,
  currentIteration: Int,
  isFieldCache: TrieMap[Long, Boolean],
  changesWereMade: AtomicBoolean,
  stopEarly: AtomicBoolean
):
  lazy val isFinalIteration: Boolean
  lazy val isFirstIteration: Boolean
  def clear(): Unit
```

The pass hierarchy:

- `abstract class XTypeRecoveryPass[CompilationUnitType <: AstNode](cpg, config) extends CpgPass(cpg)` — orchestrates the iterations, calling `generateRecoveryPass(state)` each round.
- `abstract class XTypeRecovery[CompilationUnitType <: AstNode](cpg, state) extends CpgPass(cpg)` — one iteration; `compilationUnit: Iterator[CompilationUnitType]` enumerates units and `generateRecoveryForCompilationUnitTask(unit, builder)` forks the per-unit task.
- `abstract class RecoverForXCompilationUnit[CompilationUnitType <: AstNode](cpg, cu, builder, state) extends RecursiveTask[Boolean]` — the per-unit fork-join task. It owns a `symbolTable: SymbolTable[LocalKey]` and `compute(): Boolean`, with a rich visitor surface: `visitAssignments`, `visitIdentifierAssignedToCall`, `visitIdentifierAssignedToLiteral`, `visitImport`, `setTypeInformation()`, `persistType(...)`, `methodReturnValues(...)`, and many more.

When a real type cannot be inferred, the recovery emits **dummy type tokens** so downstream passes still have something to chain on:

```scala
object XTypeRecovery:
  val DummyReturnType  = "<returnValue>"
  val DummyMemberLoad  = "<member>"
  val DummyIndexAccess = "<indexAccess>"
  def isDummyType(typ: String): Boolean
```

Dummy types are opt-out. The `TypeRecoveryParserConfig[R]` mixin adds CLI plumbing:

```scala
trait TypeRecoveryParserConfig[R <: X2CpgConfig[R]]:
  var disableDummyTypes: Boolean
  var typePropagationIterations: Int
  def withDisableDummyTypes(value: Boolean): R
  def withTypePropagationIterations(value: Int): R
```

#### 5. Tagger passes (`passes/taggers/`)

Every tagger extends `CpgPass`. They run after the CPG is built and annotate it with semantic `TAGGED_BY` edges (see Lesson 11 for the tag API):

- `CdxPass` — reads an SBOM/CycloneDX `bom.json` and tags nodes with PURL/package provenance per language.
- `PiiTagsPass` — value- and name-based PII/PCI/HIPAA/GDPR classification of literals, parameters, members and identifiers.
- `TrackersTagsPass` — detects analytics/advertising SDK namespaces.
- `ChennaiTagsPass` — framework route/input/output and sanitiser tagging, driven by `chennai.json`.
- `EasyTagsPass`, `AndroidServicesTagsPass` — language-pattern and Android service ingress/egress tagging.

### Real Commands and Code Examples

#### 1. Running semantic tagger passes against an atom file

There is no `loadCpg(...)` helper. Open a stored atom with `Cpg.withStorage`:

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.appthreat.x2cpg.passes.taggers.PiiTagsPass

val cpg = Cpg.withStorage("/tmp/app.atom")
new PiiTagsPass(cpg).createAndApply()
```

#### 2. Writing a single-threaded pass

```scala
package io.appthreat.x2cpg.passes.example

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

class CountMethodsPass(atom: Cpg) extends CpgPass(atom):
  override def run(dstGraph: DiffGraphBuilder): Unit =
    val n = atom.method.size
    println(s"This atom has $n methods")
```

#### 3. Configuring type recovery on a dynamic frontend

```scala
import io.appthreat.x2cpg.passes.frontend.XTypeRecoveryConfig

// Two propagation iterations, dummy types disabled for cleaner output.
val cfg = XTypeRecoveryConfig(iterations = 2, enabledDummyTypes = false)
```

On the command line, the corresponding flags come from `TypeRecoveryParserConfig`:

```bash
./atom.sh -l python -o app.atom --no-dummy-types --type-prop-iterations 3 /path/to/project
```

### Summary

`x2cpg` is the shared spine of every Chen frontend: base passes from `io.shiftleft.passes`, the `AstCreatorBase` subtree builders, the generic `Scope` stack, the iterative `XTypeRecovery` framework, and the tagger family. Extend these instead of reinventing CPG plumbing.
