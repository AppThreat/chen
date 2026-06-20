# Lesson 8: Modular Mini-Graph Stitching and Incremental Linking (StitchPass)

### Learning Objective

Understand how `StitchPass` links individual mini-graph fragments into a unified CPG, and master the configuration of incremental re-stitching for changed code files using the `SymbolIndex`.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen).

### Conceptual Background

In large-scale codebases, generating a whole-program CPG in a single monolithic pass is memory-intensive and slow. To scale, the compiler can generate small "mini-graphs" (or graph fragments) for individual source units (files) independently. These isolated fragments must then be linked together to form a whole-program graph. This process is called **stitching**.

The [StitchPass](https://github.com/AppThreat/chen/blob/main/platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/linking/StitchPass.scala) class manages this linking in two modes:

1. **Full Stitch**: Performs a global scan, indexing all method definitions and resolving all call sites, references, inheritance trees, and alias nodes.
2. **Incremental Stitch**: Takes a set of `dirtyUnits` (source files that have changed). Instead of re-linking the entire graph, it only re-stiches call sites and references belonging to the dirty files or targeting symbols in those files, reducing execution time.

Stitching is backed by the [SymbolIndex](https://github.com/AppThreat/chen/blob/main/platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/linking/SymbolIndex.scala), which maintains:

- **unitExports**: A lookup table mapping each source unit to the Fully Qualified Names (FQNs) of symbols it exports.
- **typeMap / methodMap**: Quick lookup mappings for types and methods across fragment boundaries, avoiding costly whole-graph traversals.

### Real Commands and Code Examples

#### 1. Running a Stitch Validation Test

Execute the C2CPG incremental stitching validation script:

```bash
sbt "c2cpg/testOnly io.appthreat.c2cpg.StitchValidation"
```

#### 2. Running StitchPass Programmatically in Scala

Below is a code example showing how to invoke `StitchPass` in both full and incremental modes:

```scala
import io.appthreat.x2cpg.passes.linking.StitchPass
import io.shiftleft.codepropertygraph.generated.Cpg
import java.nio.file.Paths

val cpg: Cpg = loadCpg("/tmp/cpg.bin")

// 1. Run a full stitch over the entire graph
val fullStitch = new StitchPass(cpg)
fullStitch.createAndApply()
println(s"Full stitch complete. Realized edges: ${fullStitch.realizedEdges}")

// 2. Run an incremental stitch on specific modified files (dirty units)
val modifiedFiles = Set("src/main/java/io/appthreat/Service.java")
val incrementalStitch = new StitchPass(cpg, dirtyUnits = Some(modifiedFiles))
incrementalStitch.createAndApply()
println(s"Incremental stitch complete. Realized edges: ${incrementalStitch.realizedEdges}")
```
