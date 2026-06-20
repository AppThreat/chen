# Lesson 7: Shared Frontend Library (x2cpg) and Compiler Pass Infrastructure

### Learning Objective

Leverage the `x2cpg` shared core library to build custom compiler frontends, implement specialized AST creation logic, and design custom post-processing tagging and type recovery passes.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen) and run `sbt compile`.

### Conceptual Background

Writing a language frontend from scratch is time-consuming. Many tasks (such as mapping local variables, managing scopes, compiling file node lists, generating method signatures, and implementing iterative type recovery) are identical across languages.

To avoid duplication, Chen implements the [x2cpg](https://github.com/AppThreat/chen/tree/main/x2cpg) module, a shared library of utility classes, base traits, and post-processing passes.

Key components of `x2cpg` include:

- **Base Pass Classes**: Generic passes like `ForkJoinParallelCpgPass` to write graph nodes and edges concurrently.
- **AST Creation Abstractions**: Traits like `AstCreatorBase` that manage variable scopes (using a scope stack) and translate AST structures into unified CPG nodes.
- **Tagger Passes**: Implementations for semantic tags:
  - [CdxPass](https://github.com/AppThreat/chen/blob/main/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/taggers/CdxPass.scala): Maps SBOM variables.
  - [PiiTagsPass](https://github.com/AppThreat/chen/blob/main/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/taggers/PiiTagsPass.scala): Tags privacy data.
  - [TrackersTagsPass](https://github.com/AppThreat/chen/blob/main/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/taggers/TrackersTagsPass.scala): Tags advertising SDKs.
  - [ChennaiTagsPass](https://github.com/AppThreat/chen/blob/main/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/taggers/ChennaiTagsPass.scala): Enforces sanitization and validation tags.
- **Generic Type Recovery**: The `XTypeRecovery` framework, which implements interprocedural type recovery. Language frontends (like JavaScript and Python) extend this framework to resolve dynamic typing structures.

### Real Commands and Code Examples

#### 1. Running Semantic Tagger Passes

The tagger passes are executed on the final CPG using a standard `createAndApply` pipeline:

```scala
import io.shiftleft.codepropertygraph.generated.Cpg
import io.appthreat.x2cpg.passes.taggers.PiiTagsPass

val cpg: Cpg = loadCpg("/tmp/cpg.bin")
new PiiTagsPass(cpg).createAndApply()
```

#### 2. Writing a Custom Type Recovery Pass in Scala

Below is a code example showing how to create a custom type recovery pass by extending the `XTypeRecovery` class:

```scala
package io.appthreat.x2cpg.passes.frontend

import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import overflowdb.BatchedUpdate

class CustomTypeRecoveryPass(cpg: Cpg) extends XTypeRecovery[Unit](cpg) {

  override def generateRecoveryPass(builder: BatchedUpdate.InternalCreator): Unit = {
    // Implement custom type inference rules
    cpg.identifier.foreach { identifier =>
      if (identifier.name.contains("token") || identifier.name.contains("key")) {
        // Tag as sensitive token type
        builder.setNodeProperty(identifier, "TYPE_FULL_NAME", "io.appthreat.types.SensitiveToken")
      }
    }
  }
}
```
