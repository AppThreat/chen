# Lesson 11: Developing Custom Semantic Taggers

### Learning Objective

Create and implement custom semantic tagger passes in the `x2cpg` module to tag parameters, call sites, and variables for data-flow filtering.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone of [chen](https://github.com/AppThreat/chen).

### Conceptual Background

Security audits and compliance checks require identifying specific source and sink categories (such as PII, framework routes, system APIs, or SQL queries). Rather than hardcoding these mappings in the query engine, Chen uses semantic taggers.

Taggers are compiler passes that inherit from `CpgPass` or `ForkJoinParallelCpgPass`. They scan graph nodes (such as `Method`, `MethodParameterIn`, `Call`, `Literal`, or `Identifier`) and apply tags:

- **PII/Sensitive Data**: The `PiiTagsPass` scans parameters and local variables for keywords (e.g. `password`, `ssn`, `credit_card`) and tags them.
- **Trackers**: The `TrackersTagsPass` detects calls to known tracking and analytics SDK namespaces.
- **Chennai/Custom Rules**: The `ChennaiTagsPass` reads a JSON configuration (declaring validator, sanitizer, and framework input functions) and applies semantic tags dynamically.

Once tagged, the data-flow engine can filter paths using these tags (e.g., tracking flows from nodes tagged `pii` to nodes tagged `tracker`).

### Real Commands and Code Examples

#### 1. Applying a Tagger Pass to an Atom File

Execute a tagging pass programmatically:

```scala
import io.shiftleft.codepropertygraph.generated.Cpg
import io.appthreat.x2cpg.passes.taggers.TrackersTagsPass

val cpg: Cpg = loadCpg("/tmp/cpg.bin")
val tagPass = new TrackersTagsPass(cpg)
tagPass.createAndApply()
```

#### 2. Implementing a Custom Tagger Pass in Scala

Below is a code example showing how to write a custom semantic tagger pass that checks for cryptographic keys:

```scala
package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import overflowdb.BatchedUpdate

class CryptoKeyTaggerPass(cpg: Cpg) extends ForkJoinParallelCpgPass[Literal](cpg) {

  // Query nodes to process (only Literals representing key strings)
  override def generateParts(): Array[Literal] = {
    cpg.literal.filter(_.code.toLowerCase.contains("key")).toArray
  }

  // Process each node concurrently and add tags
  override def runOnPart(diffGraph: BatchedUpdate.InternalCreator, part: Literal): Unit = {
    val tag = NewTag()
      .name("crypto-key")
      .value(part.code)

    // Write the tag to the node
    diffGraph.setNodeProperty(part, "TAGS", tag)
  }
}
```
