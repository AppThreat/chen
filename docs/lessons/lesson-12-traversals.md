# Lesson 12: Writing Custom Traversal Methods

### Learning Objective

Define type-safe, domain-specific traversal steps and shortcuts, extending standard nodes and collections using Scala implicit classes.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone of [chen](https://github.com/AppThreat/chen).

### Conceptual Background

In static analysis queries, repeatedly writing manual edge traversals (e.g. `node.out("AST").collect { case m: Method => m }`) is verbose and error-prone. To simplify queries, the compiler infrastructure uses Scala implicit classes to define custom traversal steps.

These custom traversal steps extend:

- **Node Types**: Extends individual nodes (e.g. adding `.isExternal` to `Call` nodes).
- **Node Collections**: Extends traversals over collections of nodes (e.g. adding `.isLiteral` or `.annotation` to an iterator of nodes).

In Chen, these extensions are declared in the `language` packages of the frontends and are imported to write high-level, readable queries.

### Real Commands and Code Examples

#### 1. Running a Custom Query Traversal

Run a high-level traversal query to find all parameters of methods inside a target package:

```scala
val params = cpg.method.name("io.appthreat.*").parameter.l
```

#### 2. Writing Custom Traversal Steps in Scala

Below is a code example demonstrating how to write custom traversal steps for method annotation matching:

```scala
package io.appthreat.x2cpg.language

import io.shiftleft.codepropertygraph.generated.nodes.{Method, Annotation}
import overflowdb.traversal.*

object CustomTraversalExtensions {

  // Extend a traversal of Method nodes
  implicit class CustomMethodTraversal(val trav: Traversal[Method]) extends AnyVal {

    // Step to filter methods containing a specific annotation
    def withAnnotation(namePattern: String): Traversal[Method] = {
      trav.where(_.annotation.name(namePattern))
    }

    // Step to quickly fetch all enclosing class names
    def classNames: Traversal[String] = {
      trav.map(_.location.className)
    }
  }

  // Extend a traversal of Annotation nodes
  implicit class CustomAnnotationTraversal(val trav: Traversal[Annotation]) extends AnyVal {
    def codeLines: Traversal[String] = {
      trav.map(_.code)
    }
  }
}
```
