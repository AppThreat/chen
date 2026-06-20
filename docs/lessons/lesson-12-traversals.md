# Lesson 12: Writing Custom Traversal Methods

### Learning Objective

Define type-safe, domain-specific traversal steps over CPG node iterators, understand how the `semanticcpg` DSL wires them up with implicit conversions, and add your own steps in the same idiom.

### Pre-requisites

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen).

### Conceptual Background

Writing raw edge walks like `node.out("AST").collect { case m: Method => m }` is verbose and untyped. The query DSL lives in
`semanticcpg/src/main/scala/io/shiftleft/semanticcpg/language/`
and turns those walks into readable, type-safe steps such as `atom.method.parameter.name`.

A core fact to internalize: **traversals in this DSL are plain `Iterator[NodeType]`**, not a bespoke `Traversal` class. Steps are added by lightweight wrapper classes that `extend AnyVal` (zero-allocation value classes wrapping the iterator), and implicit conversions in `language/package.scala` make those steps appear directly on the iterator. There are two flavours:

#### 1. Node-method classes (steps on a single node)

Found under `language/nodemethods/`. They wrap one node and add convenience accessors. Example, `ExpressionMethods`:

```scala
class ExpressionMethods(val node: Expression) extends AnyVal with NodeExtension:
  def parentExpression: Option[Expression] = ...
```

Wired in `package.scala`:

```scala
implicit def toExpressionMethods(node: Expression): ExpressionMethods =
  new ExpressionMethods(node)
```

#### 2. Traversal-step classes (steps on a collection)

These wrap an `Iterator[NodeType]` and are the steps you chain in queries. The canonical minimal example is `IdentifierTraversal` (`language/types/expressions/IdentifierTraversal.scala`):

```scala
package io.shiftleft.semanticcpg.language.types.expressions

import io.shiftleft.codepropertygraph.generated.nodes.{Declaration, Identifier}
import io.shiftleft.semanticcpg.language.toTraversalSugarExt

/** An identifier, e.g., an instance of a local variable, or a temporary variable */
class IdentifierTraversal(val traversal: Iterator[Identifier]) extends AnyVal:

  /** Traverse to all declarations of this identifier */
  def refsTo: Iterator[Declaration] =
    traversal.flatMap(_.refOut).cast[Declaration]
```

It is wired with two implicit conversions in `package.scala` (one for a single node, one for any `IterableOnce`):

```scala
implicit def singleToIdentifierTrav[A <: Identifier](a: A): IdentifierTraversal =
  new IdentifierTraversal(Iterator.single(a))
implicit def iterOnceToIdentifierTrav[A <: Identifier](a: IterableOnce[A]): IdentifierTraversal =
  new IdentifierTraversal(a.iterator)
```

That pair is what lets you write `atom.identifier.refsTo` and also `someIdentifier.refsTo`.

#### Reading tags back

Tags attached by Lesson 11's passes are read with the tag traversal steps. `TagTraversal` (`language/TagTraversal.scala`) lets you go from `Tag` nodes back to the tagged nodes by type, and the underlying `_taggedByIn` edge powers it:

```scala
class TagTraversal(val traversal: Iterator[Tag]) extends AnyVal:
  def call: Iterator[Call]               = tagged[Call]
  def parameter: Iterator[MethodParameterIn] = tagged[MethodParameterIn]
  private def tagged[A <: StoredNode: ClassTag]: Iterator[A] =
    traversal._taggedByIn.collectAll[A].sortBy(_.id).iterator
```

So `atom.tag.name("framework-input").parameter` returns every parameter tagged as a framework input.

### Real Commands and Code Examples

#### 1. Using the built-in DSL

`atom` is the node-type starter (see `docs/TRAVERSAL.md` for the full table of starters: `call`, `method`, `identifier`, `literal`, `local`, `tag`, `typeDecl`, ...):

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val atom = Cpg.withStorage("/tmp/app.atom")

// All parameters of methods whose full name matches a package pattern.
val params = atom.method.fullName("io\\.appthreat\\..*").parameter.l

// All declarations referenced by identifiers named "token".
val decls = atom.identifier.name("token").refsTo.l
```

#### 2. Writing your own traversal step

Add a step on `Method` iterators that keeps only methods carrying a given annotation, plus a step that projects to enclosing type names. Match the real idiom: wrap `Iterator[Method]`, `extend AnyVal`, return `Iterator[...]`, and import the DSL so nested steps (`.annotation`, `.typeDecl`) resolve.

```scala
package io.appthreat.x2cpg.language

import io.shiftleft.codepropertygraph.generated.nodes.{Method, TypeDecl}
import io.shiftleft.semanticcpg.language.*

class CustomMethodTraversal(val traversal: Iterator[Method]) extends AnyVal:

  /** Keep only methods that carry an annotation whose name matches the pattern. */
  def annotatedWith(namePattern: String): Iterator[Method] =
    traversal.filter(_.annotation.name(namePattern).nonEmpty)

  /** Project each method to the name of its enclosing type declaration. */
  def enclosingTypeName: Iterator[String] =
    traversal.flatMap(_.typeDecl).name

object CustomMethodTraversal:
  given Conversion[Iterator[Method], CustomMethodTraversal] = new CustomMethodTraversal(_)
```

With the `given` (Scala 3) conversion imported, the step composes naturally:

```scala
import io.appthreat.x2cpg.language.CustomMethodTraversal.given
import io.shiftleft.semanticcpg.language.*

val controllers =
  atom.method.annotatedWith(".*Controller.*").enclosingTypeName.toSet
```

The `given Conversion[Iterator[Method], CustomMethodTraversal]` mirrors exactly what `iterOnceToIdentifierTrav` does in the core DSL — it is the Scala 3 spelling of the same implicit wiring.

#### 3. Where to register first-class steps

Steps that should ship with the toolkit go under `semanticcpg/.../language/` next to their node type (e.g. expression steps under `types/expressions/`) and get their conversions added to `language/package.scala` so a single `import io.shiftleft.semanticcpg.language.*` pulls them in.

### Summary

The query DSL is built from `AnyVal` wrapper classes over `Iterator[NodeType]`, surfaced through implicit/`given` conversions in `language/package.scala`. To add a step, write such a wrapper, return `Iterator[...]` (or `Option`/scalar), provide a conversion, and import the DSL inside it so you can reuse existing steps. See `docs/TRAVERSAL.md` for the starter and step catalog.
