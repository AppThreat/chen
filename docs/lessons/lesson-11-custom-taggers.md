# Lesson 11: Developing Custom Semantic Taggers

### Learning Objective

Create custom semantic tagger passes in the `x2cpg` module that tag parameters, call sites, literals and identifiers, using the real tag API, and understand how the dataflow engine consumes those tags as sources, sinks and sanitisers.

### Pre-requisites

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen).

### Conceptual Background

Security and compliance analyses need to identify source and sink categories — PII, framework routes, system APIs, tracking SDKs, sanitisers. Rather than hardcoding these in the query engine, Chen attaches semantic **tags** to CPG nodes via a `TAGGED_BY` edge, then lets queries and the dataflow engine pivot on them.

Taggers live under
`platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/passes/taggers/`
and all extend `CpgPass`. The shipped taggers:

- **`PiiTagsPass(atom: Cpg)`** — tags literals/parameters/members/identifiers that resemble sensitive data. It works in two complementary ways: high-precision _value_ regexes for string literals (email, credit-card, SSN, AWS/Slack/GitHub tokens, JWT, ...) and _name_ keyword regexes for declared names (`ssn`, `creditCard`, `passwordHash`). Each match gets a fine-grained tag (`pii-email`, ...), an umbrella tag (`sensitive-data`), and compliance tags (`gdpr`, `pci-dss`, `hipaa`, `ccpa`, `pii`, `secret`). Categories are described by a `PiiCategory(tag, compliance, valueRegex, nameRegex, valuePredicate)` case class.
- **`TrackersTagsPass(atom: Cpg)`** — tags calls into known analytics/advertising SDK namespaces using a `Tracker(name, categories, namespaces, languages)` model; emits the `tracker` (and where relevant `adware`) tags, gated by the atom's language.
- **`ChennaiTagsPass(atom: Cpg, externalConfig: Option[String] = None)`** — framework route/input/output and sanitiser tagging. It applies built-in per-language route patterns (Python/Django/Flask, Express/Vue, PHP, Rails/Sinatra, C) and then reads a `chennai.json` config to declare additional sources/sinks/sanitisers. The `externalConfig` parameter lets a caller inject the same JSON without embedding it in the graph — this is what `atom --validation-config` uses.
- **`CdxPass`**, **`EasyTagsPass`**, **`AndroidServicesTagsPass`** — SBOM/PURL provenance, language-pattern shortcuts, and Android service ingress/egress.

#### The tag API (this is the only correct way)

Tags are **not** added with `diffGraph.setNodeProperty(node, "TAGS", ...)`. The real API is a traversal step `newTagNode(name: String)` followed by `store()(using dstGraph)`. `newTagNode` returns a `NewTagNodePairTraversal` (defined in `semanticcpg/.../language/NodeSteps.scala`), and `store` creates the `TAGGED_BY` edge:

```scala
import io.shiftleft.semanticcpg.language.*

atom.call.methodFullName(pattern)
  .newTagNode("framework-input")
  .store()(using dstGraph)
```

This works on any taggable node traversal (calls, parameters, methods, literals, members, identifiers, returns). For example, straight from `ChennaiTagsPass`:

```scala
atom.method.fullName(pattern).parameter
  .newTagNode("framework-input")
  .store()(using dstGraph)
```

and from `PiiTagsPass`, where matches are collected first and emitted in one batch:

```scala
matched.newTagNode(category.tag).store()(using dstGraph)
matched.newTagNode(SensitiveData).store()(using dstGraph)   // "sensitive-data"
category.compliance.foreach(c => matched.newTagNode(c).store()(using dstGraph))
```

Note `DiffGraphBuilder` here is `overflowdb.BatchedUpdate.DiffGraphBuilder`, the same type every pass receives in `run`/`runOnPart`.

### Real Commands and Code Examples

#### 1. Applying a shipped tagger to an atom file

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.appthreat.x2cpg.passes.taggers.TrackersTagsPass

val cpg = Cpg.withStorage("/tmp/app.atom")
new TrackersTagsPass(cpg).createAndApply()
```

For Chennai rules supplied externally:

```scala
import io.appthreat.x2cpg.passes.taggers.ChennaiTagsPass

val rules = scala.io.Source.fromFile("/etc/chennai.json").mkString
new ChennaiTagsPass(cpg, externalConfig = Some(rules)).createAndApply()
```

or on the command line:

```bash
./atom.sh -l js -o app.atom --validation-config /etc/chennai.json /path/to/project
```

#### 2. A custom parallel tagger for cryptographic key literals

This is a real, compiling shape: a `ForkJoinParallelCpgPass[Literal]` that tags string literals which look like crypto keys. `generateParts()` enumerates the work; `runOnPart` emits tags using the correct API.

```scala
package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Literal
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*

class CryptoKeyTagsPass(atom: Cpg) extends ForkJoinParallelCpgPass[Literal](atom):

  private val KeyHint = "(?i).*(secret|private[_-]?key|api[_-]?key|-----BEGIN).*".r

  override def generateParts(): Array[Literal] =
    atom.literal.filter(l => KeyHint.matches(l.code)).toArray

  override def runOnPart(builder: DiffGraphBuilder, part: Literal): Unit =
    Iterator(part).newTagNode("crypto-key").store()(using builder)
    Iterator(part).newTagNode("secret").store()(using builder)
```

Wrap a single node in `Iterator(part)` so the `newTagNode` traversal step is available; in `CpgPass` taggers you typically already hold an `Iterator`/`List` from a traversal.

#### 3. How dataflow consumes tags

Downstream reachability uses the tags as flow endpoints:

- nodes tagged **`framework-input`** are treated as **sources**,
- nodes tagged **`framework-output`** as **sinks**,
- nodes tagged **`sanitizer`** (and category-specific `sanitizer-<category>` tags) neutralise a flow that passes through them.

So a query can express "any tracker SDK call reachable from PII" or "any framework input reaching a framework output that does not pass through a sanitiser" purely in terms of the tags these passes attach. See Lesson 12 for the traversal steps (`tag`, `_taggedByIn`) that read them back.

### Summary

Custom taggers extend `CpgPass` (or `ForkJoinParallelCpgPass[P]` for parallelism), select nodes with the semantic DSL, and attach tags with `.newTagNode(name).store()(using dstGraph)`. Model your pass on `PiiTagsPass`/`TrackersTagsPass`/`ChennaiTagsPass`, and the dataflow engine will pick up the resulting source/sink/sanitiser tags for free.
