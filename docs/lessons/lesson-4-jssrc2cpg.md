# Lesson 4: JavaScript & TypeScript Frontend (jssrc2cpg)

## Learning Objective

Understand how `jssrc2cpg` turns JavaScript/TypeScript source into a CPG using the external
`astgen` tool, how the two-stage (parse → ingest) pipeline works, and how type recovery and
import resolution recover the dynamic bindings that the raw AST cannot express.

## Pre-requisites

- JDK 23+ (OpenJDK or GraalVM)
- SBT 1.10+
- Node.js 20+
- `@appthreat/atom-parsetools` installed globally (`npm install -g @appthreat/atom-parsetools`)
  — provides the `astgen` binary. The frontend also ships platform binaries it can fall back to.
- Local clone of [chen](https://github.com/AppThreat/chen): `sbt compile`

## Conceptual Background

JavaScript and TypeScript are dynamically typed, so most variables carry no declared type, and
calls are bound at runtime. `jssrc2cpg` therefore builds the graph in two clearly separated
stages:

1. **AST generation (out of process).** A native Node-based tool, `astgen` (Babel/Esprima under
   the hood), parses every `.js`, `.jsx`, `.ts`, `.tsx`, `.vue` file and emits one JSON AST file
   per source file. This is driven by
   [`AstGenRunner`](https://github.com/AppThreat/chen/blob/main/platform/frontends/jssrc2cpg/src/main/scala/io/appthreat/jssrc2cpg/utils/AstGenRunner.scala).
2. **CPG ingestion (in process).** `AstCreationPass` reads the JSON and materialises `METHOD`,
   `TYPE_DECL`, `CALL`, `BLOCK`, `LOCAL`, control-flow, and AST nodes.

Because the AST alone cannot resolve `require()`/`import` targets or propagate types across
assignments, a set of **post-processing passes** runs after the base overlays to reconstruct
that semantic information.

Source:
[platform/frontends/jssrc2cpg](https://github.com/AppThreat/chen/tree/main/platform/frontends/jssrc2cpg)

## Config Fields (real names from `Main.scala`)

```scala
final case class Config(
  tsTypes: Boolean      = true,   // generate types via the TypeScript compiler (--no-tsTypes to disable)
  flow: Boolean         = false,  // enable Flow mode  (astgen -t flow)
  astGenOutDir: Option[String] = None  // permanent astgen output dir (reuse JSON between runs)
) extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]
```

The `TypeRecoveryParserConfig` mix-in adds `disableDummyTypes` and `typePropagationIterations`
(with `withDisableDummyTypes` / `withTypePropagationIterations`).

## Pass Pipeline (`JsSrc2Cpg.createCpg`)

Inside `createCpg`, after `astgen` runs:

1. **AstCreationPass** — ingests every JSON AST file; builds the structural graph.
2. **TypeNodePass** — materialises `TYPE` nodes from `astCreationPass.allUsedTypes()`.
3. **JsMetaDataPass** — writes the `MetaData` node and a SHA-256 hash of the parsed files.
4. **BuiltinTypesPass** — seeds builtin JS/TS types (`Object`, `Array`, `String`, …).
5. **ConfigPass** — creates `CONFIG_FILE` nodes (`package.json`, `tsconfig.json`, …).
6. **PrivateKeyFilePass** — flags files that look like embedded private keys.
7. **ImportsPass** — creates `IMPORT` nodes from the AST import statements.

`createCpgWithOverlays` then runs the default overlays: **Base**, **ControlFlow**,
**TypeRelations**, **CallGraph** (see `X2Cpg.scala`).

### Post-processing passes

`JsSrc2Cpg.postProcessingPasses` (run by `createCpgWithAllOverlays`, and by the `atom` CLI) adds:

1. **JavaScriptInheritanceNamePass** — resolves `extends` parent/child relationships.
2. **ConstClosurePass** — links `const`-assigned closures to their definitions.
3. **ImportResolverPass** — resolves CommonJS `require()` and ES6 `import` to their targets.
4. **JavaScriptTypeRecoveryPass** — iterative interprocedural type propagation (extends the
   shared `XTypeRecovery` framework; iteration count from `typePropagationIterations`).
5. **JavaScriptTypeHintCallLinker** — links call sites to methods once a type hint is known.

> Note: the standalone frontend and `atom` both run these. When `atom` drives the build it also
> applies `TypeHintPass` (the atom-level call linker that uses `:` as the method-name separator).

## CLI Flags (`jssrc2cpg` standalone)

| Flag                          | Config field                                     |
| ----------------------------- | ------------------------------------------------ |
| `--no-tsTypes`                | `tsTypes=false`                                  |
| `--flow`                      | `flow=true`                                      |
| `--astgen-out d`              | `astGenOutDir`                                   |
| `XTypeRecovery.parserOptions` | `disableDummyTypes`, `typePropagationIterations` |

## Real Commands and Code Examples

### atom CLI (`-l ts` / `-l js` / `-l javascript` / `-l typescript` / `-l flow`)

```bash
atom -l ts -o app.atom /path/to/typescript/project
```

### Reuse astgen output between runs

`astGenOutDir` (also honoured via the `CHEN_ASTGEN_OUT` environment variable) points astgen at a
permanent directory. If valid `.json` files already exist there, the expensive parse step is
skipped:

```bash
CHEN_ASTGEN_OUT=/tmp/astgen-cache atom -l js -o app.atom /path/to/js/project
```

### Build with the Scala API (mirrors what atom does)

```scala
import io.appthreat.jssrc2cpg.{JsSrc2Cpg, Config}
import io.appthreat.jssrc2cpg.passes.{
  ConstClosurePass, ImportResolverPass,
  JavaScriptInheritanceNamePass, JavaScriptTypeRecoveryPass
}
import io.appthreat.atom.passes.TypeHintPass
import scala.util.{Success, Failure}

val config = Config()
  .withDisableDummyTypes(true)
  .withTypePropagationIterations(2)
  .withInputPath("/path/to/javascript/source")
  .withOutputPath("/tmp/js_project.atom")

new JsSrc2Cpg().createCpgWithOverlays(config) match
  case Success(cpg) =>
    new JavaScriptInheritanceNamePass(cpg).createAndApply()
    new ConstClosurePass(cpg).createAndApply()
    new ImportResolverPass(cpg).createAndApply()
    new JavaScriptTypeRecoveryPass(cpg).createAndApply()
    new TypeHintPass(cpg).createAndApply()
    println(s"Methods: ${cpg.method.size}")
    cpg.close()
  case Failure(ex) => println(s"Failed: ${ex.getMessage}")
```

### Open and query the atom file

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/js_project.atom")

// Find DOM-based XSS sinks
cpg.call.name("innerHTML|outerHTML|insertAdjacentHTML").l

// Calls into a resolved import (e.g. the express router)
cpg.call.methodFullName(".*express.*").code.take(20).l
```

## Notes for Security Analysts

- Without `ImportResolverPass`, calls into third-party modules keep a `methodFullName` of
  `<unknownFullName>` and cannot be matched by framework taggers — always run the
  post-processing passes (the `atom` CLI does this automatically).
- `tsTypes=true` invokes the TypeScript compiler during astgen; it produces far richer type
  information but is slower. Disable it with `--no-tsTypes` for very large pure-JS code bases.
- `PrivateKeyFilePass` is useful on its own for secret detection: it tags files whose content
  matches PEM/private-key patterns.
