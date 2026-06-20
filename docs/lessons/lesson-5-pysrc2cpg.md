# Lesson 5: Python Frontend (pysrc2cpg)

## Learning Objective

Understand how `pysrc2cpg` compiles Python source into a CPG using a **native in-process parser**
(no external AST generator), how it filters virtualenvs and ignored directories, and how the
chain of import/type-recovery passes recovers Python's runtime semantics.

## Pre-requisites

- JDK 23+ (OpenJDK or GraalVM)
- SBT 1.10+
- Local clone of [chen](https://github.com/AppThreat/chen): `sbt compile`

> Unlike JS/TS or Ruby, `pysrc2cpg` does **not** shell out to an external `astgen` binary. It
> uses a hand-written Scala parser (`PyParser`, invoked from `CodeToCpg`), so no Python runtime
> is required to build the graph.

## Conceptual Background

Python features dynamic imports (`importlib`), keyword arguments, decorators, comprehensions, and
runtime type assignment. Tracking variables is hard because types are resolved at runtime.

`pysrc2cpg` builds the graph in a single in-process pass and then runs a series of passes to
recover the dynamic structure. The file-system entry point is
[`Py2CpgOnFileSystem`](https://github.com/AppThreat/chen/blob/main/platform/frontends/pysrc2cpg/src/main/scala/io/appthreat/pysrc2cpg/Py2CpgOnFileSystem.scala),
which selects the `.py` files, applies ignore filters, and hands content providers to the inner
`Py2Cpg` builder.

Source:
[platform/frontends/pysrc2cpg](https://github.com/AppThreat/chen/tree/main/platform/frontends/pysrc2cpg)

## Config Fields (`Py2CpgOnFileSystemConfig`)

```scala
case class Py2CpgOnFileSystemConfig(
  venvDir: Path        = Paths.get(".venv"),  // virtualenv directory to ignore
  ignoreVenvDir: Boolean = true,              // skip the venv directory
  ignorePaths: Seq[Path] = Nil,               // explicit paths to ignore
  ignoreDirNames: Seq[String] = Nil,          // directory *names* to ignore anywhere
  requirementsTxt: String = "requirements.txt"// dependency manifest to parse
) extends X2CpgConfig[Py2CpgOnFileSystemConfig]
    with TypeRecoveryParserConfig[Py2CpgOnFileSystemConfig]
```

Builders: `withVenvDir`, `withIgnoreVenvDir`, `withIgnorePaths`, `withIgnoreDirNames`,
`withRequirementsTxt`, plus the inherited `withDisableDummyTypes` / `withTypePropagationIterations`.

## Pass Pipeline

`Py2Cpg.buildCpg()` runs:

1. **CodeToCpg** — the main pass. Reads each file's content, parses it with `PyParser`
   (line-break corrected), and emits the structural graph.
2. **ConfigFileCreationPass** — creates `CONFIG_FILE` nodes (`setup.py`, `pyproject.toml`,
   `requirements.txt`, …).
3. **DependenciesFromRequirementsTxtPass** — parses `requirements.txt` and records `DEPENDENCY`
   nodes.

`createCpgWithOverlays` then runs **Base**, **ControlFlow**, **TypeRelations**, **CallGraph**.

### Post-processing passes (run by `atom`)

1. **PythonImportsPass** (`ImportsPass`) — maps imports and namespaces.
2. **PyImportResolverPass** (`ImportResolverPass`) — resolves imports to their definitions.
3. **DynamicTypeHintFullNamePass** — translates `typing` hints (`Union`, `Optional`, …) into CPG
   types.
4. **PythonInheritanceNamePass** — resolves base classes / class hierarchies.
5. **PythonTypeRecoveryPass** — iterative interprocedural type recovery (extends `XTypeRecovery`).
6. **PythonTypeHintCallLinker** — re-links call sites once types are recovered.
7. **AstLinkerPass** — finalises AST parent/child edges for late-created nodes.

## Real Commands and Code Examples

### atom CLI (`-l python` / `-l py`)

```bash
atom -l python -o app.atom /path/to/python/project
```

Virtualenvs (`.venv`) are ignored by default. To ignore extra directories:

```bash
atom -l python -o app.atom --ignored-dirs "build;dist;migrations" /path/to/python/project
```

### Build with the Scala API

```scala
import io.appthreat.pysrc2cpg.{Py2CpgOnFileSystem, Py2CpgOnFileSystemConfig}
import io.appthreat.pysrc2cpg.{
  DynamicTypeHintFullNamePass, PythonInheritanceNamePass,
  PythonTypeHintCallLinker, PythonTypeRecoveryPass,
  ImportsPass as PythonImportsPass, ImportResolverPass as PyImportResolverPass
}
import io.appthreat.x2cpg.passes.base.AstLinkerPass
import io.appthreat.x2cpg.passes.frontend.XTypeRecoveryConfig
import scala.util.{Success, Failure}

val config = Py2CpgOnFileSystemConfig()
  .withDisableDummyTypes(true)
  .withTypePropagationIterations(1)
  .withInputPath("/path/to/python/source")
  .withOutputPath("/tmp/py_project.atom")

new Py2CpgOnFileSystem().createCpgWithOverlays(config) match
  case Success(cpg) =>
    new PythonImportsPass(cpg).createAndApply()
    new PyImportResolverPass(cpg).createAndApply()
    new DynamicTypeHintFullNamePass(cpg).createAndApply()
    new PythonInheritanceNamePass(cpg).createAndApply()
    new PythonTypeRecoveryPass(cpg, XTypeRecoveryConfig(enabledDummyTypes = false)).createAndApply()
    new PythonTypeHintCallLinker(cpg).createAndApply()
    new AstLinkerPass(cpg).createAndApply()
    println(s"Methods: ${cpg.method.size}")
    cpg.close()
  case Failure(ex) => println(s"Failed: ${ex.getMessage}")
```

### Open and query the atom file

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/py_project.atom")

// Flask / Django route handlers (decorated methods)
cpg.method.where(_.annotation.name(".*route|.*api_view")).name.l

// subprocess / os command-execution sinks
cpg.call.methodFullName(".*subprocess.*|.*os\\.system.*").l

// Classes and their resolved base types
cpg.typeDecl.map(td => (td.name, td.inheritsFromTypeFullName.l)).take(10).l
```

## Notes for Security Analysts

- Type recovery defaults to 2 iterations; raising `typePropagationIterations` improves precision
  on heavily dynamic code at the cost of build time. Use `withDisableDummyTypes(true)` to avoid
  speculative `<...>` placeholder types polluting queries.
- `DynamicTypeHintFullNamePass` only helps where developers used `typing` annotations; untyped
  code relies entirely on `PythonTypeRecoveryPass` propagation from assignments and literals.
- Keep `ignoreVenvDir = true` (the default). Analysing the vendored packages in `.venv` is rarely
  desired and dramatically inflates the graph.
