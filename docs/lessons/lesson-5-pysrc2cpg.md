# Lesson 5: Python Frontend (pysrc2cpg) and Dynamic Semantic Mapping

### Learning Objective

Parse Python source code repositories, map dynamic features (dynamic imports, keyword arguments, and decorators), and run type recovery and call linking passes.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Python 3.10+**: Must be installed on the system path.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen) and run `sbt compile`.

### Conceptual Background

Python features dynamic imports (e.g. `importlib`), keyword arguments, decorators, list comprehensions, and runtime type assignments. Tracking variables in Python is challenging because typing information is resolved at runtime.

The [pysrc2cpg](https://github.com/AppThreat/chen/tree/main/pysrc2cpg) frontend compiles Python source code into a CPG using the following steps:

1. **Python AST Generation**: Runs a python parsing script (`astgen.py`) to generate a JSON representation of the AST.
2. **AST Parsing**: Imports the JSON AST nodes into CPG representation.

Following this, the frontend runs several post-processing passes:

- **[PythonImportsPass](https://github.com/AppThreat/chen/blob/main/pysrc2cpg/src/main/scala/io/appthreat/pysrc2cpg/ImportsPass.scala)**: Maps python imports and namespaces.
- **[DynamicTypeHintFullNamePass](https://github.com/AppThreat/chen/blob/main/pysrc2cpg/src/main/scala/io/appthreat/pysrc2cpg/DynamicTypeHintFullNamePass.scala)**: Translates dynamic type hints (e.g. `typing.Union` or `typing.Optional`) into CPG types.
- **[PythonInheritanceNamePass](https://github.com/AppThreat/chen/blob/main/pysrc2cpg/src/main/scala/io/appthreat/pysrc2cpg/PythonInheritanceNamePass.scala)**: Traces base classes and resolves class hierarchies.
- **[PythonTypeRecoveryPass](https://github.com/AppThreat/chen/blob/main/pysrc2cpg/src/main/scala/io/appthreat/pysrc2cpg/PythonTypeRecoveryPass.scala)**: Evaluates variable values and dynamically infers parameter types.
- **[PythonTypeHintCallLinker](https://github.com/AppThreat/chen/blob/main/pysrc2cpg/src/main/scala/io/appthreat/pysrc2cpg/PythonTypeHintCallLinker.scala)**: Re-evaluates call sites and links them to the resolved methods.

### Real Commands and Code Examples

#### 1. Compiling a Python Project

Compile a Python project to a CPG, ignoring standard directories like virtual environments:

```bash
./atom.sh -l python -o app.atom /path/to/python/project
```

#### 2. Running Py2Cpg Programmatically in Scala

Below is a code example showing how to invoke `pysrc2cpg` and run post-processing passes:

```scala
import io.appthreat.pysrc2cpg.{Py2CpgOnFileSystem, Py2CpgOnFileSystemConfig}
import io.appthreat.pysrc2cpg.{
  DynamicTypeHintFullNamePass,
  PythonInheritanceNamePass,
  PythonTypeHintCallLinker,
  PythonTypeRecoveryPass,
  ImportsPass as PythonImportsPass,
  ImportResolverPass as PyImportResolverPass
}
import io.appthreat.x2cpg.passes.base.AstLinkerPass
import io.appthreat.x2cpg.passes.frontend.XTypeRecoveryConfig
import scala.util.Success

val config = Py2CpgOnFileSystemConfig()
  .withDisableDummyTypes(true)
  .withTypePropagationIterations(1)
  .withInputPath("/path/to/python/source")
  .withOutputPath("/tmp/py_project.atom")

val py2cpg = new Py2CpgOnFileSystem()
py2cpg.createCpgWithOverlays(config).map { cpg =>
  // Apply post-processing compiler passes
  new PythonImportsPass(cpg).createAndApply()
  new PyImportResolverPass(cpg).createAndApply()
  new DynamicTypeHintFullNamePass(cpg).createAndApply()
  new PythonInheritanceNamePass(cpg).createAndApply()
  new PythonTypeRecoveryPass(cpg, XTypeRecoveryConfig(enabledDummyTypes = false)).createAndApply()
  new PythonTypeHintCallLinker(cpg).createAndApply()
  new AstLinkerPass(cpg).createAndApply()

  println(s"Python CPG created successfully. Node count: ${cpg.graph.nodeCount}")
  cpg.close()
}
```
