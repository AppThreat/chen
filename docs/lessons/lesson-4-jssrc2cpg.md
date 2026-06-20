# Lesson 4: JavaScript & TypeScript Frontend (jssrc2cpg) and Type Recovery

### Learning Objective

Parse JavaScript and TypeScript source files, execute AST generation, and run type recovery and call linking passes to resolve dynamic bindings in the CPG.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Node.js 20+**: Required for JavaScript and TypeScript parsing.
- **NPM package @appthreat/atom-parsetools**: Must be installed globally (`npm install -g @appthreat/atom-parsetools`) to provide the `astgen` binary tool.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen).

### Conceptual Background

JavaScript and TypeScript are dynamic languages with complex type behaviors. Unlike Java or C++, types are often not declared explicitly. To analyze these codebases, the compiler must dynamically resolve types.

The [jssrc2cpg](https://github.com/AppThreat/chen/tree/main/jssrc2cpg) frontend compiles JS/TS in two stages:

1. **AST Generation**: Runs the global `astgen` tool (which uses Babel and Esprima under the hood) to parse JS/TS files and output structured JSON AST files.
2. **CPG Compilation**: Reads the JSON AST structures and imports them into CPG nodes.

Once the initial graph is built, `jssrc2cpg` applies post-processing compiler passes:

- **[JavaScriptInheritanceNamePass](https://github.com/AppThreat/chen/blob/main/jssrc2cpg/src/main/scala/io/appthreat/jssrc2cpg/passes/JavaScriptInheritanceNamePass.scala)**: Resolves parent-child inheritance relations.
- **[ConstClosurePass](https://github.com/AppThreat/chen/blob/main/jssrc2cpg/src/main/scala/io/appthreat/jssrc2cpg/passes/ConstClosurePass.scala)**: Tracks constants and variables inside closures.
- **[ImportResolverPass](https://github.com/AppThreat/chen/blob/main/jssrc2cpg/src/main/scala/io/appthreat/jssrc2cpg/passes/ImportResolverPass.scala)**: Maps CommonJS `require()` and ES6 `import` statements to their definitions.
- **[JavaScriptTypeRecoveryPass](https://github.com/AppThreat/chen/blob/main/jssrc2cpg/src/main/scala/io/appthreat/jssrc2cpg/passes/JavaScriptTypeRecoveryPass.scala)**: Iterates over the graph to propagate types based on assignments and function parameters.

### Real Commands and Code Examples

#### 1. Compiling a TypeScript Project to a CPG

Compile a TypeScript project, enabling TypeScript parsing and ignoring standard dependencies:

```bash
./atom.sh -l ts -o app.atom /path/to/typescript/project
```

#### 2. Running JsSrc2Cpg Programmatically in Scala

Below is a code example showing how to invoke `jssrc2cpg` and run post-processing passes:

```scala
import io.appthreat.jssrc2cpg.{JsSrc2Cpg, Config}
import io.appthreat.jssrc2cpg.passes.{
  ConstClosurePass,
  ImportResolverPass,
  JavaScriptInheritanceNamePass,
  JavaScriptTypeRecoveryPass
}
import io.appthreat.atom.passes.TypeHintPass
import scala.util.Success

val config = Config()
  .withDisableDummyTypes(true)
  .withTypePropagationIterations(2) // Run two iterations of type recovery
  .withInputPath("/path/to/javascript/source")
  .withOutputPath("/tmp/js_project.atom")

val js2cpg = new JsSrc2Cpg()
js2cpg.createCpgWithOverlays(config).map { cpg =>
  // Apply post-processing compiler passes
  new JavaScriptInheritanceNamePass(cpg).createAndApply()
  new ConstClosurePass(cpg).createAndApply()
  new ImportResolverPass(cpg).createAndApply()
  new JavaScriptTypeRecoveryPass(cpg).createAndApply()
  new TypeHintPass(cpg).createAndApply()

  println(s"JavaScript CPG created. Node count: ${cpg.graph.nodeCount}")
  cpg.close()
}
```
