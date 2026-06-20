# Lesson 10: ASTGen Runners for JS/TS/Python/Ruby

### Learning Objective

Understand how the compiler frontends interface with external AST generators (ASTGen runners) to produce JSON AST schemas for script-based languages.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Node.js 20+**: Required for the JavaScript/TypeScript AST generator.
- **NPM package @appthreat/atom-parsetools**: Must be installed globally (`npm install -g @appthreat/atom-parsetools`) to provide the `astgen` and `rbastgen` binaries.
- **Python 3.10+**: Required for the Python AST generator.

### Conceptual Background

Script-based dynamic languages (JavaScript, TypeScript, Python, Ruby, PHP) have complex grammar specifications that change frequently. To avoid rewriting custom parsers in Scala, Chen uses external AST generators written in the target languages' native runtimes. These tools are called **ASTGen Runners**.

The compilation pipeline operates as follows:

1. **Runner Invocation**: The Scala frontend (e.g. `JsSrc2Cpg`) executes the external generator (e.g. `astgen` for JavaScript or `rbastgen` for Ruby) as a subprocess.
2. **Parsing and Export**: The runner parses the source files and serializes the AST into JSON files.
3. **Graph Ingestion**: The Scala compiler reads the JSON files, maps the node attributes to CPG nodes, and builds the control flow and AST edges.

The CLI and frontends let you control this process using environment variables like `CHEN_ASTGEN_OUT` and configuration flags to customize ignored directories.

### Real Commands and Code Examples

#### 1. Running ASTGen Manually to Inspect Output

Run `astgen` on a JavaScript file to inspect the generated JSON AST output:

```bash
# Run astgen from the command line
astgen -i /path/to/source/file.js -o /tmp/ast_json_output/
cat /tmp/ast_json_output/file.js.json
```

#### 2. Executing ASTGen Runners Programmatically in Scala

Below is a code example demonstrating how to execute the AST generator runner as a subprocess using `ExternalCommand` from the [x2cpg](https://github.com/AppThreat/chen/tree/main/x2cpg) module:

```scala
package io.appthreat.x2cpg.utils

import scala.util.{Success, Failure, Try}

object AstGenRunnerExample {
  def runJsAstGen(inputPath: String, outputPath: String): Try[Seq[String]] = {
    val command = s"astgen -i $inputPath -o $outputPath"

    // Execute the parser runner as a subprocess
    ExternalCommand.run(command, inputPath) match {
      case Success(outputLines) =>
        println(s"ASTGen successfully executed. JSON files written to $outputPath")
        Success(outputLines)
      case Failure(exception) =>
        println(s"ASTGen execution failed: ${exception.getMessage}")
        Failure(exception)
    }
  }
}
```
