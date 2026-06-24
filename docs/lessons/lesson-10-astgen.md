# Lesson 10: ASTGen Runners and External Parser Integration

## Learning Objective

Understand how the script-language frontends interface with external AST generators
(the "ASTGen runners") to obtain JSON ASTs, how the correct platform binary is selected and
invoked, and how `ExternalCommand` drives the subprocess.

## Pre-requisites

- JDK 23+ (OpenJDK or GraalVM)
- SBT 1.10+
- Node.js 20+ (for the JavaScript/TypeScript `astgen`)
- A Ruby runtime (for `rbastgen` / `ruby_ast_gen`)
- `@appthreat/atom-parsetools` installed globally — provides `astgen` and `rbastgen`

## Conceptual Background

The grammars of JavaScript, TypeScript, and Ruby change frequently and are awkward to re-implement
in Scala. Rather than maintaining hand-written parsers, chen delegates parsing to native tools
written in the target ecosystems — the **ASTGen runners**:

| Language  | Binary            | Runner class                                       |
| --------- | ----------------- | -------------------------------------------------- |
| JS/TS/Vue | `astgen`          | `jssrc2cpg/.../utils/AstGenRunner`                 |
| Ruby      | `rbastgen`        | `ruby2atom/.../parser/RubyAstGenRunner`            |
| Python    | _(none)_          | native `PyParser` in `pysrc2cpg` — no subprocess   |
| PHP       | `php-parser` phar | invoked from `php2atom` via the local `php` binary |

The shared base, `AstGenRunnerBase`, lives in
[platform/frontends/x2cpg/.../astgen/AstGenRunner.scala](https://github.com/AppThreat/chen/blob/main/platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/astgen/AstGenRunner.scala).

The pipeline is:

1. **Runner invocation** — the Scala frontend executes the native generator as a subprocess.
2. **Parse and export** — the runner writes one JSON AST file per source file into an output dir.
3. **Graph ingestion** — `AstCreationPass` reads the JSON and builds the CPG.

### Binary selection

`AstGenProgramMetaData(name, configPrefix, multiArchitectureBuilds, packagePath)` describes the
generator. `executableName` picks a platform-specific suffix at runtime:

- Windows: `<name>-win.exe` / `<name>-win-arm.exe`
- Linux: `<name>-linux` / `<name>-linux-arm`
- macOS: `<name>-macos` / `<name>-macos-arm`

`astGenCommand` reads the expected version from `application.conf` (key
`<configPrefix>.<name>_version`, e.g. `jssrc2cpg.astgen_version`). If a compatible binary is on
`PATH` it uses the bare name; otherwise it falls back to the bundled binary under
`<executableDir>/astgen/`.

## The `ExternalCommand` API (real signatures)

[`io.appthreat.x2cpg.utils.ExternalCommand`](https://github.com/AppThreat/chen/blob/main/platform/frontends/x2cpg/src/main/scala/io/appthreat/x2cpg/utils/ExternalCommand.scala):

```scala
object ExternalCommand:
  // run a command (wrapped in `sh -c` / `cmd /c`) in cwd, returning stdout lines
  def run(
    command: String,
    cwd: String,
    extraEnv: Map[String, String] = Map.empty,
    separateStdErr: Boolean = false
  ): Try[Seq[String]]

  // structured result with exit code and separated stdout/stderr
  def runWithResult(
    command: Seq[String],
    cwd: String,
    mergeStdErrInStdOut: Boolean = false,
    extraEnv: Map[String, String] = Map.empty
  ): ExternalCommandResult
```

`run` returns `Success(stdoutLines)` on exit code 0, otherwise `Failure` carrying the stderr.

## Real Commands and Code Examples

### Run astgen manually to inspect output

```bash
# Emit JSON ASTs for a directory of JS/TS files
astgen -i /path/to/source -o /tmp/ast_json_output/
ls /tmp/ast_json_output/        # one .json per source file
```

### Reuse astgen output (skip re-parsing)

`jssrc2cpg` honours a permanent output directory through `--astgen-out` / `Config.astGenOutDir`
(also wired to the `CHEN_ASTGEN_OUT` environment variable). If valid `.json` files already exist
there, the parse step is skipped.

```bash
CHEN_ASTGEN_OUT=/tmp/astgen-cache atom -l ts -o app.atom /path/to/project
```

### Invoke a runner programmatically

```scala
import io.appthreat.x2cpg.utils.ExternalCommand
import scala.util.{Success, Failure}

val inputPath  = "/path/to/source"
val outputPath = "/tmp/ast_json_output"

ExternalCommand.run(s"astgen -i $inputPath -o $outputPath", inputPath) match
  case Success(lines) => println(s"astgen wrote JSON to $outputPath\n${lines.mkString("\n")}")
  case Failure(ex)    => println(s"astgen failed: ${ex.getMessage}")
```

### How the JS runner is used inside the frontend

```scala
// JsSrc2Cpg.createCpg (simplified)
val astGenResult = new AstGenRunner(config).execute(astGenDir)   // runs astgen, returns parsed files
val astCreationPass =
  new AstCreationPass(cpg, astGenResult, config, report)(using config.schemaValidation)
astCreationPass.createAndApply()                                 // ingests JSON -> CPG
```

`execute(out: File): AstGenRunnerResult` returns `parsedFiles` (input → JSON path pairs) and
`skippedFiles`.

## Notes

- **Python is the exception.** `pysrc2cpg` parses in-process with `PyParser`; there is no Python
  subprocess and no `CHEN_ASTGEN_OUT`-style reuse.
- A version mismatch between the bundled binary and the value in `application.conf` makes the
  runner fall back to the packaged binary — useful to know when debugging "wrong AST" issues
  after a global `astgen` upgrade.
- `ExternalCommand.run` wraps the command in the platform shell (`sh -c` / `cmd /c`), so shell
  metacharacters in paths must be quoted.
