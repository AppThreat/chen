# Lesson 1: C/C++ Frontend (c2cpg) and Preprocessor Resolution

## Learning Objective

Understand how the `c2cpg` frontend uses Eclipse CDT to parse C/C++ source into a Code Property
Graph, how the preprocessor is handled without stripping macro information, and how to control
include resolution, defines, C++ standard selection, and the AST fragment cache.

## Pre-requisites

- JDK 23+ (OpenJDK or GraalVM)
- SBT 1.10+
- A C/C++ compiler on PATH (gcc or clang) with glibc headers
- Local clone of [chen](https://github.com/AppThreat/chen): `sbt compile`

## Conceptual Background

C/C++ analysis differs from managed-language frontends because the preprocessor can radically change
which tokens a parser sees. `c2cpg` uses the Eclipse CDT parser, which treats macros, `#ifdef`
blocks, and `#include` directives as first-class AST nodes rather than expanding them away first.
This means macro invocations are visible in the graph, and inactive `#ifdef` branches can optionally
be retained and analysed.

Source files with extensions `.c`, `.cpp`, `.cc`, `.cxx` are handled by `C2Cpg`. Header-only
translation units (`.h`, `.hpp`, `.i`) are handled by the `C2Atom` variant that the `atom` CLI
selects when `-l H` or `-l HPP` is given.

The default output file is `app.atom` (an MVStore binary, the overflowdb2 storage format). The
fragment-cache mechanism (`enableAstCache = true` by default) stores one serialised AST fragment per
source file under `.chen/` (or a custom `cacheDir`). On the next run, unchanged files are restored
from cache without re-parsing, giving significant speed-ups on large incremental builds.

Source:
[platform/frontends/c2cpg](https://github.com/AppThreat/chen/tree/main/platform/frontends/c2cpg)

## Config Fields (real names from `Main.scala`)

```
final case class Config(
  includeFiles: Set[String]               = Set.empty,   // explicit header files to include
  includePaths: Set[String]               = Set.empty,   // -I style search directories
  macroFiles: Set[String]                 = Set.empty,   // files containing macro definitions
  defines: Set[String]                    = Set.empty,   // -D style defines, e.g. "FOO=1"
  cppStandard: String                     = "",          // e.g. "c++17", "c++20"
  includeComments: Boolean                = false,
  logProblems: Boolean                    = false,
  logPreprocessor: Boolean                = false,
  printIfDefsOnly: Boolean                = false,
  includePathsAutoDiscovery: Boolean      = false,
  includeFunctionBodies: Boolean          = false,
  includeImageLocations: Boolean          = false,
  useProjectIndex: Boolean                = false,
  parseInactiveCode: Boolean              = false,
  includeTrivialExpressions: Boolean      = false,
  enableAstCache: Boolean                 = true,        // fragment cache on by default
  cacheDir: String                        = "",          // defaults to <input>/.chen/
  onlyAstCache: Boolean                   = false        // warm the cache only, skip CPG output
) extends X2CpgConfig[Config]
```

`Config` extends `X2CpgConfig[Config]` (no `TypeRecoveryParserConfig` mixin — C has no type
recovery pass). Every field has a corresponding `withX` builder method that calls
`withInheritedFields(this)` to propagate the shared `inputPath`/`outputPath`/`ignoredFiles` fields.

## Pass Pipeline (`C2Cpg.createCpg`)

1. **MetaDataPass** — writes the `MetaData` node (language = `NEWC`, root path).
2. **IncludeAutoDiscovery** — if `includePathsAutoDiscovery = true`, scans the project for system
   include paths and merges them into `Config.includePaths` before parsing.
3. **AstCreationPass** — drives Eclipse CDT over every `.c`/`.cpp`/`.h` file; writes `METHOD`,
   `TYPE_DECL`, `CALL`, `LOCAL`, `LITERAL`, `CONTROL_STRUCTURE`, etc. Supports parallel file
   processing. When `enableAstCache` is on and the project is fully cached,
   **FragmentSplicePass** runs instead — it grafts pre-serialised AST fragments directly into the
   graph, bypassing the CDT parser entirely.
4. **ConfigFileCreationPass** — creates `CONFIG_FILE` nodes for `.cmake`, `.make`, `Makefile`,
   `CMakeLists.txt`, etc. (skipped when `onlyAstCache = true`).
5. **TypeNodePass** — materialises `TYPE` nodes from the set of types collected during AST
   creation (skipped when `onlyAstCache = true`).
6. **TypeDeclNodePass** — creates `TYPE_DECL` stubs for types seen but not declared in the parsed
   files (skipped when `onlyAstCache = true`).

`createCpgWithOverlays` additionally applies the four default overlays defined in `X2Cpg.scala`:
**Base**, **ControlFlow**, **TypeRelations**, **CallGraph**.

## CLI Flags (`c2cpg` standalone)

| Flag                                    | Config field                |
| --------------------------------------- | --------------------------- |
| `--include <path>`                      | `includePaths`              |
| `--include-files <file>`                | `includeFiles`              |
| `--macro-files <file>`                  | `macroFiles`                |
| `--define <KEY=VALUE>`                  | `defines`                   |
| `--cpp-standard <std>`                  | `cppStandard`               |
| `--include-comments`                    | `includeComments`           |
| `--log-problems`                        | `logProblems`               |
| `--log-preprocessor`                    | `logPreprocessor`           |
| `--print-ifdef-only`                    | `printIfDefsOnly`           |
| `--with-include-auto-discovery`         | `includePathsAutoDiscovery` |
| `--with-function-bodies`                | `includeFunctionBodies`     |
| `--with-image-locations`                | `includeImageLocations`     |
| `--with-project-index`                  | `useProjectIndex`           |
| `--enable-ast-cache` / `--no-ast-cache` | `enableAstCache`            |
| `--cache-dir <dir>`                     | `cacheDir`                  |
| `--only-ast-cache`                      | `onlyAstCache`              |

## atom CLI (`-l cpp` / `-l c`)

`atom` maps frontend-args as comma-separated `key=value` pairs:

```bash
atom -l cpp \
  -o app.atom \
  --frontend-args "defines=NDEBUG,VERSION=3;includes=/usr/include;cpp-standard=c++20;enable-ast-cache=true;ast-cache-dir=/tmp/chen-cache" \
  /path/to/cpp/project
```

Key frontend-arg names recognised by `Atom.scala`:

- `defines` (semicolon-separated)
- `includes` / `include-paths` (semicolon-separated)
- `cpp-standard`
- `enable-ast-cache` / `only-ast-cache`
- `ast-cache-dir`
- `function-bodies` / `parse-inactive-code` / `with-image-locations` / `include-comments`

## Real Commands and Code Examples

### Invoke the frontend directly

```bash
# Standalone c2cpg binary (after sbt stage)
./c2cpg/target/universal/stage/bin/c2cpg \
  --define "NDEBUG" \
  --define "MY_ARCH=ARM" \
  --include /usr/include \
  --cpp-standard c++17 \
  --with-include-auto-discovery \
  -o /tmp/myproject.atom \
  /path/to/src
```

### Open the resulting atom in Scala

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/myproject.atom")
// All method names defined directly in C/C++ files
cpg.method.name.l
```

### Build with the Scala API

```scala
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.shiftleft.codepropertygraph.Cpg
import scala.util.{Success, Failure}

val config = Config()
  .withInputPath("/path/to/cpp/source")
  .withOutputPath("/tmp/myproject.atom")
  .withDefines(Set("NDEBUG", "TARGET_OS=LINUX"))
  .withIncludePaths(Set("/usr/include", "/usr/local/include"))
  .withCppStandard("c++20")
  .withIncludePathsAutoDiscovery(true)

new C2Cpg().createCpgWithOverlays(config) match
  case Success(cpg) =>
    println(s"Nodes: ${cpg.graph.nodeCount}")
    cpg.close()
  case Failure(ex) =>
    println(s"Frontend failed: ${ex.getMessage}")
```

### Print `#ifdef` / `#if` statements without building a CPG

```bash
./c2cpg ... --print-ifdef-only /path/to/src
```

This runs `PreprocessorPass` only and prints a comma-separated list of all conditional compilation
directives to stdout.

### Inspecting types and call edges

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/myproject.atom")

// All calls to malloc-family functions
cpg.call.name("malloc|calloc|realloc").l

// Methods with more than 50 parameters (potential variadic abuse)
cpg.method.filter(_.parameter.size > 50).name.l

// All TYPE nodes (materialised by TypeNodePass)
cpg.typ.name.take(20).l
```

## Notes for Security Analysts

- `parseInactiveCode = true` can reveal code that is compiled only under specific build
  configurations (e.g. debug-only assertions, platform guards). Use it when auditing for latent
  vulnerabilities in conditional branches.
- Macro expansions appear as `MACRO_DEF` / `MACRO_EXPANSION` nodes in the CPG — query
  `cpg.graph.nodes("MACRO_EXPANSION")` to enumerate all macro call sites.
- `logProblems = true` surfaces CDT parse errors to stdout, which is useful when include paths are
  incomplete and many symbols are unresolved.
