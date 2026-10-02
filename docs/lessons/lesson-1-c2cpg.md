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
which tokens a parser sees. `c2cpg` uses the Eclipse CDT parser, which preprocesses each file but
records where every expansion came from. `c2cpg` uses those records to keep macro invocations
visible in the graph (see [Macros](#macros)), and inactive `#ifdef` branches can optionally be
retained and analysed.

Translation units are `.c` (C), `.cc`, `.cpp`, `.cxx`, `.c++`, `.C` (C++) and the C++20 module
interface units `.cppm`, `.ccm`, `.cxxm`, `.c++m`, `.ixx`, `.mxx`. Headers are `.h`, `.i`, `.h.in`,
`.tmh`, `.hpp`, `.hh`, `.hxx`, `.h++`, `.H`, `.ipp`, `.inl` and `.tcc`. The extensions longer than
one letter also match in upper case (`.CPP`). Every header is also parsed on its own, so code in
headers that no parsed source includes still reaches the graph (see
[How each file is parsed](#how-each-file-is-parsed) for its language). The `atom` CLI selects
`C2Cpg` for `-l c` and `-l cpp`; for `-l h`, `-l hpp` and `-l i` it runs `C2Atom`, the same AST pass
without function bodies or overlays.

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
  onlyAstCache: Boolean                   = false,       // warm the cache only, skip CPG output
  autoDefines: Boolean                    = false,       // define the macro census's build options
  macroCensusReport: String               = "",          // write the census to <file>.json/.h
  macroCensusOnly: Boolean                = false,       // write the census and stop: no CPG
  compileCommands: String                 = "",          // compile_commands.json, or its directory
  compileCommandsOnly: Boolean            = false        // parse only the database's units
) extends X2CpgConfig[Config]
```

`Config` extends `X2CpgConfig[Config]` (no `TypeRecoveryParserConfig` mixin — C has no type
recovery pass). Every field has a corresponding `withX` builder method that calls
`withInheritedFields(this)` to propagate the shared `inputPath`/`outputPath`/`ignoredFiles` fields.

## Pass Pipeline (`C2Cpg.createCpg`)

1. **MetaDataPass** — writes the `MetaData` node (language = `NEWC`, root path).
2. **IncludeAutoDiscovery** — if `includePathsAutoDiscovery = true`, guesses the project's own
   include directories and merges them into `Config.includePaths` before parsing. The same flag
   makes the parser ask the host's `gcc` (or `clang`) for its predefined macros and system include
   path (see [How each file is parsed](#how-each-file-is-parsed)).
3. **Macro census** — with `autoDefines`, scans the tree for build-option macros and defines them.
4. **AstCreationPass** — drives Eclipse CDT over every source and header file; writes `METHOD`,
   `TYPE_DECL`, `CALL`, `LOCAL`, `LITERAL`, `CONTROL_STRUCTURE`, etc. Supports parallel file
   processing. When `enableAstCache` is on and the project is fully cached,
   **FragmentSplicePass** runs instead — it grafts pre-serialised AST fragments directly into the
   graph, bypassing the CDT parser entirely.
5. **ConfigFileCreationPass** — creates `CONFIG_FILE` nodes for `.cmake`, `.make`, `Makefile`,
   `CMakeLists.txt`, etc. (skipped when `onlyAstCache = true`).
6. **TypeNodePass** — materialises `TYPE` nodes from the set of types collected during AST
   creation (skipped when `onlyAstCache = true`).
7. **TypeDeclNodePass** — creates `TYPE_DECL` stubs for types seen but not declared in the parsed
   files (skipped when `onlyAstCache = true`).
8. **ConstantTagPass** — tags reads of header `const`/`constexpr` integers with their value
   (`const-value`).

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
| `--no-include-auto-discovery` (hidden)  | `includePathsAutoDiscovery` |
| `--with-function-bodies`                | `includeFunctionBodies`     |
| `--with-image-locations`                | `includeImageLocations`     |
| `--with-project-index`                  | `useProjectIndex`           |
| `--no-ast-cache`                        | `enableAstCache`            |
| `--cache-dir <dir>`                     | `cacheDir`                  |
| `--only-ast-cache`                      | `onlyAstCache`              |
| `--auto-defines`                        | `autoDefines`               |
| `--macro-census <file>`                 | `macroCensusReport`         |
| `--compile-commands <file\|dir>`        | `compileCommands`           |
| `--compile-commands-only`               | `compileCommandsOnly`       |

## atom CLI (`-l cpp` / `-l c`)

`atom` passes frontend settings as comma-separated `key=value` pairs:

```bash
atom -l cpp \
  -o app.atom \
  --frontend-args cpp-standard=c++20,includes=/usr/local/include,enable-ast-cache=true \
  /path/to/cpp/project
```

`atom --frontend-args-keys -l cpp` prints every key the C and C++ frontends accept, with its type
and default (`defines`, `includes`/`include-paths`, `include-files`, `macro-files`,
`cpp-standard`, `compile-commands`, `compile-commands-only`, `auto-defines`, `macro-census`,
`function-bodies`, `parse-inactive-code`, `enable-ast-cache`, `ast-cache-dir`, …). A compilation
database also has its own flag: `atom -l cpp --compile-commands build/ -o app.atom .`.

## How each file is parsed

**With a compilation database** (`--compile-commands`, a `compile_commands.json` or a directory
holding one, also its `build/` subdirectory), each translation unit is parsed with its own compile
command: the include directories (`-I`, `-iquote`, `-isystem`, `-idirafter`, `/I`), macros (`-D`,
`-U`, `/D`, `/U`, in order), forced files (`-include`, `-imacros`, `/FI`) and language (`-x`, `/TP`,
`/TC`, a C++ driver such as `g++`). A `command` string is split with POSIX quoting, or the Windows
rules for `cl.exe` and `clang-cl`. Only the database's units and the project's headers are parsed
(only the units with `--compile-commands-only`); a relative path is taken from the working
directory, then from the project root. The user's `--define`s and `--include`s still apply on top.

**Headers** take the language, and with a database the flags, of the first unit that includes
them, found from the project's `#include` lines: a `.h` file included from a C++ file is parsed as
C++. A header no unit includes is C in a project without C++ sources, C++ in one without C sources,
and otherwise C++ when it declares a class, a namespace or a template.

**Predefined macros** come from the unit's real compiler: `<cc> <options> -x <lang> -dM -E -v -`
runs once per compiler and option set (target, sysroot, `-m`, `-O`, `-f`, `-std` options), and also
gives the compiler's system include path, in its search order. Results are kept for the process and
under `.chen/compilers/` keyed by the compiler's `--version`. A database's compiler is run only
when it names a GCC or Clang driver (`gcc`, `g++`, `cc`, `c++`, `clang`, `clang++`, or a prefixed or
suffixed form such as `aarch64-linux-gnu-gcc`), and only when it is a command on the `PATH` or an
absolute path outside the project tree: a database can come with the code it describes, so a
compiler inside the tree, one named by a relative path, or a program of any other name is never
run. Without a database the host's `gcc`
(or `clang`) is used when include discovery is on, asked for C++17 unless `--cpp-standard` says
otherwise. A compiler that cannot be run (a database from another machine, or MSVC's `cl.exe`,
which cannot list its macros) falls back to a table for its family and target, generated from real
compilers by `tools/predefined-macros/generate.sh`; with no compiler at all, a GCC identity
(`__GNUC__` 4.9) stands in so headers still see the attributes they gate on it. The feature tests
the parser does not evaluate (`__has_builtin`, `__has_feature`, `__has_attribute`, …) read as 0, and
MSVC's keywords (`__declspec`, `__cdecl`, …) are spelled out only for MSVC or an unknown compiler.

**C++20 modules.** Module interface units are parsed by their extensions, and the module syntax of
every C++ unit is rewritten line by line before parsing (line numbers do not change):

| Source | Read as |
|---|---|
| `import <vector>;`, `import "a.h";` | `#include <vector>`, `#include "a.h"` |
| `import hello;`, `import :part;`, `export import ...;` | `#include` of the interface unit that declares the module or partition, found in the project |
| `module hello;` (an implementation unit) | `#include` of the primary interface |
| `export module hello;` | `#pragma once` |
| `module;`, `module :private;`, `import std;` | nothing |
| `export { ... }`, `export int f();` | the declarations, without `export` |

So calls into an imported module resolve and link to the module's units. Outside a module unit,
`import name;` is a module import only when the project declares `name`.

The AST cache key includes each file's language, macros, include path and forced files.

**CDT's own log.** CDT reports internal conditions (an ambiguity it resolved another way, an
evaluation it gave up on) through its plugin's log, which normally exists only inside Eclipse.
`c2cpg` sets that log up when it first parses, so such a report no longer fails the file, and
sends the messages to the debug log (`io.appthreat.c2cpg.parser.CdtLogging`) rather than standard
output.

## Compiler builtins and FORTIFY

The C library's `_FORTIFY_SOURCE` wrappers (`__memcpy_chk`, `__sprintf_chk`, `__read_chk`, …), the
compiler's spellings of them (`__builtin___memcpy_chk`) and the builtins of library functions
(`__builtin_memcpy`, `__builtin_strlen`) are read as the functions they stand for: the
memory-safety tags are valued as the function (`mem-dst=memcpy`), the data-flow summaries are the
function's with the arguments moved past the inserted ones, and the printf-family format positions
follow. A wrapper's destination size is tagged `mem-object-size`; a constant other than `(size_t)-1`,
or `__builtin_object_size(p, k)`, gives the destination's `extent` when nothing else does. When a
header defines a function as a macro over its builtin (`#define alloca(n) __builtin_alloca(n)`), the
macro's call carries the tags.

A call to a builtin the parser does not declare (the FORTIFY builtins, or `__memcpy_chk` without
its header) gets its signature and return type from `builtin-functions.txt`, generated from the EDG
C/C++ front end's builtin definitions by `tools/builtins/generate.py`. In C++ a builtin is named as
in C (`__builtin_memcpy`, no signature in the full name), so its summary applies.

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

## Macros

Each top-level macro invocation becomes a `CALL` with dispatch type `INLINED`:

- `name` is the macro name; `methodFullName` encodes where the macro is defined,
  `<file>:<line>:<lineEnd>:<NAME>:<argc>` (plain `NULL` keeps its name).
- The invocation's arguments are matched by their source text inside the expansion and copied
  under the call as arguments `1..argc`, so data flows into the macro's value.
- The expansion itself is the call's last AST child, a block after the arguments, and the CFG runs
  through it, so guards written as macros (`MIN`, `MAX`, `CLAMP`) take part in data flow.

Only the outermost invocation of nested macros is represented, and `#define` directives are not
nodes.

## C++ Calls the Source Does Not Spell

C++ calls functions the source never writes as calls. CDT resolves each of them, and c2cpg emits a
`CALL` whose `methodFullName` is the METHOD the graph holds, so the call graph and data flow reach
the body:

| Source | CALL |
|---|---|
| `a + b` on a class with `operator+` | `operator +` → `Vec2.operator +:Vec2(Vec2 &)`, `a` as argument 0 (member operator) or `a`, `b` as arguments 1, 2 (free operator), tagged `operator-call=<operator>.addition` |
| `p->m()` on a smart pointer | the `operator ->` call on `p` is the receiver of `m`; the method call dispatches to the overrides |
| `Point a(1, 2)`, `Point a{1, 2}`, `Point a;`, `Point(1, 2)` | `Point` → `Point.Point:void(int,int)` (the default constructor for `Point a;`) |
| `new T(args)` | `<operator>.new`: argument 1 is the type, argument 2 the constructor call holding `args`; tagged `alloc-form=scalar`, `array` (`new T[n]`, the extents follow the type) or `placement` (the placement arguments go to a project's `operator new`) |
| `delete p`, `delete[] p` | `<operator>.delete`: argument 1 is the pointer, argument 2 the destructor call; tagged `alloc-form=scalar` or `array` |
| leaving a scope | one destructor call per object with a destructor, the last constructed first: where control falls out of a block, a catch handler or a statement's declarations, and before each `return`, `break`, `continue` and `goto` that leaves it early |
| `clampAdd<short>(x, 7)` | `clampAdd:ANY(ANY,ANY)`, the generic definition, tagged `template-instance=short int(short int,short int)`; an explicit specialization keeps its own name |
| `f(x)` where `f` holds a lambda | `anonymous_lambda_0` → the lambda's METHOD, `f` as the receiver |

A declared object whose constructor the graph holds (`Point a(1, 2)`, `Point a{1, 2}`, `Point a;`,
`Point a = 5;`, `Point a = {1, 2};`) is an assignment of the constructor call to the variable, so
data flow carries the constructor's arguments into it; copy-initialisation calls the converting
constructor, or the copy constructor the class declares. A value of the variable's own type
initialises it in place (`Point a = Point(1, 2);`, `Point a = make();`): the right-hand side is
the only call.

A callee is linked only when the graph holds its METHOD: a function the compiler generates (an
implicit copy assignment) or one declared only in a library header keeps the shape it has
otherwise, and an operator then stays the built-in `<operator>.*` call. Constructors and
destructors are named with a `void` return type (`Point.Point:void(int,int)`,
`Point.~Point:void()`), and every constructor carries the `CONSTRUCTOR` modifier.

Scope exits: objects are destroyed innermost scope first, and only those constructed before the
exit. A loop's condition variable and a range-based `for`'s loop variable are destroyed at the end
of each iteration and at `continue`; variables an `if`, `switch` or `while` declares in its
condition or init statement, after the statement. A `return` whose value could observe a destroyed
object (it calls a function, reads through a pointer or names one of the objects) stores the value
in a local `<return-value>` first, then destroys, then returns it. No calls follow a block that ends
in a jump. Temporaries are not covered: CDT's tree does not show the temporaries implicit
conversions create, so their destruction is left to a frontend that does.

Operator calls carry the type CDT gives the expression (`p->name[1]` is `char`), `>>` on an
unsigned operand is `<operator>.logicalShiftRight`, and `obj.*pm` / `ptr->*pm` are
`<operator>.pointerToMember` / `<operator>.indirectPointerToMember`.

## Notes for Security Analysts

- `parseInactiveCode = true` can reveal code that is compiled only under specific build
  configurations (e.g. debug-only assertions, platform guards). Use it when auditing for latent
  vulnerabilities in conditional branches.
- Macro invocations appear as calls with dispatch type `INLINED` (see [Macros](#macros)) — query
  `cpg.call.dispatchType("INLINED")` to enumerate them.
- `logProblems = true` surfaces CDT parse errors to stdout, which is useful when include paths are
  incomplete and many symbols are unresolved.
