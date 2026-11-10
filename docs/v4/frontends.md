# Frontends in chen 4.0

A frontend turns source code or bytecode into the first layer of the Code Property Graph: the
abstract syntax tree, with types, calls and imports resolved as far as the language allows. chen
4.0 adds a second C/C++ frontend built on the EDG front end, brings each language up to its
current syntax, and records many more facts as tags on the graph. This page describes what
changed in each frontend since chen 3.4.0, what a consumer has to change, and which tools each
frontend needs.

The frontends live under `platform/frontends`. [The API document](api.md) covers the shared
library changes (semantics, data flow, tags), and the [lessons](../lessons/lesson-1-c2cpg.md)
explain each frontend in depth.

## Changes a consumer may notice

Most changes add to the graph. These change something that was there before:

| Frontend | Change |
|---|---|
| c2cpg | `includeImageLocations` defaults to `true`, because macro invocations need it. |
| c2cpg | A translation unit's `<global>` method is named after the unit, not after the first header it includes. |
| c2cpg | `alignof`, `typeid`, `typeof` and `sizeof...` have their own operator names (`<operator>.alignOf`, `<operator>.typeId`, ...) instead of all being `<operator>.sizeOf`. |
| c2cpg | C++ constructors are named with a `void` return type (`Point.Point:void(int,int)`) and carry the `CONSTRUCTOR` modifier. |
| c2cpg | `--no-include-auto-discovery` now switches discovery off; before, it had no effect. |
| jssrc2cpg | `TYPE_FULL_NAME` holds one type name rather than the checker's display text: `Promise<User>` becomes `Promise`, arrays and tuples `__ecma.Array`, object literal types `object`, function and intersection types `ANY`. |
| php2atom | Column numbers are offsets from the start of the line; they were offsets from the start of the file. |
| pysrc2cpg | `import X` in a nested file resolves to the top-level `X`, not `pkg.X`; a package `X/` is preferred over `X.py`. |
| javasrc2cpg | A call's position is its member-name token, not the start of the call chain. The `enableTypeRecovery` option, which atom sets, now runs the type recovery passes. |
| ruby2atom | `db/migrate` is no longer ignored by default; the default ignores are `spec`, `test`, `tests` and `vendor`. |
| all | AST caches written by chen 3.4 are not reused, because the cache keys and revisions changed. The first run rebuilds them. |

## Shared changes (x2cpg)

### Marking vendored code external

Every source frontend accepts `--external-paths <regex>` (`X2CpgConfig.externalPaths`). Files
whose path relative to the input root matches are parsed as usual, but their methods and type
declarations get `IS_EXTERNAL = true`, and the methods are tagged `external-path`. A match must
start at a path segment, so `third_party` and `/third_party/` match `src/third_party/x.c` but not
`src/not_third_party/x.c`. An invalid expression logs a warning and marks nothing. The pass never
turns code a frontend already treats as external (`node_modules`, a virtual environment,
Composer's `vendor/`) back into project code.

`BomComponentLocations` reads the vendored directories a CycloneDX SBOM records
(`cdx:vendored:path`, `cdx:cmake:sourceDir`, as cdxgen 13.7.0 writes them), for a caller such as
atom to turn into an external-paths pattern.

### Source text

Files are decoded by their byte-order mark (UTF-8, UTF-16 or UTF-32) first, then by a declared
charset, then as UTF-8 if valid, else as windows-1252 (`SourceDecoding`). Characters outside the
Basic Multilingual Plane are kept (see [cpg2](cpg2.md)). `SourceIntegrityPass` tags Unicode
look-alike identifiers (`unicode-confusable`, using the Unicode 18.0.0 confusables table),
bidirectional control characters in literals and comments (`unicode-bidi-control`, the Trojan
Source pattern, CVE-2021-42574) and Java Unicode escapes that end a line, comment or literal
(`unicode-hidden-code`). The pass is a library pass; atom decides when to run it.

### Calls, arguments and control flow

- Arguments bind to parameters by name, position, unpacking and variadics rather than by
  argument index alone (`ArgumentBinding`, described in [the API document](api.md#argument-binding)).
  Each frontend contributes: PHP named arguments carry their name and `...$xs` is
  `<operator>.unpack`, Ruby binds keyword arguments, `**h` and `(...)`, JavaScript spread is an
  iterable unpack, Java varargs are variadic, and C extra arguments reach the `va_list`.
- New call linkers: `FunctionPointerCallLinker` for C function pointers and `RubyCallLinker`
  for calls to project methods in Ruby. `DynamicCallLinker` links C++ destructors to subclass
  destructors.
- The CFG prunes constant branches, ends paths at calls that cannot return, wires every macro
  expansion in, and treats the handlers of one `try` as alternatives (a second `catch` clause no
  longer appears to run after the first).
- C `static` functions and C++ unnamed namespaces have internal linkage (`InternalLinkage`).

### Framework and security tags

The JavaScript framework recognizers moved out of one large tagging pass into one recognizer per
framework: DOM, Angular, React, Vue, Svelte, Nitro, Node, Lit, jQuery, Ember, Astro, Alpine and
Nest. They resolve project path aliases (`tsconfig`/`jsconfig` `paths`, `package.json`
`exports`/`imports`, and the `@/`, `~/`, `~~/`, `@@/` and `$lib/` prefixes) once per graph, and
`PackageAttribution` tags sinks with the npm package URL or Node built-in they come from. A warm
`atom usages` run on ngx-admin went from 104 to about 24 seconds with these changes.

New tag families written for every language that has the construct:

- Forwarded headers: `proxy-derived`, `trusted-proxy-config`, `trusted-proxy-headers` and
  `forwarded-header-read`, for Java, JavaScript, Python, PHP and Ruby. They are opt-in sources
  for atom's reachables slice, not default ones.
- Python template sandboxes (`sandbox-render`) and AI model loading (`ai-model-artifact`, and
  `code-execution` for `trust_remote_code` and chat templates).
- Ruby and PHP sinks: on railsgoat the reachable flows went from 0 to 26, on DVWA from 36 to 152.
- Tags atom's callsites slice reads, listed per frontend below.

### Running external tools

External parsers are run with a timeout that kills the process and its children
(`ExternalCommand.runWithResult`). The project fingerprint streams files into the digest, so a
single file of 2 GiB or more no longer runs the JVM out of memory; the fingerprint value is
unchanged. This fix was contributed by August Johansson (AppThreat/chen#193).

## c2cpg: C and C++ with Eclipse CDT

c2cpg now parses each file the way its build compiles it.

- **Compilation databases.** `--compile-commands <file|dir>` reads a `compile_commands.json`
  (a directory, or its `build/` subdirectory, works too), and `--compile-commands-only` parses only
  the units it lists, plus the project headers they include. Each unit gets its own include paths,
  macros, forced includes and language from its command (`-I`, `-iquote`, `-isystem`,
  `-idirafter`, `-D`, `-U`, `-include`, `-imacros`, `-x`, and the cl.exe forms `/I`, `/D`, `/U`,
  `/FI`, `/TP`, `/TC`). A header takes the settings of the first unit, in path order, that
  includes it.
- **The real compiler's macros.** Predefined macros come from running the compiler
  (`-dM -E -v`), cached per process and under `.chen/compilers/`. Only a GCC or Clang driver on the
  `PATH`, or at an absolute path outside the project, is run; otherwise tables for GCC and Clang on
  Linux, Clang on macOS and MSVC on Windows stand in. The system include order follows the
  compiler's own.
- **Macro census.** `--macro-census <file>` writes the configuration macros a project tests
  (`<file>.json`) and a header that defines them (`<file>.h`). `--auto-defines` runs the census
  first and defines its automatic tier (`CONFIG_*`, `ENABLE_*` and switches from configure, CMake
  and Meson templates).
- **Newer C and C++.** C++20 modules are parsed (interface units `.cppm`, `.ccm`, `.cxxm`,
  `.c++m`, `.ixx`, `.mxx`). C23 attributes, digit separators, `typeof_unqual` and the C++23
  explicit object parameter, which CDT cannot parse, are rewritten before parsing. More file
  extensions are recognised: `.cxx`, `.c++` and `.C` as C++ sources, and `.hxx`, `.h++`, `.H`,
  `.ipp`, `.inl` and `.tcc` as C++ headers (`.hh` was parsed as C). UTF-16 sources are read by
  their byte-order mark. The bundled CDT is 9.3.200.
- **Robustness.** A question CDT cannot answer, or a stack overflow, now affects one node instead
  of the file: all 9,780 files of EDG's C/C++ test suite parse. The input root is always walked,
  even when its name matches an ignore pattern.

The graph records much more of what the compiler knows:

- Macro invocations are calls built from CDT's expansion records, tagged `macro-invocation`,
  `macro-parent`, `macro-origin`, `macro-argument-copy`, `nested-macro` and `macro-use`.
- C++ implicit calls are linked to their methods: overloaded operators (`operator-call`),
  constructors for every declaration form, destructors at every scope exit (with a
  `<return-value>` local where a destructor could observe the returned value) and template
  instances (`template-instance`). Designated initialisers are lowered to member assignments.
- A header prototype and its definition are one method, and a function used as a value is a
  `METHOD_REF`.
- Tags for the facts memory-safety analysis needs: `const-value`, `ptr-arith`, `ref`,
  `fn-attr`, `storage-class`, `object-size`, `pointee-size`, `flexible-member`, `capture` and
  `type-storage`.
- Where each name comes from: `IMPORT` nodes carry `include-resolved-path` and
  `include-system`, and calls, references and types carry `callee-declared-in`,
  `ref-declared-in`, `type-declared-in` and `constructs-type`.
- FORTIFY wrappers (`__memcpy_chk`) and compiler builtins (`__builtin_memcpy`) are read as the
  functions they stand for.

The AST cache key now includes the parser options and each file's own settings, so a cache built
in header mode is not replayed in a full run. c2cpg still reads `CHEN_CDT_TIMEOUT` (seconds per
file), `CHEN_CDT_DEBUG` and `CHEN_MAX_INCLUDE_PATHS`. Its
[README](https://github.com/AppThreat/chen/blob/main/platform/frontends/c2cpg/README.md) and
[lesson](../lessons/lesson-1-c2cpg.md) list every option.

## edg2atom: C and C++ with the EDG front end (new)

edg2atom builds the same graph shapes as c2cpg from the output of
[edga](https://github.com/AppThreat/edga), which runs the EDG C/C++ front end, the parser behind
several commercial compilers, on each translation unit. EDG resolves what CDT approximates:
overloads, templates, implicit conversions, virtual calls, object lifetimes and folded
constants. [edga's comparison of the two](https://github.com/AppThreat/edga/blob/main/docs/edg-versus-cdt.md)
explains the trade-off.

- **Entry point.** `io.appthreat.edg2atom.Edg2Atom(fallbackToCdt: Boolean = false)` implements
  `X2CpgFrontend[io.appthreat.c2cpg.Config]`, so every c2cpg option applies, including compilation
  databases, external paths and the AST cache. There is no separate command line; atom exposes it
  as `--c-frontend edg` or `edg-fallback`.
- **Finding edga.** The system property `edga.path`, then the `EDGA_PATH` environment variable,
  then `edga` (`edga.exe` on Windows) on the `PATH`. chen 4.0 is tested with
  [edga 0.2.0](https://github.com/AppThreat/edga/releases/tag/v0.2.0), which has binaries for
  Linux (glibc and musl), macOS and Windows. Without edga, `createCpg` throws
  `IllegalStateException`, unless `fallbackToCdt` is set, in which case c2cpg parses the project.
  With fallback, units edga cannot export, and the headers they own, are parsed by c2cpg, and the
  run prints how many units failed and the first reason.
- **Compiler emulation.** The front end's dialect comes from the compiler's predefined macros
  (`--gcc`/`--g++` with the GNU version, `--clang`, or `--microsoft` with MSVC's standard modes).
  A few shims cover the world as found: GNU modes are not strict so glibc keeps its POSIX
  declarations, libc++ gets `__OPTIMIZE_SIZE__`, NEON macros are dropped, and `_Float128` maps to
  `long double` where edga lacks float128.
- **Graph.** The same shapes and full names as c2cpg (checked by golden comparison tests), plus
  facts only EDG has: `implicit-conversion`, `virtual-call`, `default-argument`, `vla-size`,
  `compiler-generated`, `lifetime-end`, `asm` operands and names, `returns_twice` and `cleanup`
  attributes, and `noreturn`. Every `FILE` node is tagged `frontend` with `edg` or `cdt`, so a
  mixed graph shows which parser built each file.
- **Caching.** The AST cache key covers the unit, the CRCs of the project headers it includes,
  and edga's full `--edga-version` output. Each project header belongs to the first unit that
  includes it, so every run writes it from the same place. Each unit has a ten-minute timeout.

The [edg2atom README](https://github.com/AppThreat/chen/blob/main/platform/frontends/edg2atom/README.md) describes the frontend's
design.

## javasrc2cpg: Java source

- Lombok members are synthesised when delombok did not run, at javac's positions and marked
  `@lombok.Generated`. When delombok cannot fork (a native image), the original sources are
  analysed instead of an empty directory.
- Sources are read in the encoding the Maven, Gradle or Ant build declares, and Unicode escapes
  are translated as javac does.
- Catch parameters are typed locals, one per alternative of a multi-catch. An unresolved
  constructor reference is named `pkg.Foo.<init>:<unresolvedSignature>(0)`.
- A wildcard-import guess is checked against `java.lang` first, so `@Override` no longer resolves
  to a wildcard package.
- When dependencies were resolved, the atom carries `java-classpath.json` with the sorted list of
  dependency jars. Methods are tagged `callsites-throws` with their declared exceptions.

The options are unchanged. `JAVASRC_JDK_PATH`, falling back to `JAVA_HOME`, still selects the JDK
for type resolution.

## jimple2cpg: JVM bytecode and Android

- **JDK classes.** A new `--jdk-path` option, and the mode setting `chen.jimple.jdk-classes` (or
  `CHEN_JIMPLE_JDK_CLASSES`): `auto` (the default), `image`, `platform` or `none`. In `auto`, the
  running JVM's `jrt:/` is used when it works, otherwise a JDK's `lib/modules` image (read by a
  pure Scala jimage reader), or `rt.jar` for JDK 8. The JDK is looked for in `--jdk-path`,
  `ATOM_JAVA_HOME`, `JAVA_HOME`, `JDK_HOME`, `java.home`, `java` on the `PATH` and the usual
  install locations. This makes bytecode analysis work in a GraalVM native image.
- Native methods in DEX files take the bodyless path, and every method has a body block.

A move from Soot to SootUp is planned for chen 5.0.

## jssrc2cpg: JavaScript and TypeScript

- **atom-parsetools 1.x and 2.x.** jssrc2cpg runs `astgen` from either release line. With 2.x,
  `--astgen-types native|ts6` chooses between the native TypeScript 7 type engine and TypeScript
  6 (it sets `ASTGEN_TYPES`; the default is the inherited `ASTGEN_TYPES`, else `ts6`). The engine
  that actually ran is read from astgen's manifest, and the cache fingerprint includes it.
  Native type maps are normalised to the same type strings as TypeScript 6, and `.typespans`
  files, when present, type identifiers, calls and member accesses.
- **When astgen fails part way,** the files it finished are kept and the run says how many, where
  it used to produce an empty atom.
- **Transpiled copies.** A `dist/` directory with a `src/` sibling in the project is skipped.
- **Graph.** Member-call receivers are typed from the type map. Class field initialisers are
  lowered as `this.<field> = v`, with their own `this` for static ones. TC39 auto-accessors
  (`accessor x`, which needs atom-parsetools with that syntax) are class properties. Optional
  member calls are member calls, directive prologues are kept, a capitalised template element is a
  call of its component, and `??=` is an assignment. Vue, Svelte and Astro components keep the
  positions of their script blocks.
- File names and import paths use `/` on every operating system.
- Tags for atom's callsites slice: `callsites-heritage` on a class's base types and
  `callsites-typeref` on type-only references.

`jssrc2cpg.test.astgenCmd` or `JSSRC2CPG_TEST_ASTGEN_CMD` choose the astgen command in tests.

## php2atom: PHP

- PHP 8.5's pipe operator is lowered to nested calls, and PHP 8.4 property hooks are methods of
  their class.
- `Foo::C`, `Foo::$p`, `instanceof` and `catch` produce type references, `$x->m()` is named
  `Fq\Class->m` when the class is declared, anonymous classes are type declarations of their own,
  and a type declaration sits at its class name. Tags for atom's callsites slice:
  `callsites-type`, `callsites-name` and `callsites-synthetic`.
- Column numbers are offsets from the line start.
- **Batch parsing.** `PHP_ASTGEN_BIN` names the batch AST generator separately from the per-file
  parser (`--php-parser-bin` or `PHP_PARSER_BIN`); a Node script runs under node and a `.cmd` or
  `.bat` file through `cmd /c`. The frontend's ignore pattern is passed to the generator, so
  `vendor/` is not parsed in batch, while Composer's metadata in `vendor/composer` is kept.

The bundled parser is still nikic/php-parser 5.8.0.

## pysrc2cpg: Python

- **Python 3.15.** The parser matches CPython 3.15's `ast.parse` on the whole standard library
  and a 5,001-file corpus: PEP 810 lazy imports (tagged `lazy-import`), unpacking in
  comprehensions, unary plus in patterns, and Unicode 17 identifiers, including the
  supplementary planes. Source encodings follow PEP 263, and names that NFKC normalisation
  changes are tagged `unicode-confusable`.
- **Arguments.** Parameter defaults are lowered into hidden `<default>` values, `f(**opts)` is
  `<operator>.dictUnpack`, `*args` and `**kwargs` are variadic, and positional-only and
  keyword-only parameters are tagged `parameter-kind`.
- **Imports and types.** `import a.b` binds `a`, `except` and `except*` handler classes are
  references, type recovery respects shadowing, and calls without a known receiver are left
  unnamed. Methods are tagged `callsites-return-line`.

## ruby2atom: Ruby

- **Constants from outside the project** become type references named by the written path
  (`Faraday::Utils` as `Faraday.Utils`), and calls on them are named after them
  (`Faraday.Utils.escape`). `include`, `prepend`, `extend` and the superclass feed
  `inheritsFrom`, and rescue lists are named.
- **Calls to project methods** are named by `RubyCallLinker`, where they were
  `<unknownFullName>`, and keyword arguments, `**h` and `(...)` forwarding bind to parameters.
- Ruby sinks were added, and `db/migrate` is analysed by default.

The parser is still `rbastgen` from atom-parsetools, found through `rbastgen.path` or
`RBASTGEN_PATH`.

## External tools at a glance

| Frontend | Needs | Found through |
|---|---|---|
| c2cpg | nothing; a GCC or Clang driver improves macro accuracy | `PATH`, or the compilation database |
| edg2atom | edga 0.2.0 | `edga.path`, `EDGA_PATH`, `PATH` |
| jssrc2cpg | `astgen` from atom-parsetools 1.x or 2.x | `PATH` |
| php2atom | PHP and nikic/php-parser (bundled `php-parse`), or `phpastgen` | `--php-parser-bin`, `PHP_PARSER_BIN`, `PHP_ASTGEN_BIN` |
| ruby2atom | `rbastgen` from atom-parsetools | `rbastgen.path`, `RBASTGEN_PATH`, `PATH` |
| jimple2cpg | a JDK for JDK classes; the Android SDK for APKs | `--jdk-path`, `JAVA_HOME` and others; `ANDROID_HOME` |
| javasrc2cpg, pysrc2cpg | nothing beyond the JVM | |
