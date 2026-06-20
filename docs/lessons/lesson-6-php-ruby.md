# Lesson 6: PHP & Ruby Frontends (php2atom and ruby2atom)

## Learning Objective

Understand how the `php2atom` and `ruby2atom` frontends parse dynamic, script-oriented languages
into a CPG: how PHP relies on an external `php-parser` and a local PHP runtime, how Ruby uses the
`ruby_ast_gen` (`rbastgen`) JSON generator, and which passes each runs.

## Pre-requisites

- JDK 23+ (OpenJDK or GraalVM)
- SBT 1.10+
- **PHP 7.1+** (8.3+ recommended), available on `PATH`, with the zip/xml extensions — required by
  `php2atom`.
- **Ruby** with the `ruby_ast_gen` tool (shipped via `@appthreat/atom-parsetools` as `rbastgen`)
  — required by `ruby2atom`.
- Local clone of [chen](https://github.com/AppThreat/chen): `sbt compile`

## Conceptual Background

Both languages defer class layout, method dispatch, and global state to runtime, so both
frontends parse to a JSON AST first and then build the graph.

- **[php2atom](https://github.com/AppThreat/chen/tree/main/platform/frontends/php2atom)** invokes
  the bundled PHP `php-parser` (a `.phar`) through a local `php` binary to produce a JSON AST,
  ingests it, seeds builtin PHP types, and creates locals/closures.
- **[ruby2atom](https://github.com/AppThreat/chen/tree/main/platform/frontends/ruby2atom)** runs
  `rbastgen` (the `ruby_ast_gen` program), reads the per-file JSON via `RubyJsonParser`,
  converts it with `RubyJsonToNodeCreator`, and builds the AST in parallel.

## php2atom

### Config Fields (`Main.scala`)

```scala
final case class Config(
  phpIni: Option[String]       = None,  // custom php.ini
  phpParserBin: Option[String] = None,  // path to the php-parser phar
  enableAstCache: Boolean      = true,  // cache parsed ASTs
  cacheDir: Option[String]     = None
) extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]
```

Builders: `withPhpIni`, `withPhpParserBin`, `withAstCache`, `withCacheDir`. CLI flags:
`--php-ini`, `--php-parser-bin`, `--no-ast-cache`, `--cache-dir`.

### Pass Pipeline (`Php2Atom.createCpg`)

The frontend first checks `php --version` and that `PhpParser` initialises; if either fails it
returns a `Failure` and writes no atom. Otherwise:

1. **MetaDataPass** (language = `PHP`)
2. **AstCreationPass** — ingests the JSON AST from `php-parser`.
3. **ConfigFileCreationPass** — `composer.json`, `.ini`, etc.
4. **AstParentInfoPass** — records AST parent metadata used by later linking.
5. **AnyTypePass** — assigns `ANY` to as-yet-unresolved types.
6. **TypeNodePass.withTypesFromCpg** — materialises `TYPE` nodes.
7. **LocalCreationPass.allLocalCreationPasses** — creates `LOCAL` nodes per scope.
8. **ClosureRefPass** — links closures to captured variables.

Post-processing: **PhpSetKnownTypesPass** seeds builtin PHP types (`array`, `string`, `int`, …).

## ruby2atom

### Config Fields (`Main.scala`)

```scala
final case class Config(
  downloadDependencies: Boolean = false,
  useTypeStubs: Boolean         = true
) extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]
    with TypeStubConfig[Config]
    with AstGenConfig[Config]
```

Through the `AstGenConfig` mix-in the program name is `ruby_ast_gen` (invoked as `rbastgen`),
the config prefix is `ruby2atom`, and a default ignore regex skips `spec/`, `test(s)/`,
`vendor/`, and DB migration files.

### Pass Pipeline (`Ruby2Atom.createCpg`)

1. **MetaDataPass** (language = `RUBYSRC`)
2. **ConfigFileCreationPass** — `Gemfile`, `*.gemspec`, etc.
3. `RubyAstGenRunner(config).execute(tmpDir)` — runs `rbastgen` to produce JSON ASTs.
4. **AstCreationPass** — parses the JSON in parallel (`RubyJsonParser` →
   `RubyJsonToNodeCreator` → `AstCreator`) and builds the graph.
5. **TypeNodePass.withTypesFromCpg** — materialises `TYPE` nodes.

`createCpgWithOverlays` then runs the default overlays. The ruby2atom `postProcessingPasses`
(under `x2cpg.frontendspecific.ruby2atom`) add import/type-recovery and call-linking passes
(e.g. `AstLinkerPass`, `NaiveCallLinker`).

## Real Commands and Code Examples

### Compile a PHP project (ignore vendor)

```bash
atom -l php -o app.atom --ignored-dirs "vendor;docs" /path/to/php/project
```

### Compile a Ruby project

```bash
atom -l ruby -o app.atom /path/to/ruby/project
```

### Build php2atom with the Scala API

```scala
import io.appthreat.php2atom.{Php2Atom, Config}
import io.appthreat.php2atom.passes.PhpSetKnownTypesPass
import scala.util.{Success, Failure}

val config = Config()
  .withDisableDummyTypes(true)
  .withInputPath("/path/to/php/source")
  .withOutputPath("/tmp/php_project.atom")
  .withIgnoredFilesRegex(".*(?:vendor|tests).*")

new Php2Atom().createCpgWithOverlays(config) match
  case Success(cpg) =>
    new PhpSetKnownTypesPass(cpg).createAndApply()
    println(s"Methods: ${cpg.method.size}")
    cpg.close()
  case Failure(ex) => println(s"Failed: ${ex.getMessage}")
```

### Open and query either atom file

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/php_project.atom")

// PHP SQL sinks
cpg.call.name("mysqli_query|query|exec").l

// Ruby Rails controller actions (public instance methods on *Controller types)
cpg.typeDecl.name(".*Controller").method.isPublic.name.l
```

## Notes for Security Analysts

- `php2atom` silently produces **no atom** if `php` is missing or too old. Always confirm
  `php --version` succeeds before trusting an empty result.
- For Ruby, set `downloadDependencies = true` (or `--download-dependencies`) to pull gem sources
  so cross-gem calls resolve; otherwise external calls remain stubs. `useTypeStubs` (default on)
  supplies pre-built signatures for the standard library and popular gems.
- Both frontends keep an AST/parse cache; pass `--no-ast-cache` (PHP) or clear the cache dir when
  diagnosing stale-parse issues. See Lesson 9 for cache control.
