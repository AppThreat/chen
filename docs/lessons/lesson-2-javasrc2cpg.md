# Lesson 2: Java Source Frontend (javasrc2cpg)

## Learning Objective

Understand how `javasrc2cpg` uses the JavaParser library to build a CPG from Java source, how
Lombok annotations are handled via the Delombok preprocessor, how type inference is driven by
external JAR classpath entries, and how to control each of these behaviours through `Config`.

## Pre-requisites

- JDK 17+ (JDK 17 recommended for Delombok; JDK 23 for running chen itself)
- SBT 1.10+
- Local clone of [chen](https://github.com/AppThreat/chen): `sbt compile`

## Conceptual Background

`javasrc2cpg` parses `.java` source files using
[JavaParser](https://javaparser.org/), a pure-Java AST library. Unlike `jimple2cpg`, which
operates on JVM bytecode, `javasrc2cpg` works directly on source and therefore preserves the
original identifier names, Javadoc comments (as AST metadata), and source line mappings.

**Type resolution** is a two-phase process:

1. `AstCreationPass` builds raw AST nodes and records every type reference it encounters in a
   shared `Global` registry.
2. `TypeInferencePass` walks the CPG and resolves unresolved type names using JavaParser's
   `SimpleCombinedTypeSolver`, which queries: the JDK path, the project's own source files, and
   any explicitly provided inference JARs.

**Delombok** (`lombok.jar --delombok`) expands Lombok annotations (`@Data`, `@Builder`, etc.)
into their generated Java source before JavaParser sees the files. There are four modes:

| Mode           | Behaviour                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------ |
| `no-delombok`  | Skip Lombok entirely                                                                       |
| `default`      | Run Delombok if a Lombok dependency is detected in the project                             |
| `types-only`   | Run Delombok; use the expanded code **only** for type information, analyse original source |
| `run-delombok` | Run Delombok and analyse the expanded source for both AST and type information             |

The `atom` CLI defaults to `types-only` (configurable via `CHEN_DELOMBOK_MODE`).

Source:
[platform/frontends/javasrc2cpg](https://github.com/AppThreat/chen/tree/main/platform/frontends/javasrc2cpg)

## Config Fields (real names from `Main.scala`)

```
final case class Config(
  inferenceJarPaths: Set[String]       = Set.empty,    // extra JARs for type resolution
  fetchDependencies: Boolean           = false,        // try to fetch Maven/Gradle JARs
  javaFeatureSetVersion: Option[String] = None,        // target Java language version
  delombokJavaHome: Option[String]     = None,         // JDK home used to run Delombok
  delombokMode: Option[String]         = None,         // see table above
  enableTypeRecovery: Boolean          = false,        // generic type recovery (hidden flag)
  jdkPath: Option[String]             = None,          // explicit JDK for builtin type resolution
  showEnv: Boolean                     = false,        // print env-var docs and exit
  skipTypeInfPass: Boolean             = false,        // skip TypeInferencePass (dev only)
  dumpJavaparserAsts: Boolean          = false         // dump raw JavaParser AST and exit
) extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]
```

The `JAVASRC_JDK_PATH` environment variable is an alternative way to specify `jdkPath`.

## Pass Pipeline (`JavaSrc2Cpg.createCpg`)

1. **MetaDataPass** — writes the `MetaData` node (language = `JAVASRC`).
2. **AstCreationPass** — runs JavaParser over every `.java` file; builds `METHOD`, `TYPE_DECL`,
   `CALL`, `LOCAL`, `LITERAL`, and control-flow nodes. Clears JavaParser's internal caches after
   completion to free heap.
3. **ConfigFileCreationPass** — creates `CONFIG_FILE` nodes for `pom.xml`, `build.gradle`,
   `application.properties`, YAML configs, etc.
4. **TypeNodePass** — materialises `TYPE` nodes from the type registry collected during AST
   creation (`astCreationPass.global.usedTypes`).
5. **TypeInferencePass** — resolves unresolved types using `SimpleCombinedTypeSolver`; fills in
   `TYPE_FULL_NAME` edges. Skipped when `skipTypeInfPass = true`.

`createCpgWithOverlays` additionally runs: **Base**, **ControlFlow**, **TypeRelations**,
**CallGraph**.

When invoked via `atom`, two more passes run after the overlays:

- **JavaTypeRecoveryPass** — cross-file type propagation.
- **JavaTypeHintCallLinker** — resolves call edges where only a type hint is available.

## CLI Flags (`javasrc2cpg` standalone)

| Flag                           | Config field                  |
| ------------------------------ | ----------------------------- |
| `--inference-jar-paths <path>` | `inferenceJarPaths`           |
| `--fetch-dependencies`         | `fetchDependencies`           |
| `--delombok-java-home <path>`  | `delombokJavaHome`            |
| `--delombok-mode <mode>`       | `delombokMode`                |
| `--jdk-path <path>`            | `jdkPath`                     |
| `--show-env`                   | `showEnv`                     |
| `--skip-type-inf-pass`         | `skipTypeInfPass` (hidden)    |
| `--dump-javaparser-asts`       | `dumpJavaparserAsts` (hidden) |

## atom CLI (`-l java` / `-l javasrc`)

```bash
atom -l java \
  -o app.atom \
  --frontend-args "delombok-mode=types-only;fetch-dependencies=true" \
  /path/to/java/project
```

`atom` always sets `fetchDependencies = true`, `enableTypeRecovery = true`, and
`delombokMode = Some(sys.env.getOrElse("CHEN_DELOMBOK_MODE", "types-only"))`.

## Real Commands and Code Examples

### Standalone invocation

```bash
./javasrc2cpg/target/universal/stage/bin/javasrc2cpg \
  --inference-jar-paths /home/user/.m2/repository/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar \
  --fetch-dependencies \
  --delombok-mode types-only \
  --jdk-path /usr/lib/jvm/java-17-openjdk \
  -o /tmp/myapp.atom \
  /path/to/java/src
```

### Open the atom file

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/myapp.atom")
cpg.method.name.l
```

### Build with the Scala API

```scala
import io.appthreat.javasrc2cpg.{JavaSrc2Cpg, Config}
import scala.util.{Success, Failure}

val config = Config(
  inferenceJarPaths = Set("/home/user/.m2/repository/org/springframework/spring-web/6.0.0/spring-web-6.0.0.jar"),
  fetchDependencies = true,
  delombokMode = Some("types-only"),
  jdkPath = Some("/usr/lib/jvm/java-17-openjdk")
)
  .withInputPath("/path/to/java/src")
  .withOutputPath("/tmp/myapp.atom")

new JavaSrc2Cpg().createCpgWithOverlays(config) match
  case Success(cpg) =>
    println(s"Methods: ${cpg.method.size}")
    cpg.close()
  case Failure(ex) =>
    println(s"Failed: ${ex.getMessage}")
```

### Useful traversals

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/myapp.atom")

// All classes that implement Serializable
cpg.typeDecl.filter(_.implementedInterfaces.exists(_.name == "Serializable")).name.l

// SQL string concatenation sinks
cpg.call.name("executeQuery|execute").argument.isCall.name("<operator>.addition").l

// Methods with no return type declared (may indicate void or inference failure)
cpg.method.filter(_.methodReturn.typeFullName == "ANY").name.take(10).l
```

### Print environment variables recognised by the frontend

```bash
./javasrc2cpg ... --show-env /dummy
```

Prints: `JAVASRC_JDK_PATH` with description and current value.

## Notes for Security Analysts

- Always pass `--fetch-dependencies` when analysing open-source projects whose Maven coordinates
  are declared in `pom.xml` or `build.gradle`. Without the transitive JARs, `TypeInferencePass`
  can only resolve types defined in the project itself, leaving many `TYPE_FULL_NAME` edges as
  `ANY`.
- For Lombok-heavy projects (Spring Data, MapStruct), use `delombokMode = "run-delombok"` to get
  fully expanded source analysed; this produces the most complete call graph at the cost of
  analysing generated code rather than the original source.
- `dumpJavaparserAsts = true` is useful for debugging parse failures: it prints the raw
  JavaParser AST to stdout and exits without writing any atom file.
