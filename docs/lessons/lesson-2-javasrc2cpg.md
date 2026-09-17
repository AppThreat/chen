# Lesson 2: Java Source Frontend (javasrc2cpg)

## Learning Objective

Understand how `javasrc2cpg` uses the JavaParser library to build a CPG from Java source, how
Lombok annotations are handled via the Delombok preprocessor, how type inference is driven by
external JAR classpath entries, how modern Java (8 through 26) constructs are lowered into CPG
nodes, how the framework taggers recognise web/rpc/database/AI/native boundaries, and how to
control each of these behaviours through `Config`.

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

## Modern Java Lowering (Java 8 through 26)

The bundled JavaParser parses every construct through Java 26 syntax, so a missing construct is
always an AST-lowering gap, never a parser gap. The lowerings that matter for dataflow:

| Construct (version)                                          | Lowering                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Switch expression, arrow arms (14)                           | The selector is bound ONCE to a synthetic `switch$N` local (Java evaluates it once; duplicating it per arm would multiply a `compute()` selector N times in the call graph), then nested `<operator>.conditional` calls: `conditional(equals(sel, A), v1, conditional(..., default))`. The declared conditional semantic maps arms 2/3 to the result, so taint in any arm value flows to the expression's value - the JLS `14.11.2` behaviour for free. Multi-label arms (`case A, B`) OR their tests; a `when` guard ANDs into the arm condition. Pattern-bearing STATEMENT switches bind the selector the same way; constant-only ones keep the selector inline. |
| `yield e` (14)                                               | The arm value of its block. A `yield` reached in plain statement position lowers to an `<operator>.yield` call with the expression as its argument, so nothing is dropped.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `instanceof` type pattern (16)                               | The type test plus a binding: a LOCAL of the pattern's type and an assignment `<binding> = <tested expr>`. The binding is definitely assigned when the test succeeds (`JLS 6.3`), and the assignment carries exactly that taint relation. The LOCAL is registered on the scope (`Scope.registerPatternLocalAst`) and attached as a direct child of the body BLOCK - the position every `method.local`-style traversal and the dataflow engine expect.                                                                                                                                           |
| Record pattern (21)                                          | Each component variable binds the same way, aliasing the matched value: a tainted record taints every bound component. The record's type test is an `<operator>.instanceOf` call against a TYPE_REF.                                                                                                                                                                                                                                                                                                                                                                                              |
| Pattern `case` labels with guards (21)                       | Statement-form switches keep their SWITCH control structure; a pattern label adds a `case` JUMP_TARGET, the binding (as above), and - in the expression form - an `instanceof` arm condition. The guard expression is lowered in place, after the labels.                                                                                                                                                                                                                                                                                                                                       |
| Method references (8)                                        | A METHOD_REF node (the same shape a lambda lowers to) whose `methodFullName` is the resolved qualified name, or the source form when the receiver cannot be resolved. This is what lets a framework registration such as `router.get("/x").handler(this::handleItems)` resolve its handler.                                                                                                                                                                                                                                       |
| Local class / record (16)                                    | A full TYPE_DECL under the enclosing METHOD, built with the shared type-decl machinery - its fields, constructors and accessors are first-class graph citizens.                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Text blocks (15), `var`, unnamed variables `_` (22)           | Ordinary literals/locals - lowered by the existing paths; nothing special needed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Module imports (25), flexible constructor bodies (25)         | Parse-level constructs: an import is an IMPORT node; pre-`super()` statements are ordinary body statements that precede the `<init>` call.                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Virtual threads (21), stream gatherers (24), FFM (22+)        | Ordinary calls; the FFM entry points are tagged `native` by the framework taggers.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

Two invariants of the switch-expression lowering are worth remembering, because they were bugs
first:

1. **Bindings cannot ride under the value expression.** An expression-position switch funnels its
   value into an ARGUMENT slot (`String v = switch ...`, `return switch ...`), and an ARGUMENT
   edge into a LOCAL or BLOCK node violates the schema. Worse, statements tucked under the
   conditional call are invisible to reaching definitions, because the declared
   `<operator>.conditional` semantic only maps the value arms - a binding def inside the
   condition subtree never reaches an arm's use of the binding. The selector temp, the binding
   LOCALs and the arm side effects therefore return as LEADING ASTs in statement position
   (`astsForVariableDecl`, `astsForAssignExpr` and `astForReturnNode` hoist them), with the
   LOCALs on the scope channel. Stated plainly, this is an over-approximation: the hoisted
   statements run BEFORE the whole lowered switch, so every arm's side effects and pattern
   bindings are modelled as executing unconditionally - conservative for taint (a superset of
   the real flows), potentially over-counting for call-graph side effects in arms that never
   run.
2. **Annotation string values lower twice.** The historic ANNOTATION_LITERAL value node is
   untaggable (no TAGGED_BY support in the runtime schema) and invisible to literal traversals,
   so a route (`@GetMapping("/users")`) or statement (`@Query("SELECT ...")`) that exists only
   there is invisible to the taggers. A real LITERAL duplicate under the parameter assignment
   makes the value a first-class expression node - one per element for an array member
   (`@RequestMapping({"/a", "/b"})`), with backslashes and quotes re-escaped;
   `AnnotationTests` pins both shapes. Route collection reads only the `value`/`path` members
   (a `produces = "application/json"` pair is not a route), accepts relative segments and the
   root `"/"` (a class-level `@RequestMapping` may supply the prefix, which is tagged on the
   TYPE_DECL but not composed onto the method literal).

## Framework Tagging and Semantics

Java graphs get the same boundary vocabulary the other frontends have:

- **`ChennaiTagsPass.tagJavaRoutes`** (x2cpg) tags `framework-route` / `framework-input` /
  `framework-output` plus family tags. The shapes and collision gates live in
  `x2cpg/passes/taggers/JavaFrameworks.scala`:
  - HTTP: Spring mapping annotations (`@GetMapping`/`@PostMapping`/... and their request-data
    parameter annotations), JAX-RS/Jakarta (import-gated `@GET`/`@Path`/`@QueryParam`/...),
    Micronaut, servlet overrides (recognised by the servlet parameter TYPES, which keeps a user
    `service()` method untagged), and router DSLs (`router.get("/x").handler(this::h)` - route
    literals and handler resolution through METHOD_REF).
  - gRPC: methods with a `StreamObserver` parameter are tagged `grpc-service`; the observer
    parameter is framework-output, `onNext`/`onError`/`onCompleted` calls are outputs.
  - Databases: JDBC/JPA/JdbcTemplate call names and `@Query`/`@Select`/... annotation values
    tagged `sql`; document stores are import-gated.
  - AI/LLM: LangChain4j, Spring AI, OpenAI, Gemini, Bedrock, Azure - invocation calls
    `ai-llm`+`ai-invoke`, prompt builders `ai-llm`+`ai-prompt` (the Python tagger's vocabulary).
  - MCP: `@Tool` methods are `mcp-tool` entrypoints with client-facing parameters.
  - Cloud: AWS/GCP/Azure calls `cloud`; `RequestHandler.handleRequest` implementations are
    event-facing entrypoints.
  - Native: `System.loadLibrary`, NATIVE-modifier methods, and `java.lang.foreign` downcalls
    tagged `native`.
  - Messaging/SDK: `@KafkaListener`/`@JmsListener`/`@RabbitListener` methods are queue-driven
    inputs; OkHttp/Retrofit/Feign/`java.net.http` calls are `http-client`.
- **`EasyTagsPass.tagJavaPatterns`** gained the Python arm's sink families (`code-execution` for
  `Runtime.exec`/`ProcessBuilder.start`, `ssrf`, `file-io`, `unsafe-deserialization`,
  `reflection`), so a Java graph has tagged sinks without a hand-written `chennai.json`.
- **`dataflowengineoss/semantics/JavaFrameworkSemantics.scala`** is the flow-semantics home:
  OWASP Encoder/Spring/commons escapers clear taint (fully qualified, therefore language-safe in
  the global defaults), deserialisation carriers pass input taint into the returned object, and
  the request readers (`getParameter`, `getHeader`, ...) map receiver to return. The request
  readers are BARE names and are therefore language-gated through `DefaultSemantics
  .flowsForLanguage`, exactly like the PHP sanitizer list.

The fixtures that pin all of this live in `ModernJavaSyntaxTests`, `ModernJavaDataflowTests` and
`JavaFrameworkTagsTest` under `javasrc2cpg/src/test/.../querying/`, and end-to-end (frontend,
taggers, data-flow engine, reachable slicer, no `chennai.json`) in atom's
`ReachablesCrossLanguageWorkflowTests` "reachables for java" sections.

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
