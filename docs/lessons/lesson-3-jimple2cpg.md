# Lesson 3: JVM Bytecode Frontend (jimple2cpg)

## Learning Objective

Understand how `jimple2cpg` uses the Soot framework and its Jimple three-address IR to build a CPG
from compiled JVM artefacts — JARs, class files, Android APKs, DEX files, and Scala TASTy JARs —
and how the `atom` CLI selects this frontend for all JVM binary inputs.

## Pre-requisites

- JDK 23+
- SBT 1.10+
- Local clone of [chen](https://github.com/AppThreat/chen): `sbt compile`
- For APK analysis: `android.jar` from the Android SDK (path passed via `--android`)

## Conceptual Background

Jimple is Soot's typed, simplified three-address IR derived from JVM bytecode. Working at the
bytecode level has two key advantages over source analysis:

1. **No source required.** Third-party dependencies, obfuscated binaries, and compiled artifacts
   can be analysed directly.
2. **Precise types.** Bytecode carries fully-qualified type descriptors for every field access and
   method call, so type inference is unnecessary.

`jimple2cpg` accepts several input formats by examining the file extension:

| Format                      | Extension                | Soot path                                                        |
| --------------------------- | ------------------------ | ---------------------------------------------------------------- |
| Java class files / JARs     | `.class`, `.jar`         | `AstCreationPass` (Jimple IR)                                    |
| Android APK                 | `.apk`, `.apkm`, `.xapk` | `SootAstCreationPass` (Dex → Jimple via `set_src_prec_apk`)      |
| Dalvik DEX                  | `.dex`                   | `SootAstCreationPass`                                            |
| Android AAR / split bundles | `.apks`, `.aar`          | extracted then `SootAstCreationPass`                             |
| Jimple source               | `.jimple`                | `AstCreationPass`                                                |
| Scala compiled output       | TASTy / SBT project      | via `atom`'s `createScalaCpg` using `Jimple2Cpg` with `scalaSdk` |

For APK/DEX inputs, `sootLoadApk` sets `src_prec_apk` and optionally `force_android_jar` to
point Soot at the correct Android platform JARs. Nested APK bundles (`.apkm`, `.apks`, `.xapk`)
are unpacked; only APKs that contain `classes*.dex` are forwarded to Soot.

Source:
[platform/frontends/jimple2cpg](https://github.com/AppThreat/chen/tree/main/platform/frontends/jimple2cpg)

## Config Fields (real names from `Main.scala`)

```
final case class Config(
  android: Option[String]    = None,          // path to android.jar for APK analysis
  scalaSdk: Option[String]   = None,          // path to scala3-library JAR for Scala analysis
  dynamicDirs: Seq[String]   = Seq.empty,     // dirs whose classes may be loaded dynamically
  dynamicPkgs: Seq[String]   = Seq.empty,     // packages that may be loaded dynamically
  fullResolver: Boolean      = false,         // whole-program analysis mode
  recurse: Boolean           = false,         // recursively unpack nested JARs
  depth: Int                 = 1,             // max nesting depth for recursive unpacking
  onlyClasses: Boolean       = false          // only process .class files (skip resources)
) extends X2CpgConfig[Config]
```

No `TypeRecoveryParserConfig` mixin — bytecode types are fully resolved by Soot.

## Pass Pipeline (`Jimple2Cpg.createCpg`)

1. **MetaDataPass** — writes the `MetaData` node (language = `JAVA`).
2. **SootAstCreationPass** (APK/DEX inputs) — configures Soot's APK loading options
   (`set_src_prec_apk`, `set_force_android_jar`, DEX search-in-archives), then converts
   Dalvik bytecode to Jimple and creates CPG nodes.
   **OR**
   **AstCreationPass** (JAR/JIMPLE/class inputs) — unpacks JARs into a temp dir
   (`extractClassesInPackageLayout`), then runs Soot's Jimple IR over class files.
3. **ConfigFileCreationPass** — creates `CONFIG_FILE` nodes for `MANIFEST.MF`,
   `AndroidManifest.xml`, property files, etc.
4. **TypeNodePass** — materialises `TYPE` nodes from Soot's type registry.

`createCpgWithOverlays` additionally runs: **Base**, **ControlFlow**, **TypeRelations**,
**CallGraph**.

`atom` uses `createCpgWithOverlays` directly with `fullResolver = true` and `recurse = true` for
JVM binary inputs. For Scala artifacts, it also sets `scalaSdk` and `onlyClasses = true`.

## CLI Flags (`jimple2cpg` standalone)

| Flag                           | Config field   |
| ------------------------------ | -------------- |
| `--android <path>`             | `android`      |
| `--scalaSdk <path>`            | `scalaSdk`     |
| `--depth <n>`                  | `depth`        |
| `--onlyClasses`                | `onlyClasses`  |
| `--full-resolver`              | `fullResolver` |
| `--recurse`                    | `recurse`      |
| `--dynamic-dirs <d1>,<d2>,...` | `dynamicDirs`  |
| `--dynamic-pkgs <p1>,<p2>,...` | `dynamicPkgs`  |

## atom CLI (`-l jar` / `-l apk` / `-l dex` / `-l android`)

```bash
# Analyse an Android APK
atom -l apk \
  -o app.atom \
  /path/to/MyApp.apk

# Analyse a JAR with full transitive resolution
atom -l jar \
  -o library.atom \
  /path/to/library.jar
```

`atom` maps language codes: `JAR`, `JIMPLE`, `ANDROID`, `APK`, `DEX` all invoke
`createJimple2Cpg`. It sets `fullResolver = true`, `recurse = true`, `depth = 10`, and uses a
bundled `android.jar` path automatically.

## Real Commands and Code Examples

### Standalone invocation (JAR)

```bash
./jimple2cpg/target/universal/stage/bin/jimple2cpg \
  --full-resolver \
  --recurse \
  --depth 5 \
  -o /tmp/library.atom \
  /path/to/spring-boot-app.jar
```

### Standalone invocation (APK)

```bash
./jimple2cpg/target/universal/stage/bin/jimple2cpg \
  --android /path/to/android-sdk/platforms/android-33/android.jar \
  --full-resolver \
  -o /tmp/myapp.atom \
  /path/to/MyApp.apk
```

### Open the atom file

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/library.atom")
cpg.method.name.l
```

### Build with the Scala API

```scala
import io.appthreat.jimple2cpg.{Jimple2Cpg, Config}
import scala.util.{Success, Failure}

val config = Config(
  fullResolver = true,
  recurse = true,
  depth = 5
)
  .withInputPath("/path/to/myapp.jar")
  .withOutputPath("/tmp/myapp.atom")

new Jimple2Cpg().createCpgWithOverlays(config) match
  case Success(cpg) =>
    cpg.method.filter(_.isPublic).name.l.take(20).foreach(println)
    cpg.close()
  case Failure(ex) =>
    println(s"Failed: ${ex.getMessage}")
```

### Useful traversals for JVM analysis

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/myapp.atom")

// Reflection entry points — potential dynamic class loading
cpg.call.name("forName|loadClass").l

// Serialization — classes implementing java.io.Serializable
cpg.typeDecl.filter(_.implementedInterfaces.exists(_.fullName.contains("Serializable"))).name.l

// Native methods declared in JAR
cpg.method.filter(_.isNative).fullName.l
```

## Notes for Security Analysts

- **`fullResolver = true`** enables Soot's whole-program call graph. This is expensive but
  essential for finding transitive data flows through framework code.
- **Dynamic loading analysis**: use `--dynamic-dirs` and `--dynamic-pkgs` to tell Soot which
  classes the application may load reflectively; Soot will add them to the Scene and include them
  in the call graph.
- **Android**: for split-bundle formats (`.apks`, `.xapk`, `.apkm`), `jimple2cpg` automatically
  unpacks the bundle and processes only the APKs that carry Dalvik bytecode (`classes*.dex`).
- **Scala artefacts**: pass `--scalaSdk` pointing to `scala3-library_3-X.Y.Z.jar` to let Soot
  resolve Scala-specific runtime types correctly.
