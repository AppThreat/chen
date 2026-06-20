# Lesson 3: Java Bytecode & Android Frontend (jimple2cpg) via Soot IR

### Learning Objective

Parse compiled Java bytecode, JAR files, and Android DEX/APK files into a CPG by translating them to Soot Jimple 3-address Intermediate Representation (IR).

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Android SDK**: Access to an `android.jar` platform file (required if compiling Android application APKs).
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen).

### Conceptual Background

In binary audits or dependency analysis, source code is often unavailable. To analyze compiled dependencies, the [jimple2cpg](https://github.com/AppThreat/chen/tree/main/jimple2cpg) frontend translates compiled Java bytecode (class files) or Android bytecode (dex files inside an APK) into Soot Jimple IR.

Soot Jimple is a typed, 3-address intermediate representation. The advantages of compiling Jimple to a CPG instead of raw bytecode include:

- **Simplified Expression Trees**: Stack-based operations are translated to explicit 3-address statements, simplifying variable dependency tracking.
- **Type Resolution**: Soot resolves types and signatures, enabling precise edge mapping.
- **Android Framework Support**: APK resources, manifest entries, and dex instructions are processed together, using the platform `android.jar` to resolve SDK references.

### Real Commands and Code Examples

#### 1. Ingesting an Android APK File

Compile an Android APK to a CPG, passing the platform SDK reference path:

```bash
# Set ANDROID_HOME or point to the platform android.jar
./atom.sh -l android -o app.atom --frontend-args "android=/Users/user/Library/Android/sdk/platforms/android-33/android.jar" /path/to/app.apk
```

#### 2. Compiling bytecode JAR archives inside Scala

Below is a code example showing how to configure the `jimple2cpg` compiler frontend using the [Config](https://github.com/AppThreat/chen/blob/main/jimple2cpg/src/main/scala/io/appthreat/jimple2cpg/Config.scala) class:

```scala
import io.appthreat.jimple2cpg.{Jimple2Cpg, Config}
import scala.util.Success

val config = Config()
  .withInputPath("/path/to/compiled/classes.jar")
  .withOutputPath("/tmp/bytecode_project.atom")
  .withFullResolver(true)
  .withRecurse(true)
  .withDepth(10) // Limit directory recursion depth

val jimple2cpg = new Jimple2Cpg()
jimple2cpg.createCpgWithOverlays(config) match {
  case Success(cpg) =>
    println(s"Bytecode CPG successfully created using Soot Jimple IR. Node count: ${cpg.graph.nodeCount}")
    cpg.close()
  case _ =>
    println("Failed to compile Java bytecode.")
}
```
