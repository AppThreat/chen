# Lesson 2: Java Source Frontend (javasrc2cpg) and Lombok Integration

### Learning Objective

Compile Java source code repositories into a CPG, configuring dependency jar resolution and managing Lombok annotations using the delombok engine.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **Maven or Gradle**: Required to download dependency JARs for type resolution.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen) and run `sbt compile`.

### Conceptual Background

Java features static type bindings, generics, and annotations. When parsing Java source code, the compiler needs access to the definitions of referenced external libraries. Without these, nodes representing library calls lack type details, which limits data-flow precision.

The [javasrc2cpg](https://github.com/AppThreat/chen/tree/main/javasrc2cpg) frontend utilizes the JavaParser library. It resolves types by scanning standard cache folders (such as `~/.m2/repository` and `~/.gradle/caches`) for dependency JARs.

Additionally, many Java projects use Project Lombok to dynamically generate getters, setters, constructors, and builders at compile time. Since these generated methods are not present in the raw source files, JavaParser cannot resolve them. To address this, the frontend supports Lombok integration modes:

- **no-delombok**: Parses the source files as-is. Lombok-generated methods will be missing from the CPG.
- **types-only**: Automatically resolves type definitions for Lombok-generated methods without generating code blocks.
- **run-delombok**: Runs Lombok's pre-compiler to rewrite the source files, materializing all getters, setters, and constructors before parsing.

### Real Commands and Code Examples

#### 1. Ingesting a Project with Automatic Delombok Resolution

Parse a Java project, enabling delombok processing and target file filtering:

```bash
./atom.sh -l java -o app.atom --frontend-args "delombok-mode=run-delombok" /path/to/java/project
```

#### 2. Executing JavaSrc2Cpg Programmatically in Scala

Below is a code example showing how to configure type recovery and Lombok integration inside the [Config](https://github.com/AppThreat/chen/blob/main/javasrc2cpg/src/main/scala/io/appthreat/javasrc2cpg/Config.scala) object:

```scala
import io.appthreat.javasrc2cpg.{JavaSrc2Cpg, Config}
import scala.util.Success

val config = Config(
  fetchDependencies = true,
  inferenceJarPaths = Set(
    s"${System.getProperty("user.home")}/.m2/repository",
    s"${System.getProperty("user.home")}/.gradle/caches"
  ),
  enableTypeRecovery = true,
  delombokMode = Some("types-only")
)
.withInputPath("/path/to/java/source")
.withOutputPath("/tmp/java_project.atom")

val java2cpg = new JavaSrc2Cpg()
java2cpg.createCpgWithOverlays(config) match {
  case Success(cpg) =>
    println(s"Java CPG created. Type resolution succeeded for ${cpg.graph.nodeCount} nodes.")
    cpg.close()
  case _ =>
    println("Failed to compile Java source project.")
}
```
