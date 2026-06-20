# Lesson 1: C/C++ Frontend (c2cpg) and Preprocessor Resolution

### Learning Objective

Compile C/C++ source code into a Code Property Graph, configuring compiler macros, preprocessor flags, include directory paths, and header resolution using the CDT parser.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **C/C++ Build Tools**: A local compiler (such as `gcc` or `clang`) along with standard libraries (glibc header files).
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen) and run `sbt compile`.

### Conceptual Background

C/C++ compilation differs from managed environments because of the preprocessor step. Code relies heavily on macros (e.g. `#define`), conditional compilation blocks (e.g. `#ifdef`), and header path resolutions (`#include <header.h>`).

The [c2cpg](https://github.com/AppThreat/chen/tree/main/c2cpg) frontend uses the Eclipse CDT parser to parse C/C++ source files. Rather than running a separate preprocessor pass (which strips macro information, rendering the resulting graph disconnected from the original source structure), `c2cpg` parses macros as first-class AST nodes.

To resolve compiler-specific definitions and dependencies, the frontend supports several parameters:

- **Defines**: Key-value pairs simulating compiler `-D` flags (e.g., `DEBUG=1`).
- **Includes**: Specific directories to search for header files, acting as compiler `-I` flags.
- **C++ Standard**: Forces a specific language dialect (e.g., C++11, C++17, C++20).
- **Parse Inactive Code**: Decides whether to parse disabled conditional compilation blocks (e.g. the `#else` branch).

### Real Commands and Code Examples

#### 1. Invoking Compilation with Custom Header Configurations

Parse a C/C++ project, defining compiler flags and include search directories:

```bash
./atom.sh -l cpp -o app.atom --frontend-args "defines=VERSION=2.0;RELEASE,includes=/usr/local/include;/opt/local/include,cpp-standard=c++17" /path/to/cpp/project
```

#### 2. Instantiating the C2Cpg Parser in Scala

Below is a code example demonstrating how to configure and execute the `c2cpg` compiler frontend using the [Config](https://github.com/AppThreat/chen/blob/main/c2cpg/src/main/scala/io/appthreat/c2cpg/Config.scala) class:

```scala
import io.appthreat.c2cpg.{C2Cpg, Config}
import scala.util.Success

val config = Config(
  includeComments = false,
  logProblems = false,
  includePathsAutoDiscovery = true
)
.withInputPath("/path/to/cpp/source/")
.withOutputPath("/tmp/cpp_project.atom")
.withDefines(Set("DEBUG=1", "TARGET_OS=MAC"))
.withIncludePaths(Set("/usr/include", "/usr/local/include"))
.withCppStandard("c++20")

val c2cpg = new C2Cpg()
c2cpg.createCpgWithOverlays(config) match {
  case Success(cpg) =>
    println(s"C/C++ CPG created successfully. Node count: ${cpg.graph.nodeCount}")
    cpg.close()
  case _ =>
    println("Failed to compile C/C++ project.")
}
```
