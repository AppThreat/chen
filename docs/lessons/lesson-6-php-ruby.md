# Lesson 6: PHP & Ruby Frontends (php2atom and ruby2atom)

### Learning Objective

Parse PHP and Ruby source code repositories to generate CPG representations, mapping script-level globals, dynamic class layouts, and closures.

### Pre-requisites

To follow this lesson, ensure the following software is installed on your system:

- **JDK 23+**: Standard OpenJDK or GraalVM.
- **SBT 1.10+**: Standard build utility.
- **PHP 8.3+**: Required for PHP parsing with zip/xml extensions.
- **Ruby 4.0+**: Required if parsing Ruby source files.
- **Local clone of Chen**: Clone the [chen repository](https://github.com/AppThreat/chen) and compile using `sbt compile`.

### Conceptual Background

PHP and Ruby are widely used script-based dynamic languages. They compile global namespaces, dynamic assignments, block scopes, and framework routing rules.

- **[php2atom](https://github.com/AppThreat/chen/tree/main/php2atom)**: Uses a PHP-native parser to generate a JSON AST representation of the files, which is then imported into CPG nodes. It resolves script-level statements, maps local classes, handles constructor variables, and applies [PhpSetKnownTypesPass](https://github.com/AppThreat/chen/blob/main/php2atom/src/main/scala/io/appthreat/php2atom/passes/PhpSetKnownTypesPass.scala) to seed builtin PHP types (e.g. `array`, `string`, `int`).
- **[ruby2atom](https://github.com/AppThreat/chen/tree/main/ruby2atom)**: Ingests Ruby files, parses class layouts, tracks local/instance variables, resolves dynamic method invocations, and maps Ruby blocks/closures to nested method structures in the CPG.

### Real Commands and Code Examples

#### 1. Compiling a PHP Project

Parse a PHP application, ignoring vendor directories:

```bash
./atom.sh -l php -o app.atom --ignored-dirs "vendor;docs" /path/to/php/project
```

#### 2. Compiling a Ruby Project

Parse a Ruby application:

```bash
./atom.sh -l ruby -o app.atom /path/to/ruby/project
```

#### 3. Running Php2Atom programmatically inside Scala

Below is a code example demonstrating how to configure and execute `php2atom` using the [Config](https://github.com/AppThreat/chen/blob/main/php2atom/src/main/scala/io/appthreat/php2atom/Config.scala) class:

```scala
import io.appthreat.php2atom.{Php2Atom, Config}
import io.appthreat.php2atom.passes.PhpSetKnownTypesPass
import scala.util.Success

val config = Config()
  .withDisableDummyTypes(true)
  .withInputPath("/path/to/php/source")
  .withOutputPath("/tmp/php_project.atom")
  .withIgnoredFilesRegex(".*(?:vendor|tests).*")

val php2atom = new Php2Atom()
php2atom.createCpgWithOverlays(config).map { cpg =>
  // Seed PHP-specific types
  new PhpSetKnownTypesPass(cpg).createAndApply()

  println(s"PHP CPG created successfully. Node count: ${cpg.graph.nodeCount}")
  cpg.close()
}
```
