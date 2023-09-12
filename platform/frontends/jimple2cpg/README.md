# jimple2cpg

This is a [CPG](https://docs.joern.io/code-property-graph/) frontend for Soot's
Jimple IR. This language frontend is formerly known as
[Plume](https://plume-oss.github.io/plume-docs/).


## Setup

Requirements:
- \>= JDK 11. We recommend OpenJDK 11.
- sbt (https://www.scala-sbt.org/)

### Quickstart

1. Clone the project
2. Build the project `sbt stage`
3. Create a CPG `./jimple2cpg.sh /path/to/your/code -o /path/to/cpg.bin`
4. Download Joern with
   ```
   wget https://github.com/appthreat/joern/releases/latest/download/platform.zip
   unzip platform.zip
   cd platform
   ```
5. Copy `cpg.bin` into the Joern directory
6. Start Joern with `./joern.sh`
7. Import the cpg with `importCpg("cpg.bin")`
8. Now you can query the CPG 

### Development

Some general development habits for the project:

- When making a branch, use the following template `<short-name>/<feature-or-bug-name>` 
  e.g. `fabs/control-structure-nodes`.
- We currently focus around test driven development. Pay attention to the code coverage when creating new tests and 
  features. The code coverage report can be found under `./target/scala-2.13/scoverage-report`.