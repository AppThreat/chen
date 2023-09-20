# c2cpg

An [Eclipse CDT](https://wiki.eclipse.org/CDT/designs/Overview_of_Parsing) based parser for C/C++ that creates code property graphs according to the specification at https://github.com/ShiftLeftSecurity/codepropertygraph .

## Building the code

The build process has been verified on Linux, and it should be possible 
to build on OS X and BSD systems as well. The build process requires
the following prerequisites:

* Java runtime 17
  - Link: http://openjdk.java.net/install/
* Scala build tool (sbt)
  - Link: https://www.scala-sbt.org/

Additional build-time dependencies are automatically downloaded as part
of the build process. To build c2cpg issue the command `sbt stage`.

## Running

To produce a code property graph  issue the command:
```shell script
./c2cpg.sh <path/to/sourceCodeDirectory> --output <path/to/outputCpg>
`````

Additional options are available:
```shell script
./c2cpg.sh <path/to/sourceCodeDirectory> \
                --output <path/to/outputCpg> \
                --include <path/to/include/dir1>,<path/to/include/dir2>
                --define DEF
                --define DEF_VAL=2
```

Run the following to see a complete list of available options:
```shell script
./c2cpg.sh --help
```
