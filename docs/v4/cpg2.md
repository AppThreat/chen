# cpg2 in chen 4.0

[cpg2](https://github.com/AppThreat/cpg2) is AppThreat's Code Property Graph library: the schema,
the generated node and edge classes, the pass framework (`CpgPass`, `ForkJoinParallelCpgPass` and
the rest) and the protobuf bindings. chen 3.4.0 used cpg2 3.0.5. chen 4.0.0 uses cpg2 3.1.2,
which in turn uses [overflowdb2 3.1.2](overflowdb2.md).

## The schema did not change

Between cpg2 3.0.5 and 3.1.2 nothing under `schema/src` or the generated domain classes changed.
Node types, edge types, properties and enumerations such as `Languages`, `DispatchTypes` and
`EvaluationStrategies` are the same, so queries, scripts and stored property names written for
chen 3.4 keep their meaning. The schema hash in the metadata of a saved graph is therefore the
same as well.

chen 4.0 records much more in the graph than 3.4 did, but it does that with the existing schema:
new facts are `TAG` nodes (key-value tags) attached through `TAGGED_BY` edges, and new
`REACHING_DEF` and `CALL` edges between existing node types. [The API document](api.md#tags-and-properties)
lists the new tag names.

## What changed in cpg2

### Characters beyond the Basic Multilingual Plane are kept

`io.shiftleft.utils.IOUtils.readLinesInFile` and `readEntireFile` used to replace every
supplementary code point (emoji, mathematical alphanumerics, CJK extension ideographs) with
`??`. They now keep well-formed surrogate pairs and replace only a lone surrogate, with a single
`?` (cpg2 3.0.8, AppThreat/cpg2#18). Frontends read source text through these functions, so
string literals keep those characters and Python identifiers that use them now parse.

A graph built by chen 4.0 can therefore have different `CODE`, `NAME` and literal values from
one built by chen 3.4 for the same file. Line and column offsets do not change.

### The explicit collection option is gone

The system property `odb.forkjoinpass.explicitGc=1` made `ForkJoinParallelCpgPass` call
`System.gc()` after each chunk. overflowdb2 3.1.2 evicts nodes to disk under every garbage
collector, so the option no longer helped: on atom's usages slice of DefectDojo with a 192 MB
heap, 3.1.2 finishes in 54 seconds with or without it and the slices are identical. The property
was removed in cpg2 3.1.2 (AppThreat/cpg2#24). Setting it now has no effect and no error.

### Build and toolchain

cpg2 3.1.0 moved to Scala 3.10.0 and sbt 2.0.10 (AppThreat/cpg2#21). The `sbt-overflowdb`
plugin has no sbt 2 build, so cpg2 runs overflowdb's code generator through its own
`project/OdbCodegenSbtPlugin.scala`, with the same keys (`generateDomainClasses`, `outputDir`,
`classWithSchema`, `fieldName`, `disableFormatting`) and the same `ODB_CODEGEN_DISABLE=true`
switch. The generated classes are identical. The protobuf bindings still use protoc 3.25.5 and
the same `cpg.proto`.

## Using cpg2 from your own build

The organisation and artifact names are unchanged: `io.appthreat` with `cpg2`, `cpg2-schema`,
`cpg2-domain-classes` and `cpg2-protos`, built for Scala 3 (`_3`). They are published to GitHub
Packages only, so a build needs the resolver and a token that can read packages:

```scala
resolvers += "GitHub Package Registry" at "https://maven.pkg.github.com/appthreat/_"
credentials += Credentials(
  "GitHub Package Registry", "maven.pkg.github.com", "appthreat", sys.env.getOrElse("GITHUB_TOKEN", ""))
libraryDependencies += "io.appthreat" %% "cpg2" % "3.1.2"
```

Code that reads these artifacts must be compiled with Scala 3.10.0 or later, and cpg2 needs JDK
23 or newer at run time, as before.

## Upgrading from chen 3.4

- No schema migration is needed, and node and edge type names are unchanged.
- Expect different `CODE` and `NAME` values where sources contain characters outside the Basic
  Multilingual Plane, if you compare graphs or hashes across versions.
- Remove `-Dodb.forkjoinpass.explicitGc=1` from JVM options; it does nothing now.
- Compile against Scala 3.10.

## Further reading

The cpg2 repository documents the pass architectures, serialised overlays and graph algorithms in
its [README](https://github.com/AppThreat/cpg2#readme) and in its
[lessons](https://github.com/AppThreat/cpg2/tree/main/docs/lessons): the schema, code generation,
traversals, serialisation and algorithms.
