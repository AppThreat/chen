# c2cpg

The C/C++ frontend that builds the Code Property Graph with the Eclipse CDT parser (bundled in
`lib/`). It is the default; [edg2atom](../edg2atom) is the alternative built on the EDG front
end, and reuses this frontend's configuration and sources.

## How it works

- `ProjectSources` lists the translation units and headers, and gives each unit its settings:
  from a JSON compilation database (`--compile-commands`) its standard, defines, include
  directories and forced includes, and the compiler it names; otherwise the host's compiler.
  The compiler is asked once for its predefined macros and system include directories
  (`PredefinedMacros`).
- `IncludeGraph` reads the units' `#include` lines: a header is parsed as part of the first unit,
  in path order, that includes it (with that unit's settings), and a header no unit includes is
  parsed on its own. Include directories a build passes but the analysis is not told are found
  from the headers' trailing path segments.
- `AstCreator` and its traits build the AST; macro invocations are INLINED calls whose
  arguments are copies of the subtrees they became. The AST of each file is cached
  (`--no-ast-cache` to turn it off) by its fingerprint and those of the headers it includes.

## Tests

```bash
sbt "c2cpg/test"
```

The memory-safety rules are tested here (`passes/`), on graphs this frontend builds.
