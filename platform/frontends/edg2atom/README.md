# edg2atom

The C/C++ frontend that builds the Code Property Graph from the [EDG C/C++ front
end](https://github.com/edgcpp/compiler): it runs [edga](https://github.com/AppThreat/edga) on
each translation unit and reads the JSON it writes. It shares the CDT frontend's (`c2cpg`)
configuration, compilation database support, header ownership and graph shapes, so the passes
and queries written for one work on the other.

## How it works

- `ProjectSources` (from c2cpg) lists the units, their settings from a compilation database or
  the host compiler, and which unit owns each header: the first that includes it, in path order.
- `EdgaRunner` turns a unit's settings into front end options: the compiler emulated
  (`--gcc`/`--g++ --gnu_version`, `--clang --clang_version`, `--microsoft`) from the compiler's
  predefined macros, the language standard, defines, include and system include directories,
  forced includes, and the host shims below. It runs edga with a timeout per unit.
- `EdgaUnit` reads the JSON. `AstCreator` and its traits (`AstForExpressions`, `AstForCpp`,
  `MacroCalls`, `TypeNames`) build the AST as the CDT frontend writes it: full names and
  signatures in its spelling, member calls with their object as argument 0, implicit members,
  macro invocations as INLINED calls. Each unit writes its own files and the project headers it
  owns; template instances from headers another unit owns are written by each unit that uses
  them, and `DuplicateDefinitionPass` keeps one copy.
- What the front end knows beyond the shapes becomes tags (see `io.appthreat.x2cpg.Defines`):
  `implicit-conversion`, `virtual-call`, `default-argument`, `vla-size`, `compiler-generated`,
  `lifetime-end`, `const-value`, `ptr-arith`, `operator-call`, `alloc-form`, `fn-attr`,
  `macro-invocation` and `macro-origin`.
- `Edg2Atom(fallbackToCdt = true)` parses with c2cpg the units edga cannot export, into the same
  graph; `FrontendTagPass` tags each FILE `frontend=edg` or `frontend=cdt`.
- The AST cache key holds the unit's fingerprint, the CRCs of the project headers it includes
  and edga's identity (`edga --edga-version`).

## Host shims

- libc++: `__OPTIMIZE_SIZE__`, which leaves out the vectorised algorithms built on clang's
  dependent-size vector types the front end cannot instantiate.
- The NEON macros are not passed on: the front end does not declare the intrinsics they gate.
- edga built without float128 (aarch64 Linux): `_Float128` is `long double` where glibc takes it
  as the compiler's own type (GCC 7+, G++ 13+).

Each is pinned by a test in `EdgaRunnerTests`.

## Tests

```bash
EDGA_PATH=/path/to/edga sbt "edg2atom/test"
```

The tests that need edga are cancelled without it. `GoldenComparisonTests` builds the graphs of
both frontends from the fixtures in `src/test/resources/golden` and fails on any difference not
listed, with its reason, in `<fixture>.differences`; run with
`-Dedg2atom.golden.update=true` (a `Test / javaOptions` setting) to rewrite those files, then
review them. `MemorySafetyOnEdgTests` runs the memory-safety passes on edga's graphs.
