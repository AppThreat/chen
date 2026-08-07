# babel8-ts-namespace test fixture

`performance.ts` is vendored unmodified from **microsoft/TypeScript**
(`src/compiler/performance.ts`, tag `v4.4.4`), licensed **Apache-2.0**. The TypeScript
compiler is one of the few large official projects that still uses TypeScript
namespaces, and this file declares a *qualified* namespace path
(`namespace ts.performance { ... }`). Under Babel 8, astgen
(`@appthreat/atom-parsetools`) emits this as a single `TSModuleDeclaration` whose
`id` is a nested `TSQualifiedName`, which the frontend must expand into nested
`ts` -> `performance` namespace blocks.

`performance.ts.json` / `performance.ts.typemap` are the astgen output for that
file (`fullName` is the portable relative name).

To regenerate after an astgen change:

```
node astgen.js -i <this-dir> -o <this-dir> -t ts
```

Consumed by `RealWorldTsAstCreationPassTest` via `AstJsonFixture("babel8-ts-namespace")`.
