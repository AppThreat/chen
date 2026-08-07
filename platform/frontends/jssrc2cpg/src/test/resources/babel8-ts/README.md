# babel8-ts test fixture

`HTTPError.ts` is vendored from **sindresorhus/ky** (`source/errors/HTTPError.ts`),
licensed **MIT**. It is used unmodified as a real-world TypeScript sample to pin
the Babel 8 (`@babel/parser` 8.x) AST shape emitted by astgen
(`@appthreat/atom-parsetools`).

`HTTPError.ts.json` / `HTTPError.ts.typemap` are the astgen output for that file
(the JSON `fullName` was rewritten to the relative name for portability).

To regenerate after an astgen change:

```
node astgen.js -i <this-dir> -o <this-dir> -t ts
# then set the JSON's fullName to its relativeName
```

Consumed by `Babel8ShapeAstCreationPassTest` via `AstJsonFixture("babel8-ts")`.
