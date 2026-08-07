# babel8 test fixture

`protobomLoader.js` is vendored from **cdxgen v13** (`lib/inventory/protobomLoader.js`),
licensed **Apache-2.0**. It is a real-world JavaScript sample used to pin the
Babel 8 (`@babel/parser` 8.x) AST shape emitted by astgen
(`@appthreat/atom-parsetools`) — notably dynamic `import()` as an
`ImportExpression`, template literals, and optional chaining.

`protobomLoader.js.json` / `protobomLoader.js.typemap` are the astgen output for
that file (the JSON `fullName` was rewritten to the relative name for portability).

To regenerate after an astgen change:

```
node astgen.js -i <this-dir> -o <this-dir> -t ts
# then set the JSON's fullName to its relativeName
```

Consumed by `Babel8ShapeAstCreationPassTest` via `AstJsonFixture("babel8")`.
