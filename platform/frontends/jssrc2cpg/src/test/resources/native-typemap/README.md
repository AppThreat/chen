# native-typemap test fixture

`native-types.ts` is a few lines written for this test. `native-types.ts.json` is the astgen AST (the `fullName` was
rewritten to the relative name for portability) and `native-types.ts.typemap` is the type map the **native** binary
wrote for it (`ASTGEN_TYPES=native`, atom-parsetools branch feat/native-parsetools-t1). `ts6-reference.typemap.txt`
is what TypeScript 6 wrote for the same file, kept only to show the differences the test is about:

- `mode: 'strict'` keeps the quote style of the source in TypeScript 7 (TypeScript 6 wrote `"strict"`),
- a union is ordered by TypeScript 7's stable key (`"error" | "ok" | "warning"`, TypeScript 6: `"error" | "warning" | "ok"`).

Consumed by `NativeTypeMapTests` via `AstJsonFixture("native-typemap")`. To regenerate:

    cd <atom-parsetools> && ASTGEN_TYPES=native ASTGEN_NATIVE_BIN=native/_deps/bin/atom-parsetools-native \
      node astgen.js -i <dir with native-types.ts> -o <out>
