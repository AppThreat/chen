# native-kinds test fixture

`native-kinds.ts` imports `kinds-lib.ts` and uses its types in the shapes the native type map is meant to
cover: awaited calls, method calls, member access, destructuring, object and array literals, an import
specifier, `new` and a default export. The `.json` files are the astgen ASTs (absolute paths rewritten to
the relative names), and `.typemap` and `.typespans` are what the **native** binary wrote
(`ASTGEN_TYPES=native`, atom-parsetools branch feat/native-types-everywhere). To regenerate:

    cd <atom-parsetools> && ASTGEN_TYPES=native ASTGEN_NATIVE_BIN=native/_deps/bin/atom-parsetools-native \
      node astgen.js -t ts -i <dir with the two .ts files> -o <out>

Consumed by `NativeTypesEverywhereTests` via `AstJsonFixture("native-kinds")`.
