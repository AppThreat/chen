# auto-accessor test fixture

`auto-accessor.ts` is a few lines written for this test: a TypeScript class with decorated,
undecorated and private static TC39 auto-accessors (`accessor id = uuidv4()`, `static accessor
#token`), which Babel emits as `ClassAccessorProperty` nodes once astgen's plugin list has
`decoratorAutoAccessors` (atom-parsetools#34). `auto-accessor.ts.json` is that astgen AST (the
`fullName` was rewritten to the relative name for portability); there is no typemap, the assertions
do not need types.

Consumed by `AutoAccessorAstCreationPassTest` via `AstJsonFixture`, which reuses the committed
`.json` through `astGenOutDir` and never invokes astgen. To regenerate:

    cd <atom-parsetools with decoratorAutoAccessors> && node astgen.js \
      -i <dir with auto-accessor.ts> -o <out> -t ts --no-tsTypes

then copy `<out>/auto-accessor.ts.json` here and set its `fullName` to `auto-accessor.ts`.
