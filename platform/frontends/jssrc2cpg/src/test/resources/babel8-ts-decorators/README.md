# babel8-ts-decorators test fixture

`cats.controller.ts` is vendored unmodified from **nestjs/nest**
(`sample/01-cats-app/src/cats/cats.controller.ts`), licensed **MIT**. It is a
real-world TypeScript sample exercising the decorator-heavy NestJS style: a class
decorator (`@Controller`, `@UseGuards`), method decorators (`@Get`, `@Post`,
`@Roles`), parameter decorators (`@Body`, `@Param`) and constructor
dependency-injection, all under the Babel 8 (`@babel/parser` 8.x) AST shape
emitted by astgen (`@appthreat/atom-parsetools`).

`cats.controller.ts.json` / `cats.controller.ts.typemap` are the astgen output
for that file (`fullName` is the portable relative name).

To regenerate after an astgen change:

```
node astgen.js -i <this-dir> -o <this-dir> -t ts
```

Consumed by `RealWorldTsAstCreationPassTest` via `AstJsonFixture("babel8-ts-decorators")`.
