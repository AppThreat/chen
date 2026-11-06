# receiver-types test fixture

`receiver-types.ts` is a few lines written for `ReceiverTypeAstCreationPassTest`: member calls on a
field read, on a call result, through a non-null assertion and an optional member read, and the type
annotations of a field, a method return, a cast, a nullable field and a constructor parameter
property. `receiver-types.ts.json` and `receiver-types.ts.typemap` are astgen's output for it with
TypeScript 6 types (no span map), the `fullName` rewritten to the relative name. To regenerate, put
the file in a directory whose `node_modules` holds `@angular/core` and `rxjs`, then run

    node astgen.js -i <dir> -o <out> -t ts

from atom-parsetools `release/1.x`, and copy the two files here with `fullName` set to
`receiver-types.ts`.
