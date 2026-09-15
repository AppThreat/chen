# svelte5 test fixture

`Counter.svelte` is a small hand-written Svelte 5 component (runes, `{#if}`,
keyed `{#each}`, `on:click`, `{@html}`) used to pin the Babel JSX AST shape
that astgen (`@appthreat/atom-parsetools`) emits for `.svelte` files:
absolute byte offsets into the component source, template synthesized as
stock JSX nodes, template expressions sub-parsed with the TypeScript plugin.

`Counter.svelte.json` / `Counter.svelte.typemap` are the astgen output for
that file, produced by astgen 4.2.0 (`@appthreat/atom-parsetools` 1.6.0,
svelte 5.57.0). The JSON `fullName` was rewritten to the relative name for
portability.

This is the shape contract between atom-parsetools and chen: if astgen changes
the emitted shape, this fixture and `Svelte5ShapeAstCreationPassTest` force a
deliberate re-baseline here instead of failing silently downstream.

To regenerate after an astgen change:

```
astgen -i src/test/resources/svelte5 -o /tmp/svelte5-out -t ts
cp /tmp/svelte5-out/Counter.svelte.* src/test/resources/svelte5/
# then set the JSON's fullName back to its relativeName ("Counter.svelte")
```

Consumed by `Svelte5ShapeAstCreationPassTest` via `AstJsonFixture("svelte5")`.
