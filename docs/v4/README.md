# chen 4.0

chen 4.0 is the release behind atom 4. It adds a C and C++ frontend built on the EDG front end,
brings every language up to its current syntax, records far more of what each compiler knows as
tags on the graph, and makes the data-flow engine faster and more precise. The graph schema and
the on-disk format are unchanged, so tools that read chen graphs keep working; tools that call
chen as a library need Scala 3.10 and a few changes described in the API document.

## What is new

- **A second C/C++ frontend.** [edg2atom](frontends.md#edg2atom-c-and-c-with-the-edg-front-end-new)
  builds the graph from the EDG front end through [edga](https://github.com/AppThreat/edga), with
  overloads, templates, implicit conversions, virtual calls and object lifetimes resolved by a
  production compiler front end. c2cpg, the Eclipse CDT frontend, now reads compilation databases
  and the real compiler's macros, parses C++20 modules and C23, and records macro provenance and
  the facts memory-safety analysis needs.
- **Current language versions.** Python 3.15, the PHP 8.5 pipe operator and 8.4 property hooks,
  Lombok without delombok and build-declared encodings for Java, TypeScript through the native
  TypeScript 7 type engine of atom-parsetools 2.x, Ruby constants and calls from outside the
  project, and Unicode-correct source decoding everywhere.
- **Vendored code.** `--external-paths <regex>` marks vendored directories external in every
  source frontend, so slices and reachability treat them as dependencies.
- **Data flow.** The Flux solver is the default, the semantics are language aware, arguments bind
  to parameters by name and unpacking as each language does, value operators no longer spread
  taint between their operands, and C and C++ globals and struct members get def-use edges
  across functions.
- **Security facts.** Framework recognizers for thirteen JavaScript frameworks, forwarded-header
  and proxy-trust tags in five languages, Python template sandboxes and AI model loading, Unicode
  integrity checks (Trojan Source and look-alike identifiers), and a memory-safety overlay for C
  and C++.
- **Reliability under memory pressure.** cpg2 and overflowdb2 3.1.2 evict to disk under every
  garbage collector and fix the concurrency bugs that crashed or hung large runs.

## The documents

| Document | For |
|---|---|
| [Frontends](frontends.md) | What changed in each language frontend, the options and environment variables, and the external tools each needs. |
| [API and migration](api.md) | Library users: build changes, data-flow and semantics changes, new APIs and tags, and how to upgrade. |
| [cpg2](cpg2.md) | The Code Property Graph library: no schema changes, Unicode-preserving source reading, build changes. |
| [overflowdb2](overflowdb2.md) | The graph database: storage compatibility, eviction under every collector, concurrency fixes and API changes. |

## Upgrading from 3.4

For a user of atom, chen 4.0 arrives with atom 4 and needs no action beyond installing edga for
`--c-frontend edg`. AST caches from older versions are rebuilt on the first run, and atoms saved
by chen 3.4 keep their format.

For a library user, the checklist is in [the API document](api.md#upgrading-in-brief).
