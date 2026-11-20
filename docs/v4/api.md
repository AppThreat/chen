# chen 4.0 API changes and migration

This page is for code that uses chen as a library: atom, and any Scala or Java tool that builds
graphs with chen's frontends, runs its passes or queries the data-flow engine. It lists what
changed between chen 3.4.0 and 4.0.0 in the build, the semantic CPG layer (`semanticcpg`), the
data-flow engine (`dataflowengineoss`) and the shared frontend library (`x2cpg`), and what to
change when upgrading. Language-specific changes are in [the frontends document](frontends.md).

chen itself has no command line. Slicing, export and the CLI are in
[atom](https://github.com/AppThreat/atom), which uses the APIs described here.

## Upgrading in brief

1. Build with Scala 3.10.0 or later, and keep JDK 23 or newer.
2. Depend on `io.appthreat` artifacts version 4.0.0 from GitHub Packages, as before.
3. If you build `Semantics` yourself for C or C++ graphs, add the C flows
   (see [semantics](#the-default-semantics-are-language-neutral)).
4. Do not mutate `DefaultSemantics.memoised`.
5. Expect more `REACHING_DEF` and `CALL` edges on C and C++ graphs, fewer flows through
   comparison and arithmetic operators, and many new tags.
6. The data-flow layer now uses the Flux solver by default; set `useFluxEngine = false` for the
   classic one.
7. Rebuild AST caches: chen 3.4 caches are not reused.

## Build and dependencies

| | chen 3.4.0 | chen 4.0.0 |
|---|---|---|
| Scala | 3.8.4 | 3.10.0 |
| sbt | 1.x | 2.0.10 |
| JDK | 23 or newer | 23 or newer (CI builds with 25 and tests 23, 25 and 26) |
| cpg2 / overflowdb2 | 3.0.5 | 3.1.2 |

The organisation is still `io.appthreat`, and the published artifacts are `semanticcpg`,
`dataflowengineoss`, `x2cpg`, `platform` and one per frontend: `c2cpg`, `javasrc2cpg`,
`jimple2cpg`, `jssrc2cpg`, `php2atom`, `pysrc2cpg`, `ruby2atom`, and the new **`edg2atom`**. Test
jars are still published. They are hosted on GitHub Packages, so a consumer needs the resolver
and a token:

```scala
resolvers += "GitHub Package Registry" at "https://maven.pkg.github.com/appthreat/_"
credentials += Credentials(
  "GitHub Package Registry", "maven.pkg.github.com", "appthreat", sys.env.getOrElse("GITHUB_TOKEN", ""))
libraryDependencies += "io.appthreat" %% "dataflowengineoss" % "4.0.0"
```

Scala 3 artifacts compiled with 3.10 can only be read by a compiler of 3.10 or later. Scala 3.10
also drops auto-tupling, and `->` in `Predef` became an extension method, so
`node.has(Properties.CODE -> code)` no longer builds a property. Use the two-argument form,
`has(Properties.CODE, code)`, or `Properties.CODE.of(code)`; overflowdb2 3.1 restores `->` for
property keys where `overflowdb.*` is imported.

The schema of the graph is unchanged (see [cpg2](cpg2.md)), and so is the format of saved graphs
(see [overflowdb2](overflowdb2.md)).

## Data-flow engine

### Flux is the default solver

`OssDataFlowOptions.useFluxEngine` now defaults to `true`, so the `dataflowOss` layer computes
reaching definitions with `FluxReachingDefPass`, the low-allocation worklist solver, instead of
`ReachingDefPass`. Both build the same problem and produce identical `REACHING_DEF` edges; Flux
uses much less memory and garbage collection time on large methods such as bundled JavaScript.
atom already used Flux by default. To keep the classic solver:

```scala
new OssDataFlow(new OssDataFlowOptions(useFluxEngine = false)).run(new LayerCreatorContext(cpg))
```

The other defaults are unchanged: `maxNumberOfDefinitions = 4000`, `maxNumberOfCfgNodes =
50000`, and `EngineConfig(maxCallDepth = 3, useSummaries = false, ...)`. The
[engine comparison](../FLOW_ENGINE_COMPARISON.md) explains both solvers and flow summaries.

### More passes in the data-flow layer

After reaching definitions and `StaticMemberDefUsePass`, the layer now runs
`GlobalVariableDefUsePass` and `MemberDefUsePass`. They add `REACHING_DEF` edges between methods
for C and C++ globals (`VARIABLE` is the global's name) and struct members (`<owner>.<member>`),
which per-method reaching definitions cannot see. Both do nothing on graphs of other languages.
Code that relies on pass indices in `runPass` sees them shift.

### The default semantics are language neutral

`DefaultSemantics()` used to include the C library flows for every graph. A summary keyed on a
bare name then applied to a same-named function in any language, so the C flows are now added
per graph:

- `DefaultSemantics()` is `operatorFlows ++ javaFlows`.
- `DefaultSemantics.flowsForLanguage(language)` returns the flows for one language: `cFlows` for
  C and NEWC, `phpFlows` for PHP, request-reader flows for JVM languages and `javaScriptFlows`
  for JavaScript.
- `OssDataFlow` adds `flowsForLanguage` for the graph's language itself.
- `DefaultSemantics.cSemantics()` is the full C set, `operatorFlows ++ javaFlows ++ cFlows`.
  `phpSemantics()` no longer includes the C flows.

If you build an `EngineContext` with your own `Semantics` for a C or C++ graph, add the C flows:

```scala
given Semantics = DefaultSemantics.cSemantics()
// or, for any language:
given Semantics = Semantics.fromList(
  DefaultSemantics().elements ++ DefaultSemantics.flowsForLanguage(cpg.metaData.language.head))
```

`EngineContext`'s default semantics, and the default arguments of `ddgIn` and `ddgInPathElem`,
are now `DefaultSemantics.memoised`, one shared lazily built instance instead of a new one per
call. It must not be mutated, except by `loadRegexSemantics`, which the engine calls itself.

### Operator and library flows

- **Value operators** pass taint from each operand to the result only, not between operands:
  subtraction, multiplication, division, exponentiation, modulo, shifts, bitwise and logical
  operators, comparisons, `not`, `minus` and `plus`. Addition keeps its old, permissive flows, so
  string concatenation still carries taint. Queries that relied on taint moving between the
  operands of a comparison find fewer flows.
- `<operator>.pointerToMember` and `<operator>.indirectPointerToMember` pass their base to the
  result. `alignOf`, `typeId`, `parameterPackSize` and `noexcept` carry no flows.
- The C flows are much larger: the C library (copying, reading, formatting, allocation), the
  FORTIFY `__*_chk` wrappers, `__builtin_*` spellings, clamping macros such as FFmpeg's `FFMIN`,
  and resolved C++ constructors and operators.
- JavaScript template operators (`<operator>.formatString`, `interpolation`, `jsxProps`) read
  their arguments without redefining them, and a JavaScript implicit `this` receiver is not a
  definition.

### Argument binding

`io.shiftleft.semanticcpg.utils.ArgumentBinding` binds arguments to parameters the way each
language does: by position, by keyword, through `*args`/`**kwargs`, spreads, splats and
variadics. `Signature.of(method)` describes a method's parameters, `argumentsBinding(call, param)`
returns the arguments that bind to a parameter, and `parametersBound(arg, params)` the parameters
an argument binds to. Python positional-only and keyword-only parameters are tagged
`parameter-kind`.

These steps now use it instead of matching `argumentIndex` with the parameter index:
`MethodParameterTraversal.argument`, `MethodParameterOutTraversal.argument`,
`ExpressionMethods.parameter`, and the engine's argument-to-parameter task creation. Their
signatures are unchanged, but results differ for Python, PHP, Ruby, JavaScript and C variadic
calls. `MethodParameterTraversal.argument` now considers only `Call` call sites.

### Other engine changes

- `FlowSummaryComputer.computeAll` writes one summary per method full name, preferring the method
  with a body (a C or C++ definition over its prototype).
- Failures of the engine and of starting points are logged as warnings instead of being dropped.
- `reachableByFlows` uses sets for membership checks and `DdgGenerator` can share a cache across
  methods (`DdgSharedCache(sharedAcrossMethods = true)`); the flows are the same.

## Shared frontend library (x2cpg)

| Change | Notes |
|---|---|
| `X2CpgConfig.externalPaths`, `withExternalPaths(regex)`, `--external-paths` | Marks vendored code external in every source frontend. `ExternalPathsPass.applyTo(cpg, pattern)` and `ExternalPathMatcher` can be used directly. |
| `Ast` has `taggedByEdges` and `withTaggedByEdge(src, dst)` | Frontends attach tags while building the AST. The new parameter has a default, so source code compiles, but positional pattern matches on `Ast(...)` and binary compatibility break. |
| `FunctionPointerCallLinker` | Part of `CallGraph.passes`; adds `CALL` edges for C function pointers. |
| `InternalLinkage`, `RubyCallLinker` | Internal linkage for C statics and C++ unnamed namespaces; callee names for Ruby project methods. |
| `SourceDecoding`, `UnicodeSkeleton`, `SourceIntegrityPass` | Source decoding by byte-order mark, and the Unicode integrity tags. |
| `Scope.snapshot` and `restore` | Save and restore a frontend's scope stack. |
| `AstFragment.CacheRevision`, `AstFragment.NewNodeProperties` | Fragment cache key revision and the property reader for overflowdb2's fragment codec. |
| `ExternalCommand.runWithResult(..., timeoutMillis, extraEnv)` | Timeouts that kill the process tree, and extra environment for the child. |
| `DdgGenerator(semantics, sharedCache)` | New constructor parameter with a default. |

### The memory-safety overlay for C and C++

The memory-safety overlay for C and C++ is a set of library passes in
`io.appthreat.x2cpg.passes.taggers`, run in this order: `MemorySemanticsPass`, `MemoryApiPass`,
`ExtentPass`, `GuardPass`, `ValueOriginPass`, `IntegerWidthPass`, `AllocationStatePass` and
`MemorySafetyFindingPass`. They read the facts the C frontends record and the API vocabulary in
`memory-apis.json`, and report findings as `ms-finding` tags with a rule id. chen's frontends do
not run them; the caller does. atom's `memory-safety` command runs them and writes the findings
as JSON or SARIF.

A finding names a rule, a CWE and a confidence. The deallocation rules are `MS-ALLOC-001` (CWE-415,
double free), `MS-ALLOC-002` (CWE-416, use after free), `MS-ALLOC-003` (CWE-401, leak),
`MS-ALLOC-004` (CWE-1341, double close of a `file`-stream or `fd`-descriptor handle),
`MS-ALLOC-005` (CWE-590, free of non-heap storage), `MS-ALLOC-006` (CWE-761, free of an offset
pointer) and `MS-ALLOC-007` (CWE-762, mismatched deallocation), beside the `MS-BOUND-*`,
`MS-INT-*` and other families the finding pass documents. Each rule carries a default confidence;
where the evidence makes a weaker claim, the finding reports below it: a use after a region reset,
after a zero-reaching release, a use of a block a destroy may
not have reached, and a block stored into storage that outlives a scope whose cleanup releases it,
all report at `medium`, while the use after a borrowed release reports at `low`. The leak rule
itself reports at `low`.

#### Where the knowledge comes from

`MemorySemanticsPass` concludes from three kinds of evidence, never from a function's name:

- Declared attributes, which c2cpg records as `fn-attr` tags from the GCC attribute syntax:
  `malloc` names a heap allocator whose result may be NULL, `alloc_size(i)` and `alloc_size(i, j)`
  name the size arguments, `malloc(dealloc[, i])` names the matching free of argument i,
  `returns_nonnull` rules the NULL result out, `nonnull(i, ...)` says the function reads through
  argument i, and `access(read_only|write_only|read_write, ptr[, size])` gives the src, dst and
  size roles. This is how a header states the semantics of a library whose bodies sit outside the
  analysed tree.
- Bodies, iterated to a bounded fixpoint so a wrapper of a wrapper chains: allocators, free
  wrappers, destroy functions, offset families, region allocators and reference releases, each
  described under its allocation style below. A name-level guess remains for `void f(void *)`
  functions spelled like `free` with no body in scope; every finding resting on one reports at
  `low`.
- The declared inventory in `memory-apis.json`, one entry per API with the roles of its arguments,
  plus the library profiles described below. A declared entry always wins over a conclusion; the
  compiler builtins (`__builtin_memcpy`) are derived from the entries automatically.

#### Scope cleanup

Both C frontends read the GCC `cleanup` attribute off a variable's declarator, however a macro
spells it, and place a call to the attribute's function at every exit of the variable's scope:
where the block ends, before each `return` in the scope (a returned value is computed before the
cleanup call), and at a `goto`, `break` or `continue` that leaves it. Inner scopes release first,
and two cleanup variables of one scope release in reverse declaration order. The call is
`fn(&var)`, tagged `compiler-generated` and `lifetime-end` with the variable's name; c2cpg and
edg2atom emit the same shape, and a frontend comparison test pins the placement.

The allocation state treats that call as a release. A variable a cleanup call releases never
reports a leak (`MS-ALLOC-003`), wherever the variable's own value went. A variable already freed
and not reset that reaches its cleanup call is a double free, `MS-ALLOC-001` at `high`, reported
on the compiler-placed call; the hand-written free before it is neither the finding's line nor a
use after free.

```c
static void freep(void *pp) { free(*(void **)pp); }

int bad(int n)
{
    __attribute__((cleanup(freep))) char *buf = malloc(n);
    if (!buf) return -1;
    if (n > 4)
    {
        free(buf);
        return n;   /* MS-ALLOC-001, high, at the freep(&buf) call the scope exit places */
    }
    return 0;       /* no leak finding here: the cleanup releases buf */
}

int good(int n)
{
    __attribute__((cleanup(freep))) char *buf = malloc(n);
    if (!buf) return -1;
    if (n > 4)
    {
        free(buf);
        buf = NULL; /* the reset leaves the cleanup call nothing to release */
        return n;
    }
    return 0;
}
```

A method that returns a variable the cleanup goes on to release, or stores it into a field or
global that outlives the scope, hands the caller a dangling pointer. The method is summarised
`returns-freed`, so a caller's use of the result is `MS-ALLOC-002` at `high`; the store is
`MS-ALLOC-002` at `medium`. Such a method is never summarised as an allocator. Moving the value
out first, with a steal (below) or a copy, produces no finding.

#### Destroy functions

A method that frees its parameter on a path only the parameter's own NULL tests control
(`if (!p) return;`, `if (p == NULL) return;`, `if (p) { ... free(p); }`) is summarised as freeing
it. Beside the release it may free members of the parameter, directly or in a loop over a list,
call callees that neither free nor allocate, and assign to fields, provided it returns no value
and frees the parameter itself. A free through the pointee (`free(*pp)`) is the same release; a
wrapper that also stores NULL into `*pp` concludes the freep form, and the caller's slot is left
null instead of dangling. A free gated by any other condition, a flag or a counter, yields no
summary.

A call to a destroy function moves an argument the method tracks, one holding an allocation that
method can see (its own allocation, or a call summarised as allocating its result), to `freed`; a
later use of it is `MS-ALLOC-002` at `high` and a second call is `MS-ALLOC-001` at `high`. An
argument the method does not track, a bare parameter it only passes on, changes no state the
rules read.

```c
#include <stdlib.h>
#include <string.h>

struct acct { char *name; int id; };

static void acct_free(struct acct *a)
{
    if (!a) return;
    free(a->name);
    free(a);
}

int bad(void)
{
    struct acct *a = malloc(sizeof *a);
    if (!a) return -1;
    memset(a, 0, sizeof *a);
    acct_free(a);
    return a->id;   /* MS-ALLOC-002, high: a use after the destroy */
}

int good(void)
{
    struct acct *a = malloc(sizeof *a);
    if (!a) return -1;
    memset(a, 0, sizeof *a);
    int id = 0;
    if (a) id = a->id;
    acct_free(a);
    return id;      /* the value is read before the destroy: no finding */
}
```

#### Offset and header-prefix allocator families

A method whose every non-NULL value return is a known allocation advanced by one constant amount
is an allocator of a family named after it (`offset:<method>`), and a method that releases its
parameter moved back by the same amount is that family's free. The amount is normalised to bytes
where the types allow, so `h + 1` with `h` of struct type and `(char *)h + sizeof(*h)` are the
same amount, and the pair is matched through the amount and the underlying family, never through
names. A wrapper returning an allocation unchanged stays in the underlying family, so a release
of its result with the underlying free is correct and is not reported.

Within one method, a release of a pointer that arithmetic moved off its block's start is
`MS-ALLOC-006` at `high`, reported at the move: the release's own arithmetic, the identifier that
arithmetic produced, or the loop increment that walked the pointer forward. Two kinds of move
are not reported. A pointer moved back from a value whose definitions reach only parameters is how a
header-prefixed allocator frees its own block. A pointer moved back by exactly what advanced it
past an allocation in the same method (`p += 4; free(p - 4)`) is the block's own start. A release
whose family does not match the allocation's is `MS-ALLOC-007` at `high`.

```c
typedef struct { long size; } hdr_t;

void bad(void)
{
    char *p = malloc(64);
    free(p + sizeof(hdr_t));   /* MS-ALLOC-006, high: a release off the block's start */
}

void good(void *p)
{
    free((hdr_t *)p - 1);      /* the header-prefix free itself: moved back from a
                                  parameter, so no finding */
}
```

#### Declared library profiles

The inventory's `profiles` section declares the memory management of a library whose declarations
live in headers outside the analysed tree, so no body can be inferred. A profile has a name, the
headers that select it, and entries in the inventory's shape; every entry must cite a `source`,
the header and line or the documentation page that states its behaviour, and an entry without the
citation is dropped with a note. The built-in resource declares seven profiles:

| Profile | Selected by a translation unit including | Entries declare |
|---|---|---|
| glib | `glib.h`, `gmem.h`, `glib-object.h`, `gio/gio.h`, `gtk/gtk.h` | `g_new0` (heap, the element count is argument 2), `g_free` (heap; `g_free` is `free` on every platform glib supports), `g_steal_pointer` (steal), `g_autoptr_cleanup_generic_gfree` (the cleanup `g_autofree` attaches) |
| linux | `linux/slab.h`, `linux/kref.h`, `linux/gfp.h`, `linux/vmalloc.h`, `linux/device.h` | `kmalloc`, `kzalloc`, `kcalloc`, `kmalloc_array` (the `slab` family, released by `kfree`), `vmalloc` (the `vmalloc` family, released by `vfree`), `kvmalloc`, `kvzalloc` (the `kvmalloc` family), `kvfree` (releases all three families), `devm_kzalloc`, `devm_kcalloc` (region allocations owned by argument 1, the device), `kref_put` (releases the object of argument 1, calling the callback of argument 2 at zero) |
| postgresql | `postgres.h`, `utils/palloc.h`, `utils/memutils.h` | `palloc`, `palloc0` (the `pgmem` family, allocated from the `CurrentMemoryContext` global), `pfree`, `MemoryContextReset` (reset), `MemoryContextDelete` (destroy), `AllocSetContextCreate` (create) |
| apr | `apr_pools.h`, `httpd.h` | `apr_palloc` (the `aprpool` family, region argument 1), `apr_pool_create` (create through the out-pointer argument 1), `apr_pool_clear` (reset), `apr_pool_destroy` (destroy) |
| nginx | `ngx_core.h`, `ngx_palloc.h` | `ngx_alloc`, `ngx_free` (plain heap wrappers), `ngx_palloc` (the `ngxpool` family, region argument 1), `ngx_create_pool` (create), `ngx_destroy_pool` (destroy) |
| cpython | `Python.h`, `object.h`, `pymem.h` | `PyMem_Malloc`, `PyMem_Free` (the `pymem` family), `Py_DECREF` (release of argument 1), `Py_INCREF` (acquire of argument 1) |
| php | `php.h`, `zend.h`, `zend_API.h`, `zend_alloc.h`, `zend_string.h` | `emalloc`, `efree` (the `zendmm` request heap), `zend_string_release` (release of argument 1) |

The builtin descriptors are inventoried the same way: `open`, `openat`, `creat`, `socket`,
`accept`, `accept4`, `dup` and `dup2` allocate the `fd` family, released by `close` and
`closesocket`; `fopen`, `fdopen`, `freopen`, `tmpfile` and `opendir` allocate the `file` family,
released by `fclose` and `closedir`. A second close of either family is `MS-ALLOC-004` at `high`,
and a release of one family's handle with the other family's function (a `close` of a `FILE *`,
an `fclose` of a descriptor) is `MS-ALLOC-007` at `high`.

A translation unit selects a profile when its primary source file includes one of the profile's
headers, compared by basename: both frontends record each unit's includes as an `includes` tag on
the unit's FILE node, and `MemoryApiPass` selects from them. Precedence is fixed: an inventory
entry (built-in or external config) wins for the names it declares; a body in the analysed tree
wins over a profile entry of the same name, whatever the body says; a profile entry stands above
the name-level conclusions, which at best guess from a spelling; and a call the graph resolves to
a method is judged by that method's own body.

atom's `--memory-api-profiles <auto|none|name,name>` selects how units choose: `auto` (the
default) by the includes each unit carries, `none` turns profiles off, and a comma list forces
exactly those profiles onto every file, reporting a name no profile carries on stderr so a typo'd
list cannot analyse quietly as `none`. atom prints the profiles it followed, with a per-profile
file count, beside the function-summary counts the semantics pass prints, for example
`MemoryApiPass: memory-api profiles: cpython (2 files), linux (1 file)`.

A profile entry's roles land as the same tags a body-inferred conclusion would produce, so every
rule reads them without a second vocabulary. A release whose family does not match the allocation
the profile declares is `MS-ALLOC-007` at `high`:

```c
#include <pymem.h>

void bad(void)
{
    char *p = PyMem_Malloc(16);
    free(p);          /* MS-ALLOC-007, high: PyMem_Malloc memory goes back to PyMem_Free */
}

void good(void)
{
    char *p = PyMem_Malloc(16);
    PyMem_Free(p);    /* no finding */
}
```

#### Regions

A region is a pool, a context or a device: one handle owns every block handed out from it.
Inferred, a method whose every non-NULL value return is pointer arithmetic over a field of one
parameter, with no allocation behind the arithmetic, is a region allocator of that parameter; a
NULL return is the exhaustion arm and stays nullable, and a body that falls back to `malloc` when
the region is full records both the region and the heap summary. Declared, a profile entry names
one of four roles: `create` (the region is the call's result, or the out-pointer argument `arg`
names, as with `apr_pool_create(&pool, parent)`), `allocate` (the region is the argument at `arg`,
or the named `context` global, which is how `palloc` reads PostgreSQL's `CurrentMemoryContext`),
`reset` (the region keeps, its blocks go), and `destroy`.

The state a region allocation carries is its region, matched by the same local, parameter or
global name only; a copy of the handle under another name matches nothing. Region memory is never
reported as a leak: the region's destroy is its release, wherever the handle is held. A destroy
moves every pointer allocated from the same region in the method to `freed`, and a reset moves
them to `maybe-freed`. A use after an unconditional destroy is `MS-ALLOC-002` at `high`; a use
after a reset (or after a destroy that may not have reached the block) is the weaker claim,
`MS-ALLOC-002` at `medium`. A heap free of region memory is a wrong deallocation: `MS-ALLOC-005`
at `high` where the allocator declares only the region role, `MS-ALLOC-007` at `high` where the
allocator also carries a family and the comparison decides, so `pfree` of `palloc` memory is
correct while `pfree` of `malloc` memory and `free` of pool memory are mismatches.

```c
#include <apr_pools.h>
#include <string.h>

int bad(apr_pool_t *pool)
{
    char *p = apr_palloc(pool, 32);
    memset(p, 0, 32);
    apr_pool_destroy(pool);
    return p[0];   /* MS-ALLOC-002, high: a use after the pool's destroy */
}

int good(apr_pool_t *pool)
{
    char *p = apr_palloc(pool, 32);
    memset(p, 0, 32);
    int first = p[0];
    apr_pool_clear(pool);  /* the block goes with the reset, the pool stays */
    return first;          /* no finding, and no leak either: the region owns the block */
}
```

#### Declaring in-house APIs

atom's `--memory-api-config` passes a JSON file of the same schema as `memory-apis.json` to the
overlay. Its `apis` array is merged over the built-in inventory by API name, an external entry
replacing the built-in entry of the same name, and its `profiles` array is merged by profile name,
an external profile replacing a same-named built-in one wholesale. An unreadable document is
reported on stderr and ignored rather than failing the run, and an unreadable entry inside a
readable document is dropped with its own note; every declared-role field is optional, so an
existing configuration file still decodes. Two family names changed when sockets and files were
split by handle type: a `socket` family in an existing file is read as `fd`, and an entry that
declared an integer-descriptor function with the `file` family must now say `fd`, or a `close` of
its result is reported as a mismatch. A `free` may list several families for a release that accepts
blocks of each, as `kvfree` does: `"free": ["slab", "vmalloc", "kvmalloc"]`.

The declared roles a profile entry (or a plain entry) can carry beside the long-standing ones are
`release` and `acquire` (the 1-based index of the argument whose reference count the call drops or
takes), `retains` (the argument whose resource the call's result takes over, as `fdopen` takes its
descriptor), `steal` (the pointer-to-pointer argument the call empties and returns), `cleanup`
(true for a function that takes the address of a variable and releases what it points to), and
`region` with one of the four roles above. The vocabulary validates what nothing in the analysed
tree can confirm: a role index must be a number 1 or greater (a quoted number is a string and is
rejected), a `region` allocate names exactly one of `arg` and `context`, a `create` names no
`context`, and every profile entry needs its `source` citation. A rejected entry is dropped with a
note naming it, and the rest of the file still applies. The `release`, `acquire`, `retains` and
`region` roles reach the call sites as tags; a declared `steal` moves the block out of the slot it
is handed the address of, as the body-inferred steal summary does, and a declared `cleanup`
function releases the block its argument points to, which is what the cleanup calls the frontends
place then do.

The document below declares a small in-house library and is exactly what `MemApiVocab` accepts;
the c2cpg test suite loads it from this page and asserts the roles decode to the indices shown,
so the example cannot drift from what decodes.

```json
{
  "version": 1,
  "apis": [
    {
      "name": "acct_new",
      "alloc": "acctmem",
      "len": 1,
      "nullableReturn": true,
      "source": "acct/core.h:41"
    },
    {
      "name": "acct_del",
      "free": "acctmem",
      "source": "acct/core.h:52"
    }
  ],
  "profiles": [
    {
      "name": "acct",
      "headers": ["acct/pool.h"],
      "entries": [
        {
          "name": "acct_pool_new",
          "region": { "role": "create", "arg": 1 },
          "source": "acct/pool.h:23"
        },
        {
          "name": "acct_pool_alloc",
          "region": { "role": "allocate", "arg": 1 },
          "len": 2,
          "nullableReturn": true,
          "source": "acct/pool.h:34"
        },
        {
          "name": "acct_pool_clear",
          "region": { "role": "reset", "arg": 1 },
          "source": "acct/pool.h:45"
        },
        {
          "name": "acct_pool_delete",
          "region": { "role": "destroy", "arg": 1 },
          "source": "acct/pool.h:56"
        },
        {
          "name": "acct_pool_get",
          "region": { "role": "allocate", "context": "acct_current_pool" },
          "len": 1,
          "source": "acct/pool.h:67"
        },
        {
          "name": "acct_unref",
          "release": 1,
          "source": "acct/object.h:70"
        },
        {
          "name": "acct_ref",
          "acquire": 1,
          "source": "acct/object.h:81"
        },
        {
          "name": "acct_take",
          "steal": 1,
          "source": "acct/object.h:92"
        },
        {
          "name": "acct_cleanup",
          "cleanup": true,
          "source": "acct/object.h:103"
        }
      ]
    }
  ]
}
```

A translation unit that includes `pool.h` (the basename decides, whatever path the include
spelled) selects the `acct` profile, and `--memory-api-profiles acct` selects it for every file.

#### Reference counting

For each variable the method tracks, the state counts the references the method owns: a new
allocation owns one, an acquire adds one, a release drops one. The declared roles are a profile's
`release` and `acquire`; the inferred twins conclude from bodies. An acquire is a method that
increments a counter field of its parameter (the `grow` conclusion, also emitted for a declared
`increments` fact). A release is a method that decrements a field of one parameter by one and,
under the condition that the field reached zero, releases the parameter itself: frees it, hands it
to a callee summarised as freeing it, or calls a function pointer it received as another argument,
which is the shape of the kernel's `kref_put(&o->refs, release)` with the container located
through the count field's address. A release gated by anything else, a flag or another variable's
comparison, concludes nothing, and so does a method that allocates or reads.

A release that reaches zero frees the object, and a use after it is `MS-ALLOC-002` at `medium`.
A release of a reference whose ownership the method does not know, a parameter, a field read or
an unsummarised call's result, leaves the object maybe freed, and a use after it is `MS-ALLOC-002`
at `low`. A second release below zero is `MS-ALLOC-001` at `medium`. An acquire of a freed object
is itself a use, reported at the level the release that freed it earns.

```c
/* acct_new, acct_unref and acct_ref are the declarations of the example configuration;
   acct_put and acct_get are inferred, concluded from their bodies. */

struct acct { int refs; int id; };

static void acct_put(struct acct *a)
{
    a->refs -= 1;
    if (a->refs == 0) free(a);
}

static void acct_get(struct acct *a)
{
    a->refs += 1;
}

int bad(void)
{
    struct acct *a = acct_new(sizeof(struct acct)); /* the method owns one reference */
    acct_unref(a);  /* the count reaches zero: freed */
    return a->id;   /* MS-ALLOC-002, medium: a use after the zero-reaching release */
}

int worse(void)
{
    struct acct *a = acct_new(sizeof(struct acct));
    acct_unref(a);  /* reaches zero: freed */
    acct_unref(a);  /* MS-ALLOC-001, medium: a second release below zero */
    return 0;
}

int borrowed(struct acct *a)
{
    acct_put(a);    /* a is a parameter: ownership unknown, so the release is the borrowed kind */
    return a->id;   /* MS-ALLOC-002, low */
}

int good(struct acct *a)
{
    acct_get(a);    /* the acquire and its matching release net out: no finding */
    acct_put(a);
    return 0;
}
```

#### What the overlay does not report

The cpython profile declares `Py_DECREF` as a release and `Py_INCREF` as an acquire; `Py_XDECREF`
and `Py_CLEAR` have no declared entries, because their NULL-guard and reset shapes are not
expressible as a plain release role, so releases written with them are not tracked. The selecting
headers are matched against a unit's own `#include` lines, not the headers those include in turn,
so a unit that reaches a library only through a header of its own selects no profile. A missing
reference release is not reported by design: the count model reports the uses after a release and
the second releases below zero, never an omission. A release does not compose through a wrapper: a
function whose body only calls the inferred releaser draws no summary, so the use after the
wrapper-spent reference draws no finding and the block still reads as live at the exit, reporting
the leak the wrapper actually released at `low`.

### New traversal helpers

- `TagTraversal.expression` and `TagTraversal.taggedNode`, to go from tags to what they tag.
- `TypeDeclTraversal.preferredDeclaration(decls)`, now used by `unravelAlias`, picks one
  declaration deterministically when several share a name.
- `MethodRefIndex.referencing(graph, methodFullName)` and `ImplicitReceiver` in the query engine.
- `GlobalScopeMethodNames` (`<module>`, `:package`) in `io.appthreat.dataflowengineoss`.

## Tags and properties

chen 4.0 adds no node or edge types; new facts are tags. The ones a consumer is most likely to
query:

| Tags | Written for | Meaning |
|---|---|---|
| `external-path` | methods in vendored paths | Marked external by `--external-paths` (type declarations get `IS_EXTERNAL` only). |
| `frontend` = `edg` or `cdt` | C/C++ `FILE` nodes | Which parser built the file. |
| `include-resolved-path`, `include-system` | C/C++ `IMPORT` | The header an include resolved to, and whether it is a system header. |
| `callee-declared-in`, `ref-declared-in`, `type-declared-in`, `constructs-type` | C/C++ calls, references, types | The header that declares what is used. |
| `macro-invocation`, `macro-parent`, `macro-origin`, `macro-argument-copy`, `nested-macro`, `macro-use` | C/C++ | Macro provenance. |
| `const-value`, `ptr-arith`, `ref`, `fn-attr`, `storage-class`, `object-size`, `pointee-size`, `flexible-member`, `capture`, `type-storage`, `alloc-form` | C/C++ | Facts for memory-safety analysis. |
| `implicit-conversion`, `virtual-call`, `default-argument`, `vla-size`, `compiler-generated`, `lifetime-end`, `asm-operand`, `asm-name`, `operator-call`, `template-instance` | C/C++, mostly from EDG | What the compiler resolved. |
| `unicode-confusable`, `unicode-bidi-control`, `unicode-hidden-code` | all | Unicode integrity findings. |
| `parameter-kind`, `lazy-import`, `sandbox-render`, `ai-model-artifact` | Python | Parameter kinds, PEP 810 lazy imports, template sandboxes, AI model loading. |
| `proxy-derived`, `trusted-proxy-config`, `trusted-proxy-headers`, `forwarded-header-read` | calls, five languages | Values derived from forwarded headers and the proxy trust settings. |
| `framework-data`, `predicate` and npm package URLs on sinks | JavaScript | Framework recognizers and package attribution. |
| `callsites-*` | JavaScript, Python, Java, PHP | Facts atom's callsites slice reads. |
| `memory-safety`, `ms-finding`, `ms-confidence` and `mem-*` | C/C++ | Written by the memory-safety overlay when it runs. |

The tag names are constants in `io.appthreat.x2cpg.Defines`, `io.appthreat.c2cpg.astcreation.Defines`
and the tagger objects in `io.appthreat.x2cpg.passes.taggers`.

## Caches

The AST cache key of each frontend changed (new parser options, lowering revisions, the
`astgen` engine, the fragment revision), so chen 4.0 does not replay caches written by 3.4; the
first run rebuilds them. `chen.cache.disabled`, `chen.cache.disabled.<kind>` and
`chen.cache.enabled.<kind>` still control caching, and the default cache directory is still
`<input>/.chen`.

## Removed

- c2cpg's `io.appthreat.c2cpg.parser.ParserConfig`; per-file settings now come from
  `ProjectSources`.
- The `generateScaladocs` build task and `project/SbtHelper.scala`.
- cpg2's `odb.forkjoinpass.explicitGc` system property.
