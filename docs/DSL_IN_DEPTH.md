# The traversal DSL in depth

[TRAVERSAL.md](TRAVERSAL.md) lists the node types and their steps, and [DSL_OPERATIONS.md](DSL_OPERATIONS.md) gives a quick tour of the generic operations you can chain onto any traversal. This page goes further. It explains how the DSL is put together, covers the operations that only matter once you write non-trivial queries, and records how the same operation behaves across the frontends chen ships. Every example and every gotcha below was executed against small programs in Java, JavaScript, Python, PHP, Ruby, and C, analysed with the atom CLI and queried through the console, so what you read here reflects the current frontends rather than an idealised model of them.

## Where these queries run

Interactive queries run inside the chennai console. When you open an atom there, the console embeds a real Scala 3 REPL with the chen DSL already imported and the open atom bound to the name `atom`. Anything you type after that is ordinary Scala, so the full language is available: local `val`s, pattern matching in `map` and `collect`, and every step documented here. Queries typed as bare expressions are normalised to end in `.toJson` when the engine needs JSON, but you are free to end them in `.l` or `.p` yourself.

Two implicits matter for the steps on this page. The data-flow engine needs an `EngineContext`, which the console installs for you. The call graph steps need an `ICallResolver`, which the console does not install, so add one line before using `caller`, `callee`, or the parameter-mapping steps. If you embed chen in your own program, bring both yourself:

```scala
import io.shiftleft.semanticcpg.language.*
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.queryengine.EngineContext

given EngineContext  = EngineContext()   // preinstalled in the console
given ICallResolver = NoResolve          // add this line in the console too
```

The `atom` CLI itself is a batch tool with six subcommands (`parsedeps`, `data-flow`, `usages`, `reachables`, `export`, `algorithms`) and no query parser of its own. When you pass `--sink-filter` to `atom data-flow` or `--source-tag` to `atom reachables`, you are configuring the same traversals described here, executed for you. The console is where you write new ones.

## How the DSL is layered

A traversal has three layers, and knowing which layer a step comes from tells you where to look when something surprises you.

The bottom layer is the generic traversal library in overflowdb2. It provides operations that work on any iterator of graph elements: `where`, `union`, `choose`, `repeat`, `dedup`, `sortBy`, path tracking, and the terminal steps. This layer knows graphs in the abstract but nothing about code.

The middle layer is generated from the CPG schema in cpg2. Every node type gets property steps (`name`, `fullName`, `lineNumber`, `argumentIndex`, and friends) and raw edge steps (`_astOut`, `_cfgIn`, `_callOut`, `_reachingDefIn`, one pair per edge type). Property steps come in families: a string step `name(pattern)` treats its argument as a regular expression, `nameExact("Foo")` compares literally and uses the property index, and `nameNot(pattern)` negates. Integer steps grow comparison variants, so `lineNumber` also exists as `lineNumberGt`, `lineNumberGte`, `lineNumberLt`, and `lineNumberLte`, and `argumentIndex` as `argumentIndexGt` and so on. The indexed exact variants are much faster than regex filtering on large graphs, so prefer `nameExact` when you know the literal.

The top layer is chen's semanticcpg and dataflowengineoss modules, hand-written on top of the generated code. This is where `method.parameter`, `call.argument`, `method.caller`, `method.body`, `identifier.refsTo`, `cfgNext`, and the whole data-flow surface live. These steps encode meaning: `parameter` follows AST plus parameter-link edges so you get the declared parameter rather than an AST child that happens to have the same label.

One fact about the bottom layer shapes everything else: a traversal is a plain Scala `Iterator`, lazy and single-use. Materialise with `.l` when you want to look at a result twice.

```scala
// The iterator is consumed by the first terminal:
val methods = atom.method.internal   // Iterator[Method], lazy
println(methods.size)                // 3
println(methods.name.l)              // List(): already exhausted

// Make a fresh traversal per use, or store the list:
val names = atom.method.internal.name.l
```

This is the most common silent failure in practice. A query that returns nothing often reuses an exhausted iterator somewhere. In this codebase's own taggers, traversals are re-created per use for exactly this reason.

## Terminal steps and rendering

`l`, `head`, `headOption`, `last`, `lastOption`, `size`, and `countTrav` do what you expect. Note the difference between `size` and `countTrav`: the first returns a number immediately, the second stays inside the DSL by yielding a single-element traversal, which lets you keep chaining.

For other shapes: `b` gives a mutable buffer, `s` a lazy `LazyList`, `jl` a `java.util.List` for interop, `toSetMutable` and `toSetImmutable` give sets. `iterate()` drains the traversal when you only care about side effects such as accumulating into an external structure.

Aggregation lives in `groupBy`, `groupMap`, `groupMapReduce`, and `groupCount`, all of which execute immediately and return Scala maps:

```scala
// Which calls appear how often in the JavaScript atom:
atom.call.name.groupCount.toList.sortBy(-_._2)

// Methods grouped by file, Java atom:
atom.method.internal.groupBy(_.filename).view.mapValues(_.size)
```

Ordering and deduplication come as `dedup`, `dedupBy(f)`, `sorted`, and `sortBy(f)`. The first two return traversals you can keep chaining; the last two return sorted `Seq`s because sorting is a terminal operation. A useful pairing on bundled or generated code is `dedupBy` on `code` or `methodFullName`, where hundreds of identical nodes are common.

Two steps help you understand a slow query. `.profile("name")` prints the element count and wall time of the segment it wraps. `.help` prints the documented steps available for the element type at that point in the chain. In the console `help` needs one extra line because its search packages are a given, and it needs the reflections library on the classpath, which the chennai distribution ships:

```scala
given overflowdb.traversal.help.DocSearchPackages =
  overflowdb.traversal.help.DocSearchPackages("io.shiftleft", "io.appthreat")

atom.method.help   // table of steps for Method, with descriptions
```

Rendering: `.p` pretty-prints each element (for a method you get the signature; for a literal its code), and `.toJson` and `.toJsonPretty` serialise full node properties. The related `.t` step is documented as tabular output but in this version computes the representation and prints nothing, so prefer `.p` or `.l`. For flow results, which are `Path` values rather than nodes, the readable form is `resultPairs()`, shown later in this page.

## Property steps and property predicates

The generated property steps are the fast path. On top of them sit the generic element steps, which work on any node and read properties dynamically by name:

```scala
atom.method.has("SIGNATURE")            // property exists
atom.method.hasNot("SIGNATURE")         // property absent
atom.call.property("METHOD_FULL_NAME")  // values as a traversal, nulls dropped
atom.call.propertyOption("LINE_NUMBER") // Traversal[Option[Integer]]
atom.call.head.propertiesMap            // Map[String, Object] of everything
atom.call.label                         // the node label, e.g. "CALL"
atom.call.id                            // the graph id, useful for dedup across queries
```

`has` and `hasNot` accept predicates built with `P`, which is how you push string matching into the filter without a `where`. The predicate form keys on a typed `PropertyKey` rather than a property name string:

```scala
import overflowdb.{PropertyKey, PropertyKeyOps}
import overflowdb.traversal.filter.P

val FullName = new PropertyKey[String]("FULL_NAME")

atom.method.has(FullName.where(P.matches(".*getUser.*"))).fullName.l
atom.method.hasNot(FullName.where(P.matches(".*<operator>.*"))).name.l
// (P.eq is ambiguous with AnyRef.eq in Scala 3, so prefer matches, within, or neq)
```

`P` provides `eq`, `neq`, `within`, `without`, and `matches` (single regex or several). The `within`/`without` forms pair with the traversal steps of the same name, which take a `Set`:

```scala
atom.method.internal.name.within(Set("getUser", "greet")).l
atom.method.internal.name.without(Set("getUser", "greet")).l
```

A subtlety worth knowing before it bites: the generic numeric filter steps (`greaterThan`, `greaterThanEqual`, `lessThan`, `lessThanEqual`, `equiv`, `between`, `inside`, `outside`) are not in scope by default, and the generated steps return `java.lang.Integer`, for which no Scala `Numeric` instance exists. Prefer the generated comparison steps, and if you need the generic ones, convert and import:

```scala
atom.call.lineNumberGte(15).lineNumberLt(25).code.l   // works everywhere

import overflowdb.traversal.ChainedImplicitsTemp.toNumericTraversal
atom.call.lineNumber.map(_.toInt).greaterThan(15).l   // generic steps, after conversion
```

## Walking the structure

AST navigation is `astChildren`, `astParent`, `astSiblings`, `parentBlock`, and `ast`, which is the whole subtree including the starting node (`astMinusRoot` excludes it). `inAst(root)` restricts the walk to a given subtree, and `depth` measures AST depth, which is handy for finding deeply nested generated code.

The type difference between AST nodes and CFG nodes is the first structural surprise. `astChildren` yields `AstNode`, which is deliberately general: a method's children include parameters, modifiers, annotations, the body block, and the return node. Control-flow steps only exist on `CfgNode`, so going from an AST walk to a CFG walk needs a narrowing step, of which there are two kinds:

```scala
// Narrowing steps that filter by label, e.g. isCall, isLiteral, isMethod:
atom.method.body.astChildren.isCall.name.l

// Or the generic type filter:
atom.method.body.astChildren.collectAll[CfgNode].cfgNext.code.l
```

The CFG layer gives you `cfgNext` and `cfgPrev` (with an optional hop count), `controlledBy` and `controls` for conditions, and the dominator relations `dominates`/`dominatedBy` and `postDominates`/`postDominatedBy`. `method.cfgFirst` and `method.cfgLast` (also `method.methodReturn.cfgLast`) anchor a walk at the ends of a method, and `method.reversePostOrder` iterates a method's nodes in reverse post-order, the order the compiler-ish analyses prefer.

Control structures have named shortcuts on methods, one per construct: `ifBlock`, `elseBlock`, `switchBlock`, `tryBlock`, `forBlock`, `whileBlock`, `doBlock`, `goto`, `break`, `continue`, `throws`, plus the general `controlStructure(regex)` and the top-level starters `atom.ifBlock`, `atom.forBlock`, and so on for whole-graph queries. On the C probe:

```scala
atom.method.name("main").controlStructure.l.map(c => c.controlStructureType)
// List(IF)
```

Expressions add `parentExpression`, `expressionUp`, `expressionDown`, `inCall` (the call this expression is an argument of), `receivedCall`, and `isArgument`. The `argument` step on calls is the workhorse, and its indexing convention differs by language, which matters enough to get its own table in the next section.

## Arguments and receivers across languages

`call.argument` yields all arguments, `call.argument(i)` yields one, and `call.argumentOption(i)` yields an `Option`. The indexing scheme encodes the receiver, and each frontend fills slot zero differently.

| Language | Slot 0                                                     | First real argument | Observed example                                                              |
| -------- | ---------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------- |
| Java     | `this` or the receiver object                              | index 1             | `stmt.executeQuery(query)`: `argument(0)` is `stmt`, `argument(1)` is `query` |
| JS/TS    | `this`, or a compiler temp like `_tmp_1` for chained calls | index 1             | `require("child_process").exec(cmd, ...)`: `argument(0)` is `_tmp_1`          |
| Python   | receiver when the call is an attribute access              | index 1             | `cursor.execute(sql)`: `argument(0)` is `cursor`                              |
| PHP      | absent on plain calls                                      | index 1             | `file_put_contents($file, ...)`: first argument at index 1                    |
| Ruby     | `self` is a method parameter, not an argument slot         | index 1             | `where(...)` receives the string at index 1                                   |
| C        | no receiver slot exists                                    | index 1             | `system(cmd)`: `argument.code` is `List(cmd)`, `argument(1)` is `cmd`         |

Two consequences. First, `argument(0)` is not "the first thing the user wrote" in most languages, it is the receiver; user-written arguments start at 1. Second, `argument(i)` throws `NoSuchElementException` when no argument occupies that index, which on C's `system(cmd)` happens for index 0. In a query over many calls, use `argumentOption(i)` or filter first:

```scala
// Calls whose third argument (index 2) is present and a literal, safely:
atom.call.filter(_.argumentOption(2).exists(_.isLiteral)).code.l
```

## Logic and branching

`where(trav)` keeps elements for which the nested traversal, started from the element, yields something; `whereNot` and `not` (an alias) keep elements for which it yields nothing. `or(trav, trav, ...)` and `and(trav, ...)` generalise this to several nested traversals. Because the nested traversal restarts per element, these steps are the natural place to express "calls that reach a dangerous method" or "methods whose parameters carry an annotation":

```scala
// Spring handler parameters carry the web-input annotations:
atom.method.where(_.parameter.where(_.annotation.name("RequestParam|RequestBody"))).name.l
```

`union` concatenates the results of several traversals from the same point. `coalesce` evaluates traversals in order and keeps the first that yields anything, which is the standard way to prefer a precise fact and fall back to a coarse one. `choose` is the conditional branch and takes a traversal to branch on plus a partial function over what it finds; note that it branches on the first element of the traversal:

```scala
atom.method.internal.choose(_.name) {
  case "getUser" => _.parameter.name
  case _         => _.name
}.l
// List(<init>, this, id, greet): getUser contributes its parameter names,
// every other method contributes its own name
```

A correction to an older revision of the operations page: `is` filters by value, not by type. `atom.method.name.is("getUser")` keeps the name "getUser". To narrow by node type, use `collectAll[Type]` or the `isCall`/`isLiteral`/`isMethod` family. The `filter(pred)` and `filterNot(pred)` steps take a plain Scala boolean function, which is often the most readable option for conditions that do not deserve a nested traversal.

`sideEffect(fn)` runs a function per element without changing the stream, and `sideEffectPF` takes a partial function, applying it only where defined.

## Repeat, search order, and paths

`repeat` runs a traversal repeatedly and takes its configuration in a second argument list built from these options: `maxDepth(n)` caps iterations (the older name `times(n)` still works and means the same), `until(cond)` stops after an iteration whose results satisfy the condition, `whilst(cond)` stops before an iteration whose results would not, `emit` yields intermediate elements instead of only the final ones, `emitAllButFirst` is emit minus the starting elements, `emit(cond)` emits selectively, `breadthFirstSearch` or `bfs` switches from the default depth-first order, and `dedup` keeps a visited set so cycles cannot loop forever. Use `dedup` whenever you repeat over `caller`, `callee`, or `_cfgNext` walks, where cycles are normal.

```scala
// Ancestors of a method in the AST, all of them:
atom.method.name("getUser").repeat(_.astParent)(using _.maxDepth(2)).label.l
// List(NAMESPACE_BLOCK): only the element reached at the cap

atom.method.name("getUser").repeat(_.astParent)(using _.emit.maxDepth(2)).label.l
// List(METHOD, TYPE_DECL, NAMESPACE_BLOCK): every step along the way
```

The first result illustrates the trap. Without `emit`, `repeat` yields only elements that survive to wherever the walk stops, and when every branch dies out before the cap (common in data-dependency walks where chains simply end), the result is silently empty. The same walk with `.emit` returns the full ancestry. If a repeat query returns nothing and you expected something, add `emit` before you debug anything else.

Path tracking records where each result came from. Enable it with `enablePathTracking` before the steps you want recorded, read it with `path` (each result becomes the vector of elements visited), drop it again with `discardPathTracking` when you want to continue cheaper, and filter with `simplePath` to paths that visit no element twice:

```scala
atom.method.name("getUser")
  .enablePathTracking
  .repeat(_.astParent)(using _.maxDepth(2))
  .path.l
// List(Vector(METHOD, TYPE_DECL, NAMESPACE_BLOCK))
```

`path` throws if tracking was not enabled first, and steps added before `enablePathTracking` are not recorded.

## The call graph and the type layer

Chen's call graph extension gives methods `callee`, `caller`, `call` (outgoing call sites), and `callIn` (incoming call sites), and gives calls `callee` and `calledMethod`. They need an `ICallResolver` in scope, and with `NoResolve` they follow only the CALL edges the frontend and linker actually wrote, which is the honest view.

What you get out of them depends heavily on the frontend, because a call node carries a `methodFullName` the frontend may or may not have resolved. The observed resolution behaviour on identical "user input reaches a dangerous call" programs:

| Frontend                  | Example call                                                  | `methodFullName`                                                       | `callee`                                  |
| ------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------- |
| javasrc2cpg (Java source) | `stmt.executeQuery(query)`                                    | `java.sql.Statement.executeQuery:java.sql.ResultSet(java.lang.String)` | resolved, fully qualified                 |
| jssrc2cpg                 | `exec(...)` after `const { exec } = require("child_process")` | `child_process:exec`                                                   | resolved                                  |
| jssrc2cpg                 | `exec(...)` via `require("child_process").exec`               | `child_process`                                                        | resolved to the module-level stub         |
| pysrc2cpg                 | `cursor.execute(sql)`                                         | `<unknownFullName>`                                                    | empty: the receiver type was not inferred |
| pysrc2cpg                 | `app.route("/search")`, `Flask(__name__)`, `open(t)`          | `flask.Flask.route`, `flask.Flask.__init__`, `__builtin.open`          | resolved                                  |
| php2atom                  | `$request->input("q")`                                        | `<unresolvedNamespace>\$request->input`                                | unresolved namespace form                 |
| php2atom                  | `DB::select(...)`, `Route::get(...)`                          | `DB::select`, `Route::get`                                             | resolved, static call syntax              |
| c2cpg                     | `system(cmd)`                                                 | `system`                                                               | the external `system` stub                |

The practical rule: match on `call.name` when you want all calls with that name regardless of resolution, and on `call.methodFullName` when you need to know it is really the library call you think it is. For Python, where dynamic receivers often stay unresolved, name matching plus a tag or an argument-shape check is the reliable combination, and it is what the built-in taggers do.

The type layer has the same shape. `typeDecl.method`, `typeDecl.member`, `method.definingTypeDecl`, `typeDecl.baseTypeDecl` and `derivedTypeDecl` (with `Transitive` variants for full hierarchies), and the alias handling steps `isAlias`, `isCanonical`, `unravelAlias`, `canonicalType`, and `aliasTypeDecl`. Two cautions from the probes. `typeDecl` includes built-in types, so filter with `.internal` (or `isExternal(false)`) before counting declarations: the Java probe contained `ANY`, `int`, and `java.lang.Object` alongside the one real class, the JavaScript probe carried a whole `__ecma.*` family, and the C probe carried `char*` and `char[256]`. And on JVM graphs a `TypeDecl` may connect to its methods through `Binding` nodes when the frontend resolved the type's binding table; the probe's standalone file with no classpath produced none. Wherever bindings do appear, the typed accessor `binding.boundMethod` throws a `SchemaViolationException` when the binding's REF edge is missing, which happens for unresolved methods. Walk the raw edge instead when robustness matters, the same trick the built-in taggers use for method references:

```scala
// Safe binding walk (empty when the graph has none or the method is unresolved):
atom.typeDecl.internal
  .flatMap(_._bindingViaBindsOut)
  .flatMap(_._refOut.collectAll[Method])
  .fullName.l
```

## The data-flow surface

The data-flow steps turn the graph into a taint engine, and they are the reason most people open a console. The entry points hang off any `CfgNode` traversal: `reachableBy(sources...)` returns the source nodes that reach your sinks, `reachableByFlows(sources...)` returns full paths, and `df` is a short alias for `reachableByFlows`. The engine works backwards from sinks to sources, so the traversal you call these on is the sink side:

```scala
// Java probe: does web input reach the SQL query?
val sources = atom.method.name("getUser").parameter.nameExact("id").l
val sinks   = atom.call.name("executeQuery").l

sinks.reachableBy(sources).code.l
// List(@RequestParam("id") String id)

sinks.reachableByFlows(sources).l.map(_.resultPairs())
// List(List(
//   (getUser(this, @RequestParam("id") String id), Some(19)),
//   ("SELECT * FROM users WHERE id = '" + id + "'", Some(21)),
//   (stmt.executeQuery(query), Some(22))))
```

A `Path` is a list of `AstNode`s from source to sink. `resultPairs()` is the readable rendering, one `(code, line)` pair per element with duplicates collapsed. Single-element paths, where a node would be both source and sink, are dropped by the engine rather than reported.

On the results, the flow filters narrow by what a path touches. Their signatures matter and differ: `passes` and `passesNot` take a traversal function over `Iterator[AstNode]`, while `passesThrough` and `doesNotPassThrough` take a plain node predicate:

```scala
val flows = sinks.reachableByFlows(sources).l   // .l first: iterators are single-use

// Keep flows that pass through the search method (traversal form):
def inSearch(nodes: Iterator[AstNode]) =
  nodes.collectAll[CfgNode].flatMap(_.method).name("(?i)search")
flows.iterator.passes(inSearch).size

// Keep flows that pass through a call node (predicate form):
flows.iterator.passesThrough(_.isCall).size

// Drop flows neutralised by a sanitiser, e.g. an encode call seen anywhere on the path:
flows.iterator.doesNotPassThrough(n => n.isCall && n.asInstanceOf[Call].name == "encodeForHTML")
```

The `passesThrough` predicate form is the natural fit for sanitizer logic, and it is how the reachables pipeline applies validation configuration: sanitizer methods resolved from a chennai configuration file become node predicates, and flows through them are removed.

For one-step, semantics-aware backwards walks there is `ddgIn`, which follows data-dependency edges with the semantics layer applied (it knows, for instance, that a string builder's append moves its argument into its state). Combined with `repeat` and `emit` it makes an ad-hoc slice around a node:

```scala
// C probe: everything that feeds system(cmd), backwards, with the chain fully visible:
atom.call.name("system")
  .repeat(_.ddgIn)(using _.maxDepth(8).emit.dedup)
  .code.l
// List(system(cmd), cmd, cmd, "convert %s", user_input, const char *user_input)
```

Interprocedural behaviour is where the frontends differ most, verified with one input flowing through a helper into a dangerous call in each language.

| Frontend    | Source shape                                        | Result                                                                                                   |
| ----------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| javasrc2cpg | annotated parameter `id`                            | full flow through the string concatenation into `executeQuery`                                           |
| jssrc2cpg   | tagged call `req.params.host`                       | full flow through the template literal into `exec`                                                       |
| pysrc2cpg   | tagged call `request.args`                          | full flow into `cursor.execute`                                                                          |
| php2atom    | parameter `$request` or call `$request->input("q")` | both work, producing one flow each into `DB::select`                                                     |
| ruby2atom   | identifier `q` (assigned from `params[:q]`)         | full flow into `Item.where(...)`                                                                         |
| c2cpg       | identifier `query` in `main`                        | full flow across the `run_command(query)` call, through the parameter binding, `snprintf`, into `system` |
| c2cpg       | parameter `main.argv`                               | no flow: parameter sources were weaker than identifier sources in this probe                             |

The last two lines deserve emphasis because they contradict intuition. In the C probe, using `main`'s `argv` parameter as the source found nothing, while using the `query` identifier (or `argv` identifier) found the complete cross-function path, including the jump from the call argument in `main` to the `user_input` parameter in `run_command`. Interprocedural propagation itself works well; where you anchor the source decides whether the engine sees it. When a query that should find a flow does not, try anchoring the source one node later, on the identifier or call that actually carries the data, rather than on the declaration.

## Tags as a query vocabulary

Tag nodes are the bridge between framework knowledge baked in at generation time and your ad-hoc queries. Reading them goes both ways: from nodes (`method.tag.name("sql")`) and from tags (`atom.tag.name("framework-input").parameter`). The tag-side form has one step per target kind: `method`, `call`, `identifier`, `literal`, `parameter`, `local`, `member`, `methodReturn`, `file`.

What the tags mean depends on which tagger wrote them, and on a detail that is easy to miss: whether the atom was generated with data-flow enhancement. The plain `atom -l <lang> -o out.atom <dir>` generation runs only the family inventory taggers. Framework route and input tagging for JVM languages and Ruby runs during data-flow enhancement, which the `data-flow` and `reachables` subcommands imply and `--with-data-deps` requests explicitly. Verified behaviour:

| Frontend    | Plain generation                                                                                                                                     | With data-flow enhancement                                                                                                                                                       |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| javasrc2cpg | `sql` tags only                                                                                                                                      | adds `framework-input` on annotated parameters, `framework-route` with composed `route-path` values like `/api/user`, `http-method` GET/POST, `framework-output`, `flow-summary` |
| jssrc2cpg   | `framework-input` on calls like `req.params.host`, `framework-output` on `res.send`, `UNKNOWN_METHOD` and `UNKNOWN_TYPE_DECL` with structured values | unchanged plus `flow-summary`                                                                                                                                                    |
| pysrc2cpg   | `framework-input` on `request.args`, `framework-route` on handler methods, `route-path`, `sql`, `file-io`, `path-traversal`, `UNKNOWN_IMPORT`        | unchanged plus `flow-summary`                                                                                                                                                    |
| php2atom    | `framework-input` on route closure parameters and `$request->input` calls, `framework-output`                                                        | unchanged                                                                                                                                                                        |
| ruby2atom   | none                                                                                                                                                 | `framework-input` on `self` parameters of methods in files matching `.*controller.rb.*`                                                                                          |
| c2cpg       | `cli-source` on `main` argc/argv parameters                                                                                                          | unchanged                                                                                                                                                                        |

Three notes for query writers. First, the tag target kind differs by language (parameters for Java, calls for JavaScript, methods and calls for Python, both for PHP), so a source query that works against one frontend may need a different kind step against another; taking parameters, calls, and identifiers together, the way the reachables queries do, is the portable form. Second, Ruby's controller tagging keys on the filename, so a controller in a file not matching the pattern gets nothing, and its `framework-input` lands on `self`, which is a broad source; anchoring on the `params` access (an identifier like `q`) gives tighter flows. Third, the `UNKNOWN_METHOD`, `UNKNOWN_TYPE_DECL`, and `UNKNOWN_IMPORT` tags carry structured values describing what the frontend failed to resolve; they are diagnostics you can query, not noise, and `flow-summary` tags are the persisted per-method summaries that let the engine skip work on re-analysis.

## Conventions and hazards by frontend

The node naming conventions, verified on identical probe programs, are the reference you need before writing any cross-language query.

Method full names:

| Frontend    | Pattern                                                              | Examples                                                                                              |
| ----------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| javasrc2cpg | package.Type.method:ret(args), constructors are `<init>`             | `com.example.app.VulnController.getUser:java.lang.String(java.lang.String)`                           |
| jssrc2cpg   | file-relative with `::`, closures are `anonymous`, `anonymous1`, ... | `server.js::program`, `server.js::program:anonymous`, nested `server.js::program:anonymous:anonymous` |
| pysrc2cpg   | bare function names, module method named after the file              | `app`, `app.search`                                                                                   |
| php2atom    | file plus nesting, lambdas numbered                                  | `web.php:<global>`, `web.php:<global>-><lambda>0`                                                     |
| ruby2atom   | file, `<main>`, class, method; class body is `<body>`                | `app_controller.rb:<main>.AppController.search`                                                       |
| c2cpg       | bare function names, file-level scope is `<global>`                  | `run_command`, `main`, `cli.c:<global>`                                                               |

Structural conventions that regularly surprise:

In Python, imports lower to `import` calls with `methodFullName` `<unknownFullName>` plus assignments such as `sqlite3 = import(, sqlite3)`, builtin aliases (`open = __builtins__.open`) are hoisted to the top of the module, and a decorator application is a call node with an empty `name` whose `methodFullName` is the decorator (`app.route`), so `call.name("route")` finds the decoration while `call.methodFullName("app.route")` finds both. Decorators additionally appear as `Annotation` nodes on the decorated method, which is the cleaner handle.

In JavaScript, the top-level script is a method named `:program`, every closure is a `Method` (named `anonymous`, `anonymous1`, ...) with its own `TypeDecl`, template literals are calls named `<operator>.formatString` whose arguments include the interpolated values, and chained calls get synthetic receiver temporaries like `_tmp_1`. A call's `code` can span many lines, because an arrow function passed as an argument is part of the call's code; truncate before printing.

In Ruby, every `def` produces both a `Method` and a `TypeDecl` with the same full name (verified by `fullNameExact` round-trip), classes additionally get a `<class>` singleton `TypeDecl`, and class bodies execute in a `<body>` method. Counting "classes" via `typeDecl` will therefore count methods too unless you filter.

In PHP, string concatenation is `<operator>.concat`; in Java, JavaScript, Python, and Ruby the same source shape lowers to `<operator>.addition`. Array and hash subscripting is `<operator>.indexAccess` in PHP and Ruby, `<operator>.indirectIndexAccess` in C.

In C, system headers parsed from the compiler's include paths appear as `File` nodes with absolute SDK paths, and an `<includes>:<global>` method collects prelude content, so `atom.file` and `atom.method` on real projects are larger than your source tree. The same applies milder elsewhere: JavaScript gets a `builtintypes` file, Python a placeholder named `N/A`, and several frontends a `<unknown>` file. Filter `file.name` by your project root when counting.

Finally, `atom.method` includes external stub methods (one per known library or operator signature, without line numbers). This is visible in a single query: `atom.method.hasNot("LINE_NUMBER").name.l` returns the operator and library stubs, not your code. Prefer `.internal` or `.external` on both `method` and `typeDecl` before any counting or sampling, which is also why `atom.method.internal` appears in nearly every example on this page.

## One question, six languages

To close, the same security question against every frontend: can framework input reach a dangerous call? These queries ran against the probe programs and produced the flows shown.

```scala
// Java (Spring): annotated parameter to SQL.
val src = atom.method.name("getUser").parameter.nameExact("id").l
atom.call.name("executeQuery").reachableByFlows(src).l.map(_.resultPairs())

// JavaScript (Express): route params/body to process execution.
val src = atom.identifier.name("(target|cmd)").l   // or the tagged calls:
// val src = atom.tag.name("framework-input").call.l
atom.call.name("exec").reachableByFlows(src).l.map(_.resultPairs())

// Python (Flask): request argument to SQL.
val src = atom.tag.name("framework-input").call.l   // the request.args call
atom.call.name("execute").reachableByFlows(src).l.map(_.resultPairs())

// PHP (Laravel): request input to DB::select.
val src = atom.tag.name("framework-input").call.l   // $request->input("q")
atom.call.name("select").reachableByFlows(src).l.map(_.resultPairs())

// Ruby (Rails): params to where-clause string interpolation.
val src = atom.identifier.nameExact("q").l
atom.call.name("where").reachableByFlows(src).l.map(_.resultPairs())

// C (CLI): argv to system, across function boundaries.
val src = atom.identifier.nameExact("query").l
atom.call.name("system").reachableByFlows(src).l.map(_.resultPairs())
```

The Java, JavaScript, PHP, and Python versions anchor on framework tags, which those frontends write at generation time. The Ruby version anchors on an identifier because its controller tag sits on `self`. The C version anchors on the identifier that carries the data rather than on the `argv` parameter, because that is where the engine finds the definition. Same operation, six dialects, and knowing which anchor holds for which frontend is most of what separates a query that works from one that silently returns nothing.

## Sharp edges, collected

These are the failure modes observed while producing this page, in rough order of how often they seem to bite.

Traversals are single-use iterators. Reusing one silently yields nothing; materialise with `.l` or rebuild the chain.

`repeat` without `emit` yields only what survives to the stopping point, and nothing at all when branches die out first. Add `.emit` before suspecting your logic.

`call.argument(i)` throws when the index is unoccupied, which differs by language because slot zero is the receiver in some frontends and absent in C. Use `argumentOption(i)` inside `filter`.

`binding.boundMethod` and `methodRef.referencedMethod` throw when their REF edge is missing on unresolved nodes. Walk `_refOut.collectAll[Method]` when a query must survive missing links.

Generic numeric steps need `import overflowdb.traversal.ChainedImplicitsTemp.toNumericTraversal` and Scala numeric element types; generated steps like `lineNumberGt` avoid both problems.

`.is` compares values. Type narrowing is `collectAll[T]` or the `isCall` family.

CFG steps need `CfgNode`; after an AST walk, narrow with `isCfgNode`, `isCall`, or `collectAll[CfgNode]` before `cfgNext` and friends.

`count`, `size`, and `.p` consume; if you want to inspect and continue, materialise a list first.

`.toJson` relies on json4s, which the chennai console ships but a bare atom CLI classpath does not; in your own JVM embedding add it or serialise with your own library.

Framework tags for JVM languages and Ruby only exist when the atom was generated with data-flow enhancement (`--with-data-deps`, or the `data-flow` and `reachables` subcommands). A plain `atom -l ...` generation will not have them, and no query can recover what was never written.
