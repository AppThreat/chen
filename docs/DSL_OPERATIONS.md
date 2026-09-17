## Generic DSL operations

These operations can be chained on any traversal (including results from the [step methods](TRAVERSAL.md)) to filter, transform, sort, repeat, and combine results.

| Category            | Available operations                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Display / collect   | `.l`, `.head`, `.headOption`, `.last`, `.lastOption`, `.countTrav`, `.toJson`, `.toJsonPretty`                                                                     |
| Filter              | `.where(trav)`, `.whereNot(trav)`, `.filter(pred)`, `.filterNot(pred)`, `.not(trav)`, `.or(travs…)`, `.and(travs…)`, `.is(value)`, `.within(Set)`, `.without(Set)` |
| Dedup / sort        | `.dedup`, `.dedupBy(trav)`, `.sorted`, `.sortBy(trav)`                                                                                                             |
| Slice               | `.take(n)`, `.drop(n)`                                                                                                                                             |
| Transform           | `.collect(trav)`, `.collectAll[Typ]`, `.cast[Typ]`, `.sideEffect(trav)`                                                                                            |
| Combine             | `.union(travs…)`, `.choose(on)(cases…)`, `.coalesce(travs…)`                                                                                                       |
| Repeat / loop       | `.repeat(trav)`, `.maxDepth(n)`, `.until(cond)`, `.emit`, `.bfs`                                                                                                   |
| Flow (chen)         | `.passes(trav)`, `.passesNot(trav)`, `.passesThrough(pred)`, `.doesNotPassThrough(pred)`                                                                           |
| Path tracking       | `.enablePathTracking`, `.path`, `.simplePath`                                                                                                                      |
| Property predicates | `.where(_.property("key"))`, `.where(_.propertyOption("key"))`, `.has("key")`, `.hasNot("key")`                                                                    |

See [DSL_IN_DEPTH.md](DSL_IN_DEPTH.md) for what these operations do across the different language frontends, including verified examples and gotchas.

---

### Display / collect

```scala
// List all results (alias for toList)
atom.method.name("foo").l

// First / last element
atom.method.name("foo").head
atom.method.name("foo").headOption  // None if empty
atom.method.name("foo").last
atom.method.name("foo").lastOption

// Count without collecting
atom.method.name("foo").countTrav

// JSON output (engine auto-appends .toJson if omitted)
atom.method.name("foo").toJson
```

### Filter

```scala
// where / whereNot: filter by a nested traversal (keep elements where the traversal yields something / nothing)
// (.caller/.callee need a resolver in scope: given ICallResolver = NoResolve)
atom.method.where(_.caller).l                  // methods that have callers
atom.method.whereNot(_.caller).l               // methods without callers (unused)
atom.method.where(_.tag.name("framework-route")).l       // methods tagged as framework-route (target kinds differ per language, see DSL in depth)

// filter / filterNot: predicate-style filter using property values
atom.method.filter(_.isExternal == false).l    // internal methods only
atom.method.filterNot(_.name.matches(".*Test.*")).l  // exclude test methods

// not: keep elements where the inner traversal produces nothing (like whereNot)
atom.method.not(_.caller).l                    // methods with zero callers

// or / and: combine multiple conditions
atom.method.or(_.name("exec"), _.name("system")).l   // methods named exec OR system
atom.method.and(_.isExternal(true), _.name("auth")).l // external methods named auth

// is: filter by value (for narrowing to a node type use collectAll[Typ] or isCall etc.)
atom.method.name.is("exec").l

// within / without: match a set of values (takes a Scala Set)
atom.method.name.within(Set("exec", "system", "eval")).l
atom.method.name.without(Set("toString", "hashCode")).l
```

### Dedup / sort

```scala
// Remove duplicate results
atom.call.name("exec").dedup.l

// Dedup by a specific property
atom.call.dedupBy(_.code).l

// Sort (elements must be Comparable)
atom.literal.code.sorted.l

// Sort by a traversal
atom.method.sortBy(_.fullName).l
```

### Slice

```scala
// First n elements
atom.method.take(10).l

// Skip first n elements
atom.method.drop(100).take(50).l   // pagination: rows 101-150
```

### Transform

```scala
// flatMap: flatten a nested traversal (all callers of all methods)
atom.method.internal.flatMap(_.caller).l

// collect: apply a partial function, keeping only defined cases
atom.method.internal.collect { case m if m.name.endsWith("User") => m.fullName }.l

// collectAll: collect all elements of a given type
atom.annotation.collectAll[Literal].l   // all literals inside annotations

// cast: type-cast elements
atom.annotation.cast[Call].l       // treat annotation nodes as Call nodes

// sideEffect: do something without changing the stream (e.g., print debug info)
atom.method.internal.sideEffect(m => println(s"checking ${m.fullName}")).where(_.caller).l
```

### Combine

```scala
// union: merge results from multiple traversals
atom.method.name("exec").union(_.caller, _.callee).l

// choose: branch on the first value of a traversal, via a partial function
atom.method.internal.choose(_.name) {   // branch on the method name
  case "read"  => _.parameter.name     // if named "read" -> parameter names
  case _       => _.name               // otherwise -> the name itself
}.l

// coalesce: first traversal that yields a result
atom.method.coalesce(_.caller, _.callee, _.parameter).l
```

### Repeat / loop

```scala
// repeat a traversal n times (depth-first search by default)
atom.method.name("exec").repeat(_.caller)(using _.maxDepth(3)).l   // callers of callers of callers

// repeat until a condition is met
atom.method.name("main").repeat(_.caller)(using _.until(_.name("entryPoint"))).l

// limit depth (.times(n) still works but is deprecated for .maxDepth(n))
atom.method.name("main").repeat(_.caller)(using _.maxDepth(5)).l

// emit intermediate results
atom.method.name("main").repeat(_.caller)(using _.emit).l   // yields every level, not just deepest

// breadth-first search
atom.method.name("main").repeat(_.caller)(using _.bfs.maxDepth(10)).l
```

### Flow operations (chen-specific, for data-flow results)

```scala
// passes: keep flow paths where at least one element matches a traversal
flows.passes(_.collectAll[CfgNode].flatMap(_.method).name("executeQuery")).l

// passesNot: keep flow paths where NO element matches
flows.passesNot(_.collectAll[CfgNode].flatMap(_.method).name("escape")).l

// passesThrough: keep flows that pass through a node matching a predicate
flows.passesThrough(_.isCall).l

// doesNotPassThrough: exclude flows passing through a node matching a predicate
flows.doesNotPassThrough(n => n.isCall && n.asInstanceOf[Call].name.matches("escape|encode|sanitize")).l
```

`flows` above is a list of data-flow paths, obtained for example with
`val flows = atom.call.name("executeQuery").reachableByFlows(atom.method.parameter.nameExact("id")).l`.
The same operations apply to the flows that `atom reachables` and `atom data-flow` compute.

### Path tracking

```scala
// Track paths while traversing (enable before the steps you want recorded)
atom.method.name("main").enablePathTracking.repeat(_.caller)(using _.maxDepth(5)).path.l

// simplePath: only paths without repeated nodes
atom.method.name("main").enablePathTracking.repeat(_.caller)(using _.maxDepth(5)).simplePath.path.l
```

### Property predicates (alternate filtering syntax)

```scala
// has / hasNot: check property existence
atom.method.has("SIGNATURE").l               // methods with a signature property
atom.method.hasNot("SIGNATURE").l            // methods without one

// property / propertyOption: access property values
atom.method.where(_.property("FULL_NAME").filter(_.matches(".*exec.*"))).l
```
