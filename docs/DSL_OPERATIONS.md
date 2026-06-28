## Generic DSL operations

These operations can be chained on any traversal (including results from the [step methods](TRAVERSAL.md)) to filter, transform, sort, repeat, and combine results.

| Category            | Available operations                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Display / collect   | `.l`, `.head`, `.headOption`, `.last`, `.lastOption`, `.countTrav`, `.toJson`, `.toJsonPretty`                                                                     |
| Filter              | `.where(trav)`, `.whereNot(trav)`, `.filter(pred)`, `.filterNot(pred)`, `.not(trav)`, `.or(travs…)`, `.and(travs…)`, `.is(typ)`, `.within(vals)`, `.without(vals)` |
| Dedup / sort        | `.dedup`, `.dedupBy(trav)`, `.sorted`, `.sortBy(trav)`                                                                                                             |
| Slice               | `.take(n)`, `.drop(n)`                                                                                                                                             |
| Transform           | `.collect(trav)`, `.collectAll[Typ]`, `.cast[Typ]`, `.sideEffect(trav)`                                                                                            |
| Combine             | `.union(travs…)`, `.choose(cases…)`, `.coalesce(travs…)`                                                                                                           |
| Repeat / loop       | `.repeat(trav)`, `.times(n)`, `.until(cond)`, `.maxDepth(n)`, `.emit`, `.bfs`                                                                                      |
| Flow (chen)         | `.passes(trav)`, `.passesNot(trav)`, `.passesThrough(trav)`, `.doesNotPassThrough(trav)`                                                                           |
| Path tracking       | `.enablePathTracking`, `.path`, `.simplePath`                                                                                                                      |
| Property predicates | `.where(_.property("key"))`, `.where(_.propertyOption("key"))`, `.has("key")`, `.hasNot("key")`                                                                    |

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
// where / whereNot — filter by a nested traversal (keep elements where the traversal yields something / nothing)
atom.method.where(_.caller).l                  // methods that have callers
atom.method.whereNot(_.caller).l               // methods without callers (unused)
atom.method.where(_.tag.name("framework-input")).l   // methods tagged as framework-input

// filter / filterNot — predicate-style filter using property values
atom.method.filter(_.isExternal == false).l    // internal methods only
atom.method.filterNot(_.name.matches(".*Test.*")).l  // exclude test methods

// not — keep elements where the inner traversal produces nothing (like whereNot)
atom.method.not(_.caller).l                    // methods with zero callers

// or / and — combine multiple conditions
atom.method.or(_.name("exec"), _.name("system")).l   // methods named exec OR system
atom.method.and(_.isExternal, _.name("auth")).l      // external methods named auth

// is — narrow to a specific sub-type (after a generic traversal)
atom.annotation.is[Call].l                     // annotations that are also calls

// within / without — match a set of values
atom.method.name.within("exec", "system", "eval").l
atom.method.name.without("toString", "hashCode").l
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
// collect — apply a partial traversal, keeping only non-empty results
atom.method.collect(_.caller).l    // all callers of all methods (flattened)

// collectAll — collect all elements of a given type
atom.annotation.collectAll[Literal].l   // all literals inside annotations

// cast — type-cast elements
atom.annotation.cast[Call].l       // treat annotation nodes as Call nodes

// sideEffect — do something without changing the stream (e.g., print debug info)
atom.method.sideEffect(m => println(s"checking ${m.fullName}")).where(_.caller).l
```

### Combine

```scala
// union — merge results from multiple traversals
atom.method.name("exec").union(_.caller, _.callee).l

// choose — branch based on a condition
atom.method.choose(_.isExternal)(   // if external →
  _.filter(_.name("read")),         //   keep if named "read"
  _.filterNot(_.name("close"))      //   else drop if named "close"
).l

// coalesce — first traversal that yields a result
atom.method.coalesce(_.caller, _.callee, _.parameter).l
```

### Repeat / loop

```scala
// repeat a traversal n times (depth-first search by default)
atom.method.name("exec").repeat(_.caller).times(3).l   // callers of callers of callers

// repeat until a condition is met
atom.method.name("main").repeat(_.caller).until(_.name("entryPoint")).l

// limit depth
atom.method.name("main").repeat(_.caller).maxDepth(5).l

// emit intermediate results
atom.method.name("main").repeat(_.caller).emit.l   // yields every level, not just deepest

// breadth-first search
atom.method.name("main").repeat(_.caller).bfs.times(10).l
```

### Flow operations (chen-specific, for data-flow results)

```scala
// passes — keep flow paths where at least one element matches a traversal
flows.passes(_.method.name("executeQuery")).l

// passesNot — keep flow paths where NO element matches
flows.passesNot(_.method.name("escape")).l

// passesThrough — keep flows that pass through a specific node
flows.passesThrough("escape|encode|sanitize").l

// doesNotPassThrough — exclude flows passing through a node
flows.doesNotPassThrough("debug|log").l
```

These flow operations are available on the result of `dataflows`, `reachables`, or custom `atom_flows` queries.

### Path tracking

```scala
// Track paths while traversing
atom.method.name("main").enablePathTracking.repeat(_.caller).times(5).path.l

// simplePath — only paths without repeated nodes
atom.method.name("main").repeat(_.caller).simplePath.l
```

### Property predicates (alternate filtering syntax)

```scala
// has / hasNot — check property existence
atom.method.has("SIGNATURE").l               // methods with a signature property
atom.method.hasNot("SIGNATURE").l            // methods without one

// property / propertyOption — access property values
atom.method.where(_.property("FULL_NAME").matches(".*exec.*")).l
```
