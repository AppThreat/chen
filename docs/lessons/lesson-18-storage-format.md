# Lesson 18: On-Disk Atom Format (OverflowDB2 Storage)

## Learning Objective

Understand how a CPG is persisted to and loaded from an `.atom` file: the H2 MVStore backing
store, the MessagePack node serialization, the string↔int glossary that keeps files compact, and
the version compatibility rules.

## Pre-requisites

- JDK 23+ (OpenJDK or GraalVM)
- A generated atom file
- Local clones of [chen](https://github.com/AppThreat/chen) and `overflowdb2`

## Conceptual Background

An atom file is an [overflowdb2](https://github.com/AppThreat/overflowdb2) graph database
serialised to a single file. Despite the `.atom` extension it is functionally identical to the
historical `.bin` format — both are H2 **MVStore** files. The storage layer lives in
`overflowdb2/core/src/main/java/overflowdb/storage`:

| File                      | Role                                                          |
| ------------------------- | ------------------------------------------------------------- |
| `OdbStorage.java`         | MVStore manager: persist/flush/close, metadata, glossary maps |
| `NodeSerializer.java`     | Serialises a node to MessagePack bytes                        |
| `NodeDeserializer.java`   | Reconstructs nodes (lazy edge loading)                        |
| `ValueTypes.java`         | Tagged property value type enum                               |
| `GraphFragmentCodec.java` | Encodes per-file mini-graph fragments (the fragment cache)    |
| `NodesWriter.java`        | Batch node writes                                             |

### MVStore + glossary

`OdbStorage` keeps several MVStore maps. The two key ideas:

1. **Node map** — `long nodeId → byte[]` holding the MessagePack-serialised node.
2. **String glossary** — `stringToInt` / `intToString` maps that intern every label, property
   key, and edge label to a small integer. Serialised nodes store these integer IDs, not strings,
   which dramatically shrinks the file. In-heap caches sit in front of the glossary maps because a
   direct MVStore lookup per access would dominate serialization time on large graphs; schema-derived
   strings are pre-interned at open.

### Node serialization layout

`NodeSerializer` packs each node as a MessagePack sequence
(`NodeSerializer.java`):

```
packLong(nodeId)
packInt(labelId)                 // via storage.lookupStringToInt(label)
packMapHeader(nonDefaultPropertyCount)
  for each property:  packInt(keyId), <typed value>
packEdgesForOneDirection(out)    // [edgeLabelId, count, [adjacentId, edgeProps]...]
packEdgesForOneDirection(in)
```

Only **non-default** property values are written, so the schema's defaults cost nothing on disk.

### Tagged property values

Each property value is written with a one-byte type tag from `ValueTypes`:

```
BOOLEAN(0) STRING(1) BYTE(2) SHORT(3) INTEGER(4) LONG(5) FLOAT(6) DOUBLE(7)
LIST(8) NODE_REF(9) UNKNOWN(10) CHARACTER(11)
ARRAY_BYTE(12) ARRAY_SHORT(13) ARRAY_INT(14) ARRAY_LONG(15) ARRAY_FLOAT(16)
ARRAY_DOUBLE(17) ARRAY_CHAR(18) ARRAY_BOOL(19) ARRAY_OBJECT(20)
```

`NODE_REF` stores another node's `long` id, which is how property-held node references survive a
round trip.

### Metadata and version gating

`OdbStorage` writes metadata entries including:

- `STORAGE_FORMAT_VERSION` — currently **3** (`STORAGE_FORMAT_VERSION = 3`).
- `STRING_TO_INT_MAX_ID` — glossary high-water mark.
- `LIBRARY_VERSIONS_ENTRY_*` — library versions captured at persist time.

On open, if the file's `STORAGE_FORMAT_VERSION` does not match exactly, opening fails with a
`BackwardsCompatibilityError`. **Atom files are not forward/backward compatible across format
versions** — regenerate the atom after a major chen/overflowdb2 upgrade.

## Loading an atom file (the real API)

There is no `loadCpg(...)` helper. Open a file through `Cpg.withStorage`, which configures
overflowdb2 and opens the graph with the generated node/edge factories:

```scala
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

val cpg = Cpg.withStorage("/tmp/app.atom")   // -> Config.withoutOverflow.withStorageLocation -> Graph.open
println(cpg.graph.nodeCount)
cpg.close()                                   // flushes pending writes and closes the MVStore
```

Under the hood `Cpg.withStorage(path)` delegates to the generated
`io.shiftleft.codepropertygraph.generated.Cpg.withStorage`, which calls
`Graph.open(config, nodes.Factories.allAsJava, edges.Factories.allAsJava, convertPropertyForPersistence)`.

### Creating a fresh, empty CPG

```scala
import io.appthreat.x2cpg.X2Cpg
val cpg = X2Cpg.newEmptyCpg(Some("/tmp/new.atom"))  // deletes an existing file, then opens MVStore-backed
```

## Persistence lifecycle

```
build / mutate graph  -->  OdbStorage.persist(id, bytes)  (per node, on eviction/close)
                      -->  OdbStorage.flush()             (writes metadata + glossary, commits MVStore)
                      -->  OdbStorage.close()             (final flush + close)
```

`overflowdb.Config` controls compression (`NONE`, `LZF`, `DEFLATE`), MVStore cache size, and page
split size. `Config.withoutOverflow` (used by `Cpg.withStorage`) keeps the whole graph resident
rather than spilling to disk during analysis.

## Notes

- The fragment cache (Lesson 9) reuses the **same** serialization machinery via
  `GraphFragmentCodec`, encoding a single file's mini-graph so it can be warm-restored and stitched
  later (Lesson 8).
- Because the glossary interns strings, two atoms of the same project can differ byte-for-byte even
  when semantically identical — node-iteration order and glossary assignment vary. Diff at the
  graph level (node/edge counts, query results), not the byte level.
- Always `cpg.close()` (or use the frontend's managed lifecycle). An unflushed MVStore can leave a
  partially written, unopenable file.
