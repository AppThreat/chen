# overflowdb2 in chen 4.0

[overflowdb2](https://github.com/AppThreat/overflowdb2) is the graph database underneath every
chen graph. It keeps nodes on the heap while there is room and evicts them to an on-disk store
(an H2 MVStore) when the heap fills up, which is what lets chen build and query graphs larger
than the heap. chen 3.4.0 used overflowdb2 3.0.5 (through cpg2 3.0.5). chen 4.0.0 uses
overflowdb2 3.1.2.

The work between those versions was about running reliably under memory pressure and with many
threads: atom runs that used to crash, hang or lose nodes on small heaps now finish with the same
results.

## Saved graphs

The storage format is unchanged. `OdbStorage.STORAGE_FORMAT_VERSION` is 3 in both versions and
the node layout written by `NodeSerializer` is the same, so a store written by overflowdb2 3.0.5
has the format 3.1.2 expects. Together with the unchanged [cpg2 schema](cpg2.md), this means an
atom saved by chen 3.4 should open in chen 4.0. That conclusion comes from the format constants
and code; loading 3.4 atoms in 4.0 is not covered by a test.

Compression is unchanged: DEFLATE by default, chosen with
`-Dodb.storage.compression=none|lzf|deflate`.

### Graph fragments

`GraphFragmentCodec`, which chen's AST cache uses to store per-file graph fragments
(`io.appthreat.x2cpg.AstFragment`), changed twice:

- In 3.1.1 it reads node properties through a `PropertyReader` instead of reflection, and refuses
  (returns empty) for nodes, values or references it cannot write faithfully, instead of writing
  a lossy fragment or throwing. Before this, fragments written by atom's native image carried node
  labels without properties (AppThreat/overflowdb2#23, fixing AppThreat/atom#286).
- In 3.1.2 the fragment format moved from version 1 to version 2. Nodes, edges and their
  properties keep the order in which the diff created them, so a graph rebuilt from cached
  fragments is identical to one built from scratch; before, node ids and atom's slices differed
  between a cold and a warm run (AppThreat/overflowdb2#25).

Version 1 fragments are refused rather than misread, and chen also changed its fragment cache key
(`AstFragment.CacheRevision`), so existing fragment caches are simply rebuilt on the first run of
chen 4.0.

## Memory and eviction

- **Eviction under every collector.** Eviction used to react only to G1 full collections. From
  3.1.2 it works under Serial, Parallel, ZGC, Shenandoah and G1, and by polling in a native image.
  The limit is the configured share of the heap or 90% of the old generation, whichever is lower.
  Serialisation runs on its own thread pool (`overflowdb-serializer-*`) in batches of about 4 MB
  (64 to 8192 nodes); a node that fails to serialise stays queued, and a node that is unchanged
  since it was read back is released without being written again.
- **Page cache sized to the heap.** The MVStore page cache lives on the heap. Its default of 256 MB
  is now capped at 10% of the maximum heap; a size set with `Config.withCacheSize` is used as
  given, and `Config.isCacheSizeExplicit()` tells the two apart.
- **No leak from closed graphs.** Closed graphs stayed reachable through the GC listeners of
  `HeapUsageMonitor`, about 205 MB per 100 graphs in c2cpg's tests; closing a graph now removes
  them (3.0.6).
- **Faster writes and removals.** `NodesWriter` serialises in parallel (persisting DefectDojo's
  graph in atom went from 20.1 to 16.4 seconds, 3.0.7), and removing all nodes of one label is no
  longer quadratic (200,000 of 400,000 nodes: 4.1 seconds to 69 ms, 3.1.2).

## Concurrency fixes

These fix crashes, hangs and lost data that showed up in atom runs with many threads or small
heaps:

- A node is persisted before its reference is cleared, a deserialised node is published only when
  complete (a race seen on ARM), adjacency arrays are copied when they grow, and changes made
  while a node is being cleared are kept (3.0.8). A deadlock introduced by those fixes was removed
  in 3.0.9.
- `NodesList.contains` and `nodeById` take the list's lock; atom crashed in 9 of 10 runs before
  and passes 30 of 30 after (3.1.1).
- An eviction deadlock (atom hung with a 320 MB heap), nodes lost when `close()` ran during an
  eviction, a race in index creation, property indexes that did not register or kept stale
  values, and removal of a node with a self-loop are fixed (3.1.2).

## API changes

These matter only to code that uses overflowdb directly rather than through chen's traversals:

| Change | Since |
|---|---|
| An initial traversal such as `cpg.method` iterates a snapshot taken on first use. Nodes added during the iteration are not visited, and concurrent changes no longer break it. | 3.1.2 |
| `NodesList.nodesByLabel` returns a read-only `LabelNodes` snapshot instead of an `ArrayList<Node>`. | 3.1.2 |
| `NodesWriter.writeAndClearBatched` returns `Failures` instead of `void`. | 3.1.2 |
| `HeapUsageMonitor.install(ReferenceManager, int)` returns the monitor, which must be closed. | 3.0.6 |
| `GraphFragmentCodec.encode` takes a `PropertyReader`; the three-argument form remains for `DetachedNodeGeneric`. | 3.1.1 |
| `PropertyKey -> value` builds a `Property` again under Scala 3.10, through extension methods in the `overflowdb` package object; import `overflowdb.*` or use `key.of(value)`. | 3.1.0 |

## Build and toolchain

overflowdb2 3.1.0 moved to Scala 3.10.0 and sbt 2.0.10 (AppThreat/overflowdb2#20). The artifacts
are still `io.appthreat` `odb2-core`, `odb2-traversal` and `odb2-formats`, published to GitHub
Packages, and JDK 23 or newer is required.

## Upgrading from chen 3.4

- Saved atoms keep their format; fragment caches are rebuilt once.
- Any garbage collector can now be used; G1 is no longer needed for eviction to work.
- If you set a large page cache for a small heap, set it explicitly with `withCacheSize`; the
  default now follows the heap.
- Code that iterates `cpg.<nodes>` while adding nodes of the same kind no longer sees the new
  nodes in that iteration.

## Further reading

The overflowdb2 [README](https://github.com/AppThreat/overflowdb2#readme) covers configuration,
storage compression, export formats (GraphML, GraphSON, Neo4j CSV, DOT, GEXF) and algorithms, and
its [lessons](https://github.com/AppThreat/overflowdb2/tree/main/docs/lessons) explain the
architecture, schemas, serialisation and the integration with cpg2.
