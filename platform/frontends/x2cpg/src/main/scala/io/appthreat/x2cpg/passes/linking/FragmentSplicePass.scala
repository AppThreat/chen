package io.appthreat.x2cpg.passes.linking

import io.appthreat.x2cpg.AstFragment
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPass
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Warm-restore "fastest splice" (CHEN3_PLAN §3.4): reconstruct a CPG from a set of cached per-unit
  * mini-graph fragments by applying each STRAIGHT into the live graph ([[AstFragment.applyToGraph]]
  * / `BatchedUpdate.applyFragment`), skipping both re-parsing and the Scala diff-graph rebuild.
  *
  * This is a single [[CpgPass]] (one part, one thread), so the direct graph mutation is safe - it
  * runs before the framework applies this pass's (unused) diff graph. Fragments are spliced with
  * [[NoBoundaryResolver]] (chen's cross-unit refs are fullName properties), so a [[StitchPass]]
  * must be run afterwards to realise the cross-unit `CALL`/`REF`/`INHERITS_FROM` edges - the same
  * two-phase model as the in-memory build.
  *
  * @param fragments
  *   the cached unit fragments (as produced by [[AstFragment.encode]]), in a deterministic order
  * @param registerUsedTypes
  *   re-register each fragment's `usedTypes` into the frontend's global type table, so the restored
  *   graph gets the same TYPE nodes as a fresh parse
  */
class FragmentSplicePass(
  cpg: Cpg,
  fragments: Seq[Array[Byte]],
  registerUsedTypes: Seq[String] => Unit = _ => ()
) extends CpgPass(cpg):

  /** Number of fragments successfully spliced in the last run. */
  @volatile var splicedCount: Int = 0

  override def run(diffGraph: DiffGraphBuilder): Unit =
    splicedCount = 0
    fragments.foreach { bytes =>
        AstFragment.applyToGraph(bytes, cpg.graph) match
          case Some(usedTypes) =>
              registerUsedTypes(usedTypes)
              splicedCount += 1
          case None => // corrupt / incompatible fragment: skipped (caller falls back to reparse)
    }
