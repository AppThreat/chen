package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** A typed recognizer for one Python framework family's semantics.
  *
  * Recognizers replace `code`-string matching with the structural facts the frontend now emits:
  * decorator `ANNOTATION` nodes (with `ANNOTATION_PARAMETER_ASSIGN` children carrying route paths
  * and keyword arguments), `INHERITS_FROM` full names, parameter type annotations and the type
  * graph. Where a recognizer must still fall back to matching a `code`/`name` string, the missing
  * type fact is noted in a comment - those notes are the input for Task 5 (type inference).
  *
  * Design constraints (Task 4, Part A):
  *   - Everything a recognizer tags is scoped to Python. The driving pass dispatches on
  *     `metaData.language` exactly like `EasyTagsPass.tagPythonPatterns`, so Java, JS, PHP, Ruby
  *     and C tagging is untouched.
  *   - `applies` must be genuinely cheap: keyed on `cpg.imports` (or another indexed lookup), never
  *     on a sweep of call nodes. With ~20 recognizers registered, a per-recognizer full-call sweep
  *     would be 20 sweeps of a 1.3M-node graph.
  *   - One recognizer per framework family, registered once in [[PythonRecognizers.all]]. Adding a
  *     framework is adding one file plus one line, with no edits to a shared match block.
  */
trait PythonFrameworkRecognizer:

  /** Human-readable family name, e.g. "flask". */
  def name: String

  /** Cheap gate: skip the recognizer entirely when the framework isn't present. */
  def applies(cpg: Cpg): Boolean

  /** Tag framework semantics (sources, entry points, sinks, metadata) into `diff`. */
  def run(cpg: Cpg, diff: DiffGraphBuilder): Unit
