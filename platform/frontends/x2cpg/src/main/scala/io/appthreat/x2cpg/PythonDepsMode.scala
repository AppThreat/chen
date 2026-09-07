package io.appthreat.x2cpg

/** How the Python frontend treats third-party dependency code.
  *
  *   - '''Disabled''' (default) - today's behaviour: only the project's own sources are parsed;
  *     dependency code appears nowhere in the graph. Selected with `python-deps=none`.
  *   - '''Stubs''' - dependency `.py`/`.pyi` files are parsed for SIGNATURES only (methods,
  *     parameters, annotations, class hierarchies). Bodies and CFG are stripped, every created node
  *     is `isExternal = true`. Selected with `python-deps=stubs`.
  *   - '''Summaries''' - stubs, plus `MethodFlowSummary` (in
  *     `io.appthreat.dataflowengineoss.queryengine.summaries`) facts computed from the dependency
  *     bodies before they are discarded and persisted as `flow-summary` tags, so data-flow can
  *     bridge calls into the library. Selected with `python-deps=summaries`.
  *   - '''Full''' - the whole dependency tree in the graph: every `.py`/`.pyi` under every
  *     discovered origin (the project venv, an out-of-tree `venv-dir`, PDM/conda/system
  *     site-packages, the typeshed `stdlib/` when configured), parsed with bodies intact under
  *     site-packages-relative names so calls join natively, marked external for attribution while
  *     remaining explorable (the engine descends into real library statements instead of applying
  *     the permissive unknown-callee default), and carrying `pkg:pypi/<name>@<version>` identity
  *     from `.dist-info`. Trades build cost for analysis accuracy: a flow that exists only by
  *     passing through real library code is visible to the engine as ordinary intraprocedural
  *     reasoning. Not the import closure, so dynamically-imported modules are included; no
  *     `python-deps-rounds` bound applies. Opt-in. Selected with `python-deps=full`.
  */
enum PythonDepsMode:
  case Disabled, Stubs, Summaries, Full

object PythonDepsMode:

  private val logger = org.slf4j.LoggerFactory.getLogger(getClass)

  /** Parses the `python-deps` frontend-arg value, falling back to [[Disabled]] on anything
    * unrecognised. A misspelt value is reported: silently falling back means the run produces the
    * default graph while the operator believes dependencies were ingested - which is exactly how a
    * `python-deps=stubs4` typo turned a measurement run into a `none` run without anyone noticing.
    */
  def parse(value: String): PythonDepsMode =
      value.trim.toLowerCase match
        case "none"      => Disabled
        case "stubs"     => Stubs
        case "summaries" => Summaries
        case "full"      => Full
        case other =>
            if other.nonEmpty then
              logger.warn(
                s"python-deps: unrecognised value '$value'; expected one of " +
                    "none|stubs|summaries|full. Falling back to none (no dependency ingestion)."
              )
            Disabled
end PythonDepsMode
