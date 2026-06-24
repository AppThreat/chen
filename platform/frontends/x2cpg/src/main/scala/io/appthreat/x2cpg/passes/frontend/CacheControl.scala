package io.appthreat.x2cpg.passes.frontend

import scala.collection.concurrent.TrieMap

/** Central switchboard for chen's on-disk caches (AST, CPG, ...).
  *
  * Every cache consults this before reading or writing, so callers can enable/disable an individual
  * cache or all caches at runtime - from code (this API) or via system properties:
  *   - `chen.cache.disabled=true` disables all caches
  *   - `chen.cache.disabled.<kind>=true` disables one kind (e.g. `chen.cache.disabled.ast=true`)
  *   - `chen.cache.enabled.<kind>=true` enables a kind that is off by default (e.g. the CPG cache)
  *
  * Each kind has a default policy (see [[defaultEnabled]]). The per-file AST cache is on by
  * default; the whole-CPG cache is opt-in (off by default) because it only helps fully unchanged
  * re-runs and its fingerprint must be complete to be sound. Explicit [[enable]]/[[disable]] calls
  * always win.
  */
object CacheControl:

  /** Well-known cache kinds. */
  final val Ast: String     = "ast"
  final val Cpg: String     = "cpg"
  final val Astgen: String  = "astgen"
  final val Summary: String = "summary"

  /** Default on/off per kind when neither code nor a system property says otherwise. */
  private def defaultEnabled(kind: String): Boolean = kind match
    case Cpg     => false // opt-in: only helps unchanged re-runs; fingerprint must be complete
    case Summary => false // opt-in: method flow summaries are only built on request
    case _       => true

  @volatile private var allDisabled: Boolean =
      System.getProperty("chen.cache.disabled", "false").equalsIgnoreCase("true")

  private val overrides: TrieMap[String, Boolean] = TrieMap.empty

  /** True if the given cache kind may be used right now. */
  def isEnabled(kind: String): Boolean =
      !allDisabled && overrides.getOrElse(kind, systemPropertyOrDefault(kind))

  private def systemPropertyOrDefault(kind: String): Boolean =
      if boolProp(s"chen.cache.disabled.$kind") then false
      else if boolProp(s"chen.cache.enabled.$kind") then true
      else defaultEnabled(kind)

  private def boolProp(name: String): Boolean =
      System.getProperty(name, "false").equalsIgnoreCase("true")

  /** Disable every cache. */
  def disableAll(): Unit = allDisabled = true

  /** Re-enable every cache and clear per-kind overrides (kinds revert to their defaults). */
  def enableAll(): Unit =
    allDisabled = false
    overrides.clear()

  /** Disable a single cache kind. */
  def disable(kind: String): Unit = overrides.put(kind, false)

  /** Enable a single cache kind, overriding its default and any system property. */
  def enable(kind: String): Unit = overrides.put(kind, true)

  /** Whether the per-file AST cache should serialize mini-graphs with the overflowdb2
    * `GraphFragmentCodec` ([[io.appthreat.x2cpg.AstFragment]], CHEN3_PLAN §3/§4) instead of the
    * classic upickle bitcode. Off by default; enabled in code (`enableFragments()`) or via
    * `-Dchen.cache.fragments=true`. atom turns this on under `--flux`.
    */
  @volatile private var fragmentsEnabled: Boolean = boolProp("chen.cache.fragments")

  def useFragments: Boolean    = fragmentsEnabled
  def enableFragments(): Unit  = fragmentsEnabled = true
  def disableFragments(): Unit = fragmentsEnabled = false

end CacheControl
