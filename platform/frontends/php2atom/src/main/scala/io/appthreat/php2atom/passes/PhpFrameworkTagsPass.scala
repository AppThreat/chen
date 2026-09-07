package io.appthreat.php2atom.passes

import io.appthreat.dataflowengineoss.semantics.PhpFrameworkSemantics
import io.appthreat.dataflowengineoss.semantics.PhpFrameworkSemantics.{Sinks, Sources, WordPress}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{Languages, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern
import scala.collection.mutable

/** Tags PHP framework taint SOURCES and SINKS on the CPG from the vocabulary declared in
  * [[io.appthreat.dataflowengineoss.semantics.PhpFrameworkSemantics]] (php-support-upgrade design
  * §2.7, Requirements 6.2/6.3/6.4).
  *
  * Until this pass existed the source/sink half of the framework taint model was a set of unused
  * constants: only the sanitizer half (`DefaultSemantics.phpFlows`) and route/entrypoint tagging
  * (`ChennaiTagsPass.tagPhpRoutes`) were wired, so nothing marked the framework request accessors
  * or the raw query/output sinks on the graph.
  *
  * ==Tag names==
  * The existing tag vocabulary is reused rather than extended, so the tags are observable by
  * everything downstream without further changes:
  *   - `framework-input` for sources - part of atom's `DEFAULT_SOURCE_TAGS` and of the `appsec`
  *     reachability profile's source override.
  *   - `framework-output` for sinks - part of atom's `DEFAULT_SINK_TAGS`.
  *   - `sql` in addition to `framework-output` for database sinks (raw query builders, `$wpdb`
  *     access, Doctrine DQL) - also part of `DEFAULT_SINK_TAGS`, and the more specific category
  *     lets the JVM-style ingress queries and any `--sink-tag sql` run pick them up.
  *
  * ==False-positive scoping==
  * Bare call names such as `input`, `all`, `query`, `post`, `get`, `raw` and `statement` also name
  * everyday collection / ORM / HTTP-client methods, so matching them on the call name alone would
  * tag most of a codebase. Matching is therefore layered:
  *   1. qualified `methodFullName` matches (`Request::input`, `DB::raw`) are accepted outright, and
  *      also accepted when namespace qualified (`\App\Http\Request::input`); 2. bare call names are
  *      accepted only when the call's RECEIVER looks like the right kind of object - a request
  *      object for sources (`Sources.requestReceiverRegex`), a database handle or query builder for
  *      sinks (`Sinks.databaseReceiverRegex`); 3. names distinctive enough to stand alone (`echo`,
  *      `print`, `createQuery`, `createNativeQuery`) are accepted without a receiver check.
  *
  * php2atom names an instance call `$request->input(...)` with `methodFullName`
  * `<unresolvedNamespace>\$request->input` and gives it a receiver whose `code` is
  * `$request->input`, so the receiver heuristic sees the variable/class text in both the resolved
  * and unresolved case.
  *
  * Residual risk: the heuristic is textual. A request-shaped variable name that is not a request
  * (`$requestLog->all()`) is still tagged, and a request object held in a differently named
  * variable (`$r->input()`) is missed. That is the usual precision/recall trade for framework
  * tagging; the qualified-name matches carry no such risk.
  */
class PhpFrameworkTagsPass(atom: Cpg) extends CpgPass(atom):

  private val FRAMEWORK_INPUT  = "framework-input"
  private val FRAMEWORK_OUTPUT = "framework-output"
  private val SQL              = "sql"

  private val RequestReceiverPattern  = Pattern.compile(Sources.requestReceiverRegex)
  private val DatabaseReceiverPattern = Pattern.compile(Sinks.databaseReceiverRegex)

  private def language: String = atom.metaData.language.headOption.getOrElse("")

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if language != Languages.PHP then return

    val sources  = mutable.LinkedHashSet.empty[Call]
    val sinks    = mutable.LinkedHashSet.empty[Call]
    val sqlSinks = mutable.LinkedHashSet.empty[Call]

    atom.call.foreach { call =>
      if isSource(call) then sources += call
      if isSink(call) then
        sinks += call
        if isSqlSink(call) then sqlSinks += call
    }

    sources.iterator.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
    sinks.iterator.newTagNode(FRAMEWORK_OUTPUT).store()(using dstGraph)
    sqlSinks.iterator.newTagNode(SQL).store()(using dstGraph)

  // --------------------------------------------------------------------------------------------
  // Sources
  // --------------------------------------------------------------------------------------------

  private def isSource(call: Call): Boolean =
      if call.name == Operators.indexAccess then isSuperglobalRead(call)
      else
        matchesFullName(call, Sources.fullNames) ||
        (Sources.receiverGatedCallNames.contains(call.name) &&
            matchesReceiver(call, RequestReceiverPattern))

  /** `$_GET['q']` and friends: an `<operator>.indexAccess` whose base identifier is a superglobal.
    * `$_SERVER` is filtered down to the attacker-controlled keys (finding C-M2) so that reads such
    * as `$_SERVER['DOCUMENT_ROOT']` are not reported as web input.
    */
  private def isSuperglobalRead(call: Call): Boolean =
    val base = call.argument.argumentIndex(1).isIdentifier.name.headOption
    base.exists { name =>
        Sources.superglobals.contains(name) &&
        (name != "_SERVER" || isTaintedServerKey(call))
    }

  private def isTaintedServerKey(call: Call): Boolean =
    val literalKey = call.argument.argumentIndex(2).isLiteral.code.headOption.map(unquote)
    literalKey match
      // A dynamically computed key can be anything - treat it as a source.
      case None => true
      case Some(key) =>
          WordPress.taintedServerKeys.exists(_.equalsIgnoreCase(key)) ||
          WordPress.taintedServerKeyPrefixes.exists(p =>
              key.regionMatches(true, 0, p, 0, p.length)
          )

  // --------------------------------------------------------------------------------------------
  // Sinks
  // --------------------------------------------------------------------------------------------

  private def isSink(call: Call): Boolean =
      Sinks.unambiguousCallNames.contains(call.name) ||
          matchesFullName(call, Sinks.fullNames) ||
          (Sinks.receiverGatedCallNames.contains(call.name) &&
              matchesReceiver(call, DatabaseReceiverPattern))

  private def isSqlSink(call: Call): Boolean =
      matchesFullName(call, Sinks.sqlFullNames) || Sinks.sqlCallNames.contains(call.name)

  // --------------------------------------------------------------------------------------------
  // Matching helpers
  // --------------------------------------------------------------------------------------------

  /** Exact `methodFullName` match, tolerating a namespace prefix: php2atom names a static call
    * `Request::input` but a fully qualified `\App\Http\Request::input(...)` keeps its namespace.
    */
  private def matchesFullName(call: Call, fullNames: Set[String]): Boolean =
    val mfn = call.methodFullName
    fullNames.exists(fn => mfn == fn || mfn.endsWith(s"\\$fn"))

  /** The receiver text of the call: the receiver's code when there is one (`$request->input`,
    * `$wpdb->query`), otherwise the `methodFullName`, which carries the qualifier for static calls
    * (`Request::get`, `DB::raw`).
    */
  private def receiverText(call: Call): String =
    val receiverCode = call.receiver.code.headOption.getOrElse("")
    if receiverCode.nonEmpty then receiverCode else call.methodFullName

  private def matchesReceiver(call: Call, pattern: Pattern): Boolean =
      pattern.matcher(receiverText(call)).find()

  private def unquote(code: String): String =
    val trimmed = code.trim
    if trimmed.length >= 2 &&
      ((trimmed.startsWith("'") && trimmed.endsWith("'")) ||
          (trimmed.startsWith("\"") && trimmed.endsWith("\"")))
    then trimmed.substring(1, trimmed.length - 1)
    else trimmed
end PhpFrameworkTagsPass
