package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable

/** What a recognizer works with: the graph, its import index, and the shared tag emitter. */
final class JsContext(val cpg: Cpg, val modules: JsModules, val tagger: JsTagger):

  lazy val project: JsProject = JsProject(cpg)

  /** Methods holding a node tagged as a source - by this run so far, or by an earlier pass. Not
    * cached: the bridges consult it again after tagging more.
    */
  def methodsWithSources: Set[Long] =
    val tagged = tagger.taggedIds(JsTags.INPUT, JsTags.INGRESS).flatMap(id =>
        cpg.graph.node(id) match
          case n: io.shiftleft.codepropertygraph.generated.nodes.CfgNode => Some(n.method.id())
          case p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn =>
              Some(p.method.id())
          case _ => None
    )
    val earlier = cpg.tag.name(s"${JsTags.INPUT}|${JsTags.INGRESS}")._taggedByIn.collect {
        case n: io.shiftleft.codepropertygraph.generated.nodes.CfgNode => n.method.id()
        case p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn =>
            p.method.id()
    }
    (tagged ++ earlier).toSet

  /** Calls and field reads are queried by most recognizers; materialised once per run. */
  lazy val fieldAccesses: List[io.shiftleft.codepropertygraph.generated.nodes.Call] =
      cpg.call.nameExact(io.shiftleft.codepropertygraph.generated.Operators.fieldAccess).l

/** A recognizer for one JavaScript framework family's sources, sinks and sanitisers.
  *
  * The JavaScript counterpart of `PythonFrameworkRecognizer`. Recognizers work from structure - the
  * import that binds a name, the member chain a value is read from, the parameter a framework fills
  * - rather than from a regex over a call's code. A code regex also matches every call that merely
  * CONTAINS the text (a `subscribe(...)` whose callback body mentions `route.params` is not itself
  * a route read), which is where most false sources and sinks came from.
  *
  * `applies` must be cheap: it is keyed on the import index, never on a sweep of call nodes.
  */
trait JsFrameworkRecognizer:
  def name: String
  def applies(ctx: JsContext): Boolean
  def run(ctx: JsContext): Unit

/** Registry of the JavaScript framework recognizers. Adding a framework means adding one recognizer
  * and one entry here.
  */
object JsRecognizers:

  val all: Seq[JsFrameworkRecognizer] = Seq(
    // Browser platform: location, storage, messages, DOM sinks, fetch/XHR, sanitisers. Every
    // frontend framework sits on top of it.
    DomRecognizer,
    // Node.js core modules and database clients, on the server side of meta-frameworks
    NodeRecognizer,
    AngularRecognizer,
    ReactRecognizer,
    VueRecognizer,
    NitroRecognizer,
    SvelteRecognizer,
    AstroRecognizer,
    LitRecognizer,
    EmberRecognizer,
    JQueryRecognizer
  )

  /** Runs every applicable recognizer, emitting through `tagger`. */
  def run(cpg: Cpg, tagger: JsTagger): Unit =
    JsIndexes.clear()
    val ctx = JsContext(cpg, JsModules(cpg), tagger)
    all.foreach { recognizer =>
        if recognizer.applies(ctx) then recognizer.run(ctx)
    }
    // Over what the recognizers found: sources kept in a field and read by another method, and
    // values derived reactively from a source. Each can feed the other, so twice.
    (1 to 2).foreach { _ =>
        MemberTaintBridge.run(ctx)
        ReactiveBridge.run(ctx)
    }

  def isJavaScript(cpg: Cpg): Boolean =
      cpg.metaData.language.headOption.exists(l => l == Languages.JSSRC || l == Languages.JAVASCRIPT)
end JsRecognizers

/** Applies the registered [[JsFrameworkRecognizer]]s on their own, for callers that do not run
  * `ChennaiTagsPass` (which applies them as part of its JavaScript tagging). JavaScript-gated.
  */
class JsFrameworkRecognizersPass(cpg: Cpg) extends CpgPass(cpg):
  override def run(dstGraph: DiffGraphBuilder): Unit =
      if JsRecognizers.isJavaScript(cpg) then
        JsRecognizers.run(cpg, JsTagger(dstGraph, mutable.HashSet.empty))
