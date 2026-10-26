package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.{Expression, TypeDecl}
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
    // CfgNode covers MethodParameterIn too, so one case suffices
    val tagged = tagger.taggedIds(JsTags.INPUT, JsTags.INGRESS).flatMap(id =>
        cpg.graph.node(id) match
          case n: io.shiftleft.codepropertygraph.generated.nodes.CfgNode => Some(n.method.id())
          case _                                                         => None
    )
    val earlier = cpg.tag.name(s"${JsTags.INPUT}|${JsTags.INGRESS}")._taggedByIn.collect {
        case n: io.shiftleft.codepropertygraph.generated.nodes.CfgNode => n.method.id()
    }
    (tagged ++ earlier).toSet

  /** Calls and field reads are queried by most recognizers; materialised once per run. */
  lazy val fieldAccesses: List[io.shiftleft.codepropertygraph.generated.nodes.Call] =
      cpg.call.nameExact(io.shiftleft.codepropertygraph.generated.Operators.fieldAccess).l

  /** Every field write of every class, built once per run. */
  lazy val memberWrites: List[(TypeDecl, String, Expression)] = MemberTaintBridge.memberWrites(this)

  /** The template elements that render a project component, resolved once. */
  lazy val elements: ComponentCallBridge.Elements = ComponentCallBridge.resolve(this)
end JsContext

/** A recognizer for one JavaScript framework family's sources, sinks and sanitisers.
  *
  * The JavaScript counterpart of `PythonFrameworkRecognizer`. Recognizers work from structure - the
  * import that binds a name, the member chain a value is read from, the parameter a framework fills
  *   - rather than from a regex over a call's code. A code regex also matches every call that
  *     merely CONTAINS the text (a `subscribe(...)` whose callback body mentions `route.params` is
  *     not itself a route read), which is where most false sources and sinks came from.
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
    // NestJS controllers: endpoints declared by decorators
    NestRecognizer,
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
    // Schema validation, and checks that a value passed before it is used: what they let through
    // carries nothing, which the source searches of the bridges below must already know.
    ValidationBridge.tagSchemaParses(ctx)
    GuardBridge.run(ctx)
    if ReactRecognizer.applies(ctx) then ReactRecognizer.tagValidatedServerFunctions(ctx)
    // Template component elements, lowered to calls, resolved to the components they name.
    ComponentCallBridge.run(ctx)
    // Functions kept in a Map and called after a lookup, resolved to what was put in it.
    RegistryBridge.run(ctx)
    // Over what the recognizers found: sources kept in a field and read by another method, values
    // derived reactively from a source, and data a framework hands from a producer to a consumer.
    // Each can feed the others - a store member to a page, the page to a child's prop - so the
    // round is repeated.
    (1 to 3).foreach { _ =>
      MemberTaintBridge.run(ctx)
      ReactiveBridge.run(ctx)
      if ReactRecognizer.applies(ctx) then ReactRecognizer.bridgeRouteProps(ctx)
      if ReactRecognizer.applies(ctx) then ReactRecognizer.bridgeLoaderDeps(ctx)
      if SvelteRecognizer.applies(ctx) then
        SvelteRecognizer.bridgeLocals(ctx)
        SvelteRecognizer.bridgeRouteProps(ctx)
      if VueRecognizer.applies(ctx) then
        VueRecognizer.bridgePiniaStores(ctx)
        VueRecognizer.bridgeRouterProps(ctx)
      if AngularRecognizer.applies(ctx) then AngularRecognizer.bridgeInputs(ctx)
      DataLinkBridge.bridgeHookReturns(ctx)
      DataLinkBridge.bridgeBoundArguments(ctx)
      ComponentCallBridge.bridgeProps(ctx)
      VueRecognizer.bridgeDirectives(ctx)
      SvelteRecognizer.bridgeActions(ctx)
      AlpineRecognizer.bridge(ctx)
      if EmberRecognizer.applies(ctx) then EmberRecognizer.bridge(ctx)
      if VueRecognizer.applies(ctx) then VueRecognizer.bridgeOptionsApi(ctx)
    }
    // The npm package behind each sink, from the project's manifests - no SBOM needed.
    val typeOf =
        if AngularRecognizer.applies(ctx) then AngularRecognizer.injectedTypes(ctx)
        else (_: io.shiftleft.codepropertygraph.generated.nodes.Expression) => None
    PackageAttribution.run(ctx, typeOf)
  end run

  def isJavaScript(cpg: Cpg): Boolean =
      cpg.metaData.language.headOption.exists(l =>
          l == Languages.JSSRC || l == Languages.JAVASCRIPT
      )
end JsRecognizers

/** Applies the registered [[JsFrameworkRecognizer]]s on their own, for callers that do not run
  * `ChennaiTagsPass` (which applies them as part of its JavaScript tagging). JavaScript-gated.
  */
class JsFrameworkRecognizersPass(cpg: Cpg) extends CpgPass(cpg):
  override def run(dstGraph: DiffGraphBuilder): Unit =
      if JsRecognizers.isJavaScript(cpg) then
        JsRecognizers.run(cpg, JsTagger(dstGraph, mutable.HashSet.empty))
