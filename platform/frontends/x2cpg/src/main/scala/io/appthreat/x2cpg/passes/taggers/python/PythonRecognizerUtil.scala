package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{
    Annotation,
    AnnotationParameterAssign,
    Literal,
    Method,
    StoredNode
}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Tag vocabulary and shared helpers for the Python framework recognizers. Everything here is
  * private to this package; the tags themselves are the pipeline-wide contract (see atom's
  * DEFAULT_SOURCE_TAGS / DEFAULT_SINK_TAGS).
  */
object PythonRecognizerUtil:

  /** Source: request data entering a handler (Flask/Django/FastAPI/... parameters, request
    * accesses, model fields bound to handler parameters).
    */
  val INPUT_TAG: String = "framework-input"

  /** Metadata/entrypoint: a method registered as a framework route/handler. */
  val ROUTE_TAG: String = "framework-route"

  /** Route metadata carried as tag values on the route's parameter-assign node / handler. */
  val ROUTE_PATH_TAG: String  = "route-path"
  val HTTP_METHOD_TAG: String = "http-method"

  /** MCP tool/resource/prompt arguments: attacker-controlled by construction. */
  val MCP_INPUT_TAG: String = "mcp-input"

  /** AI/LLM semantics: prompt-construction calls, model/chain invocations, `|` composition. */
  val AI_PROMPT_TAG: String  = "ai-prompt"
  val AI_INVOKE_TAG: String  = "ai-invoke"
  val AI_COMPOSE_TAG: String = "ai-compose"

  /** Source: a model repository artefact entering the process - a hub download, a `from_pretrained`
    * load, a read of a model's chat-template file.
    */
  val AI_MODEL_ARTIFACT_TAG: String = "ai-model-artifact"

  /** Sink: template or expression source rendered inside the process. Written by EasyTagsPass for
    * the Jinja and evaluator calls; the AI recognizers add the inference libraries that render a
    * chat template internally, where no jinja2 call is visible.
    */
  val SANDBOX_RENDER_TAG: String = "sandbox-render"

  /** Cloud/object-storage semantics (boto3 et al.). */
  val SERVICE_INGRESS_TAG: String = "service-ingress"
  val SERVICE_EGRESS_TAG: String  = "service-egress"

  val SQL_TAG: String  = "sql"
  val CRON_TAG: String = "cron"

  val SELF_NAMES: Set[String] = Set("self", "cls", "mcs")

  /** True for a method a user actually wrote and could have registered as a handler.
    *
    * The frontend synthesizes several methods per class - `<body>`, `<fakeNew>`,
    * `<metaClassCallHandler>` and a `<metaClassAdapter>`-suffixed copy of every real method - and
    * `<module>` per file. None of them is an entry point: `<fakeNew>` and `<metaClassCallHandler>`
    * are constructor plumbing, and the `<metaClassAdapter>` copies duplicate a method that is
    * tagged on its own account, so tagging them only inflates counts. Constructors and other dunder
    * methods are not routes either, whatever their parameters are called.
    */
  def isUserMethod(m: Method): Boolean =
      !m.name.startsWith("<") && !m.name.contains("<metaClass") &&
          !(m.name.startsWith("__") && m.name.endsWith("__"))

  /** Decorator-name verbs that mark a route, matched on the annotation's LAST dotted segment
    * (`app.route` -> `route`, `router.post` -> `post`). Bare names (Bottle's `@route("/")`) work
    * the same way.
    */
  val ROUTE_VERBS: Set[String] =
      Set("route", "get", "post", "put", "patch", "delete", "head", "options", "view", "api_route")

  /** Default HTTP verb implied by a route decorator's verb segment (`router.post` -> POST). A bare
    * `route` (Flask/Bottle) defaults to GET unless a `methods=[...]` keyword says otherwise.
    */
  def defaultVerb(annotationName: String): String =
      lastSegment(annotationName).toLowerCase match
        case "post"    => "POST"
        case "put"     => "PUT"
        case "patch"   => "PATCH"
        case "delete"  => "DELETE"
        case "head"    => "HEAD"
        case "options" => "OPTIONS"
        case _         => "GET"

  def lastSegment(dotted: String): String =
    val idx = dotted.lastIndexOf('.')
    if idx >= 0 then dotted.substring(idx + 1) else dotted

  /** Import roots present in the analyzed project, e.g. `from mcp.server.fastmcp import FastMCP`
    * contributes `mcp`. This is the cheap gate substrate for every recognizer: IMPORT nodes are a
    * per-file handful, so a whole-graph imports traversal is orders of magnitude cheaper than a
    * call-node sweep.
    */
  def importedRoots(cpg: Cpg): Set[String] =
    // Memoized on the Cpg instance. Every recognizer's `applies` gate calls this, so without a
    // cache a 20-recognizer registry walks the whole import set 20 times before any of them does
    // real work - which is exactly the cost the "cheap gate" design constraint exists to avoid.
    // Recognizers only add tags, never imports, so the value cannot go stale within a run; a
    // different Cpg simply recomputes.
    val cached = importedRootsCache
    if cached != null && (cached._1 eq cpg) then cached._2
    else
      val roots = cpg.imports.importedEntity.l.map(_.takeWhile(_ != '.')).toSet
      importedRootsCache = (cpg, roots)
      roots

  @volatile private var importedRootsCache: (Cpg, Set[String]) = null

  /** True when any of `roots` is imported. */
  def importsAnyOf(cpg: Cpg, roots: Set[String]): Boolean =
      importedRoots(cpg).exists(roots.contains)

  /** The imported module and entity names per file. The frontend lowers each import to an `import`
    * call in the file's module method, with the module and the imported names as literal arguments,
    * so the file of the method holding the call is the file the import belongs to (the IMPORT nodes
    * have no path back to their file).
    */
  def importedEntitiesByFile(cpg: Cpg): Map[String, Set[String]] =
      cpg.call
          .nameExact("import")
          .l
          .groupMapReduce(_.method.filename)(
            _.argument.l.collect { case l: Literal => unquote(l.code) }.filter(_.nonEmpty).toSet
          )(_ ++ _)

  /** Whether the file imports one of `roots` or a module under one. */
  def fileImports(
    importsByFile: Map[String, Set[String]],
    filename: String,
    roots: Set[String]
  ): Boolean =
      importsByFile.getOrElse(filename, Set.empty).exists(e =>
          roots.exists(r => e == r || e.startsWith(r + "."))
      )

  /** A Python string literal's text without its quotes. */
  def unquote(s: String): String =
      s.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")

  /** The positional (non-keyword) parameter assigns of a decorator, ordered, with the source text
    * of the value they carry. For route decorators the first of these is the route path.
    */
  def positionalValueAssigns(
    annotation: Annotation
  ): List[(AnnotationParameterAssign, String)] =
      annotation.parameterAssign.l
          .sortBy(_.order)
          .flatMap { pa =>
              pa.astChildren.l
                  .find(_.label != "ANNOTATION_PARAMETER")
                  .map(n => (pa, n.property("CODE", "")))
          }

  /** HTTP verbs declared via a `methods=["POST", ...]` keyword of a route decorator. */
  def declaredVerbs(annotation: Annotation): Seq[String] =
      annotation.parameterAssign.l.flatMap { pa =>
        val keyword = pa.astChildren.l
            .find(_.label == "ANNOTATION_PARAMETER")
            .map(_.property("CODE", ""))
        if keyword.exists(_.equalsIgnoreCase("methods")) then
          positionalValueAssigns(annotation)
              .filter(_._1 == pa)
              .map(_._2)
              .flatMap(extractVerbs)
        else Nil
      }

  private def extractVerbs(listCode: String): Seq[String] =
      listCode
          .split(',')
          .map(v => v.filterNot(c => c == '"' || c == '\'' || c == '[' || c == ']' || c == ' '))
          .map(_.trim)
          .filter(_.nonEmpty)
          .toSeq

  /** Tag one node with a valueless tag. */
  def tag(node: StoredNode, tagName: String)(using diff: DiffGraphBuilder): Unit =
      Iterator(node).newTagNode(tagName).store()(using diff)

  /** Tag one node with a key/value tag (route paths, HTTP methods). */
  def tag(node: StoredNode, tagName: String, tagValue: String)(using diff: DiffGraphBuilder): Unit =
      Iterator(node).newTagNodePair(tagName, tagValue).store()(using diff)

  /** Mark a method as a framework entry point and every non-`self` parameter as a source. */
  def tagHandler(method: Method, inputTag: String = INPUT_TAG)(using diff: DiffGraphBuilder): Unit =
    tag(method, ROUTE_TAG)
    method.parameter.l
        .filterNot(p => SELF_NAMES.contains(p.name))
        .foreach(p => tag(p, inputTag))
end PythonRecognizerUtil
