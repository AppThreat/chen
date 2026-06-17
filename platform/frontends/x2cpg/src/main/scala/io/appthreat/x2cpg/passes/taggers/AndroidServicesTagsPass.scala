package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable
import scala.io.Source
import scala.util.Using

/** Tags data egress to known internet-facing services on Android.
  *
  * This pass is restricted to the JVM/Android frontends (java and jimple). It identifies usage of
  * well known cloud, AI/LLM, social network, messaging, payment, storage and HTTP-client services —
  * i.e. destinations that data from the device can be sent to — and tags the relevant nodes at
  * three levels:
  *   - literal level: string literals containing a known service host / endpoint.
  *   - parameter level: parameters of service SDK methods and parameters typed with a service SDK
  *     class (data being prepared for / received from the service).
  *   - call-argument level: arguments passed to calls into a service SDK (data leaving the device).
  *
  * Tags applied:
  *   - an umbrella tag describing the data-flow direction:
  *     - `ServiceEgress` (`service-egress`) for data leaving the device to a remote service,
  *     - `OnDeviceAi` (`on-device-ai`) for local/on-device AI & LLM inference runtimes (no data
  *       leaves the device, but PII reaching a local model is still privacy relevant), and
  *     - `ServiceIngress` (`service-ingress`) for the data-receiving calls of HTTP / cloud services
  *       (remote content fetched onto the device — download / read response body).
  *   - a category tag (`service-cloud`, `service-ai-llm`, `service-ai-local`, `service-social`,
  *     `service-messaging`, `service-payment`, `service-storage`, `service-analytics`,
  *     `service-location`, `service-monitoring`, `service-http`)
  *   - a vendor tag of the form `service:<Name>` for triage / attribution.
  *
  * For generic HTTP clients (the `http` category) only the data-sending calls (post/put/body/
  * execute/...) and their arguments are tagged — listed via the `methods` field of each entry — to
  * avoid tagging the entire client surface. The data-receiving calls listed via `ingressMethods`
  * (get/getInputStream/body/...) are tagged as ingress so remote-content→device flows can be
  * plotted.
  *
  * The signature dictionary is bundled as `android-services.json` on the classpath.
  */
class AndroidServicesTagsPass(atom: Cpg) extends CpgPass(atom):

  import AndroidServicesTagsPass.*

  private def language: String = atom.metaData.language.headOption.getOrElse("")

  override def run(dstGraph: DiffGraphBuilder): Unit =
    // Android only: java and jimple frontends.
    if !SupportedLangs.contains(language) then return
    if Services.isEmpty then return

    // Decompose each service into plain-string matchers. The bundled namespaces, hosts and
    // method names are literal, so `startsWith` / `contains` / lowercased set membership are
    // exactly equivalent to the per-service regexes but avoid regex overhead.
    val matchers = Services.map(Matcher.from).toArray

    // Matches are accumulated per (service, umbrella) so each node kind is traversed exactly
    // once, instead of re-scanning the whole graph once per service. A node is only tagged once
    // per umbrella for a given service (the set dedups), then the umbrella, category and vendor
    // tags are emitted together at the end.
    val matchesByService =
        mutable.LinkedHashMap.empty[(Int, String), mutable.LinkedHashSet[StoredNode]]
    def record(serviceIdx: Int, umbrella: String, node: StoredNode): Unit =
        matchesByService
            .getOrElseUpdate((serviceIdx, umbrella), mutable.LinkedHashSet.empty) += node

    // Methods of dedicated SDKs: tag the parameters declared on them.
    atom.method.foreach { m =>
      val fullName = m.fullName
      var i        = 0
      while i < matchers.length do
        val s = matchers(i)
        if !s.hasMethodFilter && s.matchesNamespace(fullName) then
          m.parameter.foreach(p => record(i, s.umbrella, p))
        i += 1
    }

    // Calls into a service. Generic HTTP clients only contribute their data-sending /
    // data-receiving verbs; dedicated SDKs contribute their whole call surface.
    atom.call.foreach { call =>
      val fullName  = call.methodFullName
      val shortName = call.name.toLowerCase
      var i         = 0
      while i < matchers.length do
        val s = matchers(i)
        if s.matchesNamespace(fullName) then
          if s.hasMethodFilter then
            if s.egressVerbs.contains(shortName) then
              record(i, s.umbrella, call)
              call.argument.foreach(a => record(i, s.umbrella, a))
          else
            record(i, s.umbrella, call)
            call.argument.foreach(a => record(i, s.umbrella, a))
          if s.ingressVerbs.contains(shortName) then
            record(i, ServiceIngress, call)
        i += 1
    }

    // Parameters, identifiers, locals and members whose declared type is a dedicated SDK type.
    def tagTyped(typeFullName: String, node: StoredNode): Unit =
      var i = 0
      while i < matchers.length do
        val s = matchers(i)
        if !s.hasMethodFilter && s.matchesNamespace(typeFullName) then
          record(i, s.umbrella, node)
        i += 1
    atom.parameter.foreach(p => tagTyped(p.typeFullName, p))
    atom.identifier.foreach(n => tagTyped(n.typeFullName, n))
    atom.local.foreach(n => tagTyped(n.typeFullName, n))
    atom.member.foreach(n => tagTyped(n.typeFullName, n))

    // String literals embedding a known service host / endpoint.
    atom.literal.foreach { lit =>
      val code = lit.code
      var i    = 0
      while i < matchers.length do
        val s = matchers(i)
        if s.hostFragments.exists(code.contains) then record(i, s.umbrella, lit)
        i += 1
    }

    matchesByService.foreach { case ((serviceIdx, umbrella), nodes) =>
        val s = matchers(serviceIdx)
        nodes.iterator.newTagNode(umbrella).store()(using dstGraph)
        nodes.iterator.newTagNode(s"service-${s.category}").store()(using dstGraph)
        nodes.iterator.newTagNode(s"service:${s.name}").store()(using dstGraph)
    }
  end run

end AndroidServicesTagsPass

object AndroidServicesTagsPass:

  final val ServiceEgress  = "service-egress"
  final val ServiceIngress = "service-ingress"
  final val OnDeviceAi     = "on-device-ai"

  // java and jimple frontends only (jimple covers Android apk/dex output).
  private val SupportedLangs: Set[String] = Set(
    Languages.JAVA,
    Languages.JAVASRC,
    "JIMPLE",
    "ANDROID",
    "APK",
    "DEX"
  )

  final case class Service(
    name: String,
    category: String,
    namespaces: Seq[String],
    hosts: Seq[String],
    methods: Seq[String],
    ingressMethods: Seq[String] = Nil,
    local: Boolean = false
  )

  /** A service compiled into plain-string matchers for single-pass tagging.
    *
    * @param umbrella
    *   the data-flow direction tag for this service (`on-device-ai` for local runtimes, otherwise
    *   `service-egress`).
    * @param nsPrefixes
    *   literal package/type prefixes; a node matches when its name starts with one of them.
    * @param hostFragments
    *   literal host strings; a literal matches when its code contains one of them.
    * @param egressVerbs
    *   / ingressVerbs lowercased data-sending / data-receiving method short names.
    * @param hasMethodFilter
    *   true for generic clients that restrict tagging to [[egressVerbs]] rather than the whole call
    *   surface.
    */
  final case class Matcher(
    name: String,
    category: String,
    umbrella: String,
    nsPrefixes: Array[String],
    hostFragments: Array[String],
    egressVerbs: Set[String],
    ingressVerbs: Set[String],
    hasMethodFilter: Boolean
  ):
    def matchesNamespace(value: String): Boolean = nsPrefixes.exists(value.startsWith)

  object Matcher:
    def from(s: Service): Matcher =
        Matcher(
          name = s.name,
          category = s.category,
          umbrella = if s.local then OnDeviceAi else ServiceEgress,
          nsPrefixes = s.namespaces.toArray,
          hostFragments = s.hosts.toArray,
          egressVerbs = s.methods.map(_.toLowerCase).toSet,
          ingressVerbs = s.ingressMethods.map(_.toLowerCase).toSet,
          hasMethodFilter = s.methods.nonEmpty
        )

  /** Service definitions loaded once from the bundled `android-services.json` resource. */
  lazy val Services: Seq[Service] =
    val raw =
        Using(Source.fromResource("android-services.json"))(_.mkString).toOption.getOrElse("")
    if raw.isEmpty then Seq.empty
    else
      parse(raw) match
        case Right(json) =>
            json.hcursor
                .downField("services")
                .focus
                .flatMap(_.asArray)
                .getOrElse(Vector.empty)
                .flatMap(parseEntry)
                .toSeq
        case Left(error) =>
            System.err.println(s"Failed to parse android-services.json: $error")
            Seq.empty

  private def parseEntry(json: Json): Option[Service] =
    val c          = json.hcursor
    val name       = c.downField("name").as[String].getOrElse("")
    val category   = c.downField("category").as[String].getOrElse("")
    val namespaces = c.downField("namespaces").as[List[String]].getOrElse(Nil).filter(_.nonEmpty)
    val hosts      = c.downField("hosts").as[List[String]].getOrElse(Nil).filter(_.nonEmpty)
    val methods    = c.downField("methods").as[List[String]].getOrElse(Nil).filter(_.nonEmpty)
    val ingress =
        c.downField("ingressMethods").as[List[String]].getOrElse(Nil).filter(_.nonEmpty)
    val local = c.downField("local").as[Boolean].getOrElse(false)
    if name.nonEmpty && category.nonEmpty && (namespaces.nonEmpty || hosts.nonEmpty) then
      Some(Service(name, category, namespaces, hosts, methods, ingress, local))
    else None

end AndroidServicesTagsPass
