package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern
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
  *     - [[ServiceEgress]] (`service-egress`) for data leaving the device to a remote service,
  *     - [[OnDeviceAi]] (`on-device-ai`) for local/on-device AI & LLM inference runtimes (no data
  *       leaves the device, but PII reaching a local model is still privacy relevant), and
  *     - [[ServiceIngress]] (`service-ingress`) for the data-receiving calls of HTTP / cloud
  *       services (remote content fetched onto the device — download / read response body).
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
      if SupportedLangs.contains(language) then
        Services.foreach(tag(_, dstGraph))

  private def tag(service: Service, dstGraph: DiffGraphBuilder): Unit =
    // Umbrella tag describing the direction of the data flow for this service.
    val umbrella = if service.local then OnDeviceAi else ServiceEgress
    service.namespaceRegex.foreach { regex =>
      service.methodRegex match
        case Some(verbRegex) =>
            // Generic HTTP clients: tagging the whole client surface is noisy, so restrict to the
            // data-sending calls (post/put/body/execute/...) and the arguments handed to them.
            val egressCalls = atom.call.methodFullName(regex).name(verbRegex).l
            storeTags(egressCalls.iterator, service, umbrella, dstGraph)
            storeTags(egressCalls.iterator.flatMap(_.argument), service, umbrella, dstGraph)
        case None =>
            // Dedicated service SDKs: the whole surface is relevant.
            // The SDK methods/types themselves and parameters around them.
            val params =
                (atom.method.fullName(regex).parameter.iterator ++
                    atom.parameter.typeFullName(regex).iterator).l
            storeTags(params, service, umbrella, dstGraph)

            // Calls into the service plus the arguments handed to those calls (data egress, or
            // for local AI runtimes, data fed to the on-device model).
            val serviceCalls = atom.call.methodFullName(regex).l
            storeTags(serviceCalls.iterator, service, umbrella, dstGraph)
            storeTags(serviceCalls.iterator.flatMap(_.argument), service, umbrella, dstGraph)

            // Identifiers / locals / members holding service SDK instances.
            val typed =
                (atom.identifier.typeFullName(regex).iterator ++
                    atom.local.typeFullName(regex).iterator ++
                    atom.member.typeFullName(regex).iterator).l
            storeTags(typed, service, umbrella, dstGraph)
      end match

      // Data-receiving (ingress) calls: remote content fetched onto the device. Tagged with the
      // service-ingress umbrella so remote-content -> device sinks can be plotted as flows.
      service.ingressRegex.foreach { verbRegex =>
        val ingressCalls = atom.call.methodFullName(regex).name(verbRegex).l
        storeTags(ingressCalls.iterator, service, ServiceIngress, dstGraph)
      }
    }

    // String literals carrying a known service host / endpoint.
    service.hostRegex.foreach { regex =>
        storeTags(atom.literal.code(regex), service, umbrella, dstGraph)
    }
  end tag

  private def storeTags[A <: StoredNode](
    nodes: IterableOnce[A],
    service: Service,
    umbrella: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
    val matched = nodes.iterator.toList
    if matched.nonEmpty then
      matched.newTagNode(umbrella).store()(using dstGraph)
      matched.newTagNode(s"service-${service.category}").store()(using dstGraph)
      matched.newTagNode(s"service:${service.name}").store()(using dstGraph)

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
  ):
    /** Anchored full-match regex over the SDK package/type prefixes. */
    lazy val namespaceRegex: Option[String] =
        if namespaces.isEmpty then None
        else Some(namespaces.map(ns => s"${Pattern.quote(ns)}.*").mkString("(", "|", ")"))

    /** Containment full-match regex over service hosts (matches a literal embedding the host). */
    lazy val hostRegex: Option[String] =
        if hosts.isEmpty then None
        else Some(hosts.map(h => s".*${Pattern.quote(h)}.*").mkString("(", "|", ")"))

    /** Case-insensitive full-match regex over data-sending method short names. When defined, only
      * these calls (and their arguments) are tagged for the namespace — used to avoid tagging the
      * entire surface of generic HTTP clients.
      */
    lazy val methodRegex: Option[String] =
        if methods.isEmpty then None
        else Some(methods.map(Pattern.quote).mkString("(?i)(", "|", ")"))

    /** Case-insensitive full-match regex over data-receiving (ingress) method short names. When
      * defined, these calls fetch remote content onto the device and are tagged as ingress.
      */
    lazy val ingressRegex: Option[String] =
        if ingressMethods.isEmpty then None
        else Some(ingressMethods.map(Pattern.quote).mkString("(?i)(", "|", ")"))
  end Service

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
