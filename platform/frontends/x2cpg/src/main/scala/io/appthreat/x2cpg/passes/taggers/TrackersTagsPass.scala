package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern
import scala.io.Source
import scala.util.Using

/** Tags nodes that belong to known third-party trackers, analytics and advertising/adware SDKs.
  *
  * The tracker dictionary is bundled as `trackers.json` on the classpath. It is seeded from the
  * Exodus Privacy tracker database (https://reports.exodus-privacy.eu.org/api/trackers) — which
  * provides Android/Java package namespaces and categories — and enriched with a curated set of iOS
  * (Swift / Objective-C), JavaScript / TypeScript / React-Native and Dart / Flutter SDK namespaces
  * so the pass is useful across the languages chen supports, most importantly Android.
  *
  * For every matching node the pass applies:
  *   - the umbrella tag [[TrackerTag]] (`tracker`)
  *   - a category tag per Exodus category (`tracker-analytics`, `tracker-advertisement`,
  *     `tracker-location`, `tracker-profiling`, `tracker-identification`,
  *     `tracker-crash-reporting`)
  *   - the [[Adware]] tag (`adware`) when the tracker is in the advertisement category
  *   - a vendor tag of the form `tracker:<Name>` for triage / attribution.
  */
class TrackersTagsPass(atom: Cpg) extends CpgPass(atom):

  import TrackersTagsPass.*

  private def language: String = atom.metaData.language.headOption.getOrElse("")

  /** Language groups the current atom belongs to. Used to select relevant tracker entries. */
  private lazy val activeGroups: Set[String] =
    val lang   = language
    val l      = lang.toLowerCase
    val groups = scala.collection.mutable.Set.empty[String]
    if JavaLangs.contains(lang) || l.contains("kotlin") then groups += "java"
    if lang == Languages.JSSRC || lang == Languages.JAVASCRIPT || l.contains("ts") then
      groups ++= Seq("javascript", "typescript")
    if l.contains("swift") || l.contains("objc") || l.contains("ios") then
      groups ++= Seq("swift", "objc")
    if l.contains("dart") || l.contains("flutter") then groups += "dart"
    groups.toSet

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val entries = Trackers.filter(t => t.languages.exists(activeGroups.contains))
    // When the language is unknown / unsupported by our grouping, fall back to all entries so the
    // pass still provides value (namespaces are distinctive enough to keep false positives low).
    val selected = if entries.nonEmpty then entries else Trackers
    selected.foreach(tag(_, dstGraph))

  private def tag(tracker: Tracker, dstGraph: DiffGraphBuilder): Unit =
    val regex = tracker.matchRegex
    // Note: TYPE_DECL does not support TAGGED_BY edges, so SDK classes are tagged via the
    // taggable nodes that reference them (calls, type refs, identifiers, members, locals, params).
    val matched =
        (atom.method.fullName(regex).iterator ++
            atom.call.methodFullName(regex).iterator ++
            atom.typeRef.typeFullName(regex).iterator ++
            atom.identifier.typeFullName(regex).iterator ++
            atom.parameter.typeFullName(regex).iterator ++
            atom.member.typeFullName(regex).iterator ++
            atom.local.typeFullName(regex).iterator).l

    if matched.nonEmpty then
      matched.newTagNode(TrackerTag).store()(using dstGraph)
      matched.newTagNode(s"tracker:${tracker.name}").store()(using dstGraph)
      tracker.categories.foreach { c =>
        matched.newTagNode(s"tracker-$c").store()(using dstGraph)
        if c == "advertisement" then matched.newTagNode(Adware).store()(using dstGraph)
      }
  end tag

end TrackersTagsPass

object TrackersTagsPass:

  final val TrackerTag = "tracker"
  final val Adware     = "adware"

  // Android / JVM language identifiers that map to the "java" tracker group.
  private val JavaLangs: Set[String] = Set(
    Languages.JAVA,
    Languages.JAVASRC,
    "JAR",
    "JIMPLE",
    "ANDROID",
    "APK",
    "DEX"
  )

  final case class Tracker(
    name: String,
    categories: Seq[String],
    namespaces: Seq[String],
    languages: Seq[String]
  ):
    /** A single full-match regex combining all namespaces of this tracker.
      *
      *   - Dotted package prefixes (e.g. `com.appsflyer.`) match as an anchored prefix.
      *   - Signatures beginning with `.` (Exodus class-name fragments) match anywhere.
      */
    lazy val matchRegex: String =
        namespaces.map { ns =>
            if ns.startsWith(".") then s".*${Pattern.quote(ns)}.*"
            else s"${Pattern.quote(ns)}.*"
        }.mkString("(", "|", ")")

  /** Tracker definitions loaded once from the bundled `trackers.json` resource. */
  lazy val Trackers: Seq[Tracker] =
    val raw = Using(Source.fromResource("trackers.json"))(_.mkString).toOption.getOrElse("")
    if raw.isEmpty then Seq.empty
    else
      parse(raw) match
        case Right(json) =>
            json.hcursor
                .downField("trackers")
                .focus
                .flatMap(_.asArray)
                .getOrElse(Vector.empty)
                .flatMap(parseEntry)
                .toSeq
        case Left(error) =>
            System.err.println(s"Failed to parse trackers.json: $error")
            Seq.empty

  private def parseEntry(json: Json): Option[Tracker] =
    val c          = json.hcursor
    val name       = c.downField("name").as[String].getOrElse("")
    val categories = c.downField("categories").as[List[String]].getOrElse(Nil)
    val namespaces = c.downField("namespaces").as[List[String]].getOrElse(Nil).filter(_.nonEmpty)
    val languages  = c.downField("languages").as[List[String]].getOrElse(Nil)
    if name.nonEmpty && namespaces.nonEmpty then
      Some(Tracker(name, categories, namespaces, languages))
    else None

end TrackersTagsPass
