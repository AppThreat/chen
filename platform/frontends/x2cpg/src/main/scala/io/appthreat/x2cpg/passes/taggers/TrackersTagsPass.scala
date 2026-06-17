package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern
import scala.collection.mutable
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
  *   - the umbrella tag `TrackerTag` (`tracker`)
  *   - a category tag per Exodus category (`tracker-analytics`, `tracker-advertisement`,
  *     `tracker-location`, `tracker-profiling`, `tracker-identification`,
  *     `tracker-crash-reporting`)
  *   - the `Adware` tag (`adware`) when the tracker is in the advertisement category
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
    if selected.isEmpty then return

    // Decompose each tracker's namespaces into anchored package prefixes and free-floating
    // class-name fragments. The bundled namespaces are literal strings, so a plain `startsWith`
    // / `contains` check is exactly equivalent to the previous per-tracker regex but avoids
    // regex overhead.
    val matchers: Array[(Tracker, Array[String], Array[String])] = selected.map { tracker =>
      val (fragments, prefixes) = tracker.namespaces.partition(_.startsWith("."))
      (tracker, prefixes.toArray, fragments.toArray)
    }.toArray

    // Note: TYPE_DECL does not support TAGGED_BY edges, so SDK classes are tagged via the
    // taggable nodes that reference them (calls, type refs, identifiers, members, locals, params).
    // Each node kind is traversed exactly once; every node name is matched against all trackers
    // and the hits are accumulated per tracker, rather than re-scanning the whole graph once per
    // tracker.
    val matchesByTracker = mutable.LinkedHashMap.empty[Tracker, mutable.ArrayBuffer[StoredNode]]

    def record(name: String, node: StoredNode): Unit =
        if name.nonEmpty then
          var i = 0
          while i < matchers.length do
            val (tracker, prefixes, fragments) = matchers(i)
            if prefixes.exists(name.startsWith) || fragments.exists(name.contains) then
              matchesByTracker.getOrElseUpdate(tracker, mutable.ArrayBuffer.empty) += node
            i += 1

    atom.method.foreach(m => record(m.fullName, m))
    atom.call.foreach(c => record(c.methodFullName, c))
    atom.typeRef.foreach(t => record(t.typeFullName, t))
    atom.identifier.foreach(i => record(i.typeFullName, i))
    atom.parameter.foreach(p => record(p.typeFullName, p))
    atom.member.foreach(m => record(m.typeFullName, m))
    atom.local.foreach(l => record(l.typeFullName, l))

    matchesByTracker.foreach { case (tracker, nodes) =>
        nodes.iterator.newTagNode(TrackerTag).store()(using dstGraph)
        nodes.iterator.newTagNode(s"tracker:${tracker.name}").store()(using dstGraph)
        tracker.categories.foreach { c =>
          nodes.iterator.newTagNode(s"tracker-$c").store()(using dstGraph)
          if c == "advertisement" then nodes.iterator.newTagNode(Adware).store()(using dstGraph)
        }
    }
  end run

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
