package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Languages}
import io.shiftleft.codepropertygraph.generated.nodes.{NewTag, StoredNode}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.io.File
import java.util.regex.Pattern
import scala.collection.mutable

class CdxPass(
  atom: Cpg
) extends CpgPass(atom):

  private val TAGS_COUNT  = 3
  private val PKG_NS_SIZE = 3

  /** Component properties whose value is a list of package namespaces, matched after stripping an
    * optional `internal:` prefix so that cdxgen v13 SBOMs (`internal:Namespaces`) and older ones
    * (`Namespaces`) behave identically. Every other property (SrcFile, ResolvedUrl, digests,
    * classifiers, ...) is not a namespace list and must not reach `normalizePackage`.
    * `ImportedModules` is deliberately absent: it is pypi-specific and read directly by
    * `processPypiComponent`, which turns the imported symbols into module patterns.
    */
  private val NAMESPACE_PROPERTIES = Set("Namespaces")

  override def run(dstGraph: DiffGraphBuilder): Unit =
      BomFiles.contents(atom).foreach { cdxData =>
          parse(cdxData) match
            case Right(json) =>
                val components =
                    json.hcursor.downField("components").focus.flatMap(_.asArray).getOrElse(
                      Vector.empty
                    )
                val claimedForms         = mutable.Map[String, mutable.Set[String]]()
                val unambiguousJvmGroups = jvmGroupsNamingOneComponent(components)
                val gemPaths             = rubyGemConstantPaths(components)

                components.foreach(
                  processComponent(_, claimedForms, unambiguousJvmGroups, gemPaths, dstGraph)
                )
                applyGenericJobs(dstGraph)
            case Left(error) =>
                System.err.println(s"Failed to parse cdx json: $error")
      }

  private def processComponent(
    comp: Json,
    claimedForms: mutable.Map[String, mutable.Set[String]],
    unambiguousJvmGroups: Set[String],
    gemPaths: Set[List[String]],
    dstGraph: DiffGraphBuilder
  ): Unit =
    val cursor          = comp.hcursor
    val compPurl        = cursor.downField("purl").as[String].getOrElse("")
    val compType        = cursor.downField("type").as[String].getOrElse("")
    val compDescription = cursor.downField("description").as[String].getOrElse("")
    val compTags        = cursor.downField("tags").as[List[String]].getOrElse(List.empty)

    val descTags = if compTags.nonEmpty then compTags.take(TAGS_COUNT)
    else CdxTagVocab.extractDescTags(compDescription).take(TAGS_COUNT)

    processPypiComponent(cursor, compPurl, compType, descTags, claimedForms, dstGraph)
    val taggedFromProperties =
        processProperties(cursor, compPurl, compType, descTags, claimedForms, dstGraph)
    if !taggedFromProperties then
      processJvmPurl(compPurl, compType, descTags, claimedForms, unambiguousJvmGroups, dstGraph)
      processGemPurl(compPurl, compType, descTags, claimedForms, gemPaths, dstGraph)
  end processComponent

  /** The versionless coordinate a purl names: its type, namespace and name. Version, qualifiers
    * (`?platform=aarch64-linux-gnu`) and subpath do not distinguish packages, so every purl of one
    * package compares equal - nokogiri's three platform-qualified purls on lobsters keep claiming
    * together, and a versionless purl joins its versioned siblings. Two packages whose purls end in
    * the same name are still different packages: `pkg:maven/org.a/utils` and
    * `pkg:maven/org.b/utils` both reduced to the bare name `utils`, and the second group was let
    * into the namespace the first had claimed.
    */
  private def purlCoordinate(purl: String): String =
      purl.split("#").head.split("@").head.split("\\?").head.stripPrefix("pkg:")

  /** Claims a namespace form for the package `purl` names; true when the caller must tag.
    *
    * A package present in several versions (DefectDojo pins django 5.2.17 and 6.1.2, bleach and
    * markdown too) claims its namespaces from every version, so the nodes carry each version's
    * exact purl and cdxgen can attach callstack evidence to each component. Which component the
    * SBOM lists first, or whether registry metadata enriched it, must not change that. A DIFFERENT
    * package taking an already claimed namespace is still refused: two distributions providing one
    * namespace (pyyaml and ruamel-yaml both provide `yaml`) are indistinguishable at the call site,
    * and letting the second one tag would misattribute.
    */
  private def claim(
    bpkg: String,
    purl: String,
    claimedForms: mutable.Map[String, mutable.Set[String]]
  ): Boolean =
      claimedForms.get(bpkg) match
        case None =>
            claimedForms(bpkg) = mutable.Set(purl)
            true
        case Some(purls) =>
            val coordinate = purlCoordinate(purl)
            if !purls.contains(purl) && purls.forall(purlCoordinate(_) == coordinate) then
              purls.add(purl)
              true
            else false

  /** Maven group ids that exactly one component in this SBOM belongs to.
    *
    * A group id only identifies a component when no sibling shares it. `org.springframework` is the
    * group of a dozen artifacts, so seeing `org.springframework.web.X` in the code says nothing
    * about WHICH of them it came from - attributing it to whichever component happened to be read
    * first would be a confident wrong answer, and on Spring Petclinic that was 797 nodes attributed
    * to `spring-context-support` alone. A group with a single component has no such ambiguity.
    */

  private def jvmGroupsNamingOneComponent(components: Vector[Json]): Set[String] =
      components
          .flatMap(c => mavenGroupOf(c.hcursor.downField("purl").as[String].getOrElse("")))
          .groupBy(identity)
          .collect { case (group, occurrences) if occurrences.sizeIs == 1 => group }
          .toSet

  private def mavenGroupOf(purl: String): Option[String] =
      Option.when(purl.startsWith("pkg:maven/"))(
        purl.stripPrefix("pkg:maven/").split("/").headOption
      ).flatten

  /** Tags a JVM component by the namespace its purl already names, for SBOMs that do not carry a
    * `Namespaces` property.
    *
    * That property is the precise answer - it lists the packages a jar actually declares - but it
    * only exists when the SBOM generator opened the jars. An SBOM built from build-file metadata
    * alone has none, which is what an ordinary `cdxgen -t java` run produces, and the Java path was
    * then a no-op: every component was read and none was tagged. A Maven purl carries the group id
    * (`pkg:maven/org.springframework.boot/spring-boot-starter-web`), and for the overwhelming
    * majority of JVM artifacts the group id IS the package root, so it identifies the component's
    * code well enough to attach the purl and its tags to.
    *
    * Only used when the component declared no namespaces, so an SBOM that carries them keeps the
    * precise mapping.
    */
  private def processJvmPurl(
    purl: String,
    compType: String,
    descTags: List[String],
    claimedForms: mutable.Map[String, mutable.Set[String]],
    unambiguousJvmGroups: Set[String],
    dstGraph: DiffGraphBuilder
  ): Unit =
      if isJvmLanguage then
        mavenGroupOf(purl)
            // A group id that is not a package root (a single segment, or one of the JDK's own)
            // says nothing about where the code lives, and one shared with sibling components does
            // not say which of them it is.
            .filter(group =>
                group.contains(".") && !group.startsWith("java.") &&
                    !group.startsWith("javax.") && unambiguousJvmGroups.contains(group)
            )
            .foreach { group =>
              val bpkg = normalizePackage(group)
              if bpkg.nonEmpty && claim(bpkg, purl, claimedForms) then
                tagByLanguage(bpkg, purl, compType, descTags, dstGraph)
            }

  /** Languages whose components this pass attributes by Maven group id.
    *
    * NB: `ChennaiTagsPass` gates on a shorter list (no ANDROID/APK/DEX). The two are deliberately
    * not shared - widening that one is a tagging change, not a refactor.
    */
  private val JvmLanguages: Set[String] =
      Set(Languages.JAVA, Languages.JAVASRC, "JAR", "JIMPLE", "ANDROID", "APK", "DEX")

  private def isJvmLanguage: Boolean = JvmLanguages.contains(language)

  /** Tags a Ruby component by the constant path its purl names, for SBOMs that declare no
    * namespaces.
    *
    * The `Namespaces` property is the precise answer, but it only exists when the generator opened
    * the gems; an ordinary `cdxgen -t ruby` SBOM built from the lockfile carries none, and the Ruby
    * path was then a no-op: every component was read, none was tagged, and no reachables flow could
    * carry a purl (lobsters: 195 flows, 0 purls). A gem purl carries the gem name
    * (`pkg:gem/rack-attack@6.7.0`), and the constant path the name conventionally nests is what the
    * application's calls actually reference.
    *
    * When the SBOM also carries a gem whose name extends this one (`rack` and `rack-attack`), the
    * child's constant path shadows the parent: `Rack::Attack.throttle` matches both gems' patterns,
    * and the call belongs to the more specific gem. The pass computes every gem's path upfront - so
    * the decision reads the whole SBOM, not the component order - and [[tagRuby]] leaves the
    * shadowed calls to the child. When the child is absent, nothing is shadowed and the parent
    * keeps every call its own pattern matches.
    */
  private def processGemPurl(
    purl: String,
    compType: String,
    descTags: List[String],
    claimedForms: mutable.Map[String, mutable.Set[String]],
    gemPaths: Set[List[String]],
    dstGraph: DiffGraphBuilder
  ): Unit =
      if language == Languages.RUBYSRC then
        rubyGemName(purl).foreach { gem =>
          val path = rubyConstantPath(gem)
          val bpkg = rubyModulePattern(path)
          if bpkg.nonEmpty && claim(bpkg, purl, claimedForms) then
            val shadowers = gemPaths
                .filter(child => child != path && child.take(path.length) == path)
                .map(rubyModulePattern)
                .toList
            tagByLanguage(bpkg, purl, compType, descTags, dstGraph, shadowers = shadowers)
        }

  /** The gem name a `pkg:gem` purl carries, without version, platform qualifier or subpath. */
  private def rubyGemName(purl: String): Option[String] =
      Option.when(purl.startsWith("pkg:gem/"))(
        purl.stripPrefix("pkg:gem/").split("[@?#]").head
      ).filter(_.nonEmpty)

  /** The constant path every `pkg:gem` component in this SBOM conventionally names, e.g.
    * `pkg:gem/rack-attack` -> `Rack::Attack`. Read once per SBOM, so a child gem shadows its parent
    * whichever component comes first.
    */
  private def rubyGemConstantPaths(components: Vector[Json]): Set[List[String]] =
      components
          .flatMap(c => rubyGemName(c.hcursor.downField("purl").as[String].getOrElse("")))
          .map(rubyConstantPath)
          .toSet

  /** The constant path a gem name conventionally nests: `-` separates `::` segments and `_` joins
    * the words within one (`net-http` -> `Net::HTTP`, `rack-attack` -> `Rack::Attack`,
    * `active_support` -> `ActiveSupport`, `unicode-display_width` -> `Unicode::DisplayWidth`).
    *
    * A trailing `-ruby`/`-rb` segment is dropped: it names no constant the code references -
    * `sentry-ruby` and `concurrent-ruby` define `Sentry` and `Concurrent`. Measured on lobsters: 4
    * of the 52 hyphenated gems are referenced under this convention path, and `Sentry` is the only
    * reference the dropped segment reaches (6 in config/initializers/telebugs.rb); `Concurrent` is
    * not referenced at all, so the drop adds no false match there. Two referenced gems stay
    * unmatched: `rack-mini-profiler` writes `Rack::MiniProfiler` (fused tail) and `ruby-vips`
    * writes `Vips` - both listed in the T15 Part 2 report rather than turned into heuristics on one
    * corpus each.
    */
  private def rubyConstantPath(gem: String): List[String] =
    val segments = gem.split("-").toList
    val kept =
        if segments.length > 1 && Set("ruby", "rb").contains(segments.last) then
          segments.dropRight(
            1
          )
        else segments
    kept.map(_.split("_").map(word =>
        if word.isEmpty then word else word.charAt(0).toUpper + word.drop(1)
    ).mkString)

  /** The full-name pattern for a constant path: each segment camelized with only its first letter
    * case-sensitive (a Ruby constant must start uppercase, the rest varies - `SecureRandom`,
    * `JSON`), segments chained with `::`, delimited the way Ruby delimits constants - a `::` chain,
    * a method dot, any other non-word character (underscore included, so `mod_mail` is not `mail`),
    * or the ends of the snippet.
    */
  private def rubyModulePattern(path: List[String]): String =
      if path.isEmpty then ""
      else
        val constants = path.map { segment =>
            if segment.isEmpty then segment
            else s"${segment.head}(?i:${segment.drop(1)})"
        }
        "((.*[^A-Za-z0-9_:])|)(::)?" + constants.mkString("::") +
            "(::.*|\\..*|[^A-Za-z0-9_].*)?"

  private def processPypiComponent(
    cursor: HCursor,
    purl: String,
    compType: String,
    descTags: List[String],
    claimedForms: mutable.Map[String, mutable.Set[String]],
    dstGraph: DiffGraphBuilder
  ): Unit =
      if (language == Languages.PYTHON || language == Languages.PYTHONSRC) && purl.startsWith(
          "pkg:pypi"
        )
      then
        // A purl that carries no version can still carry qualifiers
        // (`pkg:pypi/django?x`), which are not part of the package name.
        val pkgName = purl
            .split("[@?#]").head
            .replace("pkg:pypi/", "")
            .replace("python-", "")
            .replace("-", "_")

        // Prefer what the code under analysis actually imports, then what the
        // distribution provides, and only then guess from the purl name for SBOMs
        // produced by older cdxgen. The former `pkgName.replace("py", "")` arm is
        // gone: `String.replace` strips every occurrence, mangling e.g. `numpy`
        // into `num` and `pyyaml` into `yaml` by luck alone.
        val nsCandidates: List[String] =
          val imported = propertyValues(cursor, "ImportedModules").map(_.split("\\.").head)
          val provided = propertyValues(cursor, "Namespaces")
          if imported.nonEmpty then imported
          else if provided.nonEmpty then provided
          else
            List(pkgName, pkgName.stripPrefix("flask_"), pkgName.stripPrefix("django_"))

        nsCandidates.distinct.filter(_.nonEmpty).foreach { ns =>
          val forms = Set(toPyModuleForm(ns), s"$ns\\..*")
          forms.foreach { bpkg =>
              if bpkg.nonEmpty && claim(bpkg, purl, claimedForms) then
                // `methodFullName` is the pypi path's own traversal: a module-form
                // pattern matches the call's method, not its type. Everything else a
                // component implies - the purl on types and parameters, the component
                // type, the description tags - is the same work `processProperties`
                // does, so it is applied from one place for both paths.
                tagByLanguage(bpkg, purl, compType, descTags, dstGraph, tagCallMethods = true)
          }
        }
  end processPypiComponent

  /** @return
    *   whether any namespace was found to tag, which is what tells the caller a purl-derived
    *   fallback is needed.
    */
  private def processProperties(
    cursor: HCursor,
    purl: String,
    compType: String,
    descTags: List[String],
    claimedForms: mutable.Map[String, mutable.Set[String]],
    dstGraph: DiffGraphBuilder
  ): Boolean =
    var tagged     = false
    val properties = cursor.downField("properties").focus.flatMap(_.asArray).getOrElse(Vector.empty)
    properties.foreach { prop =>
      val nsstr  = prop.hcursor.downField("value").as[String].getOrElse("")
      val nsname = prop.hcursor.downField("name").as[String].getOrElse("")

      if NAMESPACE_PROPERTIES.contains(nsname.stripPrefix("internal:")) then
        nsstr
            .split("[,\n]")
            .filterNot(s =>
                s.startsWith("java.") || s.startsWith("com.sun") || s.contains("test") || s.contains(
                  "mock"
                )
            )
            .foreach(pkg =>
              var bpkg = pkg.takeWhile(_ != '$')
              bpkg = normalizePackage(bpkg)
              if bpkg.nonEmpty then
                tagged = true
                if claim(bpkg, purl, claimedForms) then
                  tagByLanguage(bpkg, purl, compType, descTags, dstGraph)
            )
    }
    tagged
  end processProperties

  private def propertyValues(cursor: HCursor, propName: String): List[String] =
    val properties = cursor.downField("properties").focus.flatMap(_.asArray).getOrElse(Vector.empty)
    properties.flatMap { prop =>
      val name  = prop.hcursor.downField("name").as[String].getOrElse("")
      val value = prop.hcursor.downField("value").as[String].getOrElse("")
      if name.stripPrefix("internal:") == propName then value.split("[,\n]").toList
      else List.empty
    }.filter(_.nonEmpty).toList

  private def normalizePackage(pkg: String): String =
    val base = pkg.split("\\.").take(PKG_NS_SIZE).mkString(".")
    language match
      case lang
          if Seq(Languages.JAVA, Languages.JAVASRC, "JAR", "JIMPLE", "ANDROID", "APK", "DEX")
              .contains(lang) =>
          s"$base.*".replace(File.separator, Pattern.quote(File.separator))
      case lang if lang == Languages.JSSRC || lang == Languages.JAVASCRIPT =>
          pkg.replace(File.separator, Pattern.quote(File.separator))
      case lang if lang == Languages.PYTHON || lang == Languages.PYTHONSRC =>
          toPyModuleForm(pkg)
      case lang if lang == Languages.RUBYSRC =>
          toRubyModuleForm(pkg)
      case lang if lang == Languages.PHP =>
          pkg.replace("\\", "\\\\").concat(".*")
      case _ => pkg

  private def tagByLanguage(
    bpkg: String,
    purl: String,
    compType: String,
    descTags: List[String],
    dstGraph: DiffGraphBuilder,
    tagCallMethods: Boolean = false,
    shadowers: List[String] = Nil
  ): Unit =
      // `tagCallMethods` is only set by the pypi path, whose language always lands in tagGeneric.
      language match
        case lang if lang == Languages.RUBYSRC =>
            tagRuby(bpkg, purl, shadowers, dstGraph)
        case lang if lang == Languages.NEWC || lang == Languages.C =>
            tagCpp(bpkg, purl, compType, descTags, dstGraph)
        case _ =>
            tagGeneric(bpkg, purl, compType, descTags, tagCallMethods)
  end tagByLanguage

  /** Tags the arguments of every call whose code names the component's constant path with the
    * component's exact purl. reachables' Ruby query (`collectRubySpecificFlows`) sources from
    * parameters in routes, controller and model files, and the purl travels with the flow when its
    * path crosses one of these arguments.
    *
    * Calls a child gem's constant path also matches (`Rack::Attack.throttle` matches the `rack`
    * pattern's `::.*` suffix just as it matches `rack-attack`) are left to the child: the
    * [[processGemPurl shadowers]] are matched here, so a parent purl lands only where no child
    * claims. When the child gem is absent from the SBOM the shadower list is empty and the parent
    * keeps every call its own pattern matches.
    *
    * The former `framework-input` / `<compType>-input` / `<compType>-value` tags are gone: they
    * derived request-data sources from the component's type - the framework-as-source problem
    * [[tagGeneric]] no longer has - and they had never fired on the corpus, because the old module
    * pattern matched no call code at all. Parameters of controller methods keep their
    * `framework-input` from the recogniser (ChennaiTagsPass.tagRubyRoutes), which reads the routes
    * and controllers, not the SBOM.
    */
  private def tagRuby(
    bpkg: String,
    purl: String,
    shadowers: List[String],
    dstGraph: DiffGraphBuilder
  ): Unit =
    // `(?s)` as overflowdb compiles the `code(bpkg)` filter: call code spans lines (a `do`
    // block), and a shadower that cannot cross a newline would hand multi-line child calls to
    // the parent.
    val shadowerPatterns = shadowers.map(pattern => s"(?s)$pattern".r)
    val owned = atom.call.code(bpkg).filterNot { call =>
        shadowerPatterns.exists(_.matches(call.code))
    }
    owned.argument.newTagNode(purl).store()(using dstGraph)

  private def tagCpp(
    bpkg: String,
    purl: String,
    compType: String,
    descTags: List[String],
    dstGraph: DiffGraphBuilder
  ): Unit =
    val isRegex = containsRegex(bpkg)
    val pattern = if isRegex then Pattern.quote(bpkg) else bpkg

    atom.method.fullNameExact(bpkg).callIn(using NoResolve).newTagNode(purl).store()(using dstGraph)
    atom.method.fullNameExact(bpkg).callIn(using NoResolve).newTagNode("library-call").store()(using
    dstGraph)
    atom.method.fullNameExact(bpkg).newTagNode(purl).store()(using dstGraph)

    if !isRegex then
      atom.parameter.typeFullName(s"$bpkg.*").newTagNode(purl).store()(using dstGraph)
      atom.parameter.typeFullName(s"$bpkg.*").newTagNode("framework-input").store()(using dstGraph)
      atom.parameter.typeFullName(s"$bpkg.*").method.callIn(using NoResolve).newTagNode(purl).store()(
        using dstGraph
      )
      atom.call.code(s".*\\.$bpkg.*").newTagNode(purl).store()(using dstGraph)
      atom.call.code(s".*\\.$bpkg.*").newTagNode("library-call").store()(using dstGraph)
      atom.call.code(s"$bpkg->.*").newTagNode(purl).store()(using dstGraph)
      atom.call.code(s"$bpkg->.*").newTagNode("library-call").store()(using dstGraph)
    else
      atom.parameter.typeFullName(s"$pattern.*").newTagNode(purl).store()(using dstGraph)
      atom.parameter.typeFullName(s"$pattern.*").newTagNode("framework-input").store()(using
      dstGraph)
      atom.parameter.typeFullName(s"$pattern.*").method.callIn(using NoResolve).newTagNode(purl)
          .store()(
            using dstGraph
          )
  end tagCpp

  private def tagGeneric(
    bpkg: String,
    purl: String,
    compType: String,
    descTags: List[String],
    tagCallMethods: Boolean
  ): Unit =
    val isRegex       = containsRegex(bpkg)
    val methodPattern = if isRegex then bpkg else s"$bpkg.*"
    genericJobs += GenericJob(
      typeMatcher = CdxPatternMatcher(bpkg),
      methodMatcher = CdxPatternMatcher(methodPattern),
      callMethodMatcher = Option.when(tagCallMethods)(CdxPatternMatcher(bpkg)),
      purl = purl,
      // The component type and description words describe the package; on calls,
      // identifiers and parameters they used to land under their bare names, and
      // those names are the reachables source/sink vocabulary (`framework` is a
      // source tag, `http`, `sql` and `rpc` are sinks). An enriched component then
      // made every call into it read as request data - on DefectDojo, 95,007 flows
      // started at `django, framework, http` calls, all of them plumbing. They are
      // namespaced instead, so no reachables query can match them while the
      // information stays on the node.
      compTypeTag = Option.when(compType != "library")(s"comp-type:$compType"),
      descTags = descTags.map(t => s"comp-desc:$t")
    )
  end tagGeneric

  /** One `tagGeneric` request, applied later by [[applyGenericJobs]]. */
  private case class GenericJob(
    typeMatcher: CdxPatternMatcher,
    methodMatcher: CdxPatternMatcher,
    callMethodMatcher: Option[CdxPatternMatcher],
    purl: String,
    compTypeTag: Option[String],
    descTags: List[String]
  )

  private val genericJobs = mutable.ArrayBuffer.empty[GenericJob]

  /** Applies every queued `tagGeneric` request in one scan per node kind.
    *
    * Tagging used to run four full-graph regex scans per (component, namespace form) - plus a
    * `where(_.methodFullName(..))` scan on the pypi path that recompiled its regex for every call
    * node - which on DefectDojo (155 components) was ~1,500 graph scans and 190 GB of allocation.
    * Here each node is visited once and its name is looked up in a [[CdxPatternIndex]], which
    * serves the common literal-prefix patterns (`django\..*`) from a hash map.
    *
    * The tags each node receives, and their order on that node, are exactly those of the former
    * per-job scans: jobs are applied in queue order and, within a job, a call gets its method-name
    * purl before its type-name tags.
    */
  private def applyGenericJobs(dstGraph: DiffGraphBuilder): Unit =
    if genericJobs.isEmpty then return
    val jobs        = genericJobs.toArray
    val typeIndex   = CdxPatternIndex(jobs.iterator.map(_.typeMatcher).zipWithIndex.toSeq)
    val methodIndex = CdxPatternIndex(jobs.iterator.map(_.methodMatcher).zipWithIndex.toSeq)
    val callMethodIndex = CdxPatternIndex(
      jobs.iterator.zipWithIndex.flatMap((j, i) => j.callMethodMatcher.map(_ -> i)).toSeq
    )

    def tag(node: StoredNode, name: String): Unit =
      val t = NewTag().name(name).value("")
      dstGraph.addNode(t)
      dstGraph.addEdge(node, t, EdgeTypes.TAGGED_BY)

    def tagJob(node: StoredNode, job: GenericJob, withCompType: Boolean): Unit =
      tag(node, job.purl)
      if withCompType then job.compTypeTag.foreach(tag(node, _))
      job.descTags.foreach(tag(node, _))

    atom.call.foreach { call =>
      val byMethod = callMethodIndex.matching(call.methodFullName)
      val byType   = typeIndex.matching(call.typeFullName)
      if byMethod.nonEmpty || byType.nonEmpty then
        (byMethod ++ byType).distinct.sorted.foreach { i =>
          if byMethod.contains(i) then tag(call, jobs(i).purl)
          if byType.contains(i) then tagJob(call, jobs(i), withCompType = true)
        }
    }
    atom.identifier.foreach { id =>
        typeIndex.matching(id.typeFullName).foreach(i => tagJob(id, jobs(i), withCompType = false))
    }
    atom.method.parameter.foreach { p =>
        typeIndex.matching(p.typeFullName).foreach(i => tagJob(p, jobs(i), withCompType = true))
    }
    atom.method.foreach { m =>
        methodIndex.matching(m.fullName).foreach(i => tagJob(m, jobs(i), withCompType = true))
    }
    genericJobs.clear()
  end applyGenericJobs

  private def containsRegex(str: String): Boolean =
    val reChars = "[](){}*+&|?.,\\$"
    str.exists(reChars.contains)

  /** The full-name pattern shape for Python. The pattern form MUST match the representation the
    * frontend produced, or every purl, `framework` and description tag silently zeroes out.
    */
  private def toPyModuleForm(str: String): String =
    if str.isEmpty then return str
    val parts = str.split("\\.")
    if parts.length > 1 then s"${parts.mkString("\\.")}.*"
    else s"${parts.head}\\..*"

  /** The full-name pattern shape for Ruby: the constant path the code writes for the module
    * (`securerandom` -> `SecureRandom`, `json` -> `JSON.parse`, a `Namespaces` value `Net::HTTP` ->
    * `Net::HTTP`), delimited the way Ruby delimits constants - a `::` chain, a method dot, any
    * other non-word character (underscore included, so `mod_mail` is not `mail`), or the ends of
    * the snippet. Only each constant's first letter is case-sensitive, because a Ruby constant must
    * start uppercase while the rest of the name varies (`SecureRandom`, `ActiveRecord`); that is
    * what separates the gem from words that merely contain it - Rails' `format.json` responder
    * label, a `mod mail` string literal and an `/oauth/token` URL are not the json, mail and oauth
    * gems, and on lobsters' flows they made up most of those purls before the case rule. The former
    * `.*(::)?<Name>(::).*` form required a lowercase name followed by `::`, which no real call site
    * satisfies - on lobsters all 186 gem components matched zero calls, so no flow could carry a
    * purl. Gem purls do not come through here: [[rubyConstantPath]] nests their `-` segments, and
    * [[rubyModulePattern]] builds the pattern for both paths.
    */
  private def toRubyModuleForm(str: String): String =
    if str.isEmpty then return str
    rubyModulePattern(
      str.split("::").toList.map(
        _.split("_").map(word =>
            if word.isEmpty then word else word.charAt(0).toUpper + word.drop(1)
        ).mkString
      )
    )

  private def language: String = atom.metaData.language.headOption.getOrElse("")
end CdxPass
