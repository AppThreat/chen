package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.io.File
import java.util.regex.Pattern
import scala.collection.mutable

class CdxPass(
  atom: Cpg
) extends CpgPass(atom):

  private val TAGS_COUNT    = 3
  private val PKG_NS_SIZE   = 3
  private val BOM_JSON_FILE = ".*(bom|cdx).json"

  /** Component properties whose value is a list of package namespaces, matched after stripping an
    * optional `internal:` prefix so that cdxgen v13 SBOMs (`internal:Namespaces`) and older ones
    * (`Namespaces`) behave identically. Every other property (SrcFile, ResolvedUrl, digests,
    * classifiers, ...) is not a namespace list and must not reach `normalizePackage`.
    * `ImportedModules` is deliberately absent: it is pypi-specific and read directly by
    * `processPypiComponent`, which turns the imported symbols into module patterns.
    */
  private val NAMESPACE_PROPERTIES = Set("Namespaces")

  override def run(dstGraph: DiffGraphBuilder): Unit =
      atom.configFile.name(BOM_JSON_FILE).content.foreach { cdxData =>
          parse(cdxData) match
            case Right(json) =>
                val components =
                    json.hcursor.downField("components").focus.flatMap(_.asArray).getOrElse(
                      Vector.empty
                    )
                val donePkgs             = mutable.Set[String]()
                val unambiguousJvmGroups = jvmGroupsNamingOneComponent(components)

                components.foreach(
                  processComponent(_, donePkgs, unambiguousJvmGroups, dstGraph)
                )
            case Left(error) =>
                System.err.println(s"Failed to parse cdx json: $error")
      }

  private def processComponent(
    comp: Json,
    donePkgs: mutable.Set[String],
    unambiguousJvmGroups: Set[String],
    dstGraph: DiffGraphBuilder
  ): Unit =
    val cursor          = comp.hcursor
    val compPurl        = cursor.downField("purl").as[String].getOrElse("")
    val compType        = cursor.downField("type").as[String].getOrElse("")
    val compDescription = cursor.downField("description").as[String].getOrElse("")
    val compTags        = cursor.downField("tags").as[List[String]].getOrElse(List.empty)

    val descTags = if compTags.nonEmpty then compTags.take(TAGS_COUNT)
    else CdxTagVocab.extractDescTags(compDescription).take(TAGS_COUNT)

    processPypiComponent(cursor, compPurl, compType, descTags, donePkgs, dstGraph)
    val taggedFromProperties =
        processProperties(cursor, compPurl, compType, descTags, donePkgs, dstGraph)
    if !taggedFromProperties then
      processJvmPurl(compPurl, compType, descTags, donePkgs, unambiguousJvmGroups, dstGraph)
  end processComponent

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
    donePkgs: mutable.Set[String],
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
              if bpkg.nonEmpty && donePkgs.add(bpkg) then
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

  private def processPypiComponent(
    cursor: HCursor,
    purl: String,
    compType: String,
    descTags: List[String],
    donePkgs: mutable.Set[String],
    dstGraph: DiffGraphBuilder
  ): Unit =
      if (language == Languages.PYTHON || language == Languages.PYTHONSRC) && purl.startsWith(
          "pkg:pypi"
        )
      then
        val pkgName = purl
            .split("@").head
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
              if bpkg.nonEmpty && donePkgs.add(bpkg) then
                // `methodFullName` is the pypi path's own traversal: a module-form
                // pattern matches the call's method, not its type. Everything else a
                // component implies - the purl on types and parameters, the component
                // type, the description tags - is the same work `processProperties`
                // does, so it is applied from one place for both paths.
                atom.call.where(_.methodFullName(bpkg)).newTagNode(purl).store()(using dstGraph)
                tagByLanguage(bpkg, purl, compType, descTags, dstGraph)
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
    donePkgs: mutable.Set[String],
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
                if donePkgs.add(bpkg) then
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
    dstGraph: DiffGraphBuilder
  ): Unit =
      language match
        case lang if lang == Languages.RUBYSRC =>
            tagRuby(bpkg, purl, compType, dstGraph)
        case lang if lang == Languages.NEWC || lang == Languages.C =>
            tagCpp(bpkg, purl, compType, descTags, dstGraph)
        case _ =>
            tagGeneric(bpkg, purl, compType, descTags, dstGraph)

  private def tagRuby(
    bpkg: String,
    purl: String,
    compType: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
    atom.call.code(bpkg).argument.newTagNode(purl).store()(using dstGraph)
    atom.call.code(bpkg).receiver.isMethod.where(_.fullName(
      s"((app|config)${Pattern.quote(File.separator)})?(routes|controller(s)?|model(s)?|application).*\\.rb.*"
    ))
        .parameter.newTagNode("framework-input").store()(using dstGraph)
    atom.call.code(bpkg).receiver.newTagNode(s"$compType-value").store()(using dstGraph)
    atom.call.code(bpkg).callee(using NoResolve).isMethod.parameter.newTagNode(s"$compType-input")
        .store()(
          using dstGraph
        )

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
    dstGraph: DiffGraphBuilder
  ): Unit =
    val isRegex = containsRegex(bpkg)
    val pattern = if isRegex then Pattern.quote(bpkg) else bpkg

    atom.call.typeFullName(if isRegex then bpkg else pattern).newTagNode(purl).store()(using
    dstGraph)
    atom.identifier.typeFullName(if isRegex then bpkg else pattern).newTagNode(purl).store()(
      using dstGraph
    )
    atom.method.parameter.typeFullName(if isRegex then bpkg else pattern).newTagNode(purl).store()(
      using dstGraph
    )

    if !isRegex then
      atom.method.fullName(s"$pattern.*").newTagNode(purl).store()(using dstGraph)
    else
      atom.method.fullName(bpkg).newTagNode(purl).store()(using dstGraph)

    if compType != "library" then
      atom.call.typeFullName(if isRegex then bpkg else pattern).newTagNode(compType).store()(
        using dstGraph
      )
      atom.method.parameter.typeFullName(if isRegex then bpkg else pattern).newTagNode(compType)
          .store()(using dstGraph)
      atom.method.fullName(if isRegex then bpkg else s"$pattern.*").newTagNode(compType).store()(
        using dstGraph
      )

    descTags.foreach { tag =>
      atom.call.typeFullName(if isRegex then bpkg else pattern).newTagNode(tag).store()(using
      dstGraph)
      atom.identifier.typeFullName(if isRegex then bpkg else pattern).newTagNode(tag).store()(
        using dstGraph
      )
      atom.method.parameter.typeFullName(if isRegex then bpkg else pattern).newTagNode(tag).store()(
        using dstGraph
      )
      atom.method.fullName(if isRegex then bpkg else s"$pattern.*").newTagNode(tag).store()(
        using dstGraph
      )
    }
  end tagGeneric

  private def containsRegex(str: String): Boolean =
    val reChars = "[](){}*+&|?.,\\$"
    str.exists(reChars.contains)

  /** The full-name pattern shape for Python. This is the blocking constraint from Task 6: the
    * pattern form MUST match the representation the frontend produced, or every purl, `framework`
    * and description tag silently zeroes out.
    */
  private def toPyModuleForm(str: String): String =
    if str.isEmpty then return str
    val parts = str.split("\\.")
    if parts.length > 1 then s"${parts.mkString("\\.")}.*"
    else s"${parts.head}\\..*"

  private def toRubyModuleForm(str: String): String =
    if str.isEmpty then return str
    s".*(::)?${str.split("::").head}(::).*"

  private def language: String = atom.metaData.language.headOption.getOrElse("")
end CdxPass
