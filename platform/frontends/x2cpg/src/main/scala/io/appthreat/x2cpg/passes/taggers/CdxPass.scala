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
import scala.io.Source

/** Creates tags on typeDecl and call nodes based on a cdx document
  */
class CdxPass(atom: Cpg) extends CpgPass(atom):

  val language: String = atom.metaData.language.head

  // Number of tags needed
  private val TAGS_COUNT: Int = 3

  // Number of dots to use in the package namespace
  // Example: org.apache.logging.* would be used for tagging purposes
  private val PKG_NS_SIZE: Int = 3

  // tags list as a seed
  private val keywords: List[String] = Source.fromResource("tags-vocab.txt").getLines.toList

  private def containsRegex(str: String) =
    val reChars = "[](){}*+&|?.,\\$"
    str.exists(reChars.contains(_))

  private val BOM_JSON_FILE = ".*(bom|cdx).json"

  private def toPyModuleForm(str: String) =
      if str.nonEmpty then
        val tmpParts = str.split("\\.")
        if str.count(_ == '.') > 1 then
          s"${tmpParts.take(2).mkString(Pattern.quote(File.separator))}.*"
        else if str.count(_ == '.') == 1 then s"${tmpParts.head}.py:<module>.*"
        else s"$str.py:<module>.*"
      else
        str

  private def toRubyModuleForm(str: String) =
      if str.nonEmpty then
        s".*(::)?${str.split("::").head}(::).*"
      else
        str

  override def run(dstGraph: DiffGraphBuilder): Unit =
      atom.configFile.name(BOM_JSON_FILE).content.foreach { cdxData =>
        val cdxJson         = parse(cdxData).getOrElse(Json.Null)
        val cursor: HCursor = cdxJson.hcursor
        val components =
            cursor.downField("components").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        val donePkgs = mutable.Map[String, Boolean]()
        components.foreach { comp =>
          val PURL_TYPE = "purl"
          val compPurl  = comp.hcursor.downField(PURL_TYPE).as[String].getOrElse("")
          val compType  = comp.hcursor.downField("type").as[String].getOrElse("")
          val compDescription: String =
              comp.hcursor.downField("description").as[String].getOrElse("")
          // Reuse existing tags from the xBOM
          val compTags: List[String] =
              comp.hcursor.downField("tags").as[List[String]].getOrElse(List.empty)
          val descTags = if compTags.nonEmpty then compTags.take(TAGS_COUNT)
          else
            keywords.filter(k =>
                compDescription.toLowerCase().contains(" " + k)
            ).take(TAGS_COUNT)
          if (language == Languages.PYTHON || language == Languages.PYTHONSRC) && compPurl.startsWith(
              "pkg:pypi"
            )
          then
            val pkgName = compPurl.split("@").head.replace("pkg:pypi/", "")
                .replace("python-", "")
                .replace("-", "_");
            Set(
              pkgName,
              pkgName.replace("flask_", ""),
              pkgName.replace("django_", ""),
              pkgName.replace("py", "")
            ).foreach { ns =>
                Set(toPyModuleForm(ns), s"$ns${Pattern.quote(File.separator)}.*").foreach {
                    bpkg =>
                      if bpkg.nonEmpty && !donePkgs.contains(bpkg) then
                        donePkgs.put(bpkg, true)
                      atom.call.where(
                        _.methodFullName(bpkg)
                      ).newTagNode(compPurl).store()(dstGraph)
                      atom.identifier.typeFullName(bpkg).newTagNode(
                        compPurl
                      ).store()(dstGraph)
                }
            }
          end if
          val properties = comp.hcursor.downField("properties").focus.flatMap(
            _.asArray
          ).getOrElse(Vector.empty)
          properties.foreach { ns =>
            val nsstr  = ns.hcursor.downField("value").as[String].getOrElse("")
            val nsname = ns.hcursor.downField("name").as[String].getOrElse("")
            // Skip the SrcFile, ResolvedUrl, GradleProfileName, cdx: properties
            if nsname != "SrcFile" && nsname != "ResolvedUrl" && nsname != "GradleProfileName" && !nsname
                  .startsWith(
                    "cdx:"
                  )
            then
              nsstr
                  .split("(\n|,)")
                  .filterNot(_.startsWith("java."))
                  .filterNot(_.startsWith("com.sun"))
                  .filterNot(_.contains("test"))
                  .filterNot(_.contains("mock"))
                  .foreach { (pkg: String) =>
                    var bpkg = pkg.takeWhile(_ != '$')
                    if language == Languages.JAVA || language == Languages.JAVASRC then
                      bpkg = bpkg.split("\\.").take(PKG_NS_SIZE).mkString(".").concat(
                        ".*"
                      ).replace(File.separator, Pattern.quote(File.separator))
                    if language == Languages.JSSRC || language == Languages.JAVASCRIPT
                    then
                      bpkg = bpkg.replace(File.separator, Pattern.quote(File.separator))
                    if language == Languages.PYTHON || language == Languages.PYTHONSRC
                    then bpkg = toPyModuleForm(bpkg)
                    if language == Languages.RUBYSRC
                    then bpkg = toRubyModuleForm(bpkg)
                    if language == Languages.PHP
                    then
                      bpkg = bpkg.replace("\\", "\\\\").concat(".*")
                    if bpkg.nonEmpty && !donePkgs.contains(bpkg) then
                      donePkgs.put(bpkg, true)
                      // Ruby
                      if language == Languages.RUBYSRC
                      then
                        atom.call.code(bpkg).argument.newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        atom.call.code(bpkg).receiver.isMethod.where(_.fullName(
                          s"((app|config)${Pattern.quote(File.separator)})?(routes|controller(s)?|model(s)?|application).*\\.rb.*"
                        )).parameter.newTagNode("framework-input").store()(dstGraph)
                        atom.call.code(bpkg).receiver.newTagNode(
                          s"$compType-value"
                        ).store()(dstGraph)
                        atom.call.code(bpkg).callee(NoResolve).isMethod.parameter.newTagNode(
                          s"$compType-input"
                        ).store()(dstGraph)
                      // C/C++
                      else if language == Languages.NEWC || language == Languages.C
                      then
                        atom.method.fullNameExact(bpkg).callIn(
                          NoResolve
                        ).newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        atom.method.fullNameExact(bpkg).callIn(
                          NoResolve
                        ).newTagNode(
                          "library-call"
                        ).store()(dstGraph)
                        atom.method.fullNameExact(bpkg).newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        if !containsRegex(bpkg) then
                          atom.parameter.typeFullName(s"$bpkg.*").newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          atom.parameter.typeFullName(s"$bpkg.*").newTagNode(
                            "framework-input"
                          ).store()(dstGraph)
                          atom.parameter.typeFullName(s"$bpkg.*").method.callIn(
                            NoResolve
                          ).newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          atom.call.code(s".*\\.$bpkg.*").newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          atom.call.code(s".*\\.$bpkg.*").newTagNode(
                            "library-call"
                          ).store()(dstGraph)
                          atom.call.code(s"$bpkg->.*").newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          atom.call.code(s"$bpkg->.*").newTagNode(
                            "library-call"
                          ).store()(dstGraph)
                        else
                          atom.parameter.typeFullName(
                            s"${Pattern.quote(bpkg)}.*"
                          ).newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          atom.parameter.typeFullName(
                            s"${Pattern.quote(bpkg)}.*"
                          ).newTagNode(
                            "framework-input"
                          ).store()(dstGraph)
                          atom.parameter.typeFullName(
                            s"${Pattern.quote(bpkg)}.*"
                          ).method.callIn(
                            NoResolve
                          ).newTagNode(
                            compPurl
                          ).store()(dstGraph)
                        end if
                      else if !containsRegex(bpkg) then
                        atom.call.typeFullNameExact(bpkg).newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        atom.identifier.typeFullNameExact(bpkg).newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        atom.method.parameter.typeFullNameExact(bpkg).newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        atom.method.fullName(
                          s"${Pattern.quote(bpkg)}.*"
                        ).newTagNode(compPurl).store()(dstGraph)
                      else
                        atom.call.typeFullName(bpkg).newTagNode(compPurl).store()(
                          dstGraph
                        )
                        atom.identifier.typeFullName(bpkg).newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        atom.method.parameter.typeFullName(bpkg).newTagNode(
                          compPurl
                        ).store()(dstGraph)
                        atom.method.fullName(bpkg).newTagNode(compPurl).store()(
                          dstGraph
                        )
                        if language == Languages.JSSRC || language == Languages.JAVASCRIPT
                        then
                          atom.method.name(bpkg).external.newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          atom.method.name(bpkg).external.parameter.newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          atom.method.name(bpkg).external.callIn(NoResolve).argument.newTagNode(
                            compPurl
                          ).store()(dstGraph)
                          if bpkg.contains(File.separator) then
                            val segments   = bpkg.split(Pattern.quote(File.separator))
                            val truncated  = segments.take(2).mkString(File.separator)
                            val re_variant = s".*${truncated}.*"
                            atom.method.fullName(re_variant).external.newTagNode(
                              compPurl
                            ).store()(dstGraph)
                            atom.method.fullName(re_variant).external.parameter.newTagNode(
                              compPurl
                            ).store()(dstGraph)
                            atom.method.fullName(re_variant).external.callIn(NoResolve).argument.newTagNode(
                              compPurl
                            ).store()(dstGraph)
                            if compType != "library" then
                              atom.method.fullName(re_variant).external.parameter.newTagNode(
                                compType
                              ).store()(dstGraph)
                              atom.method.fullName(re_variant).external.callIn(NoResolve).argument.newTagNode(
                                compType
                              ).store()(dstGraph)
                          end if
                          if compType != "library" then
                            atom.method.name(bpkg).external.parameter.newTagNode(
                              compType
                            ).store()(dstGraph)
                            atom.method.name(bpkg).external.callIn(NoResolve).argument.newTagNode(
                              compType
                            ).store()(dstGraph)
                        end if
                        if language == Languages.PYTHON || language == Languages.PYTHONSRC
                        then
                          atom.call.where(
                            _.methodFullName(bpkg)
                          ).argument.newTagNode(compPurl).store()(dstGraph)
                          atom.identifier.typeFullName(bpkg).newTagNode(
                            compPurl
                          ).store()(dstGraph)
                      end if
                      if compType != "library" then
                        if !containsRegex(bpkg) then
                          atom.call.typeFullNameExact(bpkg).newTagNode(
                            compType
                          ).store()(dstGraph)
                          atom.call.typeFullNameExact(bpkg).receiver.newTagNode(
                            s"$compType-value"
                          ).store()(dstGraph)
                          atom.method.parameter.typeFullNameExact(
                            bpkg
                          ).newTagNode(compType).store()(dstGraph)
                          atom.method.fullName(
                            s"${Pattern.quote(bpkg)}.*"
                          ).newTagNode(compType).store()(dstGraph)
                        else
                          atom.call.typeFullName(bpkg).newTagNode(
                            compType
                          ).store()(dstGraph)
                          atom.call.typeFullName(bpkg).receiver.newTagNode(
                            s"$compType-value"
                          ).store()(dstGraph)
                          atom.method.parameter.typeFullName(bpkg).newTagNode(
                            compType
                          ).store()(dstGraph)
                          atom.method.fullName(bpkg).newTagNode(compType).store()(
                            dstGraph
                          )
                          if language == Languages.PYTHON || language == Languages.PYTHONSRC
                          then
                            atom.call.where(
                              _.methodFullName(bpkg)
                            ).argument.newTagNode(compType).store()(dstGraph)
                      end if
                      if compType == "framework" then
                        def frameworkAnnotatedMethod = atom.annotation
                            .fullName(bpkg)
                            .method

                        frameworkAnnotatedMethod.parameter
                            .newTagNode(s"$compType-input")
                            .store()(dstGraph)
                        atom.ret
                            .where(_.method.annotation.fullName(bpkg))
                            .newTagNode(s"$compType-output")
                            .store()(dstGraph)
                      descTags.foreach { t =>
                        atom.call.typeFullName(bpkg).newTagNode(t).store()(dstGraph)
                        atom.identifier.typeFullName(bpkg).newTagNode(t).store()(
                          dstGraph
                        )
                        atom.method.parameter.typeFullName(bpkg).newTagNode(
                          t
                        ).store()(dstGraph)
                        if !containsRegex(bpkg) then
                          atom.method.fullName(
                            s"${Pattern.quote(bpkg)}.*"
                          ).newTagNode(t).store()(dstGraph)
                        else
                          atom.method.fullName(bpkg).newTagNode(t).store()(
                            dstGraph
                          )
                          if language == Languages.PYTHON || language == Languages.PYTHONSRC
                          then
                            atom.call.where(
                              _.methodFullName(bpkg)
                            ).newTagNode(t).store()(dstGraph)
                            atom.identifier.typeFullName(bpkg).newTagNode(
                              t
                            ).store()(dstGraph)
                      }
                    end if
                  }
            end if
          }
        }
      }
  end run
end CdxPass
