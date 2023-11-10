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
    private val TAGS_COUNT: Int = 2

    // Number of dots to use in the package namespace
    // Example: org.apache.logging.* would be used for tagging purposes
    private val PKG_NS_SIZE: Int = 3

    // tags list as a seed
    private val keywords: List[String] = Source.fromResource("tags-vocab.txt").getLines.toList

    // FIXME: Replace these with semantic fingerprints
    private def JS_REQUEST_PATTERNS =
        Array(
          "(?s)(?i).*(req|ctx|context)\\.(originalUrl|path|protocol|route|secure|signedCookies|stale|subdomains|xhr|app|pipe|file|files|baseUrl|fresh|hostname|ip|url|ips|method|body|param|params|query|cookies|request).*"
        )

    private def JS_RESPONSE_PATTERNS =
        Array(
          "(?s)(?i).*(res|ctx|context)\\.(append|attachment|body|cookie|download|end|format|json|jsonp|links|location|redirect|render|send|sendFile|sendStatus|set|vary).*",
          "(?s)(?i).*res\\.(set|writeHead|setHeader).*",
          "(?s)(?i).*(db|dao|mongo|mongoclient).*",
          "(?s)(?i).*(\\s|\\.)(list|create|upload|delete|execute|command|invoke|submit|send)"
        )

    private def PY_REQUEST_PATTERNS = Array(".*views.py:<module>.*")

    private def containsRegex(str: String) = Pattern.quote(str) == str || str.contains("*")

    private val BOM_JSON_FILE = ".*(bom|cdx).json"

    private def toPyModuleForm(str: String) =
        if str.nonEmpty then
            val tmpParts = str.split("\\.")
            if str.count(_ == '.') > 1 then
                s"${tmpParts.take(2).mkString(Pattern.quote(File.separator))}.*"
            else if str.count(_ == '.') == 1 then s"${tmpParts.head}.py:<module>.*"
            else str
        else if str.nonEmpty then
            s"$str${Pattern.quote(File.separator)}.*"
        else
            str

    override def run(dstGraph: DiffGraphBuilder): Unit =
        atom.configFile.name(BOM_JSON_FILE).content.foreach { cdxData =>
            val cdxJson         = parse(cdxData).getOrElse(Json.Null)
            val cursor: HCursor = cdxJson.hcursor
            val components =
                cursor.downField("components").focus.flatMap(_.asArray).getOrElse(Vector.empty)
            val donePkgs = mutable.Map[String, Boolean]()
            if language == Languages.JSSRC || language == Languages.JAVASCRIPT then
                JS_REQUEST_PATTERNS.foreach(p =>
                    atom.call.code(p).newTagNode("framework-input").store()(dstGraph)
                )
                JS_RESPONSE_PATTERNS.foreach(p =>
                    atom.call.code(p).newTagNode("framework-output").store()(dstGraph)
                )
            if language == Languages.PYTHON || language == Languages.PYTHONSRC then
                PY_REQUEST_PATTERNS
                    .foreach(p =>
                        atom.method.fullName(p).parameter.newTagNode("framework-input").store()(
                          dstGraph
                        )
                    )
            components.foreach { comp =>
                val PURL_TYPE = "purl"
                val compPurl  = comp.hcursor.downField(PURL_TYPE).as[String].getOrElse("")
                val compType  = comp.hcursor.downField("type").as[String].getOrElse("")
                val compDescription: String =
                    comp.hcursor.downField("description").as[String].getOrElse("")
                val descTags = keywords.filter(k =>
                    compDescription.toLowerCase().contains(" " + k)
                ).take(TAGS_COUNT)
                val properties = comp.hcursor.downField("properties").focus.flatMap(
                  _.asArray
                ).getOrElse(Vector.empty)
                properties.foreach { ns =>
                    val nsstr  = ns.hcursor.downField("value").as[String].getOrElse("")
                    val nsname = ns.hcursor.downField("name").as[String].getOrElse("")
                    // Skip the SrcFile property
                    if nsname != "SrcFile" then
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
                                    )
                                    bpkg =
                                        bpkg.replace(File.separator, Pattern.quote(File.separator))
                                if language == Languages.JSSRC || language == Languages.JAVASCRIPT
                                then
                                    bpkg = s".*${bpkg}.*"
                                    bpkg =
                                        bpkg.replace(File.separator, Pattern.quote(File.separator))
                                if language == Languages.PYTHON || language == Languages.PYTHONSRC
                                then bpkg = toPyModuleForm(bpkg)
                                if bpkg.nonEmpty && !donePkgs.contains(bpkg) then
                                    donePkgs.put(bpkg, true)
                                    if !containsRegex(bpkg) then
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
                                            atom.call.code(bpkg).argument.newTagNode(
                                              compPurl
                                            ).store()(dstGraph)
                                            atom.identifier.code(bpkg).newTagNode(compPurl).store()(
                                              dstGraph
                                            )
                                            atom.identifier.code(bpkg).inCall.newTagNode(
                                              compPurl
                                            ).store()(dstGraph)
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
                                            if language == Languages.JSSRC || language == Languages.JAVASCRIPT
                                            then
                                                atom.call.code(bpkg).argument.newTagNode(
                                                  compType
                                                ).store()(dstGraph)
                                                atom.identifier.code(bpkg).newTagNode(
                                                  compType
                                                ).store()(dstGraph)
                                                atom.identifier.code(bpkg).inCall.newTagNode(
                                                  compType
                                                ).store()(dstGraph)
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
                                    }
                                end if
                            }
                    end if
                }
            }
        }
end CdxPass
