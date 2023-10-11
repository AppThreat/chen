package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern
import scala.io.Source

/** Creates tags on typeDecl and call nodes based on a cdx document
  */
class CdxPass(cpg: Cpg) extends CpgPass(cpg) {

  // tags list as a seed
  private val keywords: List[String] = Source.fromResource("tags-vocab.txt").getLines.toList

  private def containsRegex(str: String) = Pattern.quote(str) == str

  private val BOM_JSON_FILE = "bom.json"

  override def run(dstGraph: DiffGraphBuilder): Unit = {
    cpg.configFile(BOM_JSON_FILE).content.foreach { cdxData =>
      val cdxJson         = parse(cdxData).getOrElse(Json.Null)
      val cursor: HCursor = cdxJson.hcursor
      val components      = cursor.downField("components").focus.flatMap(_.asArray).getOrElse(Vector.empty)
      components.foreach { comp =>
        val PURL_TYPE               = "purl"
        val compPurl                = comp.hcursor.downField(PURL_TYPE).as[String].getOrElse("")
        val compType                = comp.hcursor.downField("type").as[String].getOrElse("")
        val compDescription: String = comp.hcursor.downField("description").as[String].getOrElse("")
        val descTags                = keywords.filter(k => compDescription.toLowerCase().contains(" " + k))
        val properties = comp.hcursor.downField("properties").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        properties.foreach { ns =>
          val nsstr = ns.hcursor.downField("value").as[String].getOrElse("")
          nsstr.split("\n").filterNot(_.contains("test")).filterNot(_.contains("mock")).foreach { (pkg: String) =>
            val bpkg = pkg.takeWhile(_ != '$')
            cpg.call.typeFullNameExact(bpkg).newTagNode(compPurl).store()(dstGraph)
            cpg.method.parameter.typeFullNameExact(bpkg).newTagNode(compPurl).store()(dstGraph)
            if (!containsRegex(bpkg))
              cpg.method.fullName(s"${Pattern.quote(bpkg)}.*").newTagNode(compPurl).store()(dstGraph)
            if (compType != "library") {
              cpg.call.typeFullNameExact(bpkg).newTagNode(compType).store()(dstGraph)
              cpg.call.typeFullNameExact(bpkg).receiver.newTagNode(s"$compType-value").store()(dstGraph)
              cpg.method.parameter.typeFullNameExact(bpkg).newTagNode(compType).store()(dstGraph)
              if (!containsRegex(bpkg))
                cpg.method.fullName(s"${Pattern.quote(bpkg)}.*").newTagNode(compType).store()(dstGraph)
            }
            if (compType == "framework") {
              def frameworkAnnotatedMethod = cpg.annotation
                .fullNameExact(bpkg)
                .method
              frameworkAnnotatedMethod.parameter
                .newTagNode(s"$compType-input")
                .store()(dstGraph)
              cpg.ret
                .where(_.method.annotation.fullNameExact(bpkg))
                .newTagNode(s"$compType-output")
                .store()(dstGraph)
            }
            descTags.foreach { t =>
              cpg.call.typeFullNameExact(bpkg).newTagNode(t).store()(dstGraph)
              cpg.method.parameter.typeFullNameExact(bpkg).newTagNode(t).store()(dstGraph)
              if (!containsRegex(bpkg))
                cpg.method.fullName(s"${Pattern.quote(bpkg)}.*").newTagNode(t).store()(dstGraph)
            }
          }
        }
      }
    }
  }

}
