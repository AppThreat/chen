package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.NewNamespace
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** Creates tags on any node
  */
class ChennaiTagsPass(cpg: Cpg) extends CpgPass(cpg) {

  override def run(dstGraph: DiffGraphBuilder): Unit = {
    cpg.configFile(".chennai.json").content.foreach { cdxData =>
      val ctagsJson       = parse(cdxData).getOrElse(Json.Null)
      val cursor: HCursor = ctagsJson.hcursor
      val tags            = cursor.downField("tags").focus.flatMap(_.asArray).getOrElse(Vector.empty)
      tags.foreach { comp =>
        val tagName    = comp.hcursor.downField("name").as[String].getOrElse("")
        val tagParams  = comp.hcursor.downField("parameters").downArray.as[String]
        val tagMethods = comp.hcursor.downField("methods").downArray.as[String]
        val tagTypes   = comp.hcursor.downField("types").downArray.as[String]
        val tagFiles   = comp.hcursor.downField("files").downArray.as[String]
        tagParams.foreach { paramName =>
          cpg.method.parameter.typeFullNameExact(paramName).newTagNode(tagName).store()(dstGraph)
          cpg.method.parameter.typeFullName(paramName).newTagNode(tagName).store()(dstGraph)
        }
        tagMethods.foreach { methodName =>
          cpg.method.fullNameExact(methodName).newTagNode(tagName).store()(dstGraph)
          cpg.method.fullName(methodName).newTagNode(tagName).store()(dstGraph)
          cpg.call.typeFullNameExact(methodName).newTagNode(tagName).store()(dstGraph)
        }
        tagTypes.foreach { typeName =>
          cpg.typeDecl.fullNameExact(typeName).newTagNode(tagName).store()(dstGraph)
          cpg.typeDecl.fullName(typeName).newTagNode(tagName).store()(dstGraph)
          cpg.call.typeFullNameExact(typeName).newTagNode(tagName).store()(dstGraph)
        }
        tagFiles.foreach { fileName =>
          cpg.file.nameExact(fileName).newTagNode(tagName).store()(dstGraph)
          cpg.file.name(fileName).newTagNode(tagName).store()(dstGraph)
        }
      }
    }
  }

}
