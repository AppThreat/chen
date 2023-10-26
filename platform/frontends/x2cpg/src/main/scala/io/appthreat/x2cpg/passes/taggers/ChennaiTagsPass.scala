package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern

/** Creates tags on any node
  */
class ChennaiTagsPass(atom: Cpg) extends CpgPass(atom) {

  val language: String         = atom.metaData.language.head
  private val FRAMEWORK_ROUTE  = "framework-route"
  private val FRAMEWORK_INPUT  = "framework-input"
  private val FRAMEWORK_OUTPUT = "framework-output"

  private val PYTHON_ROUTES_CALL_REGEXES =
    Array("django/(conf/)?urls.py:<module>.(path|re_path|url).*", ".*(route|web\\.).*")
  private val PYTHON_ROUTES_DECORATORS_REGEXES = Array(
    ".*(route|endpoint|_request|require_http_methods|require_GET|require_POST|require_safe|_required)\\(.*"
  )
  private val HTTP_METHODS_REGEX = ".*(request|session)\\.(args|get|post|form).*"
  private def tagPythonRoutes(dstGraph: DiffGraphBuilder): Unit = {
    PYTHON_ROUTES_CALL_REGEXES.foreach { r =>
      atom.call
        .where(_.methodFullName(r))
        .argument
        .isLiteral
        .newTagNode(FRAMEWORK_ROUTE)
        .store()(dstGraph)

      PYTHON_ROUTES_DECORATORS_REGEXES.foreach { r =>
        def decoratedMethods = atom.methodRef
          .where(_.inCall.code(r).argument)
          ._refOut
          .collectAll[Method]
        decoratedMethods.call.assignment
          .code(HTTP_METHODS_REGEX)
          .argument
          .isIdentifier
          .newTagNode(FRAMEWORK_INPUT)
          .store()(dstGraph)
        decoratedMethods
          .newTagNode(FRAMEWORK_INPUT)
          .store()(dstGraph)
        decoratedMethods.parameter
          .newTagNode(FRAMEWORK_INPUT)
          .store()(dstGraph)
      }
      atom.ret
        .where(_.method.tag.name(FRAMEWORK_INPUT))
        .newTagNode(FRAMEWORK_OUTPUT)
        .store()(dstGraph)
    }
  }

  override def run(dstGraph: DiffGraphBuilder): Unit = {
    if (language == Languages.PYTHON || language == Languages.PYTHONSRC) tagPythonRoutes(dstGraph)
    atom.configFile("chennai.json").content.foreach { cdxData =>
      val ctagsJson       = parse(cdxData).getOrElse(Json.Null)
      val cursor: HCursor = ctagsJson.hcursor
      val tags            = cursor.downField("tags").focus.flatMap(_.asArray).getOrElse(Vector.empty)
      tags.foreach { comp =>
        val tagName    = comp.hcursor.downField("name").as[String].getOrElse("")
        val tagParams  = comp.hcursor.downField("parameters").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        val tagMethods = comp.hcursor.downField("methods").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        val tagTypes   = comp.hcursor.downField("types").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        val tagFiles   = comp.hcursor.downField("files").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        tagParams.foreach { paramName =>
          val pn = paramName.asString.getOrElse("")
          if (pn.nonEmpty) {
            atom.method.parameter.typeFullNameExact(pn).newTagNode(tagName).store()(dstGraph)
            if (!pn.contains("[") && !pn.contains("*"))
              atom.method.parameter.typeFullName(s".*${Pattern.quote(pn)}.*").newTagNode(tagName).store()(dstGraph)
          }
        }
        tagMethods.foreach { methodName =>
          val mn = methodName.asString.getOrElse("")
          if (mn.nonEmpty) {
            atom.method.fullNameExact(mn).newTagNode(tagName).store()(dstGraph)
            if (!mn.contains("[") && !mn.contains("*"))
              atom.method.fullName(s".*${Pattern.quote(mn)}.*").newTagNode(tagName).store()(dstGraph)
          }
        }
        tagTypes.foreach { typeName =>
          val tn = typeName.asString.getOrElse("")
          if (tn.nonEmpty) {
            atom.method.parameter.typeFullNameExact(tn).newTagNode(tagName).store()(dstGraph)
            if (!tn.contains("[") && !tn.contains("*"))
              atom.method.parameter.typeFullName(s".*${Pattern.quote(tn)}.*").newTagNode(tagName).store()(dstGraph)
            atom.call.typeFullNameExact(tn).newTagNode(tagName).store()(dstGraph)
            if (!tn.contains("[") && !tn.contains("*"))
              atom.call.typeFullName(s".*${Pattern.quote(tn)}.*").newTagNode(tagName).store()(dstGraph)
          }
        }
        tagFiles.foreach { fileName =>
          val fn = fileName.asString.getOrElse("")
          if (fn.nonEmpty) {
            atom.file.nameExact(fn).newTagNode(tagName).store()(dstGraph)
            if (!fn.contains("[") && !fn.contains("*"))
              atom.file.name(s".*${Pattern.quote(fn)}.*").newTagNode(tagName).store()(dstGraph)
          }
        }
      }
    }
  }

}
