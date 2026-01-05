package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method, MethodRef}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern
import scala.util.{Try, Using}

/** Creates tags on any node based on framework patterns and configuration */
class ChennaiTagsPass(atom: Cpg) extends CpgPass(atom):

  private val FRAMEWORK_ROUTE      = "framework-route"
  private val FRAMEWORK_INPUT      = "framework-input"
  private val FRAMEWORK_OUTPUT     = "framework-output"
  private val EscapedFileSeparator = Pattern.quote(java.io.File.separator)
  private val RE_CHARS             = "[](){}*+&|?.,\\$"

  // Language-specific route patterns
  private val PYTHON_ROUTES_CALL_REGEXES = Array(
    s"django$EscapedFileSeparator(conf$EscapedFileSeparator)?urls.py:<module>.(path|re_path|url).*".r,
    ".*(route|web\\.|add_resource).*".r
  )

  private val PYTHON_ROUTES_DECORATORS_REGEXES = Array(
    ".*(route|endpoint|_request|require_http_methods|require_GET|require_POST|require_safe|_required|api\\.doc|api\\.response|api\\.errorhandler)\\(.*",
    ".*def\\s(get|post|put)\\(.*"
  )

  private val PHP_ROUTES_METHODS_REGEXES = Array(
    ".*(router|routes|r|app|map)->(addRoute|add|before|mount|get|post|put|delete|head|option).*",
    ".*(Router)::(scope|connect|get|post|put|delete|head|option).*"
  )

  private val JS_ROUTES_CALL_REGEX =
      ".*(?i)(app|router|route|server)\\.(get|post|put|delete|patch|head|options|all|use|registerRoute).*"
  private val VUE_ROUTE_INPUT_REGEX = ".*\\$route\\.(params|query|body).*"

  private val HTTP_METHODS_REGEX  = ".*(request|session)\\.(args|get|post|put|form).*"
  private val CHENNAI_CONFIG_FILE = "chennai.json"

  private def language: String = atom.metaData.language.headOption.getOrElse("")

  override def run(dstGraph: DiffGraphBuilder): Unit =
    tagFrameworkRoutes(dstGraph)
    processChennaiConfig(dstGraph)

  private def tagFrameworkRoutes(dstGraph: DiffGraphBuilder): Unit =
      language match
        case lang if lang == Languages.PYTHON || lang == Languages.PYTHONSRC =>
            tagPythonRoutes(dstGraph)
        case lang if lang == Languages.NEWC || lang == Languages.C =>
            tagCRoutes(dstGraph)
        case lang if lang == Languages.PHP =>
            tagPhpRoutes(dstGraph)
        case lang if lang == Languages.RUBYSRC =>
            tagRubyRoutes(dstGraph)
        case lang if lang == Languages.JSSRC || lang == Languages.JAVASCRIPT =>
            tagJsRoutes(dstGraph)
        case _ => // No specific routing for this language
  private def tagJsRoutes(dstGraph: DiffGraphBuilder): Unit =
    val routeCalls = atom.call.filter { c =>
        c.methodFullName.matches(JS_ROUTES_CALL_REGEX) ||
        c.code.matches(JS_ROUTES_CALL_REGEX)
    }
    routeCalls.foreach { call =>
      call.argument
          .isLiteral
          .headOption
          .newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
      call.argument
          .lastOption
          .flatMap {
              case r: MethodRef => r._refOut.collectFirst { case m: Method => m }
              case arg          => arg._refOut.collectFirst { case m: Method => m }
          }
          .foreach { handlerMethod =>
            val params = handlerMethod.parameter.l.sortBy(_.order)
            if params.nonEmpty then
              Iterator(params.head).newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
            if params.size >= 2 then
              Iterator(params(1)).newTagNode(FRAMEWORK_OUTPUT).store()(using dstGraph)
          }
    }
    atom.call
        .code(VUE_ROUTE_INPUT_REGEX)
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)
    val controllerMethods = atom.file.name(".*(route|controller|api).*(js|ts|jsx|tsx)")
        .method
        .internal
        .filterNot(_.name.contains("<"))
    controllerMethods
        .parameter
        .filterNot(_.name == "this")
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)
  end tagJsRoutes

  private def tagCRoutes(dstGraph: DiffGraphBuilder): Unit =
    val cRoutePatterns = Array(
      "Routes::(Post|Get|Delete|Head|Options|Put).*",
      "API_CALL",
      "API_CALL_ASYNC",
      "ENDPOINT",
      "ENDPOINT_ASYNC",
      "ENDPOINT_INTERCEPTOR",
      "ENDPOINT_INTERCEPTOR_ASYNC",
      "registerHandler",
      "PATH_ADD",
      "ADD_METHOD_TO",
      "ADD_METHOD_VIA_REGEX",
      "WS_PATH_ADD",
      "svr\\.(Post|Get|Delete|Head|Options|Put)"
    )

    cRoutePatterns.foreach { pattern =>
      atom.method.fullName(pattern).parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
      atom.call
          .where(_.methodFullName(pattern))
          .argument
          .isLiteral
          .newTagNode(FRAMEWORK_ROUTE)
          .store()(using dstGraph)
    }
  end tagCRoutes

  private def tagPythonRoutes(dstGraph: DiffGraphBuilder): Unit =
    // Tag route calls
    PYTHON_ROUTES_CALL_REGEXES.foreach { regex =>
        atom.call
            .where(_.methodFullName(regex.toString()))
            .argument
            .isLiteral
            .newTagNode(FRAMEWORK_ROUTE)
            .store()(using dstGraph)
    }

    // Tag decorated methods
    PYTHON_ROUTES_DECORATORS_REGEXES.foreach { pattern =>
      val decoratedMethods = atom.methodRef
          .where(_.inCall.code(pattern).argument)
          ._refOut
          .collectAll[Method]

      decoratedMethods.call.assignment
          .code(HTTP_METHODS_REGEX)
          .argument
          .isIdentifier
          .newTagNode(FRAMEWORK_INPUT)
          .store()(using dstGraph)

      decoratedMethods.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
      decoratedMethods.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
    }

    // Django views
    atom.file.name(".*views.py.*")
        .method
        .parameter
        .name("request")
        .method
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)

    // Controller methods
    val controllerMethods = atom.file.name(".*controllers.*.py.*")
        .method
        .name("get|post|put|delete|head|option")

    controllerMethods
        .parameter
        .filterNot(_.name == "self")
        .newTagNode(FRAMEWORK_INPUT)
        .store()(using dstGraph)

    controllerMethods
        .methodReturn
        .newTagNode(FRAMEWORK_OUTPUT)
        .store()(using dstGraph)
  end tagPythonRoutes

  private def tagPhpRoutes(dstGraph: DiffGraphBuilder): Unit =
      PHP_ROUTES_METHODS_REGEXES.foreach { pattern =>
        atom.method.fullName(pattern).parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
        atom.call
            .where(_.methodFullName(pattern))
            .argument
            .isLiteral
            .newTagNode(FRAMEWORK_ROUTE)
            .store()(using dstGraph)
      }

  private def tagRubyRoutes(dstGraph: DiffGraphBuilder): Unit =
    // Rails routes
    val railsRoutePrefix = ".*(get|post|put|delete|head|option|resources|namespace)\\s('|\").*"

    val railsRoutes = atom.method.where(
      _.filename("config/routes.rb").code(railsRoutePrefix)
    )

    railsRoutes.newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
    railsRoutes.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)

    // Rails controllers
    val railsControllers = atom.method.filename(".*controller.rb.*")
    railsControllers.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
    railsControllers.methodReturn.newTagNode(FRAMEWORK_OUTPUT).store()(using dstGraph)

    // Sinatra routes
    val sinatraRoutePrefix =
        "(app\\.namespace|app\\.)?(get|post|delete|head|options|put)\\s('|\").*"

    val sinatraRoutes = atom.method.code(sinatraRoutePrefix)
    sinatraRoutes.newTagNode(FRAMEWORK_ROUTE).store()(using dstGraph)
    sinatraRoutes.parameter.newTagNode(FRAMEWORK_INPUT).store()(using dstGraph)
    sinatraRoutes.methodReturn.newTagNode(FRAMEWORK_OUTPUT).store()(using dstGraph)
  end tagRubyRoutes

  private def processChennaiConfig(dstGraph: DiffGraphBuilder): Unit =
      atom.configFile(CHENNAI_CONFIG_FILE).content.foreach { configData =>
          parse(configData) match
            case Right(json) =>
                val tags = json.hcursor
                    .downField("tags")
                    .focus
                    .flatMap(_.asArray)
                    .getOrElse(Vector.empty)

                tags.foreach(processTag(_, dstGraph))

            case Left(error) =>
                System.err.println(s"Failed to parse Chennai config: $error")
      }

  private def processTag(tagJson: Json, dstGraph: DiffGraphBuilder): Unit =
    val cursor  = tagJson.hcursor
    val tagName = cursor.downField("name").as[String].getOrElse("")

    if tagName.nonEmpty then
      processTagParameters(cursor, tagName, dstGraph)
      processTagMethods(cursor, tagName, dstGraph)
      processTagTypes(cursor, tagName, dstGraph)
      processTagFiles(cursor, tagName, dstGraph)

  private def processTagParameters(
    cursor: HCursor,
    tagName: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
    val parameters = cursor
        .downField("parameters")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    parameters.foreach { param =>
        param.asString.foreach { paramName =>
            if paramName.nonEmpty then
              atom.method.parameter.typeFullNameExact(paramName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(paramName) then
                atom.method.parameter.typeFullName(s".*${Pattern.quote(paramName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagParameters

  private def processTagMethods(
    cursor: HCursor,
    tagName: String,
    dstGraph: DiffGraphBuilder
  ): Unit =
    val methods = cursor
        .downField("methods")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    methods.foreach { method =>
        method.asString.foreach { methodName =>
            if methodName.nonEmpty then
              atom.method.fullNameExact(methodName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(methodName) then
                atom.method.fullName(s".*${Pattern.quote(methodName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagMethods

  private def processTagTypes(cursor: HCursor, tagName: String, dstGraph: DiffGraphBuilder): Unit =
    val types = cursor
        .downField("types")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    types.foreach { typ =>
        typ.asString.foreach { typeName =>
            if typeName.nonEmpty then
              atom.method.parameter.typeFullNameExact(typeName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(typeName) then
                atom.method.parameter.typeFullName(s".*${Pattern.quote(typeName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)

              atom.call.typeFullNameExact(typeName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !typeName.contains("[") && !typeName.contains("*") then
                atom.call.typeFullName(s".*${Pattern.quote(typeName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagTypes

  private def processTagFiles(cursor: HCursor, tagName: String, dstGraph: DiffGraphBuilder): Unit =
    val files = cursor
        .downField("files")
        .focus
        .flatMap(_.asArray)
        .getOrElse(Vector.empty)

    files.foreach { file =>
        file.asString.foreach { fileName =>
            if fileName.nonEmpty then
              atom.file.nameExact(fileName)
                  .newTagNode(tagName)
                  .store()(using dstGraph)

              if !containsRegex(fileName) then
                atom.file.name(s".*${Pattern.quote(fileName)}.*")
                    .newTagNode(tagName)
                    .store()(using dstGraph)
        }
    }
  end processTagFiles

  private def containsRegex(str: String): Boolean =
      str.exists(RE_CHARS.contains)
end ChennaiTagsPass
