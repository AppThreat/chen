package io.appthreat.jimple2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Operators, PropertyNames}
import io.shiftleft.passes.ConcurrentWriterCpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import java.util.Map as JMap
import scala.jdk.CollectionConverters.*
import scala.collection.mutable

class ReflectionTypeInferencePass(cpg: Cpg) extends ConcurrentWriterCpgPass[Call](cpg):

  private val invokeTypeCache = mutable.Map[String, Option[String]]()

  private val methodIndex: Map[String, Map[String, List[Method]]] =
      cpg.method
          .groupBy(_.astParentFullName)
          .view
          .mapValues(_.groupBy(_.name).view.mapValues(_.toList).toMap)
          .toMap

  override def generateParts(): Array[Call] =
    val parts = cpg.call
        .name("invoke")
        .where(_.methodFullName(".*java.lang.reflect.Method.*"))
        .toArray ++
        cpg.call
            .name("getMethod")
            .where(_.methodFullName(".*java.lang.Class.*getMethod.*"))
            .toArray
    parts

  override def runOnPart(diffGraph: DiffGraphBuilder, call: Call): Unit =
      call.name match
        case "getMethod"
            if call.methodFullName.contains("java.lang.Class") && call.methodFullName.contains(
              "getMethod"
            ) =>
            handleInvokeCall(diffGraph, call)
        case "invoke" if call.methodFullName.contains("java.lang.reflect.Method") =>
            handleInvokeCall(diffGraph, call)
        case _ =>
            ()

  private def handleInvokeCall(diffGraph: DiffGraphBuilder, invokeCall: Call): Unit =
    val cacheKey     = createCacheKey(invokeCall)
    val cachedResult = invokeTypeCache.get(cacheKey)
    val resolvedTypeOpt = cachedResult.getOrElse {
        val result = inferInvokeReturnType(invokeCall)
        invokeTypeCache.put(cacheKey, result)
        result
    }

    resolvedTypeOpt match
      case Some(refinedType) =>
          diffGraph.setNodeProperty(invokeCall, PropertyNames.TYPE_FULL_NAME, refinedType)
      case None =>

  private def createCacheKey(invokeCall: Call): String =
    val argTypes = invokeCall.argument.map(arg =>
        Option(arg.property(PropertyNames.TYPE_FULL_NAME)).getOrElse("UNKNOWN")
    ).mkString(":")
    s"${invokeCall.id()}:$argTypes"

  private def inferInvokeReturnType(invokeCall: Call): Option[String] =
    val methodReceiverOpt = if invokeCall.argument.isLiteral.nonEmpty then
      invokeCall.argument.isLiteral.headOption
    else invokeCall.argument.isIdentifier.typeFullName("java.lang.reflect.Method").headOption

    methodReceiverOpt match
      case Some(methodName: Literal)
          if cpg.method.name(methodName.code.replaceAll("\"", "")).size == 1 =>
          Some(cpg.method.name(methodName.code.replaceAll("\"", "")).head.methodReturn.typeFullName)
      case Some(methodReceiver) =>
          val invokeArgs = invokeCall.argument.filter(_.argumentIndex > 0).toList
          val result     = findMethodViaGetArguments(invokeCall, methodReceiver, invokeArgs)
          result
      case None =>
          None

  private def findMethodViaGetArguments(
    invokeCall: Call,
    methodReceiver: Any,
    invokeArgs: List[Any]
  ): Option[String] =
    methodReceiver match
      case receiverId: Literal if cpg.method.name(receiverId.code.replaceAll("\"", "")).size == 1 =>
          Some(cpg.method.name(receiverId.code.replaceAll("\"", "")).head.fullName)
      case receiverId: Identifier =>
          val definingEdges = receiverId.start.in(EdgeTypes.REF).l
          val definingAssignmentOpt = definingEdges.collectFirst {
              case call: Call if call.name == Operators.assignment =>
                  call
          }

          definingAssignmentOpt match
            case Some(assignmentCall) =>
                val rhsNodeOpt = assignmentCall.argument.order(2).headOption
                val rhsCallOpt = rhsNodeOpt.collect { case c: Call =>
                    c
                }

                rhsCallOpt match
                  case Some(getMethodCall) if getMethodCall.name == "getMethod" =>
                      val getMethodArgs =
                          getMethodCall.argument.filter(_.argumentIndex > 0).toList
                      if getMethodArgs.nonEmpty then
                        val methodNameArgOpt = getMethodArgs.headOption
                        methodNameArgOpt match
                          case Some(nameArg: Literal)
                              if nameArg.code.startsWith("\"") && nameArg.code.endsWith("\"") =>
                              val methodName = nameArg.code.stripPrefix("\"").stripSuffix("\"")
                              val classReceiverOpt = getMethodCall.argument.order(0).headOption
                              classReceiverOpt match
                                case Some(clazzId: Identifier) =>
                                    val clazzType = clazzId.typeFullName
                                    val className = extractClassNameFromType(clazzType)
                                    val signature = findMethodSignature(className, methodName)
                                    signature
                                case Some(clazzCall: Call) =>
                                    if clazzCall.name == "forName" && clazzCall.methodFullName
                                          .contains("java.lang.Class")
                                    then
                                      val forNameArgs =
                                          clazzCall.argument.filter(_.argumentIndex > 0).toList
                                      forNameArgs.headOption match
                                        case Some(classNameLiteral: Literal)
                                            if classNameLiteral.code.startsWith("\"") =>
                                            val className =
                                                classNameLiteral.code.stripPrefix("\"").stripSuffix(
                                                  "\""
                                                )
                                            val signature =
                                                findMethodSignature(className, methodName)
                                            signature
                                        case _ =>
                                            None
                                    else
                                      None
                                    end if
                                case _ =>
                                    None
                              end match
                          case _ =>
                              None
                        end match
                      else
                        None
                      end if
                  case _ =>
                      None
                end match
            case None =>
                None
          end match
      case _ =>
          None
    end match
  end findMethodViaGetArguments

  private def extractClassNameFromType(classType: String): String =
    val result = if classType.startsWith("java.lang.Class<") then
      val innerPart = classType.stripPrefix("java.lang.Class<").stripSuffix(">")
      if innerPart.endsWith("[]") then
        innerPart.stripSuffix("[]")
      else
        innerPart
    else
      classType
    result

  private def findMethodSignature(className: String, methodName: String): Option[String] =
    val classEntryOpt = methodIndex.get(className)
    val methodsOpt    = classEntryOpt.flatMap(_.get(methodName))
    methodsOpt match
      case Some(methods) =>
          if methods.length == 1 then
            val returnType = methods.head.methodReturn.typeFullName
            Some(returnType)
          else if methods.length > 1 then
            val returnType =
                methods.head.methodReturn.typeFullName
            Some(returnType)
          else
            None
      case _ =>
          None
end ReflectionTypeInferencePass
