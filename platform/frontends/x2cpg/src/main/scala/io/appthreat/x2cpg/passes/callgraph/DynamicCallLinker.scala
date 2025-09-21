package io.appthreat.x2cpg.passes.callgraph

import io.appthreat.x2cpg.Defines.DynamicCallUnknownFullName
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method, TypeDecl}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes, PropertyNames}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.{NodeDb, NodeRef}

import scala.collection.mutable
import scala.jdk.CollectionConverters.*

class DynamicCallLinker(cpg: Cpg) extends CpgPass(cpg):

  import DynamicCallLinker.*

  private lazy val typeMap: Map[String, TypeDecl] =
      cpg.typeDecl.map(td => td.fullName -> td).toMap

  private lazy val methodMap: Map[String, Method] =
      cpg.method
          .filterNot(_.name.startsWith("<operator>"))
          .map(m => m.fullName -> m).toMap

  private val methodCandidatesByFullName = mutable.Map.empty[String, mutable.LinkedHashSet[String]]
  private val subclassCache              = mutable.Map.empty[String, mutable.LinkedHashSet[String]]
  private val superclassCache            = mutable.Map.empty[String, mutable.LinkedHashSet[String]]

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if !cpg.call.exists(_.dispatchType == DispatchTypes.DYNAMIC_DISPATCH) then return

    buildMethodCandidates()
    subclassCache.clear()

    cpg.call
        .filter(_.dispatchType == DispatchTypes.DYNAMIC_DISPATCH)
        .foreach { call =>
            try linkDynamicCall(call, dstGraph)
            catch
              case ex: Exception =>
                  throw new RuntimeException(ex)
        }

  private def buildMethodCandidates(): Unit =
      for
        typeDecl <- cpg.typeDecl
        method   <- typeDecl._methodViaAstOut
      do
        val methodName = method.fullName
        val candidates = allSubclasses(typeDecl.fullName).flatMap(staticLookup(_, method))
        methodCandidatesByFullName.put(methodName, candidates)

  private def allSubclasses(typeDeclFullName: String): mutable.LinkedHashSet[String] =
      inheritanceTraversal(typeDeclFullName, subclassCache, inSuperDirection = false)

  private def allSuperClasses(typeDeclFullName: String): mutable.LinkedHashSet[String] =
      inheritanceTraversal(typeDeclFullName, superclassCache, inSuperDirection = true)

  private def inheritanceTraversal(
    typDeclFullName: String,
    cache: mutable.Map[String, mutable.LinkedHashSet[String]],
    inSuperDirection: Boolean
  ): mutable.LinkedHashSet[String] =
      cache.get(typDeclFullName) match
        case Some(classes) => classes
        case None =>
            val total = cpg.typeDecl
                .fullNameExact(typDeclFullName)
                .headOption
                .map(t => traverseInheritance(t, inSuperDirection))
                .getOrElse(mutable.LinkedHashSet.empty[String])
            cache.put(typDeclFullName, total)
            total

  private def traverseInheritance(
    current: TypeDecl,
    up: Boolean,
    visited: mutable.Set[TypeDecl] = mutable.Set.empty
  ): mutable.LinkedHashSet[String] =
    if visited.contains(current) then return mutable.LinkedHashSet.empty
    visited += current

    val nextNodes = if up then
      current.inheritsFromOut.referencedTypeDecl
    else
      cpg.typ.fullNameExact(current.fullName).flatMap(_.inheritsFromIn).collectAll[TypeDecl]

    val result = mutable.LinkedHashSet(current.fullName)
    nextNodes.foreach(t => result ++= traverseInheritance(t, up, visited))
    result

  private def staticLookup(subclass: String, baseMethod: Method): Option[String] =
      typeMap.get(subclass) match
        case Some(sc) =>
            sc._methodViaAstOut
                .nameExact(baseMethod.name)
                .and(_.signatureExact(baseMethod.signature))
                .map(_.fullName)
                .headOption
        case None => None

  private def resolveCallInSuperClasses(call: Call): Boolean =
      call.methodFullName match
        case "<operator>.indirectFieldAccess" => resolveIndirectFieldAccess(call)
        case _                                => resolveRegularMethodInSuperclass(call)

  private def resolveRegularMethodInSuperclass(call: Call): Boolean =
    val (fullName, signature) = splitMethodSignature(call)
    val typeDeclFullName      = fullName.replace(s".${call.name}", "")
    val candidates = cpg.typeDecl
        .fullNameExact(allSuperClasses(typeDeclFullName).toIndexedSeq*)
        .astChildren
        .isMethod
        .nameExact(call.name)
        .and(_.signatureExact(signature))
        .fullName
        .l

    if candidates.nonEmpty then
      methodCandidatesByFullName.put(
        call.methodFullName,
        methodCandidatesByFullName.getOrElse(
          call.methodFullName,
          mutable.LinkedHashSet.empty
        ) ++ candidates
      )
      true
    else false
  end resolveRegularMethodInSuperclass

  private def resolveIndirectFieldAccess(call: Call): Boolean =
    val calledMethodName = call.argument.last.code
    val fieldTypes       = call.argument.head.typ.l

    fieldTypes.foreach { ft =>
      val subTypes = allSubclasses(ft.fullName).filterNot(_ == ft.fullName)
      if subTypes.nonEmpty then
        val candidateMethods = cpg.typeDecl
            .fullNameExact(subTypes.toIndexedSeq*)
            .astChildren
            .isMethod
            .name(calledMethodName)
            .fullName
            .l
        if candidateMethods.nonEmpty then
          methodCandidatesByFullName.put(
            calledMethodName,
            methodCandidatesByFullName.getOrElse(
              calledMethodName,
              mutable.LinkedHashSet.empty
            ) ++ candidateMethods
          )
    }
    true
  end resolveIndirectFieldAccess

  private def splitMethodSignature(call: Call): (String, String) =
    val fullName = call.methodFullName
    val idx = if fullName.contains(":") then
      fullName.lastIndexOf(":")
    else
      fullName.lastIndexOf(".")
    (fullName.take(idx), fullName.drop(idx + 1))

  private def linkDynamicCall(call: Call, dstGraph: DiffGraphBuilder): Unit =
    if !isValidCall(call) then return

    val resolved = resolveCallInSuperClasses(call)
    val methodNameToUse = if call.methodFullName.startsWith("<operator>") && resolved then
      call.argument.last.code
    else
      call.methodFullName

    methodCandidatesByFullName.get(methodNameToUse) match
      case Some(targets) =>
          val existingEdges = call.callOut.fullName.toSetImmutable
          val targetMethods = targets.flatMap(resolveMethod).toSet

          val (externalMethods, internalMethods) = targetMethods.partition(_.isExternal)
          val finalTargets = if externalMethods.nonEmpty && internalMethods.nonEmpty then
            internalMethods
          else
            targetMethods

          finalTargets.foreach { tgt =>
              if !existingEdges.contains(tgt.fullName) then
                dstGraph.addEdge(call, tgt, EdgeTypes.CALL)
              else
                fallbackToStaticResolution(call, dstGraph)
          }
      case None =>
          fallbackToStaticResolution(call, dstGraph)
  end linkDynamicCall

  private def isValidCall(call: Call): Boolean =
      call.methodFullName != "<empty>" &&
          call.methodFullName != DynamicCallUnknownFullName

  private def resolveMethod(fullName: String): Option[Method] =
      if cpg.graph.indexManager.isIndexed(PropertyNames.FULL_NAME) then
        methodFullNameToNode(fullName)
      else
        cpg.method.fullNameExact(fullName).headOption

  private def fallbackToStaticResolution(call: Call, dstGraph: DiffGraphBuilder): Unit =
      methodMap.get(call.methodFullName) match
        case Some(target) => dstGraph.addEdge(call, target, EdgeTypes.CALL)
        case None         =>

  private def methodFullNameToNode(fullName: String): Option[Method] =
      nodesWithFullName(fullName).collectFirst { case m: Method => m }

  private def nodesWithFullName(name: String): Iterable[NodeRef[? <: NodeDb]] =
      cpg.graph.indexManager.lookup(PropertyNames.FULL_NAME, name).asScala
end DynamicCallLinker

object DynamicCallLinker {}
