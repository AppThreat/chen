package io.appthreat.c2cpg.astcreation

import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.nodes.NewMethodRef
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.internal.core.dom.parser.c.ICInternalBinding
import org.eclipse.cdt.internal.core.dom.parser.cpp.{CPPASTQualifiedName, ICPPInternalBinding}
import org.eclipse.cdt.internal.core.model.ASTStringUtil

import scala.util.Try

trait AstForPrimitivesCreator(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  protected def astForComment(comment: IASTComment): Ast =
      Ast(newCommentNode(comment, nodeSignature(comment), fileName(comment)))

  protected def astForLiteral(lit: IASTLiteralExpression): Ast =
    val tpe = cleanType(safeGetType(lit.getExpressionType))
    Ast(literalNode(lit, nodeSignature(lit), registerType(tpe)))

  private def namesForBinding(binding: ICInternalBinding | ICPPInternalBinding)
    : (Option[String], Option[String]) =
    val definition = binding match
      // sadly, there is no common interface defining .getDefinition
      case b: ICInternalBinding   => b.getDefinition
      case b: ICPPInternalBinding => b.getDefinition
    if definition == null then
      (None, None)
    else
      val functionDeclarator = definition.asInstanceOf[IASTFunctionDeclarator]
      val typeFullName = functionDeclarator.getParent match
        case d: IASTFunctionDefinition => Some(typeForDeclSpecifier(d.getDeclSpecifier))
        case _                         => None
      (Some(this.fullName(functionDeclarator)), typeFullName)

  private def maybeMethodRefForIdentifier(ident: IASTNode): Option[NewMethodRef] =
      ident match
        case id: IASTIdExpression if id.getName != null =>
            val binding = id.getName.resolveBinding()
            if binding == null then return None

            val (mayBeFullName, mayBeTypeFullName) = binding match
              case b: ICInternalBinding
                  if b.getDefinition.isInstanceOf[IASTFunctionDeclarator] =>
                  namesForBinding(b)
              case b: ICPPInternalBinding
                  if b.getDefinition.isInstanceOf[IASTFunctionDeclarator] =>
                  namesForBinding(b)
              case _ => (None, None)
            for
              fullName     <- mayBeFullName
              typeFullName <- mayBeTypeFullName
            yield methodRefNode(ident, code(ident), fullName, registerType(cleanType(typeFullName)))
        case _ => None

  protected def astForIdentifier(ident: IASTNode): Ast =
      maybeMethodRefForIdentifier(ident) match
        case Some(ref) => Ast(ref)
        case None =>
            val identifierName = ident match
              case id: IASTIdExpression => ASTStringUtil.getSimpleName(id.getName)
              case id: IASTName
                  if ASTStringUtil.getSimpleName(id).isEmpty && id.getBinding != null =>
                  id.getBinding.getName
              case id: IASTName if ASTStringUtil.getSimpleName(id).isEmpty =>
                  uniqueName("name", "", "")._1
              case _ => code(ident)
            val variableOption = scope.lookupVariable(identifierName)
            val identifierTypeName = variableOption match
              case Some((_, variableTypeName)) => variableTypeName
              case None =>
                  ident match
                    case id: IASTName =>
                        val binding = id.getBinding
                        if binding != null then
                          binding match
                            case v: IVariable =>
                                Try(v.getType).getOrElse(null) match
                                  case f: IFunctionType       => f.getReturnType.toString
                                  case other if other != null => other.toString
                                  case _                      => Defines.anyTypeName
                            case other => other.getName
                        else
                          typeFor(ident.getParent)
                    case _ => typeFor(ident)

            val node = identifierNode(
              ident,
              identifierName,
              code(ident),
              registerType(cleanType(identifierTypeName))
            )
            variableOption match
              case Some((variable, _)) =>
                  Ast(node).withRefEdge(node, variable)
              case None => Ast(node)

  protected def astForFieldReference(fieldRef: IASTFieldReference): Ast =
    val op = if fieldRef.isPointerDereference then Operators.indirectFieldAccess
    else Operators.fieldAccess
    val ma = callNode(
      fieldRef,
      nodeSignature(fieldRef),
      op,
      op,
      if fieldRef.isPointerDereference then DispatchTypes.DYNAMIC_DISPATCH
      else DispatchTypes.STATIC_DISPATCH
    )
    val owner = astForExpression(fieldRef.getFieldOwner)
    val member = fieldIdentifierNode(
      fieldRef,
      fieldRef.getFieldName.toString,
      fieldRef.getFieldName.toString
    )
    callAst(ma, List(owner, Ast(member)))

  protected def astForArrayModifier(arrMod: IASTArrayModifier): Ast =
      astForNode(arrMod.getConstantExpression)

  protected def astForInitializerList(l: IASTInitializerList): Ast =
    val op           = Operators.arrayInitializer
    val initCallNode = callNode(l, nodeSignature(l), op, op, DispatchTypes.STATIC_DISPATCH)

    val MAX_INITIALIZERS = 1000
    val clauses          = l.getClauses.slice(0, MAX_INITIALIZERS)

    val args = clauses.toList.map(x => astForNode(x))

    val ast = callAst(initCallNode, args)
    if l.getClauses.length > MAX_INITIALIZERS then
      val placeholder =
          literalNode(l, "<too-many-initializers>", Defines.anyTypeName).argumentIndex(
            MAX_INITIALIZERS
          )
      ast.withChild(Ast(placeholder)).withArgEdge(initCallNode, placeholder)
    else
      ast

  protected def astForQualifiedName(qualId: CPPASTQualifiedName): Ast =
    val op = Operators.fieldAccess
    val ma = callNode(qualId, nodeSignature(qualId), op, op, DispatchTypes.STATIC_DISPATCH)

    def fieldAccesses(names: List[IASTNode], argIndex: Int = -1): Ast = names match
      case Nil => Ast()
      case head :: Nil =>
          astForNode(head)
      case head :: tail =>
          val code = s"${nodeSignature(head)}::${tail.map(nodeSignature).mkString("::")}"
          val callNode_ =
              callNode(head, nodeSignature(head), op, op, DispatchTypes.STATIC_DISPATCH)
                  .argumentIndex(argIndex)
          callNode_.code = code
          val arg1 = astForNode(head)
          val arg2 = fieldAccesses(tail)
          callAst(callNode_, List(arg1, arg2))

    val qualifier = fieldAccesses(qualId.getQualifier.toIndexedSeq.toList)

    val owner = if qualifier != Ast() then
      qualifier
    else
      Ast(literalNode(qualId.getLastName, "<global>", Defines.anyTypeName))

    val member = fieldIdentifierNode(
      qualId.getLastName,
      fixQualifiedName(qualId.getLastName.toString),
      qualId.getLastName.toString
    )
    callAst(ma, List(owner, Ast(member)))
  end astForQualifiedName
end AstForPrimitivesCreator
