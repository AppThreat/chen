package io.appthreat.c2cpg.astcreation

import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewIdentifier, NewMethodRef}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import org.eclipse.cdt.core.dom.ast
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.core.dom.ast.cpp.*
import org.eclipse.cdt.internal.core.dom.parser.cpp.CPPTypedef
import org.eclipse.cdt.internal.core.dom.parser.cpp.semantics.TypeOfDependentExpression
import org.eclipse.cdt.core.dom.ast.gnu.IGNUASTCompoundStatementExpression
import org.eclipse.cdt.core.model.IMethod
import org.eclipse.cdt.internal.core.dom.parser.c.{
    CASTFieldReference,
    CASTFunctionCallExpression,
    CASTIdExpression,
    CBasicType,
    CFunctionType,
    CPointerType
}
import org.eclipse.cdt.internal.core.dom.parser.cpp.semantics.{EvalBinding, EvalFunctionCall}
import org.eclipse.cdt.internal.core.dom.parser.cpp.{
    CPPASTIdExpression,
    CPPASTQualifiedName,
    CPPClosureType,
    CPPField,
    CPPFunction,
    CPPFunctionType,
    CPPImplicitFunction
}

import scala.util.Try

trait AstForExpressionsCreator(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  protected def astForExpression(expression: IASTExpression): Ast =
    val r = expression match
      case lit: IASTLiteralExpression                  => astForLiteral(lit)
      case un: IASTUnaryExpression                     => astForUnaryExpression(un)
      case bin: IASTBinaryExpression                   => astForBinaryExpression(bin)
      case exprList: IASTExpressionList                => astForExpressionList(exprList)
      case idExpr: IASTIdExpression                    => astForIdExpression(idExpr)
      case call: IASTFunctionCallExpression            => astForCallExpression(call)
      case typeId: IASTTypeIdExpression                => astForTypeIdExpression(typeId)
      case fieldRef: IASTFieldReference                => astForFieldReference(fieldRef)
      case expr: IASTConditionalExpression             => astForConditionalExpression(expr)
      case arr: IASTArraySubscriptExpression           => astForArrayIndexExpression(arr)
      case castExpression: IASTCastExpression          => astForCastExpression(castExpression)
      case newExpression: ICPPASTNewExpression         => astForNewExpression(newExpression)
      case delExpression: ICPPASTDeleteExpression      => astForDeleteExpression(delExpression)
      case typeIdInit: IASTTypeIdInitializerExpression => astForTypeIdInitExpression(typeIdInit)
      case c: ICPPASTSimpleTypeConstructorExpression   => astForConstructorExpression(c)
      case lambdaExpression: ICPPASTLambdaExpression   => astForMethodRefForLambda(lambdaExpression)
      case cExpr: IGNUASTCompoundStatementExpression   => astForCompoundStatementExpression(cExpr)
      case pExpr: ICPPASTPackExpansionExpression       => astForPackExpansionExpression(pExpr)
      case _                                           => notHandledYet(expression)
    tagConstantValue(expression, r)
    val inMacro = asChildOfMacroCall(expression, r)
    if inMacro ne r then tagConstantValue(expression, inMacro)
    inMacro
  end astForExpression

  protected def astForStaticAssert(a: ICPPASTStaticAssertDeclaration): Ast =
    val name  = "static_assert"
    val call  = callNode(a, code(a), name, name, DispatchTypes.STATIC_DISPATCH)
    val cond  = nullSafeAst(a.getCondition)
    val messg = nullSafeAst(a.getMessage)
    callAst(call, List(cond, messg))

  private def astForBinaryExpression(bin: IASTBinaryExpression): Ast =
    val op = bin.getOperator match
      case IASTBinaryExpression.op_multiply  => Operators.multiplication
      case IASTBinaryExpression.op_divide    => Operators.division
      case IASTBinaryExpression.op_modulo    => Operators.modulo
      case IASTBinaryExpression.op_plus      => Operators.addition
      case IASTBinaryExpression.op_minus     => Operators.subtraction
      case IASTBinaryExpression.op_shiftLeft => Operators.shiftLeft
      case IASTBinaryExpression.op_shiftRight if isUnsignedOperand(bin.getOperand1) =>
          Operators.logicalShiftRight
      case IASTBinaryExpression.op_shiftRight      => Operators.arithmeticShiftRight
      case IASTBinaryExpression.op_lessThan        => Operators.lessThan
      case IASTBinaryExpression.op_greaterThan     => Operators.greaterThan
      case IASTBinaryExpression.op_lessEqual       => Operators.lessEqualsThan
      case IASTBinaryExpression.op_greaterEqual    => Operators.greaterEqualsThan
      case IASTBinaryExpression.op_binaryAnd       => Operators.and
      case IASTBinaryExpression.op_binaryXor       => Operators.xor
      case IASTBinaryExpression.op_binaryOr        => Operators.or
      case IASTBinaryExpression.op_logicalAnd      => Operators.logicalAnd
      case IASTBinaryExpression.op_logicalOr       => Operators.logicalOr
      case IASTBinaryExpression.op_assign          => Operators.assignment
      case IASTBinaryExpression.op_multiplyAssign  => Operators.assignmentMultiplication
      case IASTBinaryExpression.op_divideAssign    => Operators.assignmentDivision
      case IASTBinaryExpression.op_moduloAssign    => Operators.assignmentModulo
      case IASTBinaryExpression.op_plusAssign      => Operators.assignmentPlus
      case IASTBinaryExpression.op_minusAssign     => Operators.assignmentMinus
      case IASTBinaryExpression.op_shiftLeftAssign => Operators.assignmentShiftLeft
      case IASTBinaryExpression.op_shiftRightAssign if isUnsignedOperand(bin.getOperand1) =>
          Operators.assignmentLogicalShiftRight
      case IASTBinaryExpression.op_shiftRightAssign => Operators.assignmentArithmeticShiftRight
      case IASTBinaryExpression.op_binaryAndAssign  => Operators.assignmentAnd
      case IASTBinaryExpression.op_binaryXorAssign  => Operators.assignmentXor
      case IASTBinaryExpression.op_binaryOrAssign   => Operators.assignmentOr
      case IASTBinaryExpression.op_equals           => Operators.equals
      case IASTBinaryExpression.op_notequals        => Operators.notEquals
      case IASTBinaryExpression.op_pmdot            => Defines.operatorPointerToMember
      case IASTBinaryExpression.op_pmarrow          => Defines.operatorIndirectPointerToMember
      case IASTBinaryExpression.op_max              => "<operator>.max"
      case IASTBinaryExpression.op_min              => "<operator>.min"
      case IASTBinaryExpression.op_ellipses         => "<operator>.op_ellipses"
      case _                                        => "<operator>.unknown"

    val overloaded = bin match
      case cpp: ICPPASTBinaryExpression => linkedOverload(cpp.getOverload)
      case _                            => None
    overloaded match
      case Some((overload, linked)) =>
          val operands = List(nullSafeAst(bin.getOperand1), nullSafeAst(bin.getOperand2))
          overloadedOperatorAst(bin, overload, linked, op, operands)
      case None =>
          val callNode_ = callNode(
            bin,
            code(bin),
            op,
            op,
            DispatchTypes.STATIC_DISPATCH,
            None,
            Some(expressionType(bin))
          )
          val left  = nullSafeAst(bin.getOperand1)
          val right = nullSafeAst(bin.getOperand2)
          pointerArithmeticOf(bin).foreach(tagNode(callNode_, X2CpgDefines.PointerArithmeticTag, _))
          callAst(callNode_, List(left, right))
  end astForBinaryExpression

  /** A pointer or an array, through typedefs and qualifiers: what pointer arithmetic moves. */
  private def isAddressOperand(e: IASTExpression): Boolean =
    @scala.annotation.tailrec
    def unwrap(t: IType): IType = t match
      case td: ITypedef      => unwrap(td.getType)
      case q: IQualifierType => unwrap(q.getType)
      case other             => other
    e != null && Try(unwrap(e.getExpressionType)).toOption.exists {
        case _: IPointerType | _: IArrayType => true
        case _                               => false
    }

  /** The [[X2CpgDefines.PointerArithmeticTag]] value of `+`, `-`, `+=` and `-=` over a pointer. */
  private def pointerArithmeticOf(bin: IASTBinaryExpression): Option[String] =
    val (p1, p2) = (isAddressOperand(bin.getOperand1), isAddressOperand(bin.getOperand2))
    bin.getOperator match
      case IASTBinaryExpression.op_plus if p1 && !p2 => Some("add:1")
      case IASTBinaryExpression.op_plus if p2 && !p1 => Some("add:2")
      case IASTBinaryExpression.op_minus if p1 && p2 => Some("diff")
      case IASTBinaryExpression.op_minus if p1       => Some("sub:1")
      case IASTBinaryExpression.op_plusAssign if p1  => Some("add:1")
      case IASTBinaryExpression.op_minusAssign if p1 => Some("sub:1")
      case _                                         => None

  private def astForExpressionList(exprList: IASTExpressionList): Ast =
    val name = "<operator>.expressionList"
    val callNode_ =
        callNode(
          exprList,
          code(exprList),
          name,
          name,
          DispatchTypes.STATIC_DISPATCH,
          None,
          Some(expressionType(exprList))
        )
    val childAsts = exprList.getExpressions.map(nullSafeAst)
    callAst(callNode_, childAsts.toIndexedSeq)

  private def astForCppCallExpression(call: ICPPASTFunctionCallExpression): Ast =
      linkedConstructor(call) match
        case Some((constructor, linked)) =>
            // a functional cast that constructs an object: `Vec2(x, y)`
            val args = call.getArguments.toList.map(a => astForNode(a))
            val tpe  = registerType(cleanType(safeGetType(call.getExpressionType)))
            linkedCallAst(call, constructor, linked, tpe, None, args)._2
        case None => astForCppCallExpressionByCallee(call)

  private def astForCppCallExpressionByCallee(call: ICPPASTFunctionCallExpression): Ast =
    val functionNameExpr = call.getFunctionNameExpression
    val typ              = Try(functionNameExpr.getExpressionType).getOrElse(null)
    typ match
      case _: TypeOfDependentExpression =>
          astForCppCallExpressionUntyped(call)
      case pointerType: IPointerType =>
          createPointerCallAst(call, cleanType(safeGetType(call.getExpressionType)))
      case functionType: ICPPFunctionType =>
          functionNameExpr match
            case idExpr: CPPASTIdExpression =>
                val binding = idExpr.getName.getBinding
                // Check if binding is ICPPFunction.
                // It could be a CPPParameter (function pointer argument) or a variable.
                val templateDefinition = binding match
                  case f: ICPPFunction => graphFunction(f).filter(_ ne f).map(f -> _)
                  case _               => None
                if templateDefinition.isDefined then
                  // a template instance: the call reaches the generic definition's METHOD
                  val (function, linked) = templateDefinition.get
                  val args               = call.getArguments.toList.map(a => astForNode(a))
                  val tpe = registerType(cleanType(safeGetType(call.getExpressionType)))
                  val (callCpgNode, ast) = linkedCallAst(call, function, linked, tpe, None, args)
                  tagCallAttributes(callCpgNode, function)
                  ast
                else if binding != null && binding.isInstanceOf[ICPPFunction] then
                  val function = binding.asInstanceOf[ICPPFunction]
                  val name     = idExpr.getName.getLastName.toString
                  val signature =
                      if function.isExternC then
                        ""
                      else
                        functionTypeToSignature(functionType)

                  // a compiler builtin has C linkage: named as in C, so its summaries apply
                  val builtin = function.isInstanceOf[CPPImplicitFunction] &&
                      CBuiltins.isBuiltinName(name)
                  val fullName =
                      if function.isExternC || builtin then
                        name
                      else
                        val fullNameNoSig = function.getQualifiedName.mkString(".")
                        s"$fullNameNoSig:$signature"

                  val dispatchType = DispatchTypes.STATIC_DISPATCH

                  val callCpgNode = callNode(
                    call,
                    code(call),
                    name,
                    fullName,
                    dispatchType,
                    Some(signature),
                    Some(registerType(cleanType(safeGetType(call.getExpressionType))))
                  )
                  tagCallAttributes(callCpgNode, function)
                  val args = call.getArguments.toList.map(a => astForNode(a))

                  createCallAst(callCpgNode, args)
                else
                  // function pointers, parameters, or unresolved bindings
                  astForCppCallExpressionUntyped(call)
                end if

            case fieldRefExpr: ICPPASTFieldReference =>
                val instanceAst = fieldOwnerAst(fieldRefExpr)
                val args        = call.getArguments.toList.map(a => astForNode(a))

                val name      = fieldRefExpr.getFieldName.toString
                val signature = functionTypeToSignature(functionType)

                val classFullName = cleanType(safeGetType(fieldRefExpr.getFieldOwnerType))
                val fullName      = s"$classFullName.$name:$signature"

                fieldRefExpr.getFieldName.resolveBinding()
                val binding = fieldRefExpr.getFieldName.getBinding
                val linkedMethod = binding match
                  case m: ICPPMethod => graphFunction(m).map(m -> _)
                  case _             => None
                // a method of the project: named after the class that declares it, which is
                // where its METHOD is (an inherited method, a member of a template instance)
                linkedMethod match
                  case Some((method, linked)) =>
                      val tpe = cleanType(safeGetType(call.getExpressionType))
                      linkedCallAst(call, method, linked, tpe, Some(instanceAst), args)._2
                  case None =>
                      val (dispatchType, receiver) =
                          if binding != null && binding.isInstanceOf[ICPPMethod] then
                            val method = binding.asInstanceOf[ICPPMethod]
                            if method.isVirtual || method.isPureVirtual then
                              (DispatchTypes.DYNAMIC_DISPATCH, Some(instanceAst))
                            else
                              (DispatchTypes.STATIC_DISPATCH, None)
                          else
                            (DispatchTypes.STATIC_DISPATCH, None)
                      val callCpgNode = callNode(
                        call,
                        code(call),
                        name,
                        fullName,
                        dispatchType,
                        Some(signature),
                        Some(cleanType(safeGetType(call.getExpressionType)))
                      )

                      createCallAst(callCpgNode, args, base = Some(instanceAst), receiver)
                end match
            case unaryExpr: IASTUnaryExpression =>
                astForCppCallExpressionUntyped(call)
            case _ =>
                astForCppCallExpressionUntyped(call)
      case classType: ICPPClassType =>
          val evaluation = call.getEvaluation
          evaluation match
            case evalFuncCall: EvalFunctionCall =>
                val overloadOpt: Option[ICPPFunction] =
                    try
                      val overload = evalFuncCall.getOverload
                      Option(overload)
                    catch
                      case _: NullPointerException => // CDT parsing bugs
                          None
                overloadOpt match
                  case Some(overload) =>
                      val functionType = overload.getType
                      val signature    = functionTypeToSignature(functionType)
                      val name         = "<operator>()"
                      classType match
                        case closureType: CPPClosureType =>
                            // the receiver first: an immediately invoked lambda builds its
                            // METHOD there
                            val receiverAst = astForExpression(functionNameExpr)
                            val args        = call.getArguments.toList.map(a => astForNode(a))
                            val callType    = expressionType(call)
                            lambdaMethodOf(closureType) match
                              case Some((lambdaName, lambdaFullName)) =>
                                  val callCpgNode = callNode(
                                    call,
                                    code(call),
                                    lambdaName,
                                    lambdaFullName,
                                    DispatchTypes.STATIC_DISPATCH,
                                    Some(signature),
                                    Some(callType)
                                  )
                                  tagCall(callCpgNode, X2CpgDefines.OperatorCallTag, name)
                                  createCallAst(callCpgNode, args, receiver = Some(receiverAst))
                              case None =>
                                  val callCpgNode = callNode(
                                    call,
                                    code(call),
                                    name,
                                    s"$name:$signature",
                                    DispatchTypes.DYNAMIC_DISPATCH,
                                    Some(signature),
                                    Some(callType)
                                  )
                                  createCallAst(callCpgNode, args, receiver = Some(receiverAst))
                            end match
                        case _ if graphFunction(overload).isDefined =>
                            val operands = astForExpression(functionNameExpr) ::
                                call.getArguments.toList.map(a => astForNode(a))
                            overloadedOperatorAst(
                              call,
                              overload,
                              graphFunction(overload).get,
                              name,
                              operands
                            )
                        case _ =>
                            val classFullName = cleanType(safeGetType(classType))
                            val fullName      = s"$classFullName.$name:$signature"
                            val method        = overload.asInstanceOf[ICPPMethod]
                            val dispatchType =
                                if method.isVirtual || method.isPureVirtual then
                                  DispatchTypes.DYNAMIC_DISPATCH
                                else
                                  DispatchTypes.STATIC_DISPATCH
                            val callCpgNode = callNode(
                              call,
                              code(call),
                              name,
                              fullName,
                              dispatchType,
                              Some(signature),
                              Some(cleanType(safeGetType(call.getExpressionType)))
                            )
                            val instanceAst = astForExpression(functionNameExpr)
                            val args        = call.getArguments.toList.map(a => astForNode(a))
                            createCallAst(
                              callCpgNode,
                              args,
                              base = Some(instanceAst),
                              receiver = Some(instanceAst)
                            )
                      end match
                  case None => astForCppCallExpressionUntyped(call)
                end match
            case _ =>
                astForCppCallExpressionUntyped(call)
          end match
      case _: ICPPReferenceType =>
          astForCppCallExpressionUntyped(call)
      case _: ITypedef =>
          astForCppCallExpressionUntyped(call)
      case _: IProblemType =>
          astForCppCallExpressionUntyped(call)
      case _: IProblemBinding =>
          astForCppCallExpressionUntyped(call)
      case _ =>
          astForCppCallExpressionUntyped(call)
    end match
  end astForCppCallExpressionByCallee

  private def astForCppCallExpressionUntyped(call: ICPPASTFunctionCallExpression): Ast =
    val functionNameExpr = call.getFunctionNameExpression

    functionNameExpr match
      case fieldRefExpr: ICPPASTFieldReference =>
          val instanceAst = fieldOwnerAst(fieldRefExpr)
          val args        = call.getArguments.toList.map(a => astForNode(a))

          val name      = fieldRefExpr.getFieldName.toString
          val signature = X2CpgDefines.UnresolvedSignature
          val fullName  = s"${X2CpgDefines.UnresolvedNamespace}.$name:$signature(${args.size})"

          val callCpgNode = callNode(
            call,
            code(call),
            name,
            fullName,
            DispatchTypes.STATIC_DISPATCH,
            Some(signature),
            Some(X2CpgDefines.Any)
          )

          createCallAst(callCpgNode, args, base = Some(instanceAst), receiver = Some(instanceAst))
      case idExpr: CPPASTIdExpression =>
          val args = call.getArguments.toList.map(a => astForNode(a))

          val name = idExpr.getName.getLastName.toString
          // a builtin the parser does not declare (`__builtin___memcpy_chk`) is known by name
          val callCpgNode = CBuiltins.get(name) match
            case Some(builtin) =>
                callNode(
                  call,
                  code(call),
                  name,
                  name,
                  DispatchTypes.STATIC_DISPATCH,
                  Some(builtin.signature),
                  Some(registerType(builtin.returnType))
                )
            case None =>
                val signature = X2CpgDefines.UnresolvedSignature
                val fullName = s"${X2CpgDefines.UnresolvedNamespace}.$name:$signature(${args.size})"
                callNode(
                  call,
                  code(call),
                  name,
                  fullName,
                  DispatchTypes.STATIC_DISPATCH,
                  Some(signature),
                  Some(X2CpgDefines.Any)
                )

          createCallAst(callCpgNode, args)
      case other =>
          // This could either be a pointer or an operator() call we dont know at this point
          // but since it is CPP we opt for the later.
          val args = call.getArguments.toList.map(a => astForNode(a))

          val name      = "<operator>()"
          val signature = X2CpgDefines.UnresolvedSignature
          val fullName  = s"${X2CpgDefines.UnresolvedNamespace}.$name:$signature(${args.size})"

          val callCpgNode = callNode(
            call,
            code(call),
            name,
            fullName,
            DispatchTypes.STATIC_DISPATCH,
            Some(signature),
            Some(X2CpgDefines.Any)
          )

          val instanceAst = astForExpression(functionNameExpr)
          createCallAst(callCpgNode, args, base = Some(instanceAst), receiver = Some(instanceAst))
    end match
  end astForCppCallExpressionUntyped

  private def astForCCallExpression(call: CASTFunctionCallExpression): Ast =
    val functionNameExpr = call.getFunctionNameExpression
    val typ              = functionNameExpr.getExpressionType
    typ match
      case pointerType: CPointerType =>
          createPointerCallAst(call, cleanType(safeGetType(call.getExpressionType)))
      case functionType: CFunctionType =>
          functionNameExpr match
            case idExpr: CASTIdExpression =>
                createCFunctionCallAst(
                  call,
                  idExpr,
                  cleanType(safeGetType(call.getExpressionType))
                )
            case _ =>
                createPointerCallAst(call, cleanType(safeGetType(call.getExpressionType)))
      case _ =>
          astForCCallExpressionUntyped(call)

  private def createCFunctionCallAst(
    call: CASTFunctionCallExpression,
    idExpr: CASTIdExpression,
    callTypeFullName: String
  ): Ast =
    val name = idExpr.getName.getLastName.toString
    val (signature: String, fullName: String) =
      val binding = idExpr.getName.getBinding
      binding match
        case function: IFunction =>
            val functionType: IFunctionType = function.getType
            val derivedSignature            = functionTypeToSignature(functionType)
            val nameFromBinding             = function.getName
            val constructedFullName         = s"$nameFromBinding:$derivedSignature"
            (derivedSignature, constructedFullName)

        case _ =>
            val fallbackSignature = ""
            (fallbackSignature, s"$name:$fallbackSignature")

    // a builtin the parser does not declare (`__builtin___memcpy_chk`) has its known signature
    val builtin      = CBuiltins.get(name).filter(_ => callTypeFullName == X2CpgDefines.Any)
    val dispatchType = DispatchTypes.STATIC_DISPATCH
    val callCpgNode = callNode(
      call,
      code(call),
      name,
      name,
      dispatchType,
      Some(builtin.map(_.signature).getOrElse(signature)),
      Some(builtin.map(b => registerType(b.returnType)).getOrElse(callTypeFullName))
    )
    idExpr.getName.getBinding match
      case function: IFunction => tagCallAttributes(callCpgNode, function)
      case _                   => ()
    val args = call.getArguments.toList.map(a => astForNode(a))

    createCallAst(callCpgNode, args)
  end createCFunctionCallAst

  private def createPointerCallAst(
    call: IASTFunctionCallExpression,
    callTypeFullName: String
  ): Ast =
    val functionNameExpr = call.getFunctionNameExpression
    val name             = Defines.operatorPointerCall
    val signature        = ""

    val callCpgNode =
        callNode(
          call,
          code(call),
          name,
          name,
          DispatchTypes.DYNAMIC_DISPATCH,
          Some(signature),
          Some(callTypeFullName)
        )

    val args        = call.getArguments.toList.map(a => astForNode(a))
    val receiverAst = astForExpression(functionNameExpr)
    createCallAst(callCpgNode, args, receiver = Some(receiverAst))
  end createPointerCallAst

  private def astForCCallExpressionUntyped(call: CASTFunctionCallExpression): Ast =
    val functionNameExpr = call.getFunctionNameExpression

    functionNameExpr match
      case idExpr: CASTIdExpression =>
          createCFunctionCallAst(call, idExpr, X2CpgDefines.Any)
      case _ =>
          createPointerCallAst(call, X2CpgDefines.Any)

  private def astForCallExpression(call: IASTFunctionCallExpression): Ast =
      call match
        case cppCall: ICPPASTFunctionCallExpression =>
            astForCppCallExpression(cppCall)
        case cCall: CASTFunctionCallExpression =>
            astForCCallExpression(cCall)

  private def astForUnaryExpression(unary: IASTUnaryExpression): Ast =
    val operatorMethod = unary.getOperator match
      case IASTUnaryExpression.op_prefixIncr          => Operators.preIncrement
      case IASTUnaryExpression.op_prefixDecr          => Operators.preDecrement
      case IASTUnaryExpression.op_plus                => Operators.plus
      case IASTUnaryExpression.op_minus               => Operators.minus
      case IASTUnaryExpression.op_star                => Operators.indirection
      case IASTUnaryExpression.op_amper               => Operators.addressOf
      case IASTUnaryExpression.op_tilde               => Operators.not
      case IASTUnaryExpression.op_not                 => Operators.logicalNot
      case IASTUnaryExpression.op_sizeof              => Operators.sizeOf
      case IASTUnaryExpression.op_postFixIncr         => Operators.postIncrement
      case IASTUnaryExpression.op_postFixDecr         => Operators.postDecrement
      case IASTUnaryExpression.op_throw               => "<operator>.throw"
      case IASTUnaryExpression.op_typeid              => Defines.operatorTypeId
      case IASTUnaryExpression.op_alignOf             => Defines.operatorAlignOf
      case IASTUnaryExpression.op_sizeofParameterPack => Defines.operatorParameterPackSize
      case IASTUnaryExpression.op_noexcept            => Defines.operatorNoexcept
      case IASTUnaryExpression.op_labelReference      => Defines.operatorLabelAddress
      case IASTUnaryExpression.op_bracketedPrimary    => "<operator>.bracketedPrimary"
      case _                                          => "<operator>.unknown"

    if
      unary.getOperator == IASTUnaryExpression.op_bracketedPrimary &&
      !unary.getOperand.isInstanceOf[IASTExpressionList]
    then
      nullSafeAst(unary.getOperand)
    else
      val overloaded = unary match
        case cpp: ICPPASTUnaryExpression => linkedOverload(cpp.getOverload)
        case _                           => None
      overloaded match
        case Some((overload, linked)) =>
            overloadedOperatorAst(
              unary,
              overload,
              linked,
              operatorMethod,
              List(nullSafeAst(unary.getOperand))
            )
        case None =>
            val cpgUnary =
                callNode(
                  unary,
                  code(unary),
                  operatorMethod,
                  operatorMethod,
                  DispatchTypes.STATIC_DISPATCH,
                  None,
                  Some(expressionType(unary))
                )
            val operand = nullSafeAst(unary.getOperand)
            if isAddressOperand(unary.getOperand) then
              unary.getOperator match
                case IASTUnaryExpression.op_prefixIncr | IASTUnaryExpression.op_postFixIncr =>
                    tagNode(cpgUnary, X2CpgDefines.PointerArithmeticTag, "add:1")
                case IASTUnaryExpression.op_prefixDecr | IASTUnaryExpression.op_postFixDecr =>
                    tagNode(cpgUnary, X2CpgDefines.PointerArithmeticTag, "sub:1")
                case _ =>
            callAst(cpgUnary, List(operand))
      end match
    end if
  end astForUnaryExpression

  private def astForTypeIdExpression(typeId: IASTTypeIdExpression): Ast =
    val operatorMethod = typeId.getOperator match
      case IASTTypeIdExpression.op_sizeof              => Some(Operators.sizeOf)
      case IASTTypeIdExpression.op_alignof             => Some(Defines.operatorAlignOf)
      case IASTTypeIdExpression.op_typeid              => Some(Defines.operatorTypeId)
      case IASTTypeIdExpression.op_typeof              => Some(Defines.operatorTypeOf)
      case IASTTypeIdExpression.op_sizeofParameterPack => Some(Defines.operatorParameterPackSize)
      case _                                           => None
    operatorMethod match
      case Some(name) =>
          val call = callNode(
            typeId,
            code(typeId),
            name,
            name,
            DispatchTypes.STATIC_DISPATCH,
            None,
            Some(expressionType(typeId))
          )
          callAst(call, List(astForTypeIdOperand(typeId.getTypeId)))
      case None => notHandledYet(typeId)
  end astForTypeIdExpression

  /** The type a `sizeof(T)`-style operator is applied to. A plain type name keeps the identifier
    * that names it. When the type id has an abstract declarator, the identifier spells the whole
    * type id instead: `sizeof(char *)` measures a pointer and `sizeof(int[4])` an array, and naming
    * only the declaration specifier would make both read as `sizeof(char)` and `sizeof(int)`.
    */
  private def astForTypeIdOperand(typeId: IASTTypeId): Ast =
    val declarator = typeId.getAbstractDeclarator
    val hasDeclarator = declarator != null && (
      declarator.getPointerOperators.nonEmpty ||
          declarator.getNestedDeclarator != null ||
          declarator.isInstanceOf[IASTArrayDeclarator] ||
          declarator.isInstanceOf[IASTFunctionDeclarator]
    )
    if hasDeclarator then
      val spelled = code(typeId).replaceAll("\\s+", " ").strip()
      val tpe     = registerType(cleanType(safeGetNodeType(typeId)))
      Ast(identifierNode(typeId, spelled, spelled, tpe))
    else astForNode(typeId.getDeclSpecifier)

  private def astForConditionalExpression(expr: IASTConditionalExpression): Ast =
    val name = Operators.conditional
    val call = callNode(
      expr,
      code(expr),
      name,
      name,
      DispatchTypes.STATIC_DISPATCH,
      None,
      Some(expressionType(expr))
    )

    val condAst = nullSafeAst(expr.getLogicalConditionExpression)
    val posAst  = nullSafeAst(expr.getPositiveResultExpression)
    val negAst  = nullSafeAst(expr.getNegativeResultExpression)

    val children = List(condAst, posAst, negAst)
    callAst(call, children)

  private def astForArrayIndexExpression(arrayIndexExpression: IASTArraySubscriptExpression): Ast =
    val name = Operators.indirectIndexAccess
    val overloaded = arrayIndexExpression match
      case cpp: ICPPASTArraySubscriptExpression => linkedImplicitOperator(cpp)
      case _                                    => None
    // `i[a]` is `a[i]`: the pointer or array is the base whichever side it is written on
    val swapped = overloaded.isEmpty &&
        !isAddressOperand(arrayIndexExpression.getArrayExpression) &&
        (arrayIndexExpression.getArgument match
          case e: IASTExpression => isAddressOperand(e)
          case _                 => false
        )
    val (expr, arg) =
        if swapped then
          (
            astForNode(arrayIndexExpression.getArgument),
            astForExpression(arrayIndexExpression.getArrayExpression)
          )
        else
          (
            astForExpression(arrayIndexExpression.getArrayExpression),
            astForNode(arrayIndexExpression.getArgument)
          )
    overloaded match
      case Some((overload, linked)) =>
          overloadedOperatorAst(arrayIndexExpression, overload, linked, name, List(expr, arg))
      case None =>
          val cpgArrayIndexing =
              callNode(
                arrayIndexExpression,
                code(arrayIndexExpression),
                name,
                name,
                DispatchTypes.STATIC_DISPATCH,
                None,
                Some(expressionType(arrayIndexExpression))
              )
          callAst(cpgArrayIndexing, List(expr, arg))
  end astForArrayIndexExpression

  private def astForCastExpression(castExpression: IASTCastExpression): Ast =
    val cpgCastExpression =
        callNode(
          castExpression,
          code(castExpression),
          Operators.cast,
          Operators.cast,
          DispatchTypes.STATIC_DISPATCH,
          None,
          Some(expressionType(castExpression))
        )

    val expr    = astForExpression(castExpression.getOperand)
    val argNode = castExpression.getTypeId
    val arg     = unknownNode(argNode, code(argNode))

    callAst(cpgCastExpression, List(Ast(arg), expr))

  /** The arguments a `new` expression hands to the constructor: `new T(a, b)` and `new T{a, b}`. */
  private def astsForConstructorInitializer(initializer: IASTInitializer): List[Ast] =
      initializer match
        case init: ICPPASTConstructorInitializer => init.getArguments.toList.map(x => astForNode(x))
        case init: IASTInitializerList           => init.getClauses.toList.map(x => astForNode(x))
        case _                                   => Nil // null or unexpected type

  private def astsForInitializerPlacements(initializerPlacements: Array[IASTInitializerClause])
    : List[Ast] =
      if initializerPlacements != null then initializerPlacements.toList.map(x => astForNode(x))
      else Nil

  /** `new T(args)`: an `<operator>.new` call of the allocated type (argument 1), tagged with its
    * form. When the graph holds the constructor's METHOD, argument 2 is the call to it, which takes
    * the constructor arguments; otherwise they follow the type directly. The extents of an array
    * allocation follow the type (`new char[need]` allocates `need` elements), then the call to the
    * element constructor. Placement arguments come last, inside a call to the user-defined
    * `operator new` that receives them when the graph holds its METHOD.
    */
  private def astForNewExpression(newExpression: ICPPASTNewExpression): Ast =
    val name = "<operator>.new"
    val cpgNewExpression =
        callNode(
          newExpression,
          code(newExpression),
          name,
          name,
          DispatchTypes.STATIC_DISPATCH,
          None,
          Some(expressionType(newExpression))
        )

    val typeId     = newExpression.getTypeId
    val placements = Option(newExpression.getPlacementArguments).toList.flatten
    val form =
        if newExpression.isArrayAllocation then X2CpgDefines.AllocFormArray
        else if placements.nonEmpty then X2CpgDefines.AllocFormPlacement
        else X2CpgDefines.AllocFormScalar
    tagCall(cpgNewExpression, X2CpgDefines.AllocFormTag, form)

    val cpgTypeId   = astForIdentifier(typeId.getDeclSpecifier)
    val constructor = linkedConstructor(newExpression)
    def constructorCall(args: List[Ast]): Option[Ast] = constructor.map { (ctor, linked) =>
      val constructed = ctor match
        case c: ICPPConstructor => registerType(cleanType(safeGetType(c.getClassOwner)))
        case _                  => Defines.anyTypeName
      val ctorCode =
          if newExpression.isArrayAllocation then s"${nodeSignature(typeId.getDeclSpecifier)}()"
          else
            s"${nodeSignature(typeId)}${Option(newExpression.getInitializer).map(nodeSignature).getOrElse("()")}"
      linkedCallAst(typeId, ctor, linked, constructed, None, args, Some(ctorCode))._2
    }
    val placementArgs = astsForInitializerPlacements(newExpression.getPlacementArguments)
    val allocation = linkedImplicitOperator(newExpression) match
      case Some((operatorNew, linked)) =>
          val tpe = registerType(cleanType(safeGetType(operatorNew.getType.getReturnType)))
          List(
            linkedCallAst(
              newExpression,
              operatorNew,
              linked,
              tpe,
              None,
              placementArgs,
              Some(s"operator new(${placements.map(nodeSignature).mkString(", ")})")
            )._2
          )
      case None => placementArgs

    val args =
        if newExpression.isArrayAllocation then
          // the array size IS part of the allocation's meaning: `new char[need]` allocates
          // `need` bytes, and the self-sized-copy reading needs that size on the graph - it
          // must not be dropped here, or every sized new[] copy is unprovable
          val sizeArgs = Option(typeId.getAbstractDeclarator).toList.collect {
              case ad: ast.IASTArrayDeclarator => ad.getArrayModifiers.toList
          }.flatten.filter(_.getConstantExpression != null).map(astForNode)
          sizeArgs ++ constructorCall(Nil).toList ++ allocation
        else
          val ctorArgs = astsForConstructorInitializer(newExpression.getInitializer)
          constructorCall(ctorArgs).map(List(_)).getOrElse(ctorArgs) ++ allocation
    callAst(cpgNewExpression, cpgTypeId :: args)
  end astForNewExpression

  /** `delete p`: an `<operator>.delete` call of the pointer (argument 1), tagged with its form,
    * followed by the call to the destructor and to the user-defined `operator delete` it runs when
    * the graph holds their METHODs.
    */
  private def astForDeleteExpression(delExpression: ICPPASTDeleteExpression): Ast =
    val name = Operators.delete
    val cpgDeleteNode =
        callNode(
          delExpression,
          code(delExpression),
          name,
          name,
          DispatchTypes.STATIC_DISPATCH,
          None,
          Some(registerType(Defines.voidTypeName))
        )
    tagCall(
      cpgDeleteNode,
      X2CpgDefines.AllocFormTag,
      if delExpression.isVectored then X2CpgDefines.AllocFormArray
      else X2CpgDefines.AllocFormScalar
    )
    val operand = delExpression.getOperand
    val arg     = astForExpression(operand)
    // CDT names the destructor of a scalar delete; an array delete destroys elements of the
    // pointee's class
    val destructor =
        if delExpression.isVectored then
          Try(operand.getExpressionType).toOption.collect { case p: IPointerType => p.getType }
              .flatMap(destructorOf)
        else
          Try(delExpression.getImplicitNames.toList).getOrElse(Nil).filterNot(_.isOperator)
              .flatMap(n => Try(n.resolveBinding()).toOption)
              .collectFirst { case m: ICPPMethod if m.isDestructor => m }
    val destructorCall = destructor.flatMap { d =>
        destructorCallAst(delExpression, d, s"${nodeSignature(operand)}->${d.getName}()")
    }
    val operatorDelete = linkedImplicitOperator(delExpression).map { (operator, linked) =>
        linkedCallAst(
          delExpression,
          operator,
          linked,
          registerType(Defines.voidTypeName),
          None,
          Nil,
          Some(s"operator delete(${nodeSignature(operand)})")
        )._2
    }
    callAst(cpgDeleteNode, arg :: destructorCall.toList ++ operatorDelete.toList)
  end astForDeleteExpression

  private def astForTypeIdInitExpression(typeIdInit: IASTTypeIdInitializerExpression): Ast =
    val name = Operators.cast
    val cpgCastExpression =
        callNode(
          typeIdInit,
          code(typeIdInit),
          name,
          name,
          DispatchTypes.STATIC_DISPATCH,
          None,
          Some(expressionType(typeIdInit))
        )

    val typeAst = unknownNode(typeIdInit.getTypeId, code(typeIdInit.getTypeId))
    val expr    = astForNode(typeIdInit.getInitializer)
    callAst(cpgCastExpression, List(Ast(typeAst), expr))

  private def astForConstructorExpression(c: ICPPASTSimpleTypeConstructorExpression): Ast =
    val name = c.getDeclSpecifier.toString
    val callNode_ = callNode(
      c,
      code(c),
      name,
      name,
      DispatchTypes.STATIC_DISPATCH,
      None,
      Some(expressionType(c))
    )
    val arg = astForNode(c.getInitializer)
    callAst(callNode_, List(arg))

  private def astForCompoundStatementExpression(
    compoundExpression: IGNUASTCompoundStatementExpression
  ): Ast =
      nullSafeAst(compoundExpression.getCompoundStatement).headOption.getOrElse(Ast())

  private def astForPackExpansionExpression(packExpansionExpression: ICPPASTPackExpansionExpression)
    : Ast =
      astForExpression(packExpansionExpression.getPattern)

  private def astForIdExpression(idExpression: IASTIdExpression): Ast = idExpression.getName match
    case name: CPPASTQualifiedName => astForQualifiedName(name)
    case _                         => astForIdentifier(idExpression)
end AstForExpressionsCreator
