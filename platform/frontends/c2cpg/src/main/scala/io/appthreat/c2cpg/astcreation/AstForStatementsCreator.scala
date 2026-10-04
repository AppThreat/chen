package io.appthreat.c2cpg.astcreation

import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.nodes.{ExpressionNew, NewBlock, NewCall}
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.core.dom.ast.cpp.*
import org.eclipse.cdt.core.dom.ast.gnu.IGNUASTGotoStatement
import org.eclipse.cdt.internal.core.dom.parser.c.CASTIfStatement
import org.eclipse.cdt.internal.core.dom.parser.cpp.CPPASTIfStatement
import org.eclipse.cdt.internal.core.dom.parser.cpp.CPPASTNamespaceAlias
import org.eclipse.cdt.internal.core.model.ASTStringUtil

trait AstForStatementsCreator(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  import AstCreatorHelper.OptionSafeAst

  protected def astForBlockStatement(blockStmt: IASTCompoundStatement, order: Int = -1): Ast =
    val code      = nodeSignature(blockStmt)
    val blockCode = if code == "{}" || code.isEmpty then Defines.empty else code
    val node = blockNode(blockStmt, blockCode, registerType(Defines.voidTypeName))
        .order(order)
        .argumentIndex(order)
    scope.pushNewScope(node)
    var currOrder = 1
    val childAsts = blockStmt.getStatements.flatMap { stmt =>
      val r = astsForStatement(stmt, currOrder)
      currOrder = currOrder + r.length
      r
    }
    val destructorCalls = scopeEndDestructorCalls(blockStmt)
    scope.popScope()
    blockAst(node, childAsts.toList ++ destructorCalls)

  private def astsForDeclarationStatement(decl: IASTDeclarationStatement): Seq[Ast] =
      decl.getDeclaration match
        // Must precede the IASTSimpleDeclaration cases below: a structured binding declaration
        // implements IASTSimpleDeclaration but has no declarators, so it would otherwise be
        // swallowed (dropping the bound names and the initializer).
        case sb: ICPPASTStructuredBindingDeclaration =>
            Seq(astForStructuredBindingDeclaration(sb))
        case simplDecl: IASTSimpleDeclaration
            if simplDecl.getDeclarators.headOption.exists(d =>
                d.isInstanceOf[IASTFunctionDeclarator] &&
                    !isFunctionPointerLikeDeclarator(d.asInstanceOf[IASTFunctionDeclarator])
            ) =>
            Seq(astForFunctionDeclarator(
              simplDecl.getDeclarators.head.asInstanceOf[IASTFunctionDeclarator]
            ))
        case simplDecl: IASTSimpleDeclaration =>
            val locals =
                simplDecl.getDeclarators.zipWithIndex.toList.map { case (d, i) =>
                    astForDeclarator(simplDecl, d, i)
                }
            val calls =
                simplDecl.getDeclarators.toList.flatMap { d =>
                    if d.getInitializer != null then Some(astForInitializer(d, d.getInitializer))
                    else defaultConstructionAst(simplDecl, d)
                }
            locals ++ calls
        case s: ICPPASTStaticAssertDeclaration => Seq(astForStaticAssert(s))
        case usingDeclaration: ICPPASTUsingDeclaration =>
            handleUsingDeclaration(usingDeclaration)
        case alias: ICPPASTAliasDeclaration => Seq(astForAliasDeclaration(alias))
        case func: IASTFunctionDefinition   => Seq(astForFunctionDefinition(func))
        case alias: CPPASTNamespaceAlias    => Seq(astForNamespaceAlias(alias))
        case asm: IASTASMDeclaration        => Seq(astForASMDeclaration(asm))
        case _: ICPPASTUsingDirective       => Seq.empty
        case decl                           => Seq(astForNode(decl))

  private def astForReturnStatement(ret: IASTReturnStatement): Ast =
    val cpgReturn = returnNode(ret, nodeSignature(ret))
    val expr      = nullSafeAst(ret.getReturnValue)
    Ast(cpgReturn).withChild(expr).withArgEdge(cpgReturn, expr.root)

  private def astForBreakStatement(br: IASTBreakStatement): Ast =
      Ast(controlStructureNode(br, ControlStructureTypes.BREAK, nodeSignature(br)))

  private def astForContinueStatement(cont: IASTContinueStatement): Ast =
      Ast(controlStructureNode(cont, ControlStructureTypes.CONTINUE, nodeSignature(cont)))

  private def astForGotoStatement(goto: IASTGotoStatement): Ast =
    val code = s"goto ${ASTStringUtil.getSimpleName(goto.getName)};"
    Ast(controlStructureNode(goto, ControlStructureTypes.GOTO, code))

  private def astsForGnuGotoStatement(goto: IGNUASTGotoStatement): Seq[Ast] =
    // This is for GNU GOTO labels as values.
    // See: https://gcc.gnu.org/onlinedocs/gcc/Labels-as-Values.html
    // For such GOTOs we cannot statically determine the target label. As a quick
    // hack we simply put edges to all labels found indicated by *. This might be an over-taint.
    val code     = s"goto *;"
    val gotoNode = Ast(controlStructureNode(goto, ControlStructureTypes.GOTO, code))
    val exprNode = nullSafeAst(goto.getLabelNameExpression)
    Seq(gotoNode, exprNode)

  private def astsForLabelStatement(label: IASTLabelStatement): Seq[Ast] =
    val cpgLabel    = newJumpTargetNode(label)
    val nestedStmts = nullSafeAst(label.getNestedStatement)
    Ast(cpgLabel) +: nestedStmts

  private def astForDoStatement(doStmt: IASTDoStatement): Ast =
    val code         = nodeSignature(doStmt)
    val doNode       = controlStructureNode(doStmt, ControlStructureTypes.DO, code)
    val conditionAst = astForConditionExpression(doStmt.getCondition)
    val bodyAst      = nullSafeAst(doStmt.getBody)
    controlStructureAst(doNode, Some(conditionAst), bodyAst, placeConditionLast = true)

  private def astForSwitchStatement(switchStmt: IASTSwitchStatement): Ast =
    val declaration = switchStmt match
      case s: ICPPASTSwitchStatement if s.getControllerExpression == null =>
          Option(s.getControllerDeclaration)
      case _ => None
    val controller = declaration.getOrElse(switchStmt.getControllerExpression)
    val code       = s"switch(${nullSafeCode(controller)})"
    val switchNode = controlStructureNode(switchStmt, ControlStructureTypes.SWITCH, code)
    val conditionAst = declaration match
      case Some(d) => conditionDeclarationAst(d)
      case None    => astForConditionExpression(switchStmt.getControllerExpression)
    val stmtAsts = nullSafeAst(switchStmt.getBody)
    if declaration.isDefined then scope.popScope()
    controlStructureAst(switchNode, Some(conditionAst), stmtAsts)

  private def astsForCaseStatement(caseStmt: IASTCaseStatement): Seq[Ast] =
    val labelNode = newJumpTargetNode(caseStmt)
    val stmt      = astForConditionExpression(caseStmt.getExpression)
    Seq(Ast(labelNode), stmt)

  private def astForDefaultStatement(caseStmt: IASTDefaultStatement): Ast =
      Ast(newJumpTargetNode(caseStmt))

  private def astForTryStatement(tryStmt: ICPPASTTryBlockStatement): Ast =
      tryAst(tryStmt, nullSafeAst(tryStmt.getTryBody, 1), tryStmt.getCatchHandlers)

  /** A C++ try: the try body first, then one `catch` block that groups the handlers. The handlers
    * are alternatives (an exception reaches at most one of them), so each takes its own position
    * inside the group, and the CFG gives every handler its own edge from the try body.
    */
  protected def tryAst(node: IASTNode, body: Seq[Ast], handlers: Array[ICPPASTCatchHandler]): Ast =
    val cpgTry      = controlStructureNode(node, ControlStructureTypes.TRY, "try")
    val handlerAsts = withIndex(handlers)((handler, order) => astForCatchHandler(handler, order))
    val group = Option.when(handlerAsts.nonEmpty) {
        val groupNode = NewBlock()
            .code("catch")
            .typeFullName(registerType(Defines.voidTypeName))
            .lineNumber(line(handlers.head))
            .columnNumber(column(handlers.head))
            .order(2)
            .argumentIndex(2)
        blockAst(groupNode, handlerAsts.toList)
    }
    Ast(cpgTry).withChildren(body).withChildren(group.toList)

  /** One handler: the exception it binds, as a local of the handler block, then the handler's body
    * block. `catch (...)` and an unnamed `catch (int)` bind nothing.
    */
  private def astForCatchHandler(handler: ICPPASTCatchHandler, order: Int): Ast =
    val declaration = Option(handler.getDeclaration)
    val code        = s"catch (${declaration.map(nodeSignature).getOrElse("...")})"
    val node = blockNode(handler, code, registerType(Defines.voidTypeName))
        .order(order)
        .argumentIndex(order)
    scope.pushNewScope(node)
    val bound = declaration.toList.flatMap {
        case decl: IASTSimpleDeclaration =>
            decl.getDeclarators.zipWithIndex.toList.collect {
                case (d, i) if ASTStringUtil.getSimpleName(d.getName).nonEmpty =>
                    astForDeclarator(decl, d, i)
            }
        case _ => Nil
    }
    val body            = nullSafeAst(handler.getCatchBody, bound.size + 1)
    val destructorCalls = scopeEndDestructorCalls(handler)
    scope.popScope()
    blockAst(node, bound ++ body ++ destructorCalls)

  protected def astsForStatement(statement: IASTStatement, argIndex: Int = -1): Seq[Ast] =
      withOverflowRecovery(statement, Seq(_))(statementAsts(statement, argIndex))

  private def statementAsts(statement: IASTStatement, argIndex: Int): Seq[Ast] =
    val r = statement match
      case expr: IASTExpressionStatement => Seq(astForExpression(expr.getExpression))
      case block: IASTCompoundStatement  => Seq(astForBlockStatement(block, argIndex))
      case ifStmt: IASTIfStatement =>
          val init = ifStmt match
            case s: ICPPASTIfStatement => s.getInitializerStatement
            case _                     => null
          withInitStatement(ifStmt, init, astForIf(ifStmt))
      case whileStmt: IASTWhileStatement =>
          astForWhile(whileStmt) +: scopeEndDestructorCalls(whileStmt)
      case forStmt: IASTForStatement => astForFor(forStmt) +: scopeEndDestructorCalls(forStmt)
      case forStmt: ICPPASTRangeBasedForStatement =>
          astForRangedFor(forStmt) +: scopeEndDestructorCalls(forStmt)
      case doStmt: IASTDoStatement => Seq(astForDoStatement(doStmt))
      case switchStmt: IASTSwitchStatement =>
          val init = switchStmt match
            case s: ICPPASTSwitchStatement => s.getInitializerStatement
            case _                         => null
          withInitStatement(switchStmt, init, astForSwitchStatement(switchStmt))
      case ret: IASTReturnStatement => Seq(returnLeavingScopes(ret, astForReturnStatement(ret)))
      case br: IASTBreakStatement   => Seq(jumpLeavingScopes(br, astForBreakStatement(br)))
      case cont: IASTContinueStatement =>
          Seq(jumpLeavingScopes(cont, astForContinueStatement(cont)))
      case goto: IASTGotoStatement       => Seq(jumpLeavingScopes(goto, astForGotoStatement(goto)))
      case goto: IGNUASTGotoStatement    => astsForGnuGotoStatement(goto)
      case defStmt: IASTDefaultStatement => Seq(astForDefaultStatement(defStmt))
      case tryStmt: ICPPASTTryBlockStatement => Seq(astForTryStatement(tryStmt))
      case caseStmt: IASTCaseStatement       => astsForCaseStatement(caseStmt)
      case decl: IASTDeclarationStatement    => astsForDeclarationStatement(decl)
      case label: IASTLabelStatement         => astsForLabelStatement(label)
      case _: IASTNullStatement              => Seq.empty
      case _                                 => Seq(astForNode(statement))
    try
      r.map(x => asChildOfMacroCall(statement, x))
    catch
      case e: StackOverflowError => r
      case e: RuntimeException
          if e.getMessage != null && e.getMessage.contains("maximum nested depth") => r
      case e: Throwable => r
  end statementAsts

  /** An `if` or `switch` with an init statement (`if (auto n = size(); n > 0)`) is a block that
    * runs the init statement, then the statement: the init statement's variables are in scope in
    * the condition and in every branch, and are destroyed after the statement.
    */
  private def withInitStatement(stmt: IASTStatement, init: IASTStatement, build: => Ast): Seq[Ast] =
      if init == null then build +: scopeEndDestructorCalls(stmt)
      else
        val node = blockNode(stmt, Defines.empty, registerType(Defines.voidTypeName))
        scope.pushNewScope(node)
        val initAsts = astsForStatement(init)
        val ast      = build
        scope.popScope()
        Seq(blockAst(node, (initAsts :+ ast).toList ++ scopeEndDestructorCalls(stmt)))

  /** A condition that declares a variable (`while (Node *n = next())`): a block holding the
    * declaration, whose scope the caller closes once the statement's body is built.
    */
  private def conditionDeclarationAst(declaration: IASTDeclaration): Ast =
    val node = blockNode(declaration, Defines.empty, registerType(Defines.voidTypeName))
    scope.pushNewScope(node)
    val asts = astsForDeclaration(declaration)
    setArgumentIndices(asts)
    blockAst(node, asts.toList)

  private def astForConditionExpression(
    expr: IASTExpression,
    explicitArgumentIndex: Option[Int] = None
  ): Ast =
    val ast = expr match
      case exprList: IASTExpressionList =>
          val compareAstBlock =
              blockNode(expr, Defines.empty, registerType(Defines.voidTypeName))
          scope.pushNewScope(compareAstBlock)
          val compareBlockAstChildren = exprList.getExpressions.toList.map(nullSafeAst)
          setArgumentIndices(compareBlockAstChildren)
          val compareBlockAst = blockAst(compareAstBlock, compareBlockAstChildren)
          scope.popScope()
          compareBlockAst
      case other =>
          nullSafeAst(other)
    explicitArgumentIndex.foreach { i =>
        ast.root.foreach { case expr: ExpressionNew => expr.argumentIndex = i }
    }
    ast
  end astForConditionExpression

  private def astForFor(forStmt: IASTForStatement): Ast =
    val conditionDeclaration = forStmt match
      case s: ICPPASTForStatement if s.getConditionExpression == null =>
          Option(s.getConditionDeclaration)
      case _ => None
    val codeInit = nullSafeCode(forStmt.getInitializerStatement)
    val codeCond = nullSafeCode(conditionDeclaration.getOrElse(forStmt.getConditionExpression))
    val codeIter = nullSafeCode(forStmt.getIterationExpression)

    val code    = s"for ($codeInit$codeCond;$codeIter)"
    val forNode = controlStructureNode(forStmt, ControlStructureTypes.FOR, code)

    // A declaration in the init (`for (int i = 0; ...)`) is in scope for the whole statement -
    // the condition, the update and the body all read it (C11 6.8.5p5). Popping the init's scope
    // before them would leave every later `i` unresolved: no REF to the LOCAL, type ANY, and
    // nothing for a definition-keyed data-flow engine to connect.
    val initAstBlock = blockNode(forStmt, Defines.empty, registerType(Defines.voidTypeName))
    scope.pushNewScope(initAstBlock)
    val initAst = blockAst(initAstBlock, nullSafeAst(forStmt.getInitializerStatement, 1).toList)
    val compareAst = conditionDeclaration match
      case Some(d) =>
          val a = conditionDeclarationAst(d)
          a.root.foreach { case b: ExpressionNew => b.argumentIndex = 2; case _ => }
          a
      case None => astForConditionExpression(forStmt.getConditionExpression, Some(2))
    val updateAst = nullSafeAst(forStmt.getIterationExpression, 3)
    val bodyAsts =
        withIterationEnd(forStmt, forStmt.getBody, nullSafeAst(forStmt.getBody, 4))
    if conditionDeclaration.isDefined then scope.popScope()
    scope.popScope()
    forAst(forNode, Seq(), Seq(initAst), Seq(compareAst), Seq(updateAst), bodyAsts)
  end astForFor

  private def astForRangedFor(forStmt: ICPPASTRangeBasedForStatement): Ast =
    val codeDecl = nullSafeCode(forStmt.getDeclaration)
    val codeInit = nullSafeCode(forStmt.getInitializerClause)

    val code    = s"for ($codeDecl:$codeInit)"
    val forNode = controlStructureNode(forStmt, ControlStructureTypes.FOR, code)

    val initAst = astForNode(forStmt.getInitializerClause)
    val declAst = astsForDeclaration(forStmt.getDeclaration)
    val stmtAst = withIterationEnd(forStmt, forStmt.getBody, nullSafeAst(forStmt.getBody))
    controlStructureAst(forNode, None, Seq(initAst) ++ declAst ++ stmtAst)

  private def astForWhile(whileStmt: IASTWhileStatement): Ast =
    val declaration = whileStmt match
      case s: ICPPASTWhileStatement if s.getCondition == null => Option(s.getConditionDeclaration)
      case _                                                  => None
    val code = s"while (${nullSafeCode(declaration.getOrElse(whileStmt.getCondition))})"
    val compareAst = declaration match
      case Some(d) => conditionDeclarationAst(d)
      case None    => astForConditionExpression(whileStmt.getCondition)
    val bodyAst =
        withIterationEnd(whileStmt, whileStmt.getBody, nullSafeAst(whileStmt.getBody))
    if declaration.isDefined then scope.popScope()
    whileAst(
      Some(compareAst),
      bodyAst,
      Some(code),
      lineNumber = line(whileStmt),
      columnNumber = column(whileStmt)
    )

  private def astForIf(ifStmt: IASTIfStatement): Ast =
    // a condition declaration (`if (T x = f())`) is in scope in both branches: its scope stays
    // open until they are built
    var conditionScopeOpen = false
    val (code, conditionAst) = ifStmt match
      case s @ (_: CASTIfStatement | _: CPPASTIfStatement)
          if s.getConditionExpression != null =>
          val c          = s"if (${nullSafeCode(s.getConditionExpression)})"
          val compareAst = astForConditionExpression(s.getConditionExpression)
          (c, compareAst)
      case s: CPPASTIfStatement if s.getConditionExpression == null =>
          val c = s"if (${nullSafeCode(s.getConditionDeclaration)})"
          conditionScopeOpen = true
          (c, conditionDeclarationAst(s.getConditionDeclaration))

    val ifNode = controlStructureNode(ifStmt, ControlStructureTypes.IF, code)

    val thenAst = ifStmt.getThenClause match
      case block: IASTCompoundStatement => astForBlockStatement(block)
      case other if other != null =>
          val thenBlock = blockNode(other, Defines.empty, Defines.voidTypeName)
          scope.pushNewScope(thenBlock)
          val a = astsForStatement(other)
          setArgumentIndices(a)
          scope.popScope()
          blockAst(thenBlock, a.toList)
      case _ => Ast()

    val elseAst = ifStmt.getElseClause match
      case block: IASTCompoundStatement =>
          val elseNode =
              controlStructureNode(ifStmt.getElseClause, ControlStructureTypes.ELSE, "else")
          val elseAst = astForBlockStatement(block)
          Ast(elseNode).withChild(elseAst)
      case other if other != null =>
          val elseNode =
              controlStructureNode(ifStmt.getElseClause, ControlStructureTypes.ELSE, "else")
          val elseBlock = blockNode(other, Defines.empty, Defines.voidTypeName)
          scope.pushNewScope(elseBlock)
          val a = astsForStatement(other)
          setArgumentIndices(a)
          scope.popScope()
          Ast(elseNode).withChild(blockAst(elseBlock, a.toList))
      case _ => Ast()
    if conditionScopeOpen then scope.popScope()
    controlStructureAst(ifNode, Some(conditionAst), Seq(thenAst, elseAst))
  end astForIf
end AstForStatementsCreator
