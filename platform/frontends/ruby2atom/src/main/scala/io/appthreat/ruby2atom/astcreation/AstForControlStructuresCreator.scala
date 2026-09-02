package io.appthreat.ruby2atom.astcreation

import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst.{
    ArrayPattern,
    Association,
    BinaryExpression,
    BreakExpression,
    CaseExpression,
    ConstPattern,
    ControlFlowStatement,
    DoWhileExpression,
    ElseClause,
    FindPattern,
    ForExpression,
    GuardClause,
    HashPattern,
    IfExpression,
    InClause,
    MatchAlt,
    MatchAs,
    MatchNilPattern,
    DefaultMultipleAssignment,
    IndexAccess,
    StaticLiteral,
    MatchRest,
    MatchVariable,
    MemberCall,
    NextExpression,
    OperatorAssignment,
    Pin,
    RescueExpression,
    TextSpan,
    ReturnExpression,
    RightwardMatch,
    RubyExpression,
    SimpleCall,
    SimpleIdentifier,
    SingleAssignment,
    SplattingRubyNode,
    StatementList,
    UnaryExpression,
    Unknown,
    UnlessExpression,
    UntilExpression,
    WhenClause,
    WhileExpression
}
import io.appthreat.ruby2atom.parser.RubyJsonHelpers
import io.appthreat.ruby2atom.passes.Defines
import io.appthreat.ruby2atom.passes.Defines.RubyOperators
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.{ControlStructureTypes, DispatchTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.{
    NewBlock,
    NewFieldIdentifier,
    NewIdentifier,
    NewLiteral,
    NewLocal
}

trait AstForControlStructuresCreator(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  protected def astForControlStructureExpression(node: ControlFlowStatement): Ast = node match
    case node: WhileExpression    => astForWhileStatement(node)
    case node: DoWhileExpression  => astForDoWhileStatement(node)
    case node: UntilExpression    => astForUntilStatement(node)
    case node: CaseExpression     => blockAst(NewBlock(), astsForCaseExpression(node).toList)
    case node: IfExpression       => astForIfExpression(node)
    case node: UnlessExpression   => astForUnlessStatement(node)
    case node: ForExpression      => astForForExpression(node)
    case node: RescueExpression   => astForRescueExpression(node)
    case node: NextExpression     => astForNextExpression(node)
    case node: BreakExpression    => astForBreakExpression(node)
    case node: OperatorAssignment => astForOperatorAssignmentExpression(node)

  private def astForWhileStatement(node: WhileExpression): Ast =
    val conditionAst = astForExpression(node.condition)
    val bodyAsts     = astsForStatement(node.body)
    whileAst(Some(conditionAst), bodyAsts, Option(code(node)), line(node), column(node))

  private def astForDoWhileStatement(node: DoWhileExpression): Ast =
    val conditionAst = astForExpression(node.condition)
    val bodyAsts     = astsForStatement(node.body)
    doWhileAst(Some(conditionAst), bodyAsts, Option(code(node)), line(node), column(node))

  // `until T do B` is lowered as `while !T do B`
  private def astForUntilStatement(node: UntilExpression): Ast =
    val notCondition = astForExpression(UnaryExpression("!", node.condition)(node.condition.span))
    val bodyAsts     = astsForStatement(node.body)
    whileAst(Some(notCondition), bodyAsts, Option(code(node)), line(node), column(node))

  // Recursively lowers into a ternary conditional call
  private def astForIfExpression(node: IfExpression): Ast =
    def builder(node: IfExpression, conditionAst: Ast, thenAst: Ast, elseAsts: List[Ast]): Ast =
      // We want to make sure there's always an «else» clause in a ternary operator.
      // The default value is a `nil` literal.
      val elseAsts_ = if elseAsts.isEmpty then
        List(astForNilBlock)
      else
        elseAsts

      val call = callNode(
        node,
        code(node),
        Operators.conditional,
        Operators.conditional,
        DispatchTypes.STATIC_DISPATCH
      )
      callAst(call, conditionAst :: thenAst :: elseAsts_)

    // TODO: Remove or modify the builder pattern when we are no longer using ANTLR
    node.elseClause match
      case Some(elseClause) =>
          elseClause match
            case _: IfExpression => astForJsonIfStatement(node)
            case _               => foldIfExpression(builder)(node)
      case None =>
          foldIfExpression(builder)(node)
  end astForIfExpression

  private def astForJsonIfStatement(node: IfExpression): Ast =
    val conditionAst = astForExpression(node.condition)
    val thenAst      = astForThenClause(node.thenClause)
    val elseAsts = node.elseClause
        .map {
            case x: IfExpression =>
                val wrappedBlock = blockNode(x)
                Ast(wrappedBlock).withChild(astForJsonIfStatement(x))
            case x =>
                astForElseClause(x)
        }
        .getOrElse(Ast())

    val ifNode = controlStructureNode(node, ControlStructureTypes.IF, code(node))
    controlStructureAst(ifNode, Some(conditionAst), thenAst :: elseAsts :: Nil)

  // `unless T do B` is lowered as `if !T then B`
  private def astForUnlessStatement(node: UnlessExpression): Ast =
    val notConditionAst =
        astForExpression(UnaryExpression("!", node.condition)(node.condition.span))
    val thenAst = node.trueBranch match
      case stmtList: StatementList => astForStatementList(stmtList)
      case _ => astForStatementList(StatementList(List(node.trueBranch))(node.trueBranch.span))
    val elseAsts = node.falseBranch.map(astForElseClause).toList
    val ifNode   = controlStructureNode(node, ControlStructureTypes.IF, code(node))
    controlStructureAst(ifNode, Some(notConditionAst), thenAst :: elseAsts)

  protected def astForElseClause(node: RubyExpression): Ast =
      node match
        case elseNode: ElseClause =>
            elseNode.thenClause match
              case stmtList: StatementList => astForStatementList(stmtList)
              case node =>
                  astForUnknown(node)
        case elseNode =>
            astForUnknown(elseNode)

  private def astForForExpression(node: ForExpression): Ast =
    val forEachNode = controlStructureNode(node, ControlStructureTypes.FOR, code(node))

    def collectionAst  = astForExpression(node.iterableVariable)
    val collectionNode = node.iterableVariable

    val iterIdentifier =
        identifierNode(
          node = node.forVariable,
          name = node.forVariable.span.text,
          code = node.forVariable.span.text,
          typeFullName = Defines.Any
        )
    val iterVarLocal = NewLocal().name(node.forVariable.span.text).code(node.forVariable.span.text)
    scope.addToScope(node.forVariable.span.text, iterVarLocal)

    val idxName = "_idx_"
    val idxLocal =
        NewLocal().name(idxName).code(idxName).typeFullName(Defines.getBuiltInType(Defines.Integer))
    val idxIdenAtAssign = identifierNode(
      node = collectionNode,
      name = idxName,
      code = idxName,
      typeFullName = Defines.getBuiltInType(Defines.Integer)
    )

    val idxAssignment =
        callNode(
          node,
          s"$idxName = 0",
          Operators.assignment,
          Operators.assignment,
          DispatchTypes.STATIC_DISPATCH
        )
    val idxAssignmentArgs =
        List(
          Ast(idxIdenAtAssign),
          Ast(NewLiteral().code("0").typeFullName(Defines.getBuiltInType(Defines.Integer)))
        )
    val idxAssignmentAst = callAst(idxAssignment, idxAssignmentArgs)

    val idxIdAtCond = idxIdenAtAssign.copy
    val collectionCountAccess = callNode(
      node,
      s"${node.iterableVariable.span.text}.length",
      Operators.fieldAccess,
      Operators.fieldAccess,
      DispatchTypes.STATIC_DISPATCH
    )
    val fieldAccessAst = callAst(
      collectionCountAccess,
      collectionAst :: Ast(NewFieldIdentifier().canonicalName("length").code("length")) :: Nil
    )

    val idxLt = callNode(
      node,
      s"$idxName < ${node.iterableVariable.span.text}.length",
      Operators.lessThan,
      Operators.lessThan,
      DispatchTypes.STATIC_DISPATCH
    )
    val idxLtArgs  = List(Ast(idxIdAtCond), fieldAccessAst)
    val ltCallCond = callAst(idxLt, idxLtArgs)

    val idxIdAtCollAccess = idxIdenAtAssign.copy
    val collectionIdxAccess = callNode(
      node,
      s"${node.iterableVariable.span.text}[$idxName++]",
      Operators.indexAccess,
      Operators.indexAccess,
      DispatchTypes.STATIC_DISPATCH
    )
    val postIncrAst = callAst(
      callNode(
        node,
        s"$idxName++",
        Operators.postIncrement,
        Operators.postIncrement,
        DispatchTypes.STATIC_DISPATCH
      ),
      Ast(idxIdAtCollAccess) :: Nil
    )

    val indexAccessAst = callAst(collectionIdxAccess, collectionAst :: postIncrAst :: Nil)
    val iteratorAssignmentNode = callNode(
      node,
      s"${node.forVariable.span.text} = ${node.iterableVariable.span.text}[$idxName++]",
      Operators.assignment,
      Operators.assignment,
      DispatchTypes.STATIC_DISPATCH
    )
    val iteratorAssignmentArgs = List(Ast(iterIdentifier), indexAccessAst)
    val iteratorAssignmentAst  = callAst(iteratorAssignmentNode, iteratorAssignmentArgs)
    val doBodyAst              = astsForStatement(node.doBlock)

    val locals = Ast(idxLocal)
        .withRefEdge(idxIdenAtAssign, idxLocal)
        .withRefEdge(idxIdAtCond, idxLocal)
        .withRefEdge(idxIdAtCollAccess, idxLocal) :: Ast(iterVarLocal).withRefEdge(
      iterIdentifier,
      iterVarLocal
    ) :: Nil

    val conditionAsts = ltCallCond :: Nil
    val initAsts      = idxAssignmentAst :: Nil
    val updateAsts    = iteratorAssignmentAst :: Nil

    forAst(
      forNode = forEachNode,
      locals = locals,
      initAsts = initAsts,
      conditionAsts = conditionAsts,
      updateAsts = updateAsts,
      bodyAsts = doBodyAst
    )
  end astForForExpression

  protected def astsForCaseExpression(node: CaseExpression): Seq[Ast] =
    // TODO: Clean up the below
    def goCase(expr: Option[SimpleIdentifier]): List[RubyExpression] =
      val elseThenClause: Option[RubyExpression] =
          node.elseClause.map(_.asInstanceOf[ElseClause].thenClause)
      val whenClauses = node.matchClauses.collect { case x: WhenClause => x }
      val inClauses   = node.matchClauses.collect { case x: InClause => x }

      val ifElseChain = if whenClauses.nonEmpty then
        whenClauses.foldRight[Option[RubyExpression]](elseThenClause) {
            (whenClause: WhenClause, restClause: Option[RubyExpression]) =>
              // We translate multiple match expressions into an or expression.
              //
              // A single match expression is compared using `.===` to the case target expression if it is present
              // otherwise it is treated as a conditional.
              //
              // There may be a splat as the last match expression,
              // `case y when *x then c end` or
              // `case when *x then c end`
              // which is translated to `x.include? y` and `x.any?` conditions respectively

              val conditions = whenClause.matchExpressions.map { mExpr =>
                  expr.map(e => BinaryExpression(mExpr, "===", e)(mExpr.span)).getOrElse(mExpr)
              } ++ whenClause.matchSplatExpression.iterator.flatMap {
                  case splat @ SplattingRubyNode(exprList) =>
                      expr
                          .map { e =>
                              List(MemberCall(exprList, ".", "include?", List(e))(splat.span))
                          }
                          .getOrElse {
                              List(MemberCall(exprList, ".", "any?", List())(splat.span))
                          }
                  case e =>
                      List(Unknown()(e.span))
              }
              // There is always at least one match expression or a splat
              // will become an unknown in condition at the end
              val condition = conditions.init.foldRight(conditions.last) { (cond, condAcc) =>
                  BinaryExpression(cond, "||", condAcc)(whenClause.span)
              }
              val conditional = IfExpression(
                condition,
                whenClause.thenClause.asStatementList,
                List(),
                restClause.map { els => ElseClause(els.asStatementList)(els.span) }
              )(node.span)
              Some(conditional)
        }
      else
        inClauses.foldRight[Option[RubyExpression]](elseThenClause) {
            (inClause: InClause, restClause: Option[RubyExpression]) =>
              val target            = expr.getOrElse(inClause.pattern)
              val (conds, bindings) = destructureMatchPattern(inClause.pattern, target)
              val patternCondition  = conjunction(conds, inClause.span)
              val guardedCondition  = applyGuard(patternCondition, inClause.guard)
              val body =
                  if bindings.nonEmpty then
                    StatementList(
                      bindings ++ inClause.body.asStatementList.statements
                    )(inClause.body.span)
                  else inClause.body

              val conditional = IfExpression(
                guardedCondition,
                body,
                List.empty,
                restClause.map { els => ElseClause(els.asStatementList)(els.span) }
              )(node.span)
              Some(conditional)
        }
      ifElseChain.iterator.toList
    end goCase

    def generatedNode: StatementList = node.expression
        .map { e =>
          val tmp = SimpleIdentifier(None)(e.span.spanStart(this.tmpGen.fresh))
          StatementList(
            List(SingleAssignment(tmp, "=", e)(e.span)) ++
                goCase(Some(tmp))
          )(node.span)
        }
        .getOrElse(StatementList(goCase(None))(node.span))
    astsForStatement(generatedNode)
  end astsForCaseExpression

  private def astForOperatorAssignmentExpression(node: OperatorAssignment): Ast =
    val loweredAssignment = lowerAssignmentOperator(node.lhs, node.rhs, node.op, node.span)
    astForControlStructureExpression(loweredAssignment)

  private def nilPatternLiteral(span: TextSpan): RubyExpression =
      StaticLiteral(Defines.getBuiltInType(Defines.NilClass))(span.spanStart("nil"))

  private def trueLiteral(span: TextSpan): RubyExpression =
      StaticLiteral(Defines.getBuiltInType(Defines.TrueClass))(span.spanStart("true"))

  /** Folds the (possibly empty) condition list of a pattern into a single RubyExpression. */
  protected def conjunction(conds: List[RubyExpression], span: TextSpan): RubyExpression =
      conds.foldRight(trueLiteral(span): RubyExpression) { (cond, acc) =>
          BinaryExpression(cond, "&&", acc)(span)
      }

  private def applyGuard(condition: RubyExpression, guard: Option[RubyExpression]): RubyExpression =
      guard match
        case Some(GuardClause(guardCondition, isUnless)) =>
            val guarded =
                if isUnless then
                  UnaryExpression("!", guardCondition)(guardCondition.span)
                else guardCondition
            BinaryExpression(condition, "&&", guarded)(condition.span)
        case _ => condition

  private def matchVariableAssignment(
    matchVariable: MatchVariable,
    rhs: RubyExpression
  ): SingleAssignment =
    // `{ name: }` shorthand arrives with the trailing colon in the node's code.
    val name = matchVariable.span.text.stripSuffix(":")
    val lhs  = SimpleIdentifier()(matchVariable.span.spanStart(name))
    SingleAssignment(lhs, "=", rhs)(
      matchVariable.span.spanStart(s"${lhs.span.text} = ${rhs.span.text}")
    )

  /** Lowered bindings of a pattern position.
    *
    * @param pattern
    *   the (sub-)pattern being destructured.
    * @param target
    *   the expression whose value the pattern is matched against.
    * @return
    *   the conditions that must hold for the pattern to match, and the assignments binding the
    *   pattern's match variables to the corresponding parts of the target.
    */
  protected def destructureMatchPattern(
    pattern: RubyExpression,
    target: RubyExpression
  ): (List[RubyExpression], List[SingleAssignment]) =
    val equalMatch: List[RubyExpression] =
        BinaryExpression(pattern, "===", target)(pattern.span) :: Nil

    def indexedTarget(index: Int): RubyExpression =
        IndexAccess(
          target,
          StaticLiteral(Defines.getBuiltInType(Defines.Integer))(
            target.span.spanStart(index.toString)
          ) :: Nil
        )(target.span.spanStart(s"${target.span.text}[$index]"))

    pattern match
      case mv: MatchVariable => (Nil, matchVariableAssignment(mv, target) :: Nil)

      case ArrayPattern(children) =>
          val (conds, binds) = children.zipWithIndex
              .map { case (child, idx) => destructureMatchPattern(child, indexedTarget(idx)) }
              .unzip
          (equalMatch ++ conds.flatten, binds.flatten)

      case HashPattern(children) =>
          val (conds, binds) = children
              .map {
                  case assoc: Association =>
                      // `{ key: pattern }` matches `target[key]`; symbol keys keep their symbol form.
                      val subTarget = IndexAccess(target, assoc.key :: Nil)(
                        target.span.spanStart(s"${target.span.text}[${assoc.key.span.text}]")
                      )
                      destructureMatchPattern(assoc.value, subTarget)
                  case mv: MatchVariable =>
                      // `{ name: }` shorthand binds `target[:name]`.
                      val key = StaticLiteral(Defines.getBuiltInType(Defines.Symbol))(
                        mv.span.spanStart(s":${mv.span.text.stripSuffix(":")}")
                      )
                      val subTarget = IndexAccess(target, key :: Nil)(
                        target.span.spanStart(s"${target.span.text}[${key.span.text}]")
                      )
                      (Nil, matchVariableAssignment(mv, subTarget) :: Nil)
                  case rest: MatchRest => destructureMatchPattern(rest, target)
                  case other           => destructureMatchPattern(other, target)
              }
              .unzip
          (equalMatch ++ conds.flatten, binds.flatten)

      case FindPattern(children) =>
          // Element positions are not statically known, so variables bind to the whole target.
          val (conds, binds) = children.map(child => destructureMatchPattern(child, target)).unzip
          (equalMatch ++ conds.flatten, binds.flatten)

      case ConstPattern(const, inner) =>
          val (conds, binds) = destructureMatchPattern(inner, target)
          (BinaryExpression(const, "===", target)(const.span) :: conds, binds)

      case MatchAs(value, as) =>
          val (conds, binds) = destructureMatchPattern(value, target)
          as match
            case mv: MatchVariable => (conds, binds :+ matchVariableAssignment(mv, target))
            case _                 => (conds, binds)

      case MatchAlt(left, right) =>
          val (lConds, lBinds) = destructureMatchPattern(left, target)
          val (rConds, rBinds) = destructureMatchPattern(right, target)
          val altCondition =
              BinaryExpression(
                conjunction(lConds, pattern.span),
                "||",
                conjunction(rConds, pattern.span)
              )(
                pattern.span
              ) :: Nil
          // Both alternatives' bindings are emitted even though only the matching side binds at
          // runtime - approximating that would need runtime knowledge chen does not have.
          (altCondition, lBinds ++ rBinds)

      case _: MatchNilPattern =>
          (BinaryExpression(target, "==", nilPatternLiteral(target.span))(pattern.span) :: Nil, Nil)

      case Pin(value) =>
          (BinaryExpression(target, "==", value)(pattern.span) :: Nil, Nil)

      case MatchRest(optTarget) =>
          optTarget match
            case Some(mv: MatchVariable) =>
                (Nil, matchVariableAssignment(mv, target) :: Nil)
            case _ => (Nil, Nil) // anonymous `*` binds nothing

      case _ => (equalMatch, Nil) // literal/regexp/const patterns match via ===
    end match
  end destructureMatchPattern

  /** `expr => pattern` and `expr in pattern`. */
  protected def astForRightwardMatch(node: RightwardMatch): Ast =
    val (conds, bindings) = destructureMatchPattern(node.pattern, node.value)
    val lowered: RubyExpression =
        if node.raisesOnNoMatch then
          // The NoMatchingPatternError raise is control flow chen does not model; the assignment
          // side of the match is what matters for data flow.
          DefaultMultipleAssignment(bindings)(node.span)
        else StatementList(bindings :+ conjunction(conds, node.span))(node.span)
    astsForStatement(lowered).headOption.getOrElse(astForUnknown(node))
end AstForControlStructuresCreator
