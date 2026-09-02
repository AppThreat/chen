package io.appthreat.ruby2atom.parser

import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst.{RubyExpression, *}
import io.appthreat.ruby2atom.parser.RubyJsonHelpers.*
import io.appthreat.ruby2atom.passes.Defines
import io.appthreat.ruby2atom.passes.Defines.{NilClass, RubyOperators, getBuiltInType}
import io.appthreat.ruby2atom.passes.GlobalTypes.builtinPrefix
import io.appthreat.ruby2atom.utils.FreshNameGenerator
import io.appthreat.x2cpg.frontendspecific.ruby2atom.ImportsPass
import io.appthreat.x2cpg.frontendspecific.ruby2atom.ImportsPass.ImportCallNames
import org.slf4j.LoggerFactory
import ujson.*

import scala.collection.mutable

class RubyJsonToNodeCreator(
  variableNameGen: FreshNameGenerator[String] = FreshNameGenerator(id => s"<tmp-$id>"),
  procParamGen: FreshNameGenerator[Left[String, Nothing]] =
      FreshNameGenerator(id => Left(s"<proc-param-$id>")),
  fileName: String = ""
):

  private val logger       = LoggerFactory.getLogger(getClass)
  private val classNameGen = FreshNameGenerator(id => s"<anon-class-$id>")

  /** Counts node types that could not be lowered (unknown to `AstType`, or depth-truncated by the
    * generator), aggregated over this file instead of one warn log per node. `Ruby2Atom` folds the
    * reports of all files into a single per-run summary.
    */
  private val unknownTypeCounts = mutable.LinkedHashMap.empty[String, Int]

  /** Number of nodes per offending type, e.g. `unknown:kwargs -> 1`, `truncated:array -> 2`. */
  def unknownTypeReport: Map[String, Int] = unknownTypeCounts.toMap

  /** True when the file's `generator_version` is new enough that the syntax facts are complete,
    * i.e. an absent fact key means the fact does not hold rather than "unknown".
    */
  private var syntaxFactsAuthoritative: Boolean = false

  /** Reads a boolean syntax fact, using `fallback` only for JSON older than the facts. */
  private def booleanFact(obj: Obj, key: String, fallback: => Boolean): Boolean =
      obj.getAsBool(key) match
        case Some(value) => value
        case None        => !syntaxFactsAuthoritative && fallback

  private def countUnknownNode(kind: String): Unit =
      unknownTypeCounts.updateWith(kind)((old) => Some(old.getOrElse(0) + 1))

  private implicit val implVisit: ujson.Value => RubyExpression = (x: ujson.Value) => visit(x)

  protected def freshClassName(span: TextSpan): SimpleIdentifier =
      SimpleIdentifier(None)(span.spanStart(classNameGen.fresh))

  private def defaultTextSpan(code: String = ""): TextSpan =
      TextSpan(None, None, None, None, None, code)

  private def defaultResult(span: Option[TextSpan] = None): RubyExpression =
      Unknown()(span.getOrElse(defaultTextSpan()))

  private def visit(v: ujson.Value): RubyExpression =
      v match
        case obj: ujson.Obj => visit(obj)
        case ujson.Null     => StatementList(Nil)(defaultTextSpan())
        case ujson.Str(x)   => StaticLiteral(getBuiltInType(Defines.String))(defaultTextSpan(x))
        case x =>
            countUnknownNode(s"json:${x.getClass.getSimpleName}")
            defaultResult()

  /** Main entrypoint of JSON deserialization.
    */
  def visitProgram(obj: ujson.Value): StatementList =
    // The syntax facts (has_parentheses, heredoc, ...) are emitted only when they hold, so an
    // absent key means "false" - but only for a generator that emits them at all. Deciding that
    // once per file from generator_version is what makes the text fallbacks below actually
    // unreachable for current JSON; keying off the individual absent key would leave the old
    // heuristic deciding every negative case (it misread multiline strings as heredocs).
    syntaxFactsAuthoritative = obj.obj.get(ParserKeys.GeneratorVersion)
        .flatMap(v => v.strOpt)
        .flatMap(v => v.takeWhile(_.isDigit).toIntOption)
        .exists(_ >= 2)
    visit(obj.obj) match
      case x: StatementList => x
      case x                => StatementList(x :: Nil)(x.span)

  private def visit(obj: ujson.Obj): RubyExpression =

    def visitAstType(typ: AstType): RubyExpression =
        typ match
          case AstType.Alias                        => visitAlias(obj)
          case AstType.And                          => visitAnd(obj)
          case AstType.AndAssign                    => visitAndAssign(obj)
          case AstType.Arg                          => visitArg(obj)
          case AstType.ArgExpression                => visitValueExpression(obj)
          case AstType.Args                         => visitArgs(obj)
          case AstType.Array                        => visitArray(obj)
          case AstType.ArrayPattern                 => visitArrayPattern(obj)
          case AstType.ArrayPatternWithTail         => visitArrayPatternWithTail(obj)
          case AstType.ConstPattern                 => visitConstPattern(obj)
          case AstType.BackRef                      => visitBackRef(obj)
          case AstType.Begin                        => visitBegin(obj)
          case AstType.Block                        => visitBlock(obj)
          case AstType.BlockArg                     => visitBlockArg(obj)
          case AstType.BlockArgExpression           => visitValueExpression(obj)
          case AstType.BlockNilArg                  => visitBlockNilArg(obj)
          case AstType.BlockPass                    => visitBlockPass(obj)
          case AstType.BlockWithNumberedParams      => visitBlockWithNumberedParams(obj)
          case AstType.ItBlock                      => visitItBlock(obj)
          case AstType.Break                        => visitBreak(obj)
          case AstType.CaseExpression               => visitCaseExpression(obj)
          case AstType.CaseMatchStatement           => visitCaseMatchStatement(obj)
          case AstType.ClassDefinition              => visitClassDefinition(obj)
          case AstType.ClassVariable                => visitClassVariable(obj)
          case AstType.ClassVariableAssign          => visitSingleAssignment(obj)
          case AstType.ConstVariableAssign          => visitSingleAssignment(obj)
          case AstType.Complex                      => visitComplex(obj)
          case AstType.ConditionalSend              => visitSend(obj, isConditional = true)
          case AstType.Defined                      => visitDefined(obj)
          case AstType.DynamicString                => visitDynamicString(obj)
          case AstType.DynamicSymbol                => visitDynamicSymbol(obj)
          case AstType.EmptyElse                    => visitEmptyElse(obj)
          case AstType.EncodingLiteral              => visitEncodingLiteral(obj)
          case AstType.Ensure                       => visitEnsure(obj)
          case AstType.ExclusiveFlipFlop            => visitExclusiveFlipFlop(obj)
          case AstType.ExclusiveRange               => visitExclusiveRange(obj)
          case AstType.ExecutableString             => visitExecutableString(obj)
          case AstType.False                        => visitFalse(obj)
          case AstType.FileLiteral                  => visitFileLiteral(obj)
          case AstType.FindPattern                  => visitFindPattern(obj)
          case AstType.Float                        => visitFloat(obj)
          case AstType.ForStatement                 => visitForStatement(obj)
          case AstType.ForPostStatement             => visitForStatement(obj)
          case AstType.ForwardArg                   => visitForwardArg(obj)
          case AstType.ForwardArgs                  => visitForwardArgs(obj)
          case AstType.ForwardedArgs                => visitForwardedArgs(obj)
          case AstType.ForwardedKwRestArg           => visitForwardedKwRestArg(obj)
          case AstType.ForwardedRestArg             => visitForwardedRestArg(obj)
          case AstType.GlobalVariable               => visitGlobalVariable(obj)
          case AstType.GlobalVariableAssign         => visitGlobalVariableAssign(obj)
          case AstType.Hash                         => visitHash(obj)
          case AstType.HashPattern                  => visitHashPattern(obj)
          case AstType.Identifier                   => visitIdentifier(obj)
          case AstType.IfGuard                      => visitIfGuard(obj)
          case AstType.IfStatement                  => visitIfStatement(obj)
          case AstType.Index                        => visitIndexAccessAsSend(obj)
          case AstType.IndexAssignment              => visitIndexAssignment(obj)
          case AstType.InclusiveFlipFlop            => visitInclusiveFlipFlop(obj)
          case AstType.InclusiveRange               => visitInclusiveRange(obj)
          case AstType.InMatch                      => visitMatchPatternP(obj)
          case AstType.InPattern                    => visitInPattern(obj)
          case AstType.Int                          => visitInt(obj)
          case AstType.InstanceVariable             => visitInstanceVariable(obj)
          case AstType.InstanceVariableAssign       => visitSingleAssignment(obj)
          case AstType.ItArg                        => visitItArg(obj)
          case AstType.KwArg                        => visitKwArg(obj)
          case AstType.KwBegin                      => visitKwBegin(obj)
          case AstType.Kwargs                       => visitKwargs(obj)
          case AstType.KwNilArg                     => visitKwNilArg(obj)
          case AstType.KwOptArg                     => visitKwOptArg(obj)
          case AstType.KwRestArg                    => visitKwRestArg(obj)
          case AstType.KwSplat                      => visitKwSplat(obj)
          case AstType.LocalVariable                => visitLocalVariable(obj)
          case AstType.LocalVariableAssign          => visitSingleAssignment(obj)
          case AstType.Lambda                       => visitLambda(obj)
          case AstType.LineLiteral                  => visitLineLiteral(obj)
          case AstType.MatchAlt                     => visitMatchAlt(obj)
          case AstType.MatchAs                      => visitMatchAs(obj)
          case AstType.MatchCurrentLine             => visitMatchCurrentLine(obj)
          case AstType.MatchNilPattern              => visitMatchNilPattern(obj)
          case AstType.MatchPattern                 => visitMatchPattern(obj)
          case AstType.MatchPatternP                => visitMatchPatternP(obj)
          case AstType.MatchRest                    => visitMatchRest(obj)
          case AstType.MatchVariable                => visitMatchVariable(obj)
          case AstType.MatchWithLocalVariableAssign => visitMatchWithLocalVariableAssign(obj)
          case AstType.MatchWithTrailingComma       => visitValueExpression(obj)
          case AstType.MatchWrite                   => visitMatchPattern(obj)
          case AstType.MethodDefinition             => visitMethodDefinition(obj)
          case AstType.ModuleDefinition             => visitModuleDefinition(obj)
          case AstType.MultipleAssignment           => visitMultipleAssignment(obj)
          case AstType.MultipleLeftHandSide         => visitMultipleLeftHandSide(obj)
          case AstType.Next                         => visitNext(obj)
          case AstType.Nil                          => visitNil(obj)
          case AstType.Not                          => visitNot(obj)
          case AstType.NumArgs                      => visitNumArgs(obj)
          case AstType.NthRef                       => visitNthRef(obj)
          case AstType.OperatorAssign               => visitOperatorAssign(obj)
          case AstType.ObjCKwArg                    => visitObjCKwArg(obj)
          case AstType.ObjCRestArg                  => visitNumArgs(obj)
          case AstType.ObjCVarArgs                  => visitNumArgs(obj)
          case AstType.OptionalArgument             => visitOptionalArgument(obj)
          case AstType.Or                           => visitOr(obj)
          case AstType.OrAssign                     => visitOrAssign(obj)
          case AstType.Pair                         => visitPair(obj)
          case AstType.Pin                          => visitPin(obj)
          case AstType.PostExpression               => visitPostExpression(obj)
          case AstType.PreExpression                => visitPreExpression(obj)
          case AstType.ProcArgument                 => visitProcArgument(obj)
          case AstType.Rational                     => visitRational(obj)
          case AstType.Redo                         => visitRedo(obj)
          case AstType.Retry                        => visitRetry(obj)
          case AstType.Return                       => visitReturn(obj)
          case AstType.RegexExpression              => visitRegexExpression(obj)
          case AstType.RegexOption                  => visitRegexOption(obj)
          case AstType.ResBody                      => visitResBody(obj)
          case AstType.RestArg                      => visitRestArg(obj)
          case AstType.RestArgExpression            => visitValueExpression(obj)
          case AstType.RescueStatement              => visitRescueStatement(obj)
          case AstType.ScopedConstant               => visitScopedConstant(obj)
          case AstType.Self                         => visitSelf(obj)
          case AstType.Send                         => visitSend(obj)
          case AstType.ShadowArg                    => visitShadowArg(obj)
          case AstType.SingletonMethodDefinition    => visitSingletonMethodDefinition(obj)
          case AstType.SingletonClassDefinition     => visitSingletonClassDefinition(obj)
          case AstType.Splat                        => visitSplat(obj)
          case AstType.StaticString                 => visitStaticString(obj)
          case AstType.StaticSymbol                 => visitStaticSymbol(obj)
          case AstType.Super                        => visitSuper(obj)
          case AstType.SuperNoArgs                  => visitSuperNoArgs(obj)
          case AstType.TopLevelConstant             => visitTopLevelConstant(obj)
          case AstType.True                         => visitTrue(obj)
          case AstType.UnDefine                     => visitUnDefine(obj)
          case AstType.UnlessExpression             => visitUnlessExpression(obj)
          case AstType.UnlessGuard                  => visitUnlessGuard(obj)
          case AstType.UntilExpression              => visitUntilExpression(obj)
          case AstType.UntilPostExpression          => visitUntilPostExpression(obj)
          case AstType.WhenStatement                => visitWhenStatement(obj)
          case AstType.WhileStatement               => visitWhileStatement(obj)
          case AstType.WhilePostStatement           => visitWhileStatement(obj)
          case AstType.Yield                        => visitYield(obj)

    val astTypeStr = obj(ParserKeys.Type).str
    // Depth-truncated nodes arrive as {type, meta_data, nested: true, truncated: true} with no
    // per-type keys, so they must not be dispatched into the regular visitors (whose mandatory
    // key reads would throw and cost the whole file). One truncated node degrades to one node.
    if obj.contains(ParserKeys.Truncated) then
      countUnknownNode(s"truncated:$astTypeStr")
      Unknown()(obj.toTextSpan)
    else
      AstType.fromString(astTypeStr) match
        case Some(typ) => visitAstType(typ)
        case _ =>
            countUnknownNode(s"unknown:$astTypeStr")
            defaultResult(Option(obj.toTextSpan))
  end visit

  private def visitAccessModifier(obj: Obj): RubyExpression =
      obj(ParserKeys.Name).str match
        case "public"    => PublicModifier()(obj.toTextSpan)
        case "private"   => PrivateModifier()(obj.toTextSpan)
        case "protected" => ProtectedModifier()(obj.toTextSpan)
        case modifierName =>
            logger.warn(s"Unknown modifier type $modifierName")
            defaultResult(Option(obj.toTextSpan))

  private def visitAlias(obj: Obj): RubyExpression =
    val name  = visit(obj(ParserKeys.Name)).text.stripPrefix(":")
    val alias = visit(obj(ParserKeys.Alias)).text.stripPrefix(":")
    AliasStatement(alias, name)(obj.toTextSpan)

  private def visitAnd(obj: Obj): RubyExpression =
    val op  = "&&"
    val lhs = visit(obj(ParserKeys.Lhs))
    val rhs = visit(obj(ParserKeys.Rhs))
    BinaryExpression(lhs, op, rhs)(obj.toTextSpan)

  private def visitAndAssign(obj: Obj): RubyExpression =
    val lhs = visit(obj(ParserKeys.Lhs)) match
      case param: MandatoryParameter => param.toSimpleIdentifier
      case x                         => x
    val rhs = visit(obj(ParserKeys.Rhs))
    OperatorAssignment(lhs, "&&=", rhs)(obj.toTextSpan)

  private def visitArg(obj: Obj): RubyExpression =
      MandatoryParameter(obj(ParserKeys.Value).str)(obj.toTextSpan)

  /** `args` nodes are wrappers; their children are consumed contextually (method/block parameter
    * lists read them directly), so a placeholder is correct here.
    */
  private def visitArgs(obj: Obj): RubyExpression = defaultResult(Option(obj.toTextSpan))

  private def visitArray(obj: Obj): RubyExpression =
    val children = obj.visitArray(ParserKeys.Children).flatMap {
        case x: AssociationList => x.elements
        case x                  => x :: Nil
    }

    ArrayLiteral(children, obj.getAsString(ParserKeys.PercentArray))(obj.toTextSpan)

  private def visitArrayPattern(obj: Obj): RubyExpression =
    val children = obj.visitArray(ParserKeys.Children)
    ArrayPattern(children)(obj.toTextSpan)

  private def visitArrayPatternWithTail(obj: Obj): RubyExpression =
      // `in [a,]` - same destructuring semantics as array_pattern.
      ArrayPattern(obj.visitArray(ParserKeys.Children))(obj.toTextSpan)

  /** `Constant(pattern)` - live under `case ... in Foo(x)`. */
  private def visitConstPattern(obj: Obj): RubyExpression =
      ConstPattern(visit(obj(ParserKeys.Const)), visit(obj(ParserKeys.Pattern)))(obj.toTextSpan)

  private def visitBackRef(obj: Obj): RubyExpression = SimpleIdentifier()(obj.toTextSpan)

  private def visitBegin(obj: Obj): RubyExpression =
      lowerBodyList(obj, ParserKeys.Body, obj.toTextSpan)

  /** Lowers a raw statement array into a `StatementList`, attaching Sorbet signatures on the way
    * (see [[attachSigTypes]]). `visitArray` maps the raw values one-to-one, so the raw statements
    * and the lowered ones stay positionally aligned.
    */
  private def lowerBodyList(container: Obj, bodyKey: String, span: TextSpan): StatementList =
    val lowered = container.visitArray(bodyKey)
    StatementList(attachSigTypes(container(bodyKey).arr.toList, lowered))(span)

  /** Sorbet `sig` blocks: the generator (ruby_ast_gen 2.x) marks the def/defs immediately
    * preceded by one in the same statement list with `has_sig`, and the marked def's preceding
    * sibling is the `sig` block whose body carries the types. The fact is read with `booleanFact` -
    * never `getOrElse(<heuristic>)` - so for current JSON absence decides every negative case and
    * no adjacency heuristic ever runs; JSON from an older generator has no marked defs and keeps
    * `Any` types.
    */
  private def attachSigTypes(
    rawStatements: List[ujson.Value],
    lowered: List[RubyExpression]
  ): List[RubyExpression] =
      if rawStatements.sizeCompare(lowered) != 0 then lowered
      else
        rawStatements
            .zip(lowered)
            .zipWithIndex
            .map { case ((raw, statement), index) =>
                val marked = raw match
                  case rawObj: ujson.Obj => booleanFact(rawObj, ParserKeys.HasSig, fallback = false)
                  case _                 => false
                if !marked then statement
                else
                  statement match
                    case declaration: MethodDeclaration =>
                        precedingSig(lowered, index).fold(declaration) { sig =>
                            MethodDeclaration(
                              declaration.methodName,
                              declaration.parameters,
                              declaration.body
                            )(declaration.span, Option(sig))
                        }
                    case declaration: SingletonMethodDeclaration =>
                        precedingSig(lowered, index).fold(declaration) { sig =>
                            SingletonMethodDeclaration(
                              declaration.target,
                              declaration.methodName,
                              declaration.parameters,
                              declaration.body
                            )(declaration.span, Option(sig))
                        }
                    case other => other
                end if
            }
            .toList
  end attachSigTypes

  /** The preceding statement must actually *be* the `sig` block for the fact to be usable; if it
    * lowered to something unexpected, the def keeps no signature rather than guessing. Every form
    * the generator marks is recognised here, matched structurally rather than on the span text:
    * `sig { ... }`, `sig { ... }.checked(:never)` (the block is the receiver of a trailing send
    * chain) and `T::Sig::WithoutRuntime.sig { ... }` (the call has a constant receiver).
    */
  private def precedingSig(lowered: List[RubyExpression], index: Int): Option[Sig] =
      if index == 0 then None else sigBlockBody(lowered(index - 1)).flatMap(sigTypesFrom)

  private def sigBlockBody(statement: RubyExpression): Option[RubyExpression] =
      statement match
        case call: SimpleCallWithBlock if call.target.text == "sig" => Option(call.block.body)
        case call: MemberCallWithBlock if call.methodName == "sig"  => Option(call.block.body)
        // `.checked(:never)`, `.on_failure(...)`: unwrap the chain to reach the block.
        case call: MemberCall => sigBlockBody(call.target)
        case _                => None

  /** Reads the types out of a `sig` block body. The chain shape is Sorbet's: `params(x: X,
    * ...).returns(Y)` is one expression where `returns` hangs off the `params` call,
    * `abstract.void` is a member-access chain, and a bare `sig { void }` is an identifier.
    */
  private def sigTypesFrom(body: RubyExpression): Option[Sig] =
    val statements = body match
      case list: StatementList => list.statements
      case expression          => expression :: Nil

    var parameterTypes: List[(String, String)] = List.empty
    var returnType: String                     = Defines.Any
    var recognized                             = false

    statements.foreach {
        case MemberCall(target, _, "returns", returnArgs) =>
            recognized = true
            returnType = returnArgs.headOption.fold(Defines.Any)(sigTypeText)
            target match
              case SimpleCall(_, parameterArgs) => parameterTypes = sigParameterTypes(parameterArgs)
              case _                            =>
        case SimpleCall(target, parameterArgs) =>
            recognized = true
            target.text match
              case "params"  => parameterTypes = sigParameterTypes(parameterArgs)
              case "returns" => returnType = parameterArgs.headOption.fold(Defines.Any)(sigTypeText)
              case "void"    => returnType = Defines.Void
              case _         =>
        case MemberAccess(target, _, "void") =>
            recognized = true
            returnType = Defines.Void
            // `params(label: String).void` ends the chain in void: the parameters hang off the
            // member access's target.
            target match
              case SimpleCall(_, parameterArgs) => parameterTypes = sigParameterTypes(parameterArgs)
              case _                            =>
        case identifier: SimpleIdentifier if identifier.text == "void" =>
            recognized = true
            returnType = Defines.Void
        case _ =>
    }
    if recognized then Option(Sig(parameterTypes, returnType)) else None
  end sigTypesFrom

  /** `params(x: X, y: Y)` argument associations, the names stripped of their symbol colon. */
  private def sigParameterTypes(args: List[RubyExpression]): List[(String, String)] =
      args.collect { case Association(key: StaticLiteral, value) =>
          (key.innerText.stripPrefix(":"), sigTypeText(value))
      }

  /** A single Sorbet type expression as the summary's type text. `T.nilable(X)` collapses to `X`;
    * `T.untyped`/`T.anything`/`T.any(...)` map to the summary's unknown, and generic applications
    * such as `T::Array[X]` degrade to `ANY` too - a follow-up once the summary can express them.
    */
  private def sigTypeText(expression: RubyExpression): String =
      expression match
        case MemberCall(_, _, "nilable", inner :: _)             => sigTypeText(inner)
        case MemberAccess(_, _, "untyped" | "anything")          => Defines.Any
        case MemberCall(_, _, "untyped" | "anything" | "any", _) => Defines.Any
        case _: IndexAccess                                      => Defines.Any
        case other                                               => other.text

  private def visitGroupedParameter(arrayParam: ArrayLiteral): RubyExpression =
    val freshTmpVar       = variableNameGen.fresh
    val tmpMandatoryParam = MandatoryParameter(freshTmpVar)(arrayParam.span.spanStart(freshTmpVar))

    val singleAssignments = arrayParam.elements.map { param =>
      val rhsSplattingNode =
          SplattingRubyNode(tmpMandatoryParam)(arrayParam.span.spanStart(s"*$freshTmpVar"))
      val lhs = param match
        case x: SimpleIdentifier => SimpleIdentifier()(x.span)
        case x: ArrayParameter =>
            SplattingRubyNode(
              SimpleIdentifier()(arrayParam.span.spanStart(x.span.text.stripPrefix("*")))
            )(
              arrayParam.span.spanStart(x.span.text)
            )
        case x: ArrayLiteral =>
            visitGroupedParameter(x)
        case x =>
            logger.warn(
              s"Invalid parameter type in grouped parameter list: ${x.getClass} (code: ${arrayParam.span.text})"
            )
            defaultResult(Option(arrayParam.span))
      SingleAssignment(lhs, "=", rhsSplattingNode)(
        arrayParam.span.spanStart(s"${lhs.span.text} = ${rhsSplattingNode.span.text}")
      )
    }

    GroupedParameter(
      tmpMandatoryParam.span.text,
      tmpMandatoryParam,
      GroupedParameterDesugaring(singleAssignments)(arrayParam.span)
    )(arrayParam.span)
  end visitGroupedParameter

  private def visitBlock(obj: Obj): RubyExpression =
    val parameters = obj.getAsObj(ParserKeys.Arguments) match
      case Some(argsObj) =>
          argsObj.visitArray(ParserKeys.Children).map {
              case x: ArrayLiteral => visitGroupedParameter(x)
              case x               => x
          }
      case None => Nil

    val assignments = parameters.collect { case x: GroupedParameter =>
        x.multipleAssignment
    }

    val body = obj.visitOption(ParserKeys.Body) match
      case Some(stmt: StatementList) => stmt.copy(stmt.statements ++ assignments)(stmt.span)
      case Some(expr)                => StatementList(expr +: assignments)(expr.span)
      case None                      => StatementList(Nil)(obj.toTextSpan)

    attachBodyToCall(obj(ParserKeys.CallName), parameters, body, obj.toTextSpan)
  end visitBlock

  /** Builds the `Block` node and attaches it to the (visited) call it belongs to. Shared by
    * `block`, `numblock` and `itblock`, which carry the same call/param/body shape.
    */
  private def attachBodyToCall(
    callJson: ujson.Value,
    parameters: List[RubyExpression],
    body: RubyExpression,
    span: TextSpan
  ): RubyExpression =
    val block = Block(parameters, body)(body.span.spanStart(span.text))
    visit(callJson) match
      case classNew: ObjectInstantiation if classNew.span.text == "Class.new" =>
          AnonymousClassDeclaration(freshClassName(span), None, block.toStatementList)(span)
      case objNew: ObjectInstantiation => objNew.withBlock(block)
      case lambda: SimpleIdentifier if lambda.text == "lambda" =>
          ProcOrLambdaExpr(block)(span)
      case ident: SimpleIdentifier if ident.span.text == "loop" =>
          val trueLiteral =
              StaticLiteral(Defines.getBuiltInType(Defines.TrueClass))(ident.span.spanStart("true"))
          DoWhileExpression(trueLiteral, body)(ident.span)
      case simpleIdentifier: SimpleIdentifier =>
          SimpleCall(simpleIdentifier, Nil)(span).withBlock(block)
      case simpleCall: RubyCall => simpleCall.withBlock(block)
      case memberAccess @ MemberAccess(target, op, memberName) =>
          val memberCall = MemberCall(target, op, memberName, List.empty)(memberAccess.span)
          memberCall.withBlock(block)
      case x: ProtectedModifier =>
          SimpleCall(x.toSimpleIdentifier, Nil)(span).withBlock(block)
      case x =>
          logger.warn(s"Unexpected call type used for block ${x.getClass}, ignoring block")
          x
    end match
  end attachBodyToCall

  /** `x.each { _1 + _2 }` - the block carries numbered parameters; chen synthesizes the
    * conventional `_1.._n` parameter names (plan 04 §3).
    */
  private def visitBlockWithNumberedParams(obj: Obj): RubyExpression =
    val paramIdx = obj(ParserKeys.ParamIdx) match
      case ujson.Num(n) => n.toInt
      case ujson.Str(s) => s.toIntOption.getOrElse(0)
      case _            => 0
    val parameters =
        (1 to paramIdx)
            .map { i => MandatoryParameter(s"_$i")(obj.toTextSpan.spanStart(s"_$i")) }
            .toList
    val body = obj.visitOption(ParserKeys.Body) match
      case Some(stmt: StatementList) => stmt
      case Some(expr)                => StatementList(expr :: Nil)(expr.span)
      case None                      => StatementList(Nil)(obj.toTextSpan)
    attachBodyToCall(obj(ParserKeys.Call), parameters, body, obj.toTextSpan)

  /** Ruby 3.4 `it` block (`items.select { it.even? }`): lowers to a block with one synthetic `it`
    * parameter. Body references arrive as `lvar it` under the prism backend, which become regular
    * identifier references to that parameter (plan 04 §3, plan 01 §1).
    *
    * Note the parser-gem backend has no `itblock` at all - there, bare `it` parses as a plain
    * `send(nil, :it)`, i.e. a method call, and is left as one (README fact #7).
    */
  private def visitItBlock(obj: Obj): RubyExpression =
    val parameters = MandatoryParameter("it")(obj.toTextSpan.spanStart("it")) :: Nil
    val body = obj.visitOption(ParserKeys.Body) match
      case Some(stmt: StatementList) => stmt
      case Some(expr)                => StatementList(expr :: Nil)(expr.span)
      case None                      => StatementList(Nil)(obj.toTextSpan)
    attachBodyToCall(obj(ParserKeys.Call), parameters, body, obj.toTextSpan)

  private def visitBlockArg(obj: Obj): RubyExpression =
    val span = obj.toTextSpan
    val name = obj(ParserKeys.Value).strOpt.filterNot(_ == "&").getOrElse(procParamGen.fresh.value)
    ProcParameter(name)(span)

  private def visitBlockPass(obj: Obj): RubyExpression =
    lazy val default = SimpleIdentifier()(obj.toTextSpan.spanStart(procParamGen.current.value))
    obj.visitOption(ParserKeys.Value).getOrElse(default)

  private def visitBracketAssignmentAsSend(obj: Obj): RubyExpression =
    val lhsBase = visit(obj(ParserKeys.Receiver))
    val args    = obj.visitArray(ParserKeys.Arguments)

    val lhs =
        IndexAccess(lhsBase, List(args.head))(
          obj.toTextSpan.spanStart(s"${lhsBase.span.text}[${args.head.span.text}]")
        )

    val rhs =
        if args.size == 2 then args(1)
        else SimpleIdentifier()(obj.toTextSpan.spanStart("*"))

    SingleAssignment(lhs, "=", rhs)(obj.toTextSpan)

  private def visitBreak(obj: Obj): RubyExpression = BreakExpression()(obj.toTextSpan)

  private def visitCaseExpression(obj: Obj): RubyExpression =
    val expression  = obj.visitOption(ParserKeys.CaseExpression)
    val whenClauses = obj.visitArray(ParserKeys.WhenClauses)

    val elseClause = obj.visitOption(ParserKeys.ElseClause) match
      case Some(elseClause) => Some(ElseClause(elseClause)(elseClause.span))
      case None             => None

    CaseExpression(expression, whenClauses, elseClause)(obj.toTextSpan)

  private def visitCaseMatchStatement(obj: Obj): RubyExpression =
    val expression = visit(obj(ParserKeys.Statement))
    val inClauses  = obj.visitArray(ParserKeys.Bodies)
    val elseClause = obj.visitOption(ParserKeys.ElseClause).map(x => ElseClause(x)(x.span))

    CaseExpression(Some(expression), inClauses, elseClause)(obj.toTextSpan)

  private def visitClassDefinition(obj: Obj): RubyExpression =
    val (name, namespaceParts) = visit(obj(ParserKeys.Name)) match
      case memberAccess: MemberAccess =>
          val memberIdentifier =
              SimpleIdentifier()(memberAccess.span.spanStart(memberAccess.memberName))
          (memberIdentifier, Option(getParts(memberAccess).dropRight(1)))
      case identifier => (identifier, None)
    val baseClass      = obj.visitOption(ParserKeys.SuperClass)
    val (body, fields) = createClassBodyAndFields(obj)
    val bodyMemberCall = createBodyMemberCall(name.text, obj.toTextSpan)
    ClassDeclaration(
      name = name,
      baseClass = baseClass,
      body = body,
      fields = fields,
      bodyMemberCall = Option(bodyMemberCall),
      namespaceParts = namespaceParts
    )(obj.toTextSpan)

  private def visitClassVariable(obj: Obj): RubyExpression = ClassFieldIdentifier()(obj.toTextSpan)

  private def visitCollectionAliasSend(obj: Obj): RubyExpression =
    // Modify this `obj` to conform to what the AstCreator would expect i.e, Array [1,2,3] would be an Array::[] call
    val collectionName = obj(ParserKeys.Name).str
    val metaData       = obj(ParserKeys.MetaData)
    metaData.obj.put(ParserKeys.Code, collectionName)
    val receiver = ujson.Obj(
      ParserKeys.Type     -> ujson.Str(AstType.ScopedConstant.name),
      ParserKeys.MetaData -> metaData,
      ParserKeys.Base     -> ujson.Null,
      ParserKeys.Name     -> ujson.Str(collectionName)
    )
    val arguments = obj(ParserKeys.Arguments).arr.headOption
        .flatMap {
            case x: ujson.Obj => AstType.fromString(x(ParserKeys.Type).str).map(t => t -> x)
            case _            => None
        }
        .map {
            case (AstType.Array, o) =>
                o.visitArray(ParserKeys.Children).flatMap {
                    case x: AssociationList => x.elements
                    case x                  => x :: Nil
                }
            case (_, o) =>
                visit(o) :: Nil
        }
        .getOrElse(Nil)

    val textSpan =
        obj.toTextSpan.spanStart(s"$collectionName [${arguments.map(_.span.text).mkString(", ")}]")

    IndexAccess(visit(receiver), arguments)(textSpan)
  end visitCollectionAliasSend

  private def visitDefined(obj: Obj): RubyExpression =
    val name = SimpleIdentifier(Option(getBuiltInType(Defines.Defined)))(
      obj.toTextSpan.spanStart(Defines.Defined)
    )
    val arguments = obj.visitArray(ParserKeys.Arguments)
    SimpleCall(name, arguments)(obj.toTextSpan)

  private def visitDynamicString(obj: Obj): RubyExpression =
    val typeFullName = getBuiltInType(Defines.String)
    val expressions  = obj.visitArray(ParserKeys.Children)
    DynamicLiteral(typeFullName, expressions)(obj.toTextSpan)

  private def visitDynamicSymbol(obj: Obj): RubyExpression =
    val typeFullName = getBuiltInType(Defines.Symbol)
    val expressions  = obj.visitArray(ParserKeys.Children)
    DynamicLiteral(typeFullName, expressions)(obj.toTextSpan)

  private def visitEnsure(obj: Obj): RubyExpression =
    val ensureClause = EnsureClause(visit(obj(ParserKeys.Body)))(obj.toTextSpan)
    visit(obj(ParserKeys.Statement)) match
      case rescueExpression: RescueExpression =>
          rescueExpression.copy(
            rescueExpression.body,
            rescueExpression.rescueClauses,
            rescueExpression.elseClause,
            Some(ensureClause)
          )(obj.toTextSpan)
      case x =>
          RescueExpression(x, List.empty, Option.empty, Some(ensureClause))(obj.toTextSpan)

  /** Flip-flop `...` condition (stateful; the state machine is not modelled). */
  private def visitExclusiveFlipFlop(obj: Obj): RubyExpression =
      visitFlipFlop(obj, "...")

  private def visitExclusiveRange(obj: Obj): RubyExpression =
    val start = visit(obj(ParserKeys.Start))
    val end   = visit(obj(ParserKeys.End))
    val op    = RangeOperator(true)(obj.toTextSpan.spanStart("..."))
    RangeExpression(start, end, op)(obj.toTextSpan)

  private def visitExecutableString(obj: Obj): RubyExpression =
    val operatorName = RubyOperators.backticks
    val callName = SimpleIdentifier(Option(getBuiltInType(operatorName)))(
      obj.toTextSpan.spanStart(operatorName)
    )
    val arguments = obj.visitArray(ParserKeys.Arguments)
    SimpleCall(callName, arguments)(obj.toTextSpan)

  private def visitFalse(obj: Obj): RubyExpression =
      StaticLiteral(getBuiltInType(Defines.FalseClass))(obj.toTextSpan)

  private def visitFieldDeclaration(obj: Obj): RubyExpression =
    val arguments  = obj.visitArray(ParserKeys.Arguments)
    val accessType = obj(ParserKeys.Name).str
    FieldsDeclaration(arguments, accessType)(obj.toTextSpan)

  private def visitFindPattern(obj: Obj): RubyExpression =
      FindPattern(obj.visitArray(ParserKeys.Children))(obj.toTextSpan)

  private def visitFieldAssignmentSend(obj: Obj, fieldName: String): RubyExpression =
    val span     = obj.toTextSpan
    val receiver = visit(obj(ParserKeys.Receiver))
    val memberAccess = MemberAccess(receiver, ".", fieldName)(
      receiver.span.spanStart(s"${receiver.text}.@$fieldName")
    )
    val argument = obj
        .visitArray(ParserKeys.Arguments)
        .headOption
        .getOrElse(StaticLiteral(getBuiltInType(Defines.NilClass))(span.spanStart("nil")))
    SingleAssignment(memberAccess, "=", argument)(span)

  private def visitFloat(obj: Obj): RubyExpression =
      StaticLiteral(getBuiltInType(Defines.Float))(obj.toTextSpan)

  private def visitForStatement(obj: Obj): RubyExpression =
    val forVariable      = visit(obj(ParserKeys.Variable))
    val iterableVariable = visit(obj(ParserKeys.Collection))
    val doBlock = visit(obj(ParserKeys.Body)) match
      case stmtList: StatementList => stmtList
      case other                   => StatementList(List(other))(other.span)

    ForExpression(forVariable, iterableVariable, doBlock)(obj.toTextSpan)

  /** Never emitted by the generator (`emit_forward_arg=false`, README fact #10); kept
    * forward-compatible with `forward_args`.
    */
  private def visitForwardArg(obj: Obj): RubyExpression =
      MandatoryParameter("...")(obj.toTextSpan)

  // Note: Forward args should probably be handled more explicitly, but this should preserve flows if the same
  // identifier is used in latter forwarding
  private def visitForwardArgs(obj: Obj): RubyExpression = MandatoryParameter("...")(obj.toTextSpan)

  private def visitForwardedArgs(obj: Obj): RubyExpression = SimpleIdentifier()(obj.toTextSpan)

  private def visitGlobalVariable(obj: Obj): RubyExpression =
    val span     = obj.toTextSpan
    val name     = obj(ParserKeys.Value).str
    val selfBase = SelfIdentifier()(span.spanStart("self"))
    MemberAccess(selfBase, ".", name)(span)

  private def visitGlobalVariableAssign(obj: Obj): RubyExpression =
    val span = obj.toTextSpan

    val selfBase = SelfIdentifier()(span.spanStart("self"))
    val lhsName  = obj(ParserKeys.Lhs).str
    val lhs =
        MemberAccess(selfBase, ".", lhsName)(span.spanStart(s"${selfBase.span.text}.$lhsName"))

    val rhs = visit(obj(ParserKeys.Rhs))
    val op  = "="

    SingleAssignment(lhs, op, rhs)(obj.toTextSpan)

  private def visitHash(obj: Obj): RubyExpression =
    // The generator emits no syntax fact distinguishing a `{ ... }` literal from a bare
    // association list (e.g. inside `case`/`when`), so the code prefix stays the discriminator.
    val isHashLiteral = obj.toTextSpan.text.stripMargin.startsWith("{")

    obj.visitArray(ParserKeys.Children) match
      case (assoc: Association) :: Nil =>
          if isHashLiteral then HashLiteral(List(assoc))(obj.toTextSpan)
          else assoc // 2 => 1 is interpreted as {2: 1}, so we lower this for now
      case children =>
          if isHashLiteral then HashLiteral(children)(obj.toTextSpan)
          else AssociationList(children)(obj.toTextSpan)

  private def visitHashPattern(obj: Obj): RubyExpression =
      HashPattern(obj.visitArray(ParserKeys.Children))(obj.toTextSpan)

  private def visitIdentifier(obj: Obj): RubyExpression = SimpleIdentifier()(obj.toTextSpan)

  private def visitIfGuard(obj: Obj): RubyExpression =
      GuardClause(visit(obj(ParserKeys.Condition)), isUnless = false)(obj.toTextSpan)

  private def visitIfStatement(obj: Obj): RubyExpression =
    val condition = visit(obj(ParserKeys.Condition))

    val elseClause = obj.visitOption(ParserKeys.ElseBranch).map {
        case x: IfExpression => x
        case x               => ElseClause(StatementList(List(x))(x.span))(x.span)
    }

    obj.visitOption(ParserKeys.ThenBranch) match
      case Some(thenBranch) =>
          IfExpression(condition, thenBranch, elsifClauses = List.empty, elseClause)(obj.toTextSpan)
      case None =>
          val nilBlock = ReturnExpression(
            List(StaticLiteral(Defines.getBuiltInType(Defines.NilClass))(
              obj.toTextSpan.spanStart("nil")
            ))
          )(obj.toTextSpan.spanStart("return nil"))
          IfExpression(condition, nilBlock, elsifClauses = List.empty, elseClause)(obj.toTextSpan)

  private def visitInclude(obj: Obj): RubyExpression =
    val callName = obj(ParserKeys.Name).str
    val target   = SimpleIdentifier()(obj.toTextSpan.spanStart(callName))
    val argument = obj.visitArray(ParserKeys.Arguments).head

    IncludeCall(target, argument)(obj.toTextSpan)

  /** Flip-flop `..` condition (stateful; the state machine is not modelled). */
  private def visitInclusiveFlipFlop(obj: Obj): RubyExpression =
      visitFlipFlop(obj, "..")

  private def visitInclusiveRange(obj: Obj): RubyExpression =
    val start = obj.visitOption(ParserKeys.Start) match
      case Some(expr) => expr
      case None       => infinityLowerBound(obj)
    val end = obj.visitOption(ParserKeys.End) match
      case Some(expr) => expr
      case None       => infinityUpperBound(obj)
    val op = RangeOperator(false)(obj.toTextSpan.spanStart(".."))
    RangeExpression(start, end, op)(obj.toTextSpan)

  private def visitIndexAccessAsSend(obj: Obj): RubyExpression =
    val target  = visit(obj(ParserKeys.Receiver))
    val indices = obj.visitArray(ParserKeys.Arguments)
    IndexAccess(target, indices)(obj.toTextSpan)

  private def visitInPattern(obj: Obj): RubyExpression =
    val patternType = visit(obj(ParserKeys.Pattern))
    val patternBody = visit(obj(ParserKeys.Body))
    val guard       = obj.visitOption(ParserKeys.Guard)

    InClause(patternType, guard, patternBody)(obj.toTextSpan)

  private def visitInt(obj: Obj): RubyExpression =
    val typeFullName = getBuiltInType(Defines.Integer)
    StaticLiteral(typeFullName)(obj.toTextSpan)

  private def visitInstanceVariable(obj: Obj): RubyExpression =
      InstanceFieldIdentifier()(obj.toTextSpan)

  private def visitKwArg(obj: Obj): RubyExpression =
    val name = obj(ParserKeys.Key).str
    val default = obj
        .visitOption(ParserKeys.Value)
        .getOrElse(StaticLiteral(getBuiltInType(Defines.NilClass))(obj.toTextSpan.spanStart("nil")))
    OptionalParameter(name, default)(obj.toTextSpan)

  private def visitKwBegin(obj: Obj): RubyExpression =
    val stmts = obj(ParserKeys.Body) match
      case o: Obj => visit(o) :: Nil
      case _: Arr =>
          attachSigTypes(obj(ParserKeys.Body).arr.toList, obj.visitArray(ParserKeys.Body))
      case _ =>
          val span = obj.toTextSpan
          logger.warn(s"Unhandled JSON body type for `KwBegin`: ${span.text}")
          defaultResult(Option(span)) :: Nil
    StatementList(stmts)(obj.toTextSpan)

  /** `def foo(**nil)` - declares that the method accepts no keyword arguments. The generator emits
    * `{key: null, value: null}` for it (README fact #11); lower it to a hash parameter with the
    * syntactic name so the parameter list keeps its shape.
    */
  private def visitKwNilArg(obj: Obj): RubyExpression =
      HashParameter("**nil")(obj.toTextSpan)

  private def visitKwOptArg(obj: Obj): RubyExpression = visitKwArg(obj)

  private def visitKwRestArg(obj: Obj): RubyExpression =
    val name =
        if obj.contains(ParserKeys.Value) then obj(ParserKeys.Value).str else obj.toTextSpan.text
    HashParameter(name)(obj.toTextSpan)

  private def visitKwSplat(obj: Obj): RubyExpression =
    val values = visit(obj(ParserKeys.Value)) match
      case x: StatementList => x.statements.head
      case x                => x
    SplattingRubyNode(values)(obj.toTextSpan)

  private def visitLocalVariable(obj: Obj): RubyExpression = SimpleIdentifier()(obj.toTextSpan)

  private def visitMatchAlt(obj: Obj): RubyExpression =
      MatchAlt(visit(obj(ParserKeys.Left)), visit(obj(ParserKeys.Right)))(obj.toTextSpan)

  private def visitMatchAs(obj: Obj): RubyExpression =
      MatchAs(visit(obj(ParserKeys.Value)), visit(obj(ParserKeys.As)))(obj.toTextSpan)

  private def visitMatchNilPattern(obj: Obj): RubyExpression =
      MatchNilPattern()(obj.toTextSpan)

  /** `expr => pattern` - rightward assignment; raises `NoMatchingPatternError` on failure. */
  private def visitMatchPattern(obj: Obj): RubyExpression =
      RightwardMatch(
        visit(obj(ParserKeys.Lhs)),
        visit(obj(ParserKeys.Rhs)),
        raisesOnNoMatch = true
      )(
        obj.toTextSpan
      )

  /** `expr in pattern` - one-line pattern match evaluating to the match result. Also used for
    * `in_match`, the ruby27-grammar spelling of the same construct (README fact #14).
    */
  private def visitMatchPatternP(obj: Obj): RubyExpression =
      RightwardMatch(
        visit(obj(ParserKeys.Lhs)),
        visit(obj(ParserKeys.Rhs)),
        raisesOnNoMatch = false
      )(
        obj.toTextSpan
      )

  private def visitMatchRest(obj: Obj): RubyExpression =
      MatchRest(obj.visitOption(ParserKeys.Value))(obj.toTextSpan)

  private def visitMatchVariable(obj: Obj): RubyExpression = MatchVariable()(obj.toTextSpan)

  private def visitMatchWithLocalVariableAssign(obj: Obj): RubyExpression =
    val lhs = visit(obj(ParserKeys.Lhs))
    val rhs = visit(obj(ParserKeys.Rhs))
    MemberCall(lhs, ".", RubyOperators.regexpMatch, rhs :: Nil)(obj.toTextSpan)

  private def visitMethodAccessModifier(obj: Obj): RubyExpression =
    val body = obj.visitArray(ParserKeys.Arguments) match
      case head :: Nil => head
      case xs          => xs.head

    obj(ParserKeys.Name).str match
      case "public_class_method" =>
          PublicMethodModifier(body)(obj.toTextSpan)
      case "private_class_method" =>
          PrivateMethodModifier(body)(obj.toTextSpan)
      case modifierName =>
          logger.warn(s"Unknown modifier type $modifierName")
          defaultResult(Option(obj.toTextSpan))

  private def visitMethodDefinition(obj: Obj): RubyExpression =
    val name = obj(ParserKeys.Name).str
    val parameters = obj.getAsObj(ParserKeys.Arguments) match
      case Some(argsObj) => visitMethodParameters(argsObj)
      case None          => Nil
    val body = obj
        .visitOption(ParserKeys.Body)
        .map {
            case x: StatementList => x
            case x                => StatementList(List(x))(x.span)
        }
        .getOrElse(StatementList(Nil)(obj.toTextSpan.spanStart("<empty>")))
    MethodDeclaration(name, parameters, body)(obj.toTextSpan)

  private def visitModuleDefinition(obj: Obj): RubyExpression =
    val (name, namespaceParts) = visit(obj(ParserKeys.Name)) match
      case memberAccess: MemberAccess =>
          val memberIdentifier =
              SimpleIdentifier()(memberAccess.span.spanStart(memberAccess.memberName))
          (memberIdentifier, Option(getParts(memberAccess).dropRight(1)))
      case identifier => (identifier, None)
    val (body, fields) = createClassBodyAndFields(obj)
    val bodyMemberCall = createBodyMemberCall(name.text, obj.toTextSpan)
    ModuleDeclaration(
      name = name,
      body = body,
      fields = fields,
      bodyMemberCall = Option(bodyMemberCall),
      namespaceParts = namespaceParts
    )(obj.toTextSpan)

  private def visitMultipleAssignment(obj: Obj): RubyExpression =
    val lhs = visit(obj(ParserKeys.Lhs)) match
      case _ @ArrayLiteral(elements, _) => elements
      case expr                         => expr :: Nil
    val rhs = visit(obj(ParserKeys.Rhs)) match
      case _ @ArrayLiteral(elements, _) => elements
      case expr                         => expr :: Nil
    lowerMultipleAssignment(
      obj,
      lhs,
      rhs,
      () => defaultResult(),
      () => StaticLiteral(getBuiltInType(Defines.NilClass))(obj.toTextSpan)
    )

  private def visitMultipleLeftHandSide(obj: Obj): RubyExpression =
    val arr = visitArray(obj).asInstanceOf[ArrayLiteral]
    arr.copy(elements = arr.elements.map {
        case param: MandatoryParameter => param.toSimpleIdentifier
        case expr                      => expr
    })(arr.span)

  private def visitNext(obj: Obj): RubyExpression = NextExpression()(obj.toTextSpan)

  private def visitNil(obj: Obj): RubyExpression =
      StaticLiteral(getBuiltInType(Defines.NilClass))(obj.toTextSpan)

  /** Shared lowering for the `{value: <node>}` expr-arg family (`arg_expr`, `blockarg_expr`,
    * `restarg_expr`). None of these are emitted by the generator today (they belong to grammars or
    * builder settings chen does not receive yet), so this is a forward-compatible case.
    */
  private def visitValueExpression(obj: Obj): RubyExpression =
      visit(obj(ParserKeys.Value))

  /** `complex` literal, e.g. `1i` (live: emitted by both backends).
    */
  private def visitComplex(obj: Obj): RubyExpression =
      StaticLiteral(getBuiltInType(Defines.Complex))(obj.toTextSpan)

  /** `case ... else end` with an empty else body evaluates to `nil`. (Live.) */
  private def visitEmptyElse(obj: Obj): RubyExpression =
      StatementList(Nil)(obj.toTextSpan)

  /** `__ENCODING__` evaluates to the file's encoding. Latent today: the parser normalizes it to a
    * `str`/`const` node in the grammars chen receives.
    */
  private def visitEncodingLiteral(obj: Obj): RubyExpression =
      StaticLiteral(getBuiltInType(Defines.Encoding))(obj.toTextSpan)

  /** `__FILE__` evaluates to the file name; the generator carries it in `value`. Latent today for
    * the same reason as `__ENCODING__`.
    */
  private def visitFileLiteral(obj: Obj): RubyExpression =
    val text = obj.getAsString(ParserKeys.Value).getOrElse(obj.toTextSpan.text)
    StaticLiteral(getBuiltInType(Defines.String))(obj.toTextSpan.spanStart(text))

  /** `__LINE__` evaluates to the line number. Latent today, like `__FILE__`. */
  private def visitLineLiteral(obj: Obj): RubyExpression =
    val text = obj(ParserKeys.Value) match
      case ujson.Num(n) => n.toInt.toString
      case ujson.Str(s) => s
      case _            => obj.toTextSpan.text
    StaticLiteral(getBuiltInType(Defines.Integer))(obj.toTextSpan.spanStart(text))

  /** `index`/`indexasgn` are only emitted when the parser's `emit_index` builder flag is on, which
    * is off on every backend chen supports (README fact #10): `a[1]` arrives as a `send` of `[]`.
    * These visitors exist for forward compatibility.
    */
  private def visitIndexAssignment(obj: Obj): RubyExpression =
    val lhsBase = visit(obj(ParserKeys.Receiver))
    val indices = obj.visitArray(ParserKeys.Arguments)
    val lhs = IndexAccess(lhsBase, indices)(
      obj.toTextSpan.spanStart(s"${lhsBase.span.text}[${indices.map(_.span.text).mkString(", ")}]")
    )
    val rhs = obj.visitOption(ParserKeys.Value).getOrElse(
      StaticLiteral(getBuiltInType(Defines.NilClass))(obj.toTextSpan.spanStart("nil"))
    )
    SingleAssignment(lhs, "=", rhs)(obj.toTextSpan)

  /** `itarg` is the 3.4 `it` parameter marker; the prism translation emits a bare `:it` symbol as
    * the `itblock` param instead (plan 01 §1), so this is forward compatibility.
    */
  private def visitItArg(obj: Obj): RubyExpression =
      MandatoryParameter(obj.getAsString(ParserKeys.Value).getOrElse("it"))(obj.toTextSpan)

  /** `blocknilarg` is the 4.1 `def foo(&nil)` marker. No available grammar parses it yet, so this
    * is forward compatibility. `&nil` binds no parameter; approximating it with the usual anonymous
    * proc parameter keeps the args list shape stable.
    */
  private def visitBlockNilArg(obj: Obj): RubyExpression =
      ProcParameter(obj.getAsString(ParserKeys.Value).filterNot(_ == "&").getOrElse(
        procParamGen.fresh.value
      ))(obj.toTextSpan)

  /** `kwargs` is the keyword-arguments wrapper node, only emitted with `emit_kwargs` on (off today,
    * README fact #10). Lowering to an association list lets `visitSend` treat it like any other
    * named-argument hash.
    */
  private def visitKwargs(obj: Obj): RubyExpression =
      HashLiteral(obj.visitArray(ParserKeys.Children))(obj.toTextSpan)

  /** Standalone `lambda` node, only emitted with `emit_lambda` on (off today). With the flag off,
    * `->(x) {}` arrives as a `block` on `send(nil, :lambda)`, which `visitBlock` already lowers to
    * `ProcOrLambdaExpr`.
    */
  private def visitLambda(obj: Obj): RubyExpression =
    val emptyBlock = Block(Nil, StatementList(Nil)(obj.toTextSpan))(obj.toTextSpan)
    ProcOrLambdaExpr(emptyBlock)(obj.toTextSpan)

  /** `if /re/ then ...` - an implicit regexp match against the last read line, `$_`. (Live.)
    */
  private def visitMatchCurrentLine(obj: Obj): RubyExpression =
    val dollarUnderscore = MemberAccess(
      SelfIdentifier()(obj.toTextSpan.spanStart("self")),
      ".",
      "$_"
    )(obj.toTextSpan.spanStart("self.$_"))
    BinaryExpression(dollarUnderscore, RubyOperators.regexpMatch, visit(obj(ParserKeys.Value)))(
      obj.toTextSpan
    )

  /** Anonymous `*` argument marker (`numargs`/`objc_restarg`/`objc_varargs`; the objc variants
    * belong to the macRuby grammars chen never receives).
    */
  private def visitNumArgs(obj: Obj): RubyExpression =
      ArrayParameter(obj.getAsString(ParserKeys.Value).getOrElse("*"))(obj.toTextSpan)

  /** `objc_kwarg` is the macRuby keyword argument; shaped like `pair`/`optarg`. */
  private def visitObjCKwArg(obj: Obj): RubyExpression =
    val name = obj.getAsString(ParserKeys.Key).getOrElse(obj.toTextSpan.text)
    val default = obj.visitOption(ParserKeys.Value).getOrElse(
      StaticLiteral(getBuiltInType(Defines.NilClass))(obj.toTextSpan.spanStart("nil"))
    )
    OptionalParameter(name, default)(obj.toTextSpan)

  private def visitNthRef(obj: Obj): RubyExpression =
    val span     = obj.toTextSpan
    val name     = obj(ParserKeys.Value).num.toInt
    val selfBase = SelfIdentifier()(span.spanStart("self"))
    MemberAccess(selfBase, ".", s"$$$name")(span)

  private def visitObjectInstantiation(obj: Obj): RubyExpression =
    // The receiver is the target with the JSON parser
    val receiver  = visit(obj(ParserKeys.Receiver))
    val arguments = obj.visitArray(ParserKeys.Arguments)
    SimpleObjectInstantiation(receiver, arguments)(obj.toTextSpan)

  private def visitOperatorAssign(obj: Obj): RubyExpression =
    val lhs = visit(obj(ParserKeys.Lhs)) match
      case param: MandatoryParameter => param.toSimpleIdentifier
      case x                         => x
    val op  = s"${obj(ParserKeys.Op).str}="
    val rhs = visit(obj(ParserKeys.Rhs))
    SingleAssignment(lhs, op, rhs)(obj.toTextSpan)

  private def visitOptionalArgument(obj: Obj): RubyExpression =
    val name    = obj(ParserKeys.Key).str
    val default = visit(obj(ParserKeys.Value))
    OptionalParameter(name, default)(obj.toTextSpan)

  private def visitOr(obj: Obj): RubyExpression =
    val op  = "||"
    val lhs = visit(obj(ParserKeys.Lhs))
    val rhs = visit(obj(ParserKeys.Rhs))
    BinaryExpression(lhs, op, rhs)(obj.toTextSpan)

  private def visitOrAssign(obj: Obj): RubyExpression =
    val lhs = visit(obj(ParserKeys.Lhs)) match
      case param: MandatoryParameter => param.toSimpleIdentifier
      case x                         => x
    val rhs = visit(obj(ParserKeys.Rhs))
    OperatorAssignment(lhs, "||=", rhs)(obj.toTextSpan)

  /** `^value` in a pattern - equality against an already-bound value; binds nothing. (Live.) */
  private def visitPin(obj: Obj): RubyExpression =
      Pin(visit(obj(ParserKeys.Value)))(obj.toTextSpan)

  /** `not x` - normalized to `!x`. Latent today: the grammars chen receives normalize `not` to a
    * `send` of `!`, so this is forward compatibility.
    */
  private def visitNot(obj: Obj): RubyExpression =
      UnaryExpression("!", visit(obj(ParserKeys.Arguments).arr.head))(obj.toTextSpan)

  /** Anonymous `*` / `**` inside a forwarded-args parameter list. Latent (README fact #10). */
  private def visitForwardedRestArg(obj: Obj): RubyExpression =
      ArrayParameter("*")(obj.toTextSpan)

  private def visitForwardedKwRestArg(obj: Obj): RubyExpression =
      HashParameter("**")(obj.toTextSpan)

  private def visitPair(obj: Obj): RubyExpression =
    val key   = visit(obj(ParserKeys.Key))
    val value = visit(obj(ParserKeys.Value))
    Association(key, value)(obj.toTextSpan)

  private def visitMethodParameters(paramsNode: Obj): List[RubyExpression] =
      AstType.fromString(paramsNode(ParserKeys.Type).str) match
        case Some(AstType.Args)        => paramsNode.visitArray(ParserKeys.Children)
        case Some(AstType.ForwardArgs) => visit(paramsNode) :: Nil
        case Some(x) =>
            logger.warn(s"Not explicitly handled parameter type '$x', no special handling applied")
            visit(paramsNode) :: Nil
        case _ =>
            logger.error(
              s"Unknown JSON type used as method parameter ${paramsNode(ParserKeys.Type).str}"
            )
            defaultResult(Option(paramsNode.toTextSpan)) :: Nil

  /** `END { ... }` - the phase timing is control flow chen does not model; the body's statements
    * are preserved (plan 04 §4).
    */
  private def visitPostExpression(obj: Obj): RubyExpression =
      visitBodyStatements(obj)

  /** `BEGIN { ... }` - see `visitPostExpression`. */
  private def visitPreExpression(obj: Obj): RubyExpression =
      visitBodyStatements(obj)

  /** Latent today (`emit_procarg0=false`, README fact #10): the whole `|x, y|` list as one node.
    * Lowered with the existing grouped-parameter machinery.
    */
  private def visitProcArgument(obj: Obj): RubyExpression =
      visitGroupedParameter(ArrayLiteral(obj.visitArray(ParserKeys.Children))(obj.toTextSpan))

  private def visitRaise(obj: Obj): RubyExpression =
    val callName = obj(ParserKeys.Name).str
    val target   = SimpleIdentifier()(obj.toTextSpan.spanStart(callName))

    obj.visitArray(ParserKeys.Arguments) match
      case Nil => RaiseCall(target, List.empty)(obj.toTextSpan)
      case (argument: StaticLiteral) :: Nil =>
          val simpleErrorId =
              SimpleIdentifier(Option(s"$builtinPrefix.StandardError"))(
                argument.span.spanStart("StandardError")
              )
          val implicitSimpleErrInst = SimpleObjectInstantiation(simpleErrorId, argument :: Nil)(
            argument.span.spanStart(s"StandardError.new(${argument.text})")
          )
          RaiseCall(target, implicitSimpleErrInst :: Nil)(obj.toTextSpan)
      case argument :: Nil =>
          RaiseCall(target, List(argument))(obj.toTextSpan)
      case arguments =>
          RaiseCall(target, arguments)(obj.toTextSpan)

  private def visitBodyStatements(obj: Obj): RubyExpression =
      StatementList(visit(obj(ParserKeys.Body)) :: Nil)(obj.toTextSpan)

  private def visitFlipFlop(obj: Obj, op: String): RubyExpression =
    val lhs = visit(obj(ParserKeys.Start))
    val rhs = visit(obj(ParserKeys.End))
    BinaryExpression(lhs, op, rhs)(obj.toTextSpan)

  private def visitRational(obj: Obj): RubyExpression =
      StaticLiteral(getBuiltInType(Defines.Rational))(obj.toTextSpan)

  private def visitRedo(obj: Obj): RubyExpression =
    val callTarget = SimpleIdentifier()(obj.toTextSpan.spanStart("redo"))
    SimpleCall(callTarget, Nil)(obj.toTextSpan)

  private def visitRetry(obj: Obj): RubyExpression =
    val callTarget = SimpleIdentifier()(obj.toTextSpan.spanStart("retry"))
    SimpleCall(callTarget, Nil)(obj.toTextSpan)

  private def visitReturn(obj: Obj): RubyExpression =
      if obj.contains(ParserKeys.Values) then
        val returnExpressions = obj.visitArray(ParserKeys.Values)
        ReturnExpression(returnExpressions)(obj.toTextSpan)
      else if obj.contains(ParserKeys.Value) then
        ReturnExpression(visit(obj(ParserKeys.Value)) :: Nil)(obj.toTextSpan)
      else
        ReturnExpression(List.empty)(obj.toTextSpan)

  private def visitRegexExpression(obj: Obj): RubyExpression =
      obj.visitOption(ParserKeys.Value) match
        case Some(_ @StatementList(stmts)) =>
            DynamicLiteral(Defines.getBuiltInType(Defines.Regexp), stmts)(obj.toTextSpan)
        case _ => StaticLiteral(Defines.getBuiltInType(Defines.Regexp))(obj.toTextSpan)

  private def visitRegexOption(obj: Obj): RubyExpression = defaultResult(Option(obj.toTextSpan))

  private def visitResBody(obj: Obj): RubyExpression =
    val exceptionClassList = obj.visitOption(ParserKeys.ExecList)
    val variables          = obj.visitOption(ParserKeys.ExecVar)
    val body = obj.visitOption(ParserKeys.Body) match
      case Some(stmt: StatementList) => stmt
      case Some(expr)                => StatementList(expr :: Nil)(expr.span)
      case None                      => StatementList(Nil)(obj.toTextSpan)
    RescueClause(exceptionClassList, variables, body)(obj.toTextSpan)

  private def visitRestArg(obj: Obj): RubyExpression =
      obj(ParserKeys.Value) match
        case ujson.Null      => ArrayParameter("*")(obj.toTextSpan)
        case ujson.Str(name) => ArrayParameter(name)(obj.toTextSpan)
        case x =>
            logger.warn(s"Unhandled `restarg` JSON type '$x'")
            defaultResult(Option(obj.toTextSpan))

  private def visitRescueStatement(obj: Obj): RubyExpression =
    val stmt = visit(obj(ParserKeys.Statement))
    // A non-clause body here used to be an unchecked cast that cost the whole file; drop the
    // stray node instead.
    val rescueClauses = obj.visitArray(ParserKeys.Bodies).collect { case x: RescueClause => x }
    val elseClause = obj.visitOption(ParserKeys.ElseClause) match
      case Some(body) => Option(ElseClause(body)(body.span))
      case None       => Option.empty

    RescueExpression(stmt, rescueClauses, elseClause, Option.empty)(obj.toTextSpan)

  private def visitRequireLike(obj: Obj): RubyExpression =
    val callName = obj(ParserKeys.Name).str
    val target   = SimpleIdentifier()(obj.toTextSpan.spanStart(callName))
    val argument = obj
        .visitArray(ParserKeys.Arguments)
        .headOption
        .getOrElse(StaticLiteral(getBuiltInType(Defines.NilClass))(obj.toTextSpan.spanStart("nil")))
    val isRelative = callName == "require_relative" || callName == "require_all"
    val isWildcard = callName == "require_all"
    RequireCall(target, argument, isRelative, isWildcard)(obj.toTextSpan)

  private def visitScopedConstant(obj: Obj): RubyExpression =
    val identifier = obj(ParserKeys.Name).str
    if obj.contains(ParserKeys.Base) then
      val target = visit(obj(ParserKeys.Base))
      // A `const` node with a base is always written `Base::Name` in Ruby source (`A.B` parses
      // as a send), so the operator is not derived from the code text. The generator emits no
      // call_operator fact for const nodes.
      MemberAccess(target, "::", identifier)(obj.toTextSpan)
    else
      SimpleIdentifier()(obj.toTextSpan)

  private def visitSelf(obj: Obj): RubyExpression = SelfIdentifier()(obj.toTextSpan)

  private def visitSend(obj: Obj, isConditional: Boolean = false): RubyExpression =
    val callName    = obj(ParserKeys.Name).str
    val hasReceiver = obj.contains(ParserKeys.Receiver)
    callName match
      case "new"                                           => visitObjectInstantiation(obj)
      case "Array" | "Hash"                                => visitCollectionAliasSend(obj)
      case "[]"                                            => visitIndexAccessAsSend(obj)
      case "[]="                                           => visitBracketAssignmentAsSend(obj)
      case "raise"                                         => visitRaise(obj)
      case "include"                                       => visitInclude(obj)
      case "attr_reader" | "attr_writer" | "attr_accessor" => visitFieldDeclaration(obj)
      case "private" | "public" | "protected"              => visitAccessModifier(obj)
      case "private_class_method" | "public_class_method"  => visitMethodAccessModifier(obj)
      case requireLike if ImportCallNames.contains(requireLike) && !hasReceiver =>
          visitRequireLike(obj)
      case _ if BinaryOperators.isBinaryOperatorName(callName) =>
          val lhs = visit(obj(ParserKeys.Receiver))
          val rhs = obj.visitArray(ParserKeys.Arguments).head
          BinaryExpression(lhs, callName, rhs)(obj.toTextSpan)
      case _ if UnaryOperators.isUnaryOperatorName(callName) =>
          UnaryExpression(callName, visit(obj(ParserKeys.Receiver)))(obj.toTextSpan)
      case s"$name=" if hasReceiver => visitFieldAssignmentSend(obj, name)
      case _ =>
          val target      = SimpleIdentifier()(obj.toTextSpan.spanStart(callName))
          val argumentArr = obj.visitArray(ParserKeys.Arguments)
          val arguments = argumentArr.flatMap {
              case hashLiteral: HashLiteral =>
                  hashLiteral.elements // a hash is likely named arguments
              case assocList: AssociationList => assocList.elements // same as above
              case x                          => x :: Nil
          }
          val objSpan      = obj.toTextSpan
          val hasArguments = arguments.nonEmpty
          // The generator records whether the call was written with parentheses and which
          // operator it used (call_operator/has_parentheses, plan 02 §4). The text checks are
          // only a fallback for JSON emitted by generators older than 2.0.
          val usesParenthesis =
              booleanFact(obj, ParserKeys.HasParentheses, objSpan.text.endsWith(")"))
          if obj.contains(ParserKeys.Receiver) then
            val base         = visit(obj(ParserKeys.Receiver))
            val isMemberCall = usesParenthesis || callName == "<<" || hasArguments
            val op = obj.getAsString(ParserKeys.CallOperator).getOrElse {
                val dot = if objSpan.text.stripPrefix(base.text).startsWith("::") then "::" else "."
                if isConditional then s"&$dot" else dot
            }
            if isMemberCall then MemberCall(base, op, callName, arguments)(obj.toTextSpan)
            else MemberAccess(base, op, callName)(obj.toTextSpan)
          else if hasArguments || usesParenthesis then
            SimpleCall(target, arguments)(obj.toTextSpan)
          else
            // The following allows the AstCreator to approximate when an identifier could be a call or not - puts less
            //  strain on data-flow tracking for externally inherited accessor calls such as `params` in RubyOnRails
            SimpleIdentifier()(obj.toTextSpan.spanStart(callName))
    end match
  end visitSend

  /** Block-local variable declaration (`proc { |x; y| }`); it is a real binding, so it becomes a
    * parameter-like node instead of being dropped (plan 04 §4).
    */
  private def visitShadowArg(obj: Obj): RubyExpression =
      MandatoryParameter(obj.getAsString(ParserKeys.Value).getOrElse(obj.toTextSpan.text))(
        obj.toTextSpan
      )

  private def visitSingletonMethodDefinition(obj: Obj): RubyExpression =
    val base = visit(obj(ParserKeys.Base))
    val name = obj(ParserKeys.Name).str
    val parameters = obj.getAsObj(ParserKeys.Arguments) match
      case Some(argsObj) => visitMethodParameters(argsObj)
      case None          => Nil
    val body =
        obj.visitOption(ParserKeys.Body).getOrElse(
          StatementList(Nil)(obj.toTextSpan.spanStart("<empty>"))
        ) match
          case stmtList: StatementList => stmtList
          case expr                    => StatementList(expr :: Nil)(expr.span)
    SingletonMethodDeclaration(base, name, parameters, body)(obj.toTextSpan)

  private def visitSingletonClassDefinition(obj: Obj): RubyExpression =
    val name      = visit(obj(ParserKeys.Name))
    val baseClass = obj.visitOption(ParserKeys.SuperClass)
    val body = obj.visitOption(ParserKeys.Body).getOrElse(
      StatementList(Nil)(obj.toTextSpan.spanStart("<empty>"))
    )

    obj.visitOption(ParserKeys.Def) match
      case Some(body) =>
          name match
            case _: SelfIdentifier =>
                val bodyList = body match
                  case stmtList: StatementList => stmtList
                  case expr                    => StatementList(expr :: Nil)(expr.span)

                val base = baseClass match
                  case Some(baseClass) => baseClass
                  case None            => SelfIdentifier()(obj.toTextSpan.spanStart("self"))

                SingletonClassDeclaration(freshClassName(obj.toTextSpan), Some(base), bodyList)(
                  obj.toTextSpan
                )
            case _ =>
                def mapDefBody(defBody: RubyExpression): RubyExpression = defBody match
                  case method @ MethodDeclaration(methodName, parameters, body) =>
                      val memberAccess =
                          MemberAccess(name, ".", methodName)(
                            method.span.spanStart(s"${name.span.text}.${methodName}")
                          )
                      val singletonBlockMethod =
                          SingletonObjectMethodDeclaration(methodName, parameters, body, name)(
                            method.span,
                            method.sig
                          )
                      SingleAssignment(memberAccess, "=", singletonBlockMethod)(
                        method.span.spanStart(s"${memberAccess.span.text} = ${method.span.text}")
                      )
                  case expr => expr

                val stmts = body match
                  case _ @StatementList(stmts) => stmts.map(mapDefBody)
                  case expr                    => mapDefBody(expr) :: Nil
                SingletonStatementList(stmts)(obj.toTextSpan)

      case None =>
          val anonName = freshClassName(obj.toTextSpan)
          SingletonClassDeclaration(name = anonName, baseClass = baseClass, body = body)(
            obj.toTextSpan
          )
    end match
  end visitSingletonClassDefinition

  private def visitSingleAssignment(obj: Obj): RubyExpression =
    val lhsSpan = obj.toTextSpan.spanStart(obj(ParserKeys.Lhs).str)
    val lhs = obj(ParserKeys.Lhs).str match
      case s"@@$_" => ClassFieldIdentifier()(lhsSpan)
      case s"@$_"  => InstanceFieldIdentifier()(lhsSpan)
      case _       => SimpleIdentifier()(lhsSpan)
    obj.visitOption(ParserKeys.Rhs) match
      case Some(rhs) =>
          SingleAssignment(lhs, "=", rhs)(obj.toTextSpan)
      case None =>
          if AstType.fromString(obj(ParserKeys.Type).str) == AstType.LocalVariableAssign then
            // `lvasgn` is used in exec_var for rescueExpr, which only has LHS
            MandatoryParameter(lhs.span.text)(lhs.span)
          else
            lhs

  private def visitSplat(obj: Obj): RubyExpression =
      obj.visitOption(ParserKeys.Value) match
        case Some(x) => SplattingRubyNode(x)(obj.toTextSpan)
        case None =>
            val emptyStar = SimpleIdentifier()(obj.toTextSpan.spanStart("_"))
            SplattingRubyNode(emptyStar)(obj.toTextSpan)

  private def visitStaticString(obj: Obj): RubyExpression =
    val typeFullName = getBuiltInType(Defines.String)
    val originalSpan = obj.toTextSpan
    val value        = obj(ParserKeys.Value).str
    // A heredoc string's code/offsets cover only the `<<~SQL` marker, so its span text becomes
    // the node's value (the body). The generator flags heredocs explicitly; the containment
    // check is the fallback for older generators, where it also caught multiline strings.
    val span =
        booleanFact(obj, ParserKeys.Heredoc, !originalSpan.text.contains(value)) match
          case true  => originalSpan.spanStart(value)
          case false => originalSpan
    StaticLiteral(typeFullName)(span)

  private def visitStaticSymbol(obj: Obj): RubyExpression =
    val typeFullName = getBuiltInType(Defines.Symbol)
    val objTextSpan  = obj.toTextSpan

    // Symbols have no syntax fact in the generator contract, and hash-key symbols
    // (`{ "status": ... }`) legitimately arrive without the leading colon, so the prefix
    // normalization stays.
    if objTextSpan.text.startsWith(":") then StaticLiteral(typeFullName)(obj.toTextSpan)
    else StaticLiteral(typeFullName)(objTextSpan.spanStart(s":${objTextSpan.text}"))

  private def visitSuper(obj: Obj): RubyExpression =
    val name = SimpleIdentifier(Option(getBuiltInType(Defines.Super)))(
      obj.toTextSpan.spanStart(Defines.Super)
    )
    val arguments = obj.visitArray(ParserKeys.Arguments)
    SimpleCall(name, arguments)(obj.toTextSpan)

  private def visitSuperNoArgs(obj: Obj): RubyExpression =
    val name = SimpleIdentifier(Option(getBuiltInType(Defines.Super)))(
      obj.toTextSpan.spanStart(Defines.Super)
    )
    SimpleCall(name, Nil)(obj.toTextSpan)

  private def visitTopLevelConstant(obj: Obj): RubyExpression =
      if obj.contains(ParserKeys.Name) then
        val identifier = obj(ParserKeys.Name).str
        SimpleIdentifier()(obj.toTextSpan.spanStart(identifier))
      else
        SelfIdentifier()(obj.toTextSpan.spanStart("self"))

  private def visitTrue(obj: Obj): RubyExpression =
      StaticLiteral(getBuiltInType(Defines.TrueClass))(obj.toTextSpan)

  /** `undef sym, ...` - lowered to a call so the undefined names stay reachable. */
  private def visitUnDefine(obj: Obj): RubyExpression =
    val target = SimpleIdentifier()(obj.toTextSpan.spanStart("undef"))
    SimpleCall(target, obj.visitArray(ParserKeys.Children))(obj.toTextSpan)

  private def visitUnlessExpression(obj: Obj): RubyExpression =
      defaultResult(Option(obj.toTextSpan))

  private def visitUnlessGuard(obj: Obj): RubyExpression =
      GuardClause(visit(obj(ParserKeys.Condition)), isUnless = true)(obj.toTextSpan)

  private def visitUntilExpression(obj: Obj): RubyExpression =
    val condition = visit(obj(ParserKeys.Condition))
    val body      = visit(obj(ParserKeys.Body))

    UntilExpression(condition, body)(obj.toTextSpan)

  private def visitUntilPostExpression(obj: Obj): RubyExpression =
    val condition = visit(obj(ParserKeys.Condition))
    val body      = visit(obj(ParserKeys.Body))

    DoWhileExpression(condition, body)(obj.toTextSpan)

  private def visitWhenStatement(obj: Obj): RubyExpression =
    val (matchCondition, matchSplatCondition) = obj.visitArray(ParserKeys.Conditions).partition {
        case x: SplattingRubyNode => false
        case x                    => true
    }

    val thenClause = visit(obj(ParserKeys.ThenBranch))

    WhenClause(matchCondition, matchSplatCondition.headOption, thenClause)(obj.toTextSpan)

  private def visitWhileStatement(obj: Obj): RubyExpression =
    val condition = visit(obj(ParserKeys.Condition)) match
      case x: StatementList => x.statements.head
      case x                => x

    val body = visit(obj(ParserKeys.Body))

    WhileExpression(condition, body)(obj.toTextSpan)

  private def visitYield(obj: Obj): RubyExpression =
    val arguments = obj.visitArray(ParserKeys.Arguments)
    YieldExpr(arguments)(obj.toTextSpan)
end RubyJsonToNodeCreator
