package io.appthreat.c2cpg.astcreation

import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.NewCall
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.core.dom.ast.cpp.*
import org.eclipse.cdt.core.dom.ast.gnu.IGNUASTGotoStatement
import org.eclipse.cdt.internal.core.dom.parser.ASTNode

/** Destructor calls where C++ objects with automatic storage end their lifetime: where control
  * falls out of the scope that declares them, and at every `return`, `break`, `continue` and `goto`
  * that leaves the scope early. Objects are destroyed in the reverse order of their construction,
  * innermost scope first, and only those constructed before the exit are destroyed.
  *
  * The scopes are blocks, catch handlers, the declarations of a `for` statement, the loop variable
  * of a range-based `for`, and the variables an `if`, `switch` or `while` declares in its condition
  * or init statement. A loop's condition variable and a range-based `for`'s loop variable live for
  * one iteration: they are destroyed at the end of the body and at a `continue`. A `return` whose
  * value could observe a destroyed object (it calls a function, reads through a pointer or names
  * one of the objects) first stores the value in a local named `<return-value>`, then destroys the
  * objects, then returns the local: the order C++ evaluates them in.
  *
  * Like the other implicit calls, a destructor call is emitted only when the graph holds the
  * destructor's METHOD (see [[CppCallResolution]]). Temporaries are not covered.
  */
trait CppScopeExits(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  import CppScopeExits.*

  /** An object a scope destroys: the name that declares it, and its destructor. */
  private case class Destruction(owner: IASTNode, declaredAt: IASTName, destructor: IBinding)

  private def offsetOf(node: IASTNode): Int = node match
    case n: ASTNode => n.getOffset
    case _          => -1

  private def endOf(node: IASTNode): Int = node match
    case n: ASTNode => n.getOffset + n.getLength
    case _          => -1

  private def encloses(outer: IASTNode, inner: IASTNode): Boolean =
      offsetOf(outer) <= offsetOf(inner) && endOf(inner) <= endOf(outer)

  /** The objects `owner` destroys when control leaves it, in destruction order. */
  private def destructionsOf(owner: IASTNode): List[Destruction] = owner match
    case _: IASTExpression => Nil
    case o: IASTImplicitDestructorNameOwner =>
        CdtQuery(o.getImplicitDestructorNames.toList).getOrElse(Nil).flatMap { n =>
            Option(n.getConstructionPoint).flatMap(point =>
                CdtQuery(n.resolveBinding()).toOption.map(Destruction(owner, point, _))
            )
        }
    case s: ICPPASTIfStatement =>
        declaredIn(owner, List(s.getInitializerStatement, s.getConditionDeclaration))
    case s: ICPPASTSwitchStatement =>
        declaredIn(owner, List(s.getInitializerStatement, s.getControllerDeclaration))
    case s: ICPPASTWhileStatement => declaredIn(owner, List(s.getConditionDeclaration))
    case _                        => Nil

  /** The class-type variables the given declarations of `owner` declare, in destruction order. */
  private def declaredIn(owner: IASTNode, declarations: List[IASTNode]): List[Destruction] =
    val declarators = declarations.filter(_ != null).flatMap {
        case s: IASTDeclarationStatement => Option(s.getDeclaration).toList
        case d                           => List(d)
    }.flatMap {
        case d: IASTSimpleDeclaration => d.getDeclarators.toList
        case _                        => Nil
    }
    declarators.flatMap { d =>
      val name = d.getName
      CdtQuery(name.resolveBinding()).toOption.collect { case v: ICPPVariable => v }
          .flatMap(v => destructorOf(v.getType))
          .map(Destruction(owner, name, _))
    }.reverse

  /** Whether `d` lives for one iteration of its loop. */
  private def isPerIteration(d: Destruction): Boolean = d.owner match
    case f: ICPPASTRangeBasedForStatement =>
        Option(f.getDeclaration).exists(encloses(_, d.declaredAt))
    case f: ICPPASTForStatement =>
        Option(f.getConditionDeclaration).exists(encloses(_, d.declaredAt))
    case _: ICPPASTWhileStatement => true
    case _                        => false

  private def destructorCalls(
    destructions: List[Destruction],
    at: IASTNode,
    atEnd: Boolean
  ): List[Ast] =
      destructions.flatMap { d =>
        val callCode = s"${d.declaredAt}.${d.destructor.getName}()"
        destructorCallAst(at, d.destructor, callCode).map { ast =>
          if atEnd then
            ast.root.foreach {
                case call: NewCall => call.lineNumber(lineEnd(at)).columnNumber(columnEnd(at))
                case _             =>
            }
          ast
        }
      }

  /** The destructor calls placed where control falls out of `owner`: the end of a block or catch
    * handler, or right after a statement whose declarations outlive its body (`for`, `if`,
    * `switch`, and the last iteration of a `while`). None after a block whose last statement jumps
    * away, as control never falls out of it.
    */
  protected def scopeEndDestructorCalls(owner: IASTNode): List[Ast] =
    val fallsThrough = owner match
      case b: IASTCompoundStatement => !b.getStatements.lastOption.exists(isJump)
      case _                        => true
    val destructions = destructionsOf(owner).filter {
        case d @ Destruction(_: ICPPASTRangeBasedForStatement, _, _) => !isPerIteration(d)
        case _                                                       => true
    }
    if fallsThrough then destructorCalls(destructions, owner, atEnd = true) else Nil

  /** The destructor calls that end one iteration of `loop`'s body: those of its per-iteration
    * variables.
    */
  protected def iterationEndDestructorCalls(loop: IASTNode, body: IASTStatement): List[Ast] =
      if body == null || isJump(body) then Nil
      else
        body match
          case b: IASTCompoundStatement if b.getStatements.lastOption.exists(isJump) => Nil
          case _ => destructorCalls(destructionsOf(loop).filter(isPerIteration), body, atEnd = true)

  /** `bodyAsts` followed by the destructor calls that end one iteration of `loop`, as one block. */
  protected def withIterationEnd(
    loop: IASTNode,
    body: IASTStatement,
    bodyAsts: Seq[Ast]
  ): Seq[Ast] =
    val calls = iterationEndDestructorCalls(loop, body)
    if calls.isEmpty then bodyAsts
    else
      val index = bodyAsts.headOption.flatMap(_.root).collect {
          case e: io.shiftleft.codepropertygraph.generated.nodes.ExpressionNew => e.argumentIndex
      }.getOrElse(-1)
      val node = blockNode(body, Defines.empty, registerType(Defines.voidTypeName))
          .order(index)
          .argumentIndex(index)
      Seq(blockAst(node, bodyAsts.toList ++ calls))

  private def isJump(statement: IASTStatement): Boolean = statement match
    case _: IASTReturnStatement | _: IASTBreakStatement | _: IASTContinueStatement |
        _: IASTGotoStatement | _: IGNUASTGotoStatement => true
    case _ => false

  private def isLoop(node: IASTNode): Boolean = node match
    case _: IASTForStatement | _: ICPPASTRangeBasedForStatement | _: IASTWhileStatement |
        _: IASTDoStatement => true
    case _ => false

  private def isFunctionBoundary(node: IASTNode): Boolean = node match
    case _: IASTFunctionDefinition | _: ICPPASTLambdaExpression => true
    case _                                                      => false

  /** The scopes enclosing `node`, innermost first, up to the function it is in. */
  private def enclosingScopes(node: IASTNode): List[IASTNode] =
      Iterator.iterate(node.getParent)(_.getParent).takeWhile(n =>
          n != null && !isFunctionBoundary(n)
      ).toList

  /** The objects a jump statement destroys, in destruction order. */
  private def destructionsLeftBy(jump: IASTStatement): List[Destruction] =
    val jumpAt                                   = offsetOf(jump)
    def constructedBefore(ds: List[Destruction]) = ds.filter(d => offsetOf(d.declaredAt) < jumpAt)
    val scopes                                   = enclosingScopes(jump)
    jump match
      case _: IASTReturnStatement => scopes.flatMap(s => constructedBefore(destructionsOf(s)))
      case _: IASTBreakStatement | _: IASTContinueStatement =>
          val isTarget: IASTNode => Boolean = jump match
            case _: IASTBreakStatement => n => isLoop(n) || n.isInstanceOf[IASTSwitchStatement]
            case _                     => isLoop
          val (inside, rest) = scopes.span(n => !isTarget(n))
          // The target's own declarations are destroyed by the calls placed after it, which a
          // `break` reaches; a range-based `for`'s loop variable is not, and a `continue` ends
          // the iteration of every per-iteration variable.
          val ofTarget = rest.headOption.toList.flatMap(destructionsOf).filter { d =>
              jump match
                case _: IASTBreakStatement =>
                    d.owner.isInstanceOf[ICPPASTRangeBasedForStatement] && isPerIteration(d)
                case _ => isPerIteration(d)
          }
          inside.flatMap(s => constructedBefore(destructionsOf(s))) ++ constructedBefore(ofTarget)
      case goto: IASTGotoStatement =>
          CdtQuery(goto.getName.resolveBinding()).toOption.collect { case l: ILabel => l }
              .flatMap(l => Option(l.getLabelStatement)) match
            case Some(label) =>
                val (inside, rest) = scopes.span(s => !encloses(s, label))
                // in the scope holding both, a jump back past a declaration destroys the object
                val common = rest.headOption.toList.flatMap(destructionsOf).filter(d =>
                    offsetOf(label) < offsetOf(d.declaredAt)
                )
                inside.flatMap(s => constructedBefore(destructionsOf(s))) ++
                    constructedBefore(common)
            case None => Nil
      case _ => Nil
    end match
  end destructionsLeftBy

  /** A `break`, `continue` or `goto`, preceded by the destructor calls for the scopes it leaves. */
  protected def jumpLeavingScopes(jump: IASTStatement, jumpAst: Ast): Ast =
    val calls = destructorCalls(destructionsLeftBy(jump), jump, atEnd = false)
    if calls.isEmpty then jumpAst
    else
      blockAst(
        blockNode(jump, Defines.empty, registerType(Defines.voidTypeName)),
        calls :+ jumpAst
      )

  /** A `return` and the destructor calls for the scopes it leaves (see the trait's description). */
  protected def returnLeavingScopes(ret: IASTReturnStatement, plainReturn: => Ast): Ast =
    val destructions = destructionsLeftBy(ret)
    val calls        = destructorCalls(destructions, ret, atEnd = false)
    val value        = Option(ret.getReturnValue).collect { case e: IASTExpression => e }
    if calls.isEmpty then plainReturn
    else
      val block = blockNode(ret, Defines.empty, registerType(Defines.voidTypeName))
      value match
        case Some(v)
            if observesDestruction(v, destructions.flatMap(d => bindingOf(d.declaredAt))) =>
            scope.pushNewScope(block)
            val tpe   = expressionType(v)
            val local = localNode(ret, ReturnValueName, s"$tpe $ReturnValueName", tpe)
            scope.addToScope(ReturnValueName, (local, tpe))
            val target = identifierNode(ret, ReturnValueName, ReturnValueName, tpe)
            val store = callNode(
              ret,
              s"$ReturnValueName = ${code(v)}",
              Operators.assignment,
              Operators.assignment,
              DispatchTypes.STATIC_DISPATCH,
              None,
              Some(tpe)
            )
            val storeAst =
                callAst(store, List(Ast(target).withRefEdge(target, local), astForNode(v)))
            val read    = identifierNode(ret, ReturnValueName, ReturnValueName, tpe)
            val retNode = returnNode(ret, nodeSignature(ret))
            val retAst =
                Ast(retNode).withChild(Ast(read).withRefEdge(read, local)).withArgEdge(
                  retNode,
                  read
                )
            scope.popScope()
            blockAst(block, List(Ast(local), storeAst) ++ calls :+ retAst)
        case _ => blockAst(block, calls :+ plainReturn)
      end match
    end if
  end returnLeavingScopes

  private def bindingOf(name: IASTName): Option[IBinding] = CdtQuery(name.resolveBinding()).toOption

  /** Whether evaluating `expr` after the destructors ran could give a different value: it calls a
    * function (an overloaded operator or a conversion included), reads through a pointer or a
    * reference, or names one of the `destroyed` objects.
    */
  private def observesDestruction(expr: IASTNode, destroyed: List[IBinding]): Boolean =
    val here = expr match
      case _: IASTFunctionCallExpression | _: ICPPASTNewExpression | _: ICPPASTDeleteExpression |
          _: ICPPASTLambdaExpression | _: IASTArraySubscriptExpression => true
      case u: IASTUnaryExpression if u.getOperator == IASTUnaryExpression.op_star => true
      case f: IASTFieldReference if f.isPointerDereference                        => true
      case id: IASTIdExpression =>
          bindingOf(id.getName).exists {
              case v: ICPPVariable =>
                  destroyed.contains(v) || CdtQuery(v.getType).toOption.exists(
                    _.isInstanceOf[ICPPReferenceType]
                  )
              case _ => false
          }
      case o: IASTImplicitNameOwner => CdtQuery(o.getImplicitNames.nonEmpty).getOrElse(false)
      case _                        => false
    here || expr.getChildren.exists(observesDestruction(_, destroyed))
end CppScopeExits

object CppScopeExits:
  /** The local a `return` stores its value in when destructors must run after it is computed. */
  val ReturnValueName = "<return-value>"
