package io.appthreat.c2cpg.astcreation

import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewNode}
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.core.dom.ast.cpp.*
import org.eclipse.cdt.core.dom.ast.gnu.IGNUASTGotoStatement
import org.eclipse.cdt.internal.core.dom.parser.ASTNode

/** Destructor calls where objects with automatic storage end their lifetime: where control falls
  * out of the scope that declares them, and at every `return`, `break`, `continue` and `goto` that
  * leaves the scope early. Objects are destroyed in the reverse order of their construction,
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
  * A variable declared with the GCC `cleanup` attribute (C and C++ alike, however a macro spells
  * it) is destroyed the same way: the scope calls the attribute's function with the variable's
  * address, tagged `compiler-generated` and ending the variable's lifetime. Where control falls out
  * of a block, such a call sits where the block ends, on the closing bracket's line.
  *
  * Like the other implicit calls, a destructor call is emitted only when the graph holds the
  * destructor's METHOD (see [[CppCallResolution]]); a cleanup call is emitted whatever the graph
  * holds for its function, as a written call to an undeclared function is. Temporaries are not
  * covered.
  */
trait CppScopeExits(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  import CppScopeExits.*

  /** An object a scope destroys: the name that declares it and its destructor, or the function its
    * `cleanup` attribute names, which the scope calls with the object's address.
    */
  private case class Destruction(
    owner: IASTNode,
    declaredAt: IASTName,
    destructor: IBinding,
    cleanupFunction: Option[CleanupFunction] = None,
    declarator: Option[IASTDeclarator] = None
  ):
    /** Where the object starts to exist: its declaration's name for a constructed object, and the
      * end of the whole declarator (its initializer included) for a `cleanup` variable, which GCC
      * registers for cleanup only once it is initialised. A jump before that point leaves the
      * object alone.
      */
    def readyAt: Int = declarator match
      case Some(d: ASTNode) => d.getOffset + d.getLength
      case _ => declaredAt match
            case n: ASTNode => n.getOffset
            case _          => -1

  /** The locals the declarators of this unit declared, by declarator: what a cleanup call's
    * argument binds to, so that a variable of the same name in an inner scope, or the scope's own
    * end having been left already (a `for` statement's declarations), cannot redirect it.
    */
  protected val localsByDeclarator: java.util.IdentityHashMap[IASTDeclarator, (NewNode, String)] =
      new java.util.IdentityHashMap()

  private val destructionsCache: java.util.IdentityHashMap[IASTNode, List[Destruction]] =
      new java.util.IdentityHashMap()

  /** A `cleanup` attribute's function: as its argument spells it, and as this unit resolves a call
    * to that name.
    */
  private case class CleanupFunction(name: String, binding: Option[IFunction])

  private def offsetOf(node: IASTNode): Int = node match
    case n: ASTNode => n.getOffset
    case _          => -1

  private def endOf(node: IASTNode): Int = node match
    case n: ASTNode => n.getOffset + n.getLength
    case _          => -1

  private def encloses(outer: IASTNode, inner: IASTNode): Boolean =
      offsetOf(outer) <= offsetOf(inner) && endOf(inner) <= endOf(outer)

  /** The objects `owner` destroys when control leaves it, in destruction order. Computed once per
    * owner: every jump asks it of each scope the jump leaves.
    */
  private def destructionsOf(owner: IASTNode): List[Destruction] =
    val cached = destructionsCache.get(owner)
    if cached != null then cached
    else
      val computed = computeDestructionsOf(owner)
      destructionsCache.put(owner, computed)
      computed

  private def computeDestructionsOf(owner: IASTNode): List[Destruction] =
    val destructed = owner match
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
    val cleaned = cleanupDestructionsOf(owner)
    // destructors and cleanup calls interleave by where their variables are declared
    if destructed.isEmpty then cleaned
    else if cleaned.isEmpty then destructed
    else (destructed ++ cleaned).sortBy(d => -offsetOf(d.declaredAt))
  end computeDestructionsOf

  /** The variables `owner`'s own declarations give a `cleanup` function, in destruction order
    * (reverse declaration order). The declarations are a block's statements and a `for` statement's
    * initializer, the two places C declares variables whose scope is that owner.
    */
  private def cleanupDestructionsOf(owner: IASTNode): List[Destruction] =
    val declarations: List[IASTSimpleDeclaration] = owner match
      case b: IASTCompoundStatement =>
          b.getStatements.toList.collect { case ds: IASTDeclarationStatement => ds.getDeclaration }
              .collect { case sd: IASTSimpleDeclaration => sd }
      case f: IASTForStatement =>
          Option(f.getInitializerStatement).toList
              .collect { case ds: IASTDeclarationStatement => ds.getDeclaration }
              .collect { case sd: IASTSimpleDeclaration => sd }
      case _ => Nil
    declarations.flatMap(cleanupDestructionsOf(owner, _)).reverse

  /** The declarators of `declaration` that carry a `cleanup` attribute, with the function it names.
    * The attribute sits on the declarator itself (the trailing `char *p
    * __attribute__((cleanup(f)))` form) or on the declaration's specifiers (the leading form the
    * g_autofree-style macros expand to), and it reaches the parser after macro expansion, so every
    * spelling that preprocesses to the attribute is read here. GCC ignores the attribute on a
    * `static` or `extern` variable, whose storage outlives the scope, and so does this.
    */
  private def cleanupDestructionsOf(
    owner: IASTNode,
    declaration: IASTSimpleDeclaration
  ): List[Destruction] =
    val storage = Option(declaration.getDeclSpecifier).map(_.getStorageClass)
    if storage.exists(c => c == IASTDeclSpecifier.sc_static || c == IASTDeclSpecifier.sc_extern)
    then Nil
    else
      declaration.getDeclarators.toList.filterNot(_.isInstanceOf[IASTFunctionDeclarator]).flatMap {
          declarator =>
            val specifierAttributes = declaration.getDeclSpecifier match
              case o: IASTAttributeOwner => attributeOwnersAttributes(o)
              case _                     => Nil
            (attributeOwnersAttributes(declarator) ++ specifierAttributes)
                .collectFirst {
                    case ("cleanup", argument) if argument.nonEmpty =>
                        CleanupFunction(argument, unitFunctionsByName.get(argument))
                }
                .map(fn =>
                    Destruction(
                      owner,
                      effectiveDeclaratorName(declarator),
                      null,
                      Some(fn),
                      Some(declarator)
                    )
                )
      }
    end if
  end cleanupDestructionsOf

  /** The attributes of an AST node CDT attaches GNU and standard attributes to, normalised to
    * `name` and `argument` with the name's leading and trailing `__` dropped.
    */
  private def attributeOwnersAttributes(owner: IASTAttributeOwner): List[(String, String)] =
    val fromLists = owner.getAttributeSpecifiers.toList.flatMap {
        case l: IASTAttributeList => l.getAttributes.toList
        case _                    => Nil
    }
    (fromLists ++ owner.getAttributes.toList).flatMap { a =>
      val name = new String(a.getName).stripPrefix("__").stripSuffix("__").trim
      Option.when(name.nonEmpty) {
          val argument = Option(a.getArgumentClause).map(attributeArgument).getOrElse("")
          (name, argument)
      }
    }.distinct

  /** A `cleanup` attribute's argument: its tokens joined, as the function's name is spelled. */
  private def attributeArgument(token: IASTToken): String =
    def text(t: IASTToken): String = t match
      case l: IASTTokenList => l.getTokens.map(text).mkString
      case single           => new String(single.getTokenCharImage)
    text(token).filterNot(_.isWhitespace).stripPrefix("(").stripSuffix(")")

  /** The functions of the translation unit by name: what a `cleanup` attribute's spelled function
    * resolves against, as a written call resolves its callee. Built once, and only when a cleanup
    * attribute is found.
    */
  private lazy val unitFunctionsByName: Map[String, IFunction] =
    val found = scala.collection.mutable.LinkedHashMap.empty[String, IFunction]
    def collect(node: IASTNode): Unit =
      node match
        case d: IASTFunctionDeclarator =>
            CdtQuery(effectiveDeclaratorName(d).resolveBinding()).toOption.collect {
                case f: IFunction => f
            }.foreach(f => found.getOrElseUpdate(f.getName, f))
        case _ =>
      node.getChildren.foreach(collect)
    cdtAst.getDeclarations.foreach(collect)
    found.toMap

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
        val built: Option[Ast] = d.cleanupFunction match
          case Some(fn) =>
              val variable = d.declaredAt.toString
              val local    = d.declarator.flatMap(dd => Option(localsByDeclarator.get(dd)))
              Some(cleanupCallAst(at, variable, fn, local))
          case None =>
              val callCode = s"${d.declaredAt}.${d.destructor.getName}()"
              // the destroyed object: the identifier the declaration's name gives, bound to the
              // local in scope, as the call's argument 0
              val receiver = bindingOf(d.declaredAt).collect { case v: ICPPVariable => v }.flatMap {
                  vb =>
                      CdtQuery(vb.getType).toOption.map(t => safeGetType(t)).map { tpe =>
                        val nm      = d.declaredAt.toString
                        val objNode = identifierNode(at, nm, nm, tpe)
                        scope.lookupVariable(nm)
                            .map { case (local, _) => Ast(objNode).withRefEdge(objNode, local) }
                            .getOrElse(Ast(objNode))
                      }
              }
              destructorCallAst(at, d.destructor, callCode, receiver)
        built.map { ast =>
          if atEnd then
            ast.root.foreach {
                case call: NewCall => call.lineNumber(lineEnd(at)).columnNumber(columnEnd(at))
                case _             =>
            }
          ast
        }
      }

  /** `fn(&var)`: the call a variable's `cleanup` attribute makes as control leaves the variable's
    * scope, tagged `compiler-generated` and ending the variable's lifetime. The callee and its
    * signature resolve as a written call to that name resolves, so the call reaches the function's
    * METHOD when the graph holds one.
    */
  private def cleanupCallAst(
    at: IASTNode,
    variable: String,
    fn: CleanupFunction,
    declaredLocal: Option[(NewNode, String)]
  ): Ast =
    val functionType = fn.binding.flatMap(f => CdtQuery(f.getType).toOption)
    val signature    = functionType.map(t => functionTypeToSignature(t))
    val returnType = functionType
        .map(t => cleanType(safeGetType(t.getReturnType)))
        .getOrElse(Defines.anyTypeName)
    val call = callNode(
      at,
      s"${fn.name}(&$variable)",
      fn.name,
      fn.name,
      DispatchTypes.STATIC_DISPATCH,
      signature,
      Some(registerType(returnType))
    )
    val (variableAst, varType) = declaredLocal.orElse(scope.lookupVariable(variable)) match
      case Some((local, tpe)) =>
          val id = identifierNode(at, variable, variable, tpe)
          (Ast(id).withRefEdge(id, local), tpe)
      case None =>
          (Ast(identifierNode(at, variable, variable, Defines.anyTypeName)), Defines.anyTypeName)
    val address = callNode(
      at,
      s"&$variable",
      Operators.addressOf,
      Operators.addressOf,
      DispatchTypes.STATIC_DISPATCH,
      None,
      Some(registerType(s"$varType*"))
    )
    val ast = callAst(call, List(callAst(address, List(variableAst))))
    tagNode(call, X2CpgDefines.CompilerGeneratedTag, "true")
    tagNode(call, X2CpgDefines.LifetimeEndTag, variable)
    ast
  end cleanupCallAst

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
        case d @ Destruction(_: ICPPASTRangeBasedForStatement, _, _, _, _) => !isPerIteration(d)
        case _                                                             => true
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
    case l: IASTLabelStatement => isJump(l.getNestedStatement)
    case _                     => false

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
    def constructedBefore(ds: List[Destruction]) = ds.filter(_.readyAt < jumpAt)
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
              case v: IVariable => destroyed.contains(v)
              case _            => false
          }
      case o: IASTImplicitNameOwner => CdtQuery(o.getImplicitNames.nonEmpty).getOrElse(false)
      case _                        => false
    here || expr.getChildren.exists(observesDestruction(_, destroyed))
end CppScopeExits

object CppScopeExits:
  /** The local a `return` stores its value in when destructors must run after it is computed. */
  val ReturnValueName = "<return-value>"
