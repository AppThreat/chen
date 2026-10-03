package io.appthreat.c2cpg.astcreation

import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewNode, NewTag}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes}
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.core.dom.ast.cpp.*
import org.eclipse.cdt.internal.core.dom.parser.cpp.{
    CPPClosureType,
    CPPImplicitFunction,
    ICPPInternalBinding
}

import java.nio.file.{Path, Paths}
import scala.annotation.tailrec
import scala.collection.mutable
import scala.util.Try

/** The calls C++ makes without spelling them as calls: overloaded operators, constructors and
  * destructors, and calls whose callee is a template instance or a lambda's closure. CDT resolves
  * each of them; the helpers here turn a resolution into a CALL whose `methodFullName` is the full
  * name of the METHOD the graph holds for the callee, so the call graph and the data-flow engine
  * reach its body.
  *
  * A callee is linked only when the graph holds a METHOD for it: a function declared in a file of
  * the analysed project. A function the compiler generates (an implicit copy constructor or
  * assignment operator) has no METHOD, and neither does one declared only in a library header
  * outside the project. Those keep the shape the frontend gives them otherwise; for an operator
  * that is the built-in operator call, whose data-flow semantics summarise an opaque library
  * operator better than an unknown external call would.
  *
  * Naming: a METHOD's full name is `<qualified name>:<signature>`. Constructors and destructors
  * have no declared return type and are given `void`: `Point.Point:void(int,int)`,
  * `Point.~Point:void()`. A template instance is called by the name of the generic definition the
  * graph holds (`clampAdd:ANY(ANY,ANY)`), and an explicit specialization by its own.
  */
trait CppCallResolution(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  private val declaredInProject = new java.util.IdentityHashMap[IBinding, java.lang.Boolean]()

  private lazy val projectRoot: Option[Path] =
      Try(Paths.get(config.inputPath).toAbsolutePath.normalize).toOption

  /** The name and full name of the METHOD built for each lambda of this file, by the lambda
    * expression: a call through the lambda's closure links to it.
    */
  private val lambdaMethods =
      new java.util.IdentityHashMap[ICPPASTLambdaExpression, (String, String)]()

  /** One tag node per (name, value) per translation unit, shared by the calls that carry it. */
  private val callTags = mutable.HashMap.empty[(String, String), NewTag]

  protected def registerLambdaMethod(
    lambda: ICPPASTLambdaExpression,
    name: String,
    fullName: String
  ): Unit = lambdaMethods.put(lambda, (name, fullName))

  /** The METHOD built for the lambda whose closure `closureType` is, when this file built it. */
  protected def lambdaMethodOf(closureType: CPPClosureType): Option[(String, String)] =
      CdtQuery(closureType.getDefinition).toOption.collect { case l: ICPPASTLambdaExpression =>
          l
      }.flatMap(l => Option(lambdaMethods.get(l)))

  protected def tagCall(call: NewCall, name: String, value: String): Unit =
      tagNode(call, name, value)

  /** Tags waiting for the AST to be final, in the order they were written. A macro expansion is
    * copied into its INLINED call and the original dropped, so a tag follows its node to each copy
    * ([[copyTags]]), and only nodes of a stored AST are tagged ([[storeAst]], [[flushTags]]).
    */
  private val pendingTags = mutable.LinkedHashMap.empty[NewNode, List[(String, String)]]

  private val storedNodes = mutable.HashSet.empty[NewNode]

  /** Tags a node of this file; one TAG node per name and value. */
  protected def tagNode(node: NewNode, name: String, value: String): Unit =
    val tags = pendingTags.getOrElse(node, Nil)
    if !tags.contains((name, value)) then pendingTags.update(node, tags :+ (name, value))

  /** Whether `node` is waiting for a tag named `name`. */
  protected def hasPendingTag(node: NewNode, name: String): Boolean =
      pendingTags.get(node).exists(_.exists(_._1 == name))

  /** The copies of tagged nodes carry the same tags. */
  protected def copyTags(copies: collection.Map[? <: NewNode, ? <: NewNode]): Unit =
      copies.foreach { (original, copy) =>
          pendingTags.get(original).foreach(tags => pendingTags.update(copy, tags))
      }

  /** Stores an AST of this file in the diff graph; its nodes take their tags at [[flushTags]]. */
  protected def storeAst(ast: Ast): Unit =
    Ast.storeInDiffGraph(ast, diffGraph)
    storedNodes.addAll(ast.nodes)

  /** Writes the tags of the stored nodes; a node no stored AST holds was dropped. */
  protected def flushTags(): Unit =
    pendingTags.foreach { (node, tags) =>
        if storedNodes.contains(node) then
          tags.foreach { (name, value) =>
            val tag = callTags.getOrElseUpdate((name, value), NewTag().name(name).value(value))
            diffGraph.addEdge(node, tag, EdgeTypes.TAGGED_BY)
          }
    }
    pendingTags.clear()
    storedNodes.clear()

  private def isUnderProject(node: IASTNode): Boolean =
      Option(node.getFileLocation).flatMap(l => Option(l.getFileName)).exists { file =>
          projectRoot.exists(root =>
              Try(Paths.get(file).toAbsolutePath.normalize.startsWith(root)).getOrElse(false)
          )
      }

  private def isDeclaredInProject(binding: IBinding): Boolean =
      declaredInProject.computeIfAbsent(
        binding,
        b =>
          val nodes = b match
            case internal: ICPPInternalBinding =>
                Option(internal.getDefinition).toSeq ++
                    Option(internal.getDeclarations).toSeq.flatten.filter(_ != null)
            case _ => Nil
          java.lang.Boolean.valueOf(nodes.exists(isUnderProject))
      )

  private def isCompilerGenerated(function: ICPPFunction): Boolean = function match
    case _: CPPImplicitFunction => true
    case m: ICPPMethod          => m.isImplicit
    case _                      => false

  /** The function whose METHOD the graph holds for a resolved callee: the callee itself, or for a
    * template instance (and a member of a class template instance) the generic definition. None
    * when the graph holds no METHOD for it (see the trait's description).
    */
  protected def graphFunction(binding: IBinding): Option[ICPPFunction] =
    @tailrec def generic(function: ICPPFunction): ICPPFunction = function match
      case i: ICPPTemplateInstance if i.isExplicitSpecialization => i
      case s: ICPPSpecialization =>
          s.getSpecializedBinding match
            case g: ICPPFunction => generic(g)
            case _               => function
      case other => other
    binding match
      case f: ICPPFunction =>
          CdtQuery(generic(f)).toOption.filterNot(isCompilerGenerated).filter(isDeclaredInProject)
      case _ => None

  private def isConstructorOrDestructor(function: IFunction): Boolean = function match
    case _: ICPPConstructor => true
    case m: ICPPMethod      => m.isDestructor
    case _                  => false

  /** The signature part of a METHOD full name for `function`. When CDT cannot deduce its type (an
    * `auto` return type it fails on), the return type is unknown and the parameter types still tell
    * overloads apart.
    */
  protected def methodSignature(function: IFunction): String =
    val returnType = Option.when(isConstructorOrDestructor(function))(Defines.voidTypeName)
    CdtQuery(function.getType).toOption.filter(_ != null) match
      case Some(functionType) => functionTypeToSignature(functionType, returnType)
      case None =>
          val parameterTypes = CdtQuery(function.getParameters.toList).getOrElse(Nil).map(p =>
              CdtQuery(cleanType(safeGetType(p.getType))).getOrElse(Defines.anyTypeName)
          )
          s"${returnType.getOrElse(Defines.anyTypeName)}(${parameterTypes.mkString(",")})"

  /** The full name of the METHOD for `function`, as its definition is named. */
  protected def methodFullNameOf(function: ICPPFunction): String =
      if function.isExternC then function.getName
      else s"${function.getQualifiedName.mkString(".")}:${methodSignature(function)}"

  /** The signature a template instance has, for the `template-instance` tag of a call that links to
    * the generic definition instead. None when the callee is not such an instance.
    */
  protected def templateInstanceSignature(
    callee: ICPPFunction,
    linked: ICPPFunction
  ): Option[String] =
      Option.when((callee ne linked) && callee.isInstanceOf[ICPPSpecialization])(
        methodSignature(callee)
      )

  private def dispatchOf(function: ICPPFunction): String = function match
    case m: ICPPMethod if m.isVirtual || m.isPureVirtual => DispatchTypes.DYNAMIC_DISPATCH
    case _                                               => DispatchTypes.STATIC_DISPATCH

  private def isInstanceMember(function: ICPPFunction): Boolean = function match
    case m: ICPPMethod => !m.isStatic
    case _             => false

  /** A call to `linked`, the graph's METHOD for `callee`, with `receiver` as the object of a member
    * call (argument 0) and `args` as the arguments.
    */
  protected def linkedCallAst(
    node: IASTNode,
    callee: ICPPFunction,
    linked: ICPPFunction,
    typeFullName: String,
    receiver: Option[Ast],
    args: List[Ast],
    callCode: Option[String] = None
  ): (NewCall, Ast) =
    val dispatch = dispatchOf(linked)
    val call = callNode(
      node,
      callCode.getOrElse(code(node)),
      linked.getName,
      methodFullNameOf(linked),
      dispatch,
      Some(methodSignature(linked)),
      Some(typeFullName)
    )
    templateInstanceSignature(callee, linked).foreach(tagCall(
      call,
      X2CpgDefines.TemplateInstanceTag,
      _
    ))
    val ast = receiver match
      case Some(self) =>
          createCallAst(
            call,
            args,
            base = Some(self),
            receiver = Option.when(dispatch == DispatchTypes.DYNAMIC_DISPATCH)(self)
          )
      case None => createCallAst(call, args)
    (call, ast)
  end linkedCallAst

  /** An operator expression that calls a user-defined operator function: a CALL to that function,
    * tagged with the built-in operator the expression is written with. A member operator takes its
    * first operand as the object it is called on.
    */
  protected def overloadedOperatorAst(
    node: IASTExpression,
    overload: ICPPFunction,
    linked: ICPPFunction,
    builtinOperator: String,
    operands: List[Ast]
  ): Ast =
    val typeFullName = expressionType(node)
    val (receiver, args) =
        if isInstanceMember(linked) then (operands.headOption, operands.drop(1))
        else (None, operands)
    val (call, ast) = linkedCallAst(node, overload, linked, typeFullName, receiver, args)
    tagCall(call, X2CpgDefines.OperatorCallTag, builtinOperator)
    ast

  /** The graph's METHOD for the user-defined operator an expression calls, if any. */
  protected def linkedOverload(overload: => ICPPFunction): Option[(ICPPFunction, ICPPFunction)] =
      CdtQuery(Option(overload)).toOption.flatten.flatMap(o => graphFunction(o).map(o -> _))

  /** The operator function an expression with implicit names calls (`a[i]` calling `operator[]`),
    * and the graph's METHOD for it.
    */
  protected def linkedImplicitOperator(owner: IASTImplicitNameOwner)
    : Option[(ICPPFunction, ICPPFunction)] =
      CdtQuery(owner.getImplicitNames.toList).getOrElse(Nil)
          .filter(_.isOperator)
          .flatMap(n => CdtQuery(n.resolveBinding()).toOption)
          .collectFirst { case f: ICPPFunction => f }
          .flatMap(f => graphFunction(f).map(f -> _))

  /** The constructor a declarator, a `new` expression or a functional cast calls, and the graph's
    * METHOD for it.
    */
  protected def linkedConstructor(owner: IASTNode): Option[(ICPPFunction, ICPPFunction)] =
    val names = owner match
      case o: IASTImplicitNameOwner => CdtQuery(o.getImplicitNames.toList).getOrElse(Nil)
      case _                        => Nil
    names.filterNot(_.isOperator).flatMap(n => CdtQuery(n.resolveBinding()).toOption).collectFirst {
        case c: ICPPConstructor => c
    }.flatMap(c => graphFunction(c).map(c -> _))

  /** A call to the destructor `destructor` (resolved by CDT) when the graph holds its METHOD. The
    * destroyed object is named in the call's code only: the destructor's body reads it through
    * `this`, which the graph does not model as an argument.
    */
  protected def destructorCallAst(
    node: IASTNode,
    destructor: IBinding,
    callCode: String
  ): Option[Ast] =
      destructor match
        case d: ICPPFunction =>
            graphFunction(d).map { linked =>
                linkedCallAst(
                  node,
                  d,
                  linked,
                  registerType(Defines.voidTypeName),
                  None,
                  Nil,
                  Some(callCode)
                )._2
            }
        case _ => None

  /** The object a member access `p->m` reads through. When `p` is an object whose user-defined
    * `operator->` the access applies (a smart pointer), the object is what those operators return:
    * each is called in turn, so `p->m` reads `p.operator->()->m`. A chain that reaches an operator
    * the graph holds no METHOD for keeps the plain owner.
    */
  protected def fieldOwnerAst(fieldRef: IASTFieldReference): Ast =
    val owner = astForExpression(fieldRef.getFieldOwner)
    fieldRef match
      case cpp: ICPPASTFieldReference if cpp.isPointerDereference =>
          val operators = CdtQuery(cpp.getImplicitNames.toList).getOrElse(Nil)
              .flatMap(n => CdtQuery(n.resolveBinding()).toOption)
              .collect { case f: ICPPFunction => f }
          val linked = operators.map(f => graphFunction(f).map(f -> _))
          if operators.isEmpty || linked.exists(_.isEmpty) then owner
          else
            val ownerNode = cpp.getFieldOwner
            val callCode  = s"${code(ownerNode)}.operator->()"
            linked.flatten.foldLeft(owner) { case (obj, (operator, target)) =>
                val tpe = registerType(cleanType(safeGetType(operator.getType.getReturnType)))
                linkedCallAst(ownerNode, operator, target, tpe, Some(obj), Nil, Some(callCode))._2
            }
      case _ => owner

  /** The destructor of the class `tpe` names (through typedefs and qualifiers). */
  protected def destructorOf(tpe: IType): Option[ICPPMethod] =
    @tailrec def unwrap(t: IType): IType = t match
      case td: ITypedef      => unwrap(td.getType)
      case q: IQualifierType => unwrap(q.getType)
      case other             => other
    CdtQuery(unwrap(tpe)).toOption.collect { case ct: ICPPClassType => ct }
        .flatMap(ct => CdtQuery(ct.getDeclaredMethods.toList).toOption)
        .flatMap(_.find(_.isDestructor))
end CppCallResolution
