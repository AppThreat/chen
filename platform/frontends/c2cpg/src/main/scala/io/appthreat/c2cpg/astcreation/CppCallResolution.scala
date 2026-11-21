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
    ICPPDeferredClassInstance,
    ICPPInstanceCache,
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

  // the input root as given and as its real path: the parser names a translation unit by the path
  // it was given and an included header by its real path (macOS `/var` is `/private/var`)
  private lazy val projectRoots: Seq[Path] =
      Try(Paths.get(config.inputPath).toAbsolutePath.normalize).toOption.toSeq.flatMap(root =>
          (root +: Try(root.toRealPath()).toOption.toSeq).distinct
      )

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

  /** Writes the tags of the stored nodes; a node no stored AST holds was dropped. The dependent
    * calls take their callee list here too: the instances they reach exist only once the whole unit
    * has been walked and every binding resolved.
    */
  protected def flushTags(): Unit =
    pendingTags.foreach { (node, tags) =>
        if storedNodes.contains(node) then
          tags.foreach { (name, value) =>
            val tag = callTags.getOrElseUpdate((name, value), NewTag().name(name).value(value))
            diffGraph.addEdge(node, tag, EdgeTypes.TAGGED_BY)
          }
    }
    pendingTags.clear()
    dependentCalls.foreach { (call, cdtCall) =>
        if storedNodes.contains(call) then
          val callees = dependentCallees(cdtCall)
          if callees.nonEmpty then call.dynamicTypeHintFullName(callees)
    }
    dependentCalls.clear()
    storedNodes.clear()

  private def isUnderProject(node: IASTNode): Boolean =
      Option(node.getFileLocation).flatMap(l => Option(l.getFileName)).exists { file =>
          Try(Paths.get(file).toAbsolutePath.normalize).toOption.exists(path =>
              projectRoots.exists(path.startsWith)
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

  /** The arguments a template instance was written with, in order, as the `template-args` of a call
    * to it: its own when it is an instance of a function template, else those of the class template
    * instance it is a member of. A type argument is written as the frontend writes types, a
    * non-type argument by its value. None when the callee is no instance of a template.
    */
  protected def templateArguments(callee: ICPPFunction): Option[String] =
    def argsOf(binding: IBinding): Option[Seq[ICPPTemplateArgument]] = binding match
      case instance: ICPPTemplateInstance =>
          CdtQuery(instance.getTemplateArguments).toOption.map(_.toSeq.filter(_ != null))
      case _ => None
    val args = argsOf(callee).orElse(callee match
      case method: ICPPMethod => CdtQuery(method.getOwner).toOption.flatMap(argsOf)
      case _                  => None
    )
    args.filter(_.nonEmpty).map(_.map { arg =>
        if arg.isTypeValue then
          CdtQuery(cleanType(safeGetType(arg.getTypeValue))).getOrElse(Defines.anyTypeName)
        else
          CdtQuery(Option(arg.getNonTypeValue).map(_.toString).getOrElse("")).getOrElse("")
    }.mkString(","))

  /** The calls written in template code whose callee depends on a template parameter, by the CALL
    * node each produced: the METHODs they reach exist per instance, and the unit's instances are
    * only known once the whole unit has been walked, so [[flushTags]] fills the callee list.
    */
  private val dependentCalls =
      mutable.LinkedHashMap.empty[NewCall, ICPPASTFunctionCallExpression]

  /** Registers a call whose callee depends on a template parameter for the callee list at
    * [[flushTags]]. A call copied into a macro expansion is dropped with its original, like every
    * other node the expansion replaced.
    */
  protected def registerDependentCall(
    call: NewCall,
    cdtCall: ICPPASTFunctionCallExpression
  ): Unit = dependentCalls.put(call, cdtCall)

  /** Whether the callee of a member call depends on a template parameter: the object it is called
    * on is a template parameter, or an instance of a class template the pattern has not built yet.
    */
  protected def calleeDependsOnTemplateParameter(fieldRef: ICPPASTFieldReference): Boolean =
      Option(fieldRef.getFieldOwnerType).exists { ownerType =>
          CdtQuery(unwrappedType(ownerType)).toOption.exists {
              case _: ICPPTemplateTypeParameter | _: ICPPDeferredClassInstance => true
              case _                                                           => false
          }
      }

  /** The METHOD full names a dependent call reaches across the instances the unit built. For every
    * instance of the template the call is written in, the object it is called on takes that
    * instance's argument, and the METHOD the call names there is the callee it reaches. An instance
    * the unit never built contributes nothing, and so does a callee the graph holds no METHOD for.
    * The list is sorted, and each name once.
    */
  private def dependentCallees(call: ICPPASTFunctionCallExpression): List[String] =
      CdtQuery {
          val functionNameExpr = call.getFunctionNameExpression
          for
            fieldRef <-
                Option(functionNameExpr).collect { case f: ICPPASTFieldReference => f }.toList
            memberName = fieldRef.getFieldName.toString
            ownerType <- Option(fieldRef.getFieldOwnerType).toList
            template  <- enclosingTemplateOf(call).toList
            instance  <- instancesOf(template)
            classType <- realisedOwnerType(ownerType, instance.getTemplateParameterMap).toList
            callee    <- memberCallees(classType, memberName, call, argumentCountOf(call))
            linked    <- graphFunction(callee).toList
          yield methodFullNameOf(linked)
      }.toOption.getOrElse(Nil).distinct.sorted
  end dependentCallees

  /** The number of arguments a call passes. */
  private def argumentCountOf(call: IASTFunctionCallExpression): Int =
      Option(call.getArguments).map(_.length).getOrElse(0)

  /** The template the node is written in: the function template the node's enclosing function
    * definition declares, or the class template that declares it as a member. A node outside both
    * has no template, and its calls depend on nothing.
    */
  private def enclosingTemplateOf(node: IASTNode): Option[IBinding] =
    @tailrec def enclosing(current: IASTNode): Option[IBinding] =
        if current == null then None
        else
          current match
            case definition: IASTFunctionDefinition =>
                CdtQuery(definition.getDeclarator.getName.resolveBinding).toOption.flatMap {
                    case template: ICPPFunctionTemplate => Some(template)
                    case method: ICPPMethod =>
                        CdtQuery(method.getOwner).toOption.collect {
                            case cls: ICPPClassTemplate => cls
                        }
                    case _ => None
                }
            case _ => enclosing(current.getParent)
    enclosing(node)

  /** The instances the unit built for a template, in the order CDT created them. */
  private def instancesOf(template: IBinding): List[ICPPTemplateInstance] =
      template match
        case cache: ICPPInstanceCache =>
            CdtQuery(cache.getAllInstances).toOption.map(_.toList.filter(_ != null)).getOrElse(Nil)
        case _ => Nil

  /** The class the dependent call's object has once an instance's arguments are substituted in: the
    * parameter's bound type, or the instance of the class template the pattern spelled the object
    * with. None when the substitution leaves a parameter in (the unit built no such instance).
    */
  private def realisedOwnerType(
    ownerType: IType,
    map: ICPPTemplateParameterMap
  ): Option[ICPPClassType] =
      unwrappedType(ownerType) match
        case parameter: ICPPTemplateTypeParameter =>
            CdtQuery(map.getArgument(parameter)).toOption
                .flatMap(arg => Option(arg))
                .flatMap(arg => Option(arg.getTypeValue))
                .collect { case cls: ICPPClassType => cls }
        case deferred: ICPPDeferredClassInstance =>
            val patternArgs = Option(deferred.getTemplateArguments).map(_.toList).getOrElse(Nil)
            val args        = patternArgs.flatMap(substitutedArg(_, map))
            if args.size != patternArgs.size then None
            else
              deferred.getSpecializedBinding match
                case cache: ICPPInstanceCache =>
                    CdtQuery(cache.getInstance(args.toArray)).toOption
                        .flatMap(instance => Option(instance))
                        .collect { case cls: ICPPClassType => cls }
                case _ => None
        case _ => None
  end realisedOwnerType

  /** The argument an instance binds for one argument the pattern wrote: a template parameter
    * becomes the type the instance bound it to, everything else stays as written. None when the
    * parameter is not among the instance's arguments.
    */
  private def substitutedArg(
    arg: ICPPTemplateArgument,
    map: ICPPTemplateParameterMap
  ): Option[ICPPTemplateArgument] =
      if arg.isTypeValue then
        arg.getTypeValue match
          case parameter: ICPPTemplateTypeParameter =>
              CdtQuery(map.getArgument(parameter)).toOption.flatMap(a => Option(a))
          case _ => Some(arg)
      else Some(arg)

  /** The methods of `cls` the call names: the same name, and as many declared parameters as the
    * call passes arguments (a member's own object is not among them). Inherited methods count.
    */
  private def memberCallees(
    cls: ICPPClassType,
    memberName: String,
    point: IASTNode,
    argumentCount: Int
  ): List[ICPPFunction] =
    val methods = cls match
      case spec: ICPPClassSpecialization => CdtQuery(spec.getMethods(point)).toOption
      case _                             => CdtQuery(cls.getMethods).toOption
    methods.map(_.toList).getOrElse(Nil).collect { case f: ICPPFunction => f }
        .filter { m =>
            m.getName == memberName &&
            CdtQuery(m.getParameters).toOption.exists(_.length == argumentCount)
        }

  /** The type without the references, qualifiers and typedefs its spelling carries. */
  @tailrec
  private def unwrappedType(tpe: IType): IType = tpe match
    case null                 => null
    case r: ICPPReferenceType => unwrappedType(r.getType)
    case q: IQualifierType    => unwrappedType(q.getType)
    case td: ITypedef         => unwrappedType(td.getType)
    case other                => other

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
    templateInstanceSignature(callee, linked).foreach { signature =>
      tagCall(call, X2CpgDefines.TemplateInstanceTag, signature)
      templateArguments(callee).foreach(tagCall(call, X2CpgDefines.TemplateArgsTag, _))
    }
    tagCalleeHeader(call, callee)
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

  /** The `operator[]` a comma-separated subscript calls (the multidimensional subscript): the front
    * end parses the syntax and types the operands but leaves no implicit name for the operator, so
    * the base's class is asked directly. Only an operator of the base's own class whose parameter
    * count matches the written indices, exactly one of them, links - anything ambiguous or
    * inherited stays the built-in index access.
    */
  protected def multidimSubscriptOperator(
    base: IASTExpression,
    indices: Int
  ): Option[(ICPPFunction, ICPPFunction)] =
    val baseBinding = base match
      case id: IASTIdExpression => CdtQuery(id.getName.resolveBinding).toOption
      case _                    => None
    val owner = baseBinding.collectFirst { case v: ICPPVariable => v }
        .flatMap(v => CdtQuery(v.getType).toOption.collectFirst { case t: ICPPClassType => t })
    owner.flatMap { cls =>
      val operators: Array[ICPPMethod] =
          CdtQuery(cls.getDeclaredMethods).toOption.getOrElse(Array.empty[ICPPMethod])
      operators
          .filter(m =>
              m.getName.replace(" ", "") == "operator[]" &&
                  CdtQuery(m.getParameters).toOption.exists(ps => indices == ps.length)
          )
          .toList match
        case List(one) => graphFunction(one).map(one -> _)
        case _         => None
    }
  end multidimSubscriptOperator

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

  /** The constructor a declarator, a `new` expression or a functional cast calls, whether or not
    * the graph holds its METHOD: a class a header declares has none, and its constructor call still
    * tells which header the code relies on.
    */
  protected def constructorBindingOf(owner: IASTNode): Option[ICPPConstructor] =
    val names = owner match
      case o: IASTImplicitNameOwner => CdtQuery(o.getImplicitNames.toList).getOrElse(Nil)
      case _                        => Nil
    names.filterNot(_.isOperator).flatMap(n => CdtQuery(n.resolveBinding()).toOption).collectFirst {
        case c: ICPPConstructor => c
    }

  /** The constructor a declarator, a `new` expression or a functional cast calls, and the graph's
    * METHOD for it.
    */
  protected def linkedConstructor(owner: IASTNode): Option[(ICPPFunction, ICPPFunction)] =
      constructorBindingOf(owner).flatMap(c => graphFunction(c).map(c -> _))

  /** A call to the destructor `destructor` (resolved by CDT) when the graph holds its METHOD. The
    * destroyed object is the call's argument 0: the destructor's body reads it through `this`, and
    * a rule reads WHICH object the lifetime ended for.
    */
  protected def destructorCallAst(
    node: IASTNode,
    destructor: IBinding,
    callCode: String,
    receiver: => Option[Ast] = None
  ): Option[Ast] =
      destructor match
        case d: ICPPFunction =>
            graphFunction(d).map { linked =>
                linkedCallAst(
                  node,
                  d,
                  linked,
                  registerType(Defines.voidTypeName),
                  receiver,
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
