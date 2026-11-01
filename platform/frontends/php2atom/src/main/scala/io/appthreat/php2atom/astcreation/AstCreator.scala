package io.appthreat.php2atom.astcreation

import io.appthreat.php2atom.astcreation.AstCreator.{NameConstants, TypeConstants, operatorSymbols}
import io.appthreat.php2atom.datastructures.ArrayIndexTracker
import io.appthreat.php2atom.parser.Domain.*
import io.appthreat.php2atom.parser.Domain.PhpModifiers.containsAccessModifier
import io.appthreat.php2atom.utils.{Scope, VariableTypes}
import io.appthreat.x2cpg.Ast.storeInDiffGraph
import io.appthreat.x2cpg.Defines.{StaticInitMethodName, UnresolvedNamespace, UnresolvedSignature}
import io.appthreat.x2cpg.utils.AstPropertiesUtil.RootProperties
import io.appthreat.x2cpg.utils.NodeBuilders.*
import io.appthreat.x2cpg.{Ast, AstCreatorBase, AstNodeBuilder, ValidationMode}
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.IntervalKeyPool
import io.shiftleft.semanticcpg.language.types.structure.NamespaceTraversal
import org.slf4j.LoggerFactory
import overflowdb.BatchedUpdate

class AstCreator(filename: String, phpAst: PhpFile, lineStarts: Array[Int] = Array.empty)(implicit
  withSchemaValidation: ValidationMode
) extends AstCreatorBase(filename)
    with AstNodeBuilder[PhpNode, AstCreator]:

  private val logger          = LoggerFactory.getLogger(AstCreator.getClass)
  private val scope           = new Scope()(using () => nextClosureName())
  private val tmpKeyPool      = new IntervalKeyPool(first = 0, last = Long.MaxValue)
  private val globalNamespace = globalNamespaceBlock()

  // The class a variable holds, by declaration alone (see VariableTypes), and the class each
  // property of the enclosing class declares, for naming `$x->m()` and `$this->p->m()` calls.
  private var variableTypes: Map[String, String] = Map.empty
  private var propertyTypes: Map[String, String] = Map.empty
  // the method that holds the file's top-level code, which tags the file's class heritage
  private var fileMethod: Option[NewMethod] = None

  /** A class name a type, `new` or `::` writes, as opposed to `self`, `static` and `parent`. */
  private def writtenClass(name: PhpNameExpr): Option[String] =
      Option.unless(VariableTypes.special(name.name) || name.name.isEmpty)(name.name)

  /** One tag per class name a declaration writes, with the name's own position: the types of
    * parameters, returns, properties and class constants (`decltype`), and a class's `extends`,
    * `implements` and trait `use` names. The slice reads them for the positions a node's single
    * `typeFullName` cannot carry (each member of a union type, each name of an implements list).
    */
  private def tagWrittenNames(node: NewNode, names: List[PhpNameExpr], kind: String): Unit =
      names.foreach(name => tagWrittenName(node, name, kind, ""))

  private def tagWrittenName(node: NewNode, name: PhpNameExpr, kind: String, member: String): Unit =
      for
        cls <- writtenClass(name)
        ln  <- line(name)
      do
        val value = ujson.Obj(
          "type"   -> cls,
          "line"   -> ln.intValue,
          "col"    -> column(name).map(_.intValue).getOrElse(-1),
          "kind"   -> kind,
          "member" -> member
        ).render()
        val tag = NewTag().name(AstCreator.WrittenNameTag).value(value)
        diffGraph.addNode(tag)
        diffGraph.addEdge(node, tag, EdgeTypes.TAGGED_BY)

  /** A parameter's default value has no place in the graph, so the classes it names (`Foo::BAR`,
    * `Foo::class`, `new Foo`) are tagged on the parameter, each with its own position.
    */
  private def tagDefaultValueNames(param: NewNode, default: PhpExpr): Unit =
      VariableTypes.classReferencesIn(default).foreach { (name, kind, member) =>
          tagWrittenName(param, name, kind, member)
      }

  /** Marks a call the frontend makes up while lowering (`$xs[] = v` as `array_push`, the calls of a
    * `foreach`), which no source text writes and no use of a function can come from.
    */
  private def tagSynthetic(call: NewNode): Unit =
    val tag = NewTag().name(AstCreator.SyntheticCallTag).value("")
    diffGraph.addNode(tag)
    diffGraph.addEdge(call, tag, EdgeTypes.TAGGED_BY)

  /** A reference to a class by name (`Foo::C`, `Foo::$p`, `$x instanceof Foo`, `catch (Foo $e)`): a
    * type reference carrying the resolved class, at the name's own position. `self`, `static` and
    * `parent` keep the identifier the frontend always made for them.
    */
  private def astForClassNameRef(expr: PhpExpr): Ast = expr match
    case name: PhpNameExpr if writtenClass(name).isDefined =>
        Ast(typeRefNode(name, name.name, name.name))
    case other => astForExpr(other)

  private def getNewTmpName(prefix: String = "tmp"): String =
      s"$prefix${tmpKeyPool.next.toString}"

  override def createAst(): BatchedUpdate.DiffGraphBuilder =
    val ast = astForPhpFile(phpAst)
    storeInDiffGraph(ast, diffGraph)
    diffGraph

  private def flattenGlobalNamespaceStmt(stmt: PhpStmt): List[PhpStmt] =
      stmt match
        case namespace: PhpNamespaceStmt if namespace.name.isEmpty =>
            namespace.stmts

        case _ => stmt :: Nil

  private def globalTypeDeclNode(file: PhpFile, globalNamespace: NewNamespaceBlock): NewTypeDecl =
      typeDeclNode(
        file,
        globalNamespace.name,
        globalNamespace.fullName,
        filename,
        globalNamespace.code,
        NodeTypes.NAMESPACE_BLOCK,
        globalNamespace.fullName
      )

  private def globalMethodDeclStmt(file: PhpFile, bodyStmts: List[PhpStmt]): PhpMethodDecl =
    val modifiersList = List(ModifierTypes.VIRTUAL, ModifierTypes.PUBLIC, ModifierTypes.STATIC)
    PhpMethodDecl(
      name = PhpNameExpr(NamespaceTraversal.globalNamespaceName, file.attributes),
      params = Nil,
      modifiers = modifiersList,
      returnType = None,
      stmts = bodyStmts,
      returnByRef = false,
      namespacedName = None,
      isClassMethod = false,
      attributes = file.attributes
    )

  private def astForPhpFile(file: PhpFile): Ast =
    scope.pushNewScope(globalNamespace)

    val (globalDeclStmts, globalMethodStmts) =
        file.children.flatMap(flattenGlobalNamespaceStmt).partition(
          _.isInstanceOf[PhpConstStmt]
        )

    val globalMethodStmt = globalMethodDeclStmt(file, globalMethodStmts)

    val globalTypeDeclStmt = PhpClassLikeStmt(
      name = Some(PhpNameExpr(globalNamespace.name, file.attributes)),
      modifiers = Nil,
      extendsNames = Nil,
      implementedInterfaces = Nil,
      stmts = globalDeclStmts.appended(globalMethodStmt),
      classLikeType = ClassLikeTypes.Class,
      scalarType = None,
      hasConstructor = false,
      attributes = file.attributes
    )

    val globalTypeDeclAst = astForClassLikeStmt(globalTypeDeclStmt)

    scope.popScope() // globalNamespace

    Ast(globalNamespace).withChild(globalTypeDeclAst)
  end astForPhpFile

  private def astsForStmt(stmt: PhpStmt): List[Ast] =
      stmt match
        case echoStmt: PhpEchoStmt           => astForEchoStmt(echoStmt) :: Nil
        case methodDecl: PhpMethodDecl       => astForMethodDecl(methodDecl) :: Nil
        case expr: PhpExpr                   => astForExpr(expr) :: Nil
        case breakStmt: PhpBreakStmt         => astForBreakStmt(breakStmt) :: Nil
        case contStmt: PhpContinueStmt       => astForContinueStmt(contStmt) :: Nil
        case whileStmt: PhpWhileStmt         => astForWhileStmt(whileStmt) :: Nil
        case doStmt: PhpDoStmt               => astForDoStmt(doStmt) :: Nil
        case forStmt: PhpForStmt             => astForForStmt(forStmt) :: Nil
        case ifStmt: PhpIfStmt               => astForIfStmt(ifStmt) :: Nil
        case switchStmt: PhpSwitchStmt       => astForSwitchStmt(switchStmt) :: Nil
        case tryStmt: PhpTryStmt             => astForTryStmt(tryStmt) :: Nil
        case returnStmt: PhpReturnStmt       => astForReturnStmt(returnStmt) :: Nil
        case classLikeStmt: PhpClassLikeStmt => astForClassLikeStmt(classLikeStmt) :: Nil
        case gotoStmt: PhpGotoStmt           => astForGotoStmt(gotoStmt) :: Nil
        case labelStmt: PhpLabelStmt         => astForLabelStmt(labelStmt) :: Nil
        case namespace: PhpNamespaceStmt     => astForNamespaceStmt(namespace) :: Nil
        case declareStmt: PhpDeclareStmt     => astForDeclareStmt(declareStmt) :: Nil
        case _: NopStmt => Nil // TODO This'll need to be updated when comments are added.
        case haltStmt: PhpHaltCompilerStmt => astForHaltCompilerStmt(haltStmt) :: Nil
        case unsetStmt: PhpUnsetStmt       => astForUnsetStmt(unsetStmt) :: Nil
        case globalStmt: PhpGlobalStmt     => astForGlobalStmt(globalStmt) :: Nil
        case useStmt: PhpUseStmt           => astForUseStmt(useStmt) :: Nil
        case groupUseStmt: PhpGroupUseStmt => astForGroupUseStmt(groupUseStmt) :: Nil
        case foreachStmt: PhpForeachStmt   => astForForeachStmt(foreachStmt) :: Nil
        case traitUseStmt: PhpTraitUseStmt => astforTraitUseStmt(traitUseStmt) :: Nil
        case enumCase: PhpEnumCaseStmt     => astForEnumCase(enumCase) :: Nil
        case staticStmt: PhpStaticStmt     => astsForStaticStmt(staticStmt)
        case unhandled =>
            logger.debug(s"Unhandled stmt $unhandled in $filename")
            ???

  private def astForEchoStmt(echoStmt: PhpEchoStmt): Ast =
    val args = echoStmt.exprs.map(astForExpr)
    val code = s"echo ${args.map(_.rootCodeOrEmpty).mkString(",")}"
    val callNode =
        newOperatorCallNode("echo", code, line = line(echoStmt), column = column(echoStmt))
    callAst(callNode, args)

  private def thisParamAstForMethod(originNode: PhpNode): Ast =
    val typeFullName = scope.getEnclosingTypeDeclTypeFullName.getOrElse(TypeConstants.Any)

    val thisNode = parameterInNode(
      originNode,
      name = NameConstants.This,
      code = NameConstants.This,
      index = 0,
      isVariadic = false,
      evaluationStrategy = EvaluationStrategies.BY_SHARING,
      typeFullName = typeFullName
    ).dynamicTypeHintFullName(typeFullName :: Nil)
    // TODO Add dynamicTypeHintFullName to parameterInNode param list

    scope.addToScope(NameConstants.This, thisNode)

    Ast(thisNode)

  private def thisIdentifier(lineNumber: Option[Integer]): NewIdentifier =
    val typ = scope.getEnclosingTypeDeclTypeName
    newIdentifierNode(NameConstants.This, typ.getOrElse("ANY"), typ.toList, lineNumber)
        .code(s"$$${NameConstants.This}")

  private def setParamIndices(asts: Seq[Ast]): Seq[Ast] =
    asts.map(_.root).zipWithIndex.foreach {
        case (Some(root: NewMethodParameterIn), idx) =>
            root.index(idx + 1)

        case (root, _) =>
            logger.debug(s"Trying to set index for unsupported node $root")
    }

    asts

  private def composeMethodFullName(methodName: String, isStatic: Boolean): String =
      if methodName == NamespaceTraversal.globalNamespaceName then
        globalNamespace.fullName
      else
        val className = getTypeDeclPrefix
        val methodDelimiter =
            if isStatic then StaticMethodDelimiter else InstanceMethodDelimiter

        val nameWithClass = List(className, Some(methodName)).flatten.mkString(methodDelimiter)

        prependNamespacePrefix(nameWithClass)

  private def astForMethodDecl(
    decl: PhpMethodDecl,
    bodyPrefixAsts: List[Ast] = Nil,
    fullNameOverride: Option[String] = None,
    isConstructor: Boolean = false,
    inheritedTypes: Map[String, String] = Map.empty
  ): Ast =
    val outerVariableTypes = variableTypes
    variableTypes = variableTypesOf(decl, inheritedTypes)
    val isStatic = decl.modifiers.contains(ModifierTypes.STATIC)
    val thisParam = if decl.isClassMethod && !isStatic then
      Option(thisParamAstForMethod(decl))
    else
      None

    val methodName = decl.name.name
    val fullName   = fullNameOverride.getOrElse(composeMethodFullName(methodName, isStatic))

    val signature = s"$UnresolvedSignature(${decl.params.size})"

    val parameters = thisParam.toList ++ decl.params.zipWithIndex.map { case (param, idx) =>
        astForParam(param, idx + 1)
    }

    val constructorModifier = Option.when(isConstructor)(ModifierTypes.CONSTRUCTOR)
    val defaultAccessModifier =
        Option.unless(containsAccessModifier(decl.modifiers))(ModifierTypes.PUBLIC)

    val allModifiers      = constructorModifier ++: defaultAccessModifier ++: decl.modifiers
    val modifiers         = allModifiers.map(newModifierNode)
    val excludedModifiers = Set("MODULE", "LAMBDA")
    val modifierString = decl.modifiers.filterNot(excludedModifiers.contains) match
      case Nil  => ""
      case mods => s"${mods.mkString(" ")} "
    val methodCode =
        s"${modifierString}function $methodName(${parameters.map(_.rootCodeOrEmpty).mkString(",")})"

    val method = methodNode(decl, methodName, methodCode, fullName, Some(signature), filename)

    if methodName == NamespaceTraversal.globalNamespaceName then fileMethod = Some(method)
    scope.pushNewScope(method)

    val returnType = decl.returnType.map(_.name).getOrElse(TypeConstants.Any)

    val methodBodyStmts = bodyPrefixAsts ++ decl.stmts.flatMap(astsForStmt)
    val methodReturn    = newMethodReturnNode(returnType, line = line(decl), column = column(decl))
    decl.returnType.foreach(t => tagWrittenNames(methodReturn, t.members, "decltype"))

    val methodBody = blockAst(blockNode(decl), methodBodyStmts)

    scope.popScope()
    variableTypes = outerVariableTypes
    // PHP 8.0+ attribute groups on the method (e.g. `#[Route("/users")]`) map to CPG annotations
    // so routed controller methods surface as entrypoints downstream. Additive: a method with no
    // attribute groups yields no annotations.
    val annotationAsts = astsForAttributeGroups(decl.attributeGroups)
    methodAstWithAnnotations(
      method,
      parameters,
      methodBody,
      methodReturn,
      modifiers,
      annotationAsts
    )
  end astForMethodDecl

  /** The variables of `decl` whose class is declared: parameters with a single class type and
    * locals assigned `new Foo` once, none written otherwise, plus the variables a closure or arrow
    * function inherits from its enclosing function and does not write itself.
    */
  private def variableTypesOf(
    decl: PhpMethodDecl,
    inherited: Map[String, String]
  ): Map[String, String] =
    val writes = VariableTypes.writesOf(decl.stmts)
    if writes.dynamic then Map.empty
    else
      val paramNames = decl.params.map(_.name).toSet
      val params = decl.params.filterNot(p => p.byRef || p.isVariadic || writes.written(p.name))
          .flatMap(p => VariableTypes.singleClass(p.paramType).map(p.name -> _))
      val locals = writes.onlyNew.filterNot((name, _) => paramNames.contains(name))
      inherited.filterNot((name, _) =>
          writes.written(name) || paramNames.contains(name)
      ) ++ params ++ locals

  private def stmtBodyBlockAst(stmt: PhpStmtWithBody): Ast =
    val bodyBlock    = blockNode(stmt)
    val bodyStmtAsts = stmt.stmts.flatMap(astsForStmt)
    Ast(bodyBlock).withChildren(bodyStmtAsts)

  private def astForParam(param: PhpParam, index: Int): Ast =
    val evaluationStrategy =
        if param.byRef then
          EvaluationStrategies.BY_REFERENCE
        else
          EvaluationStrategies.BY_VALUE

    val typeFullName = param.paramType.map(_.name).getOrElse(TypeConstants.Any)

    val byRefCodePrefix = if param.byRef then "&" else ""
    // `...$args` collects the positional and the named arguments no other parameter takes
    val variadicPrefix = if param.isVariadic then "..." else ""
    val code           = s"$byRefCodePrefix$variadicPrefix$$${param.name}"
    val paramNode = parameterInNode(
      param,
      param.name,
      code,
      index,
      param.isVariadic,
      evaluationStrategy,
      typeFullName
    )

    scope.addToScope(param.name, paramNode)
    param.paramType.foreach(t => tagWrittenNames(paramNode, t.members, "decltype"))
    param.default.foreach(tagDefaultValueNames(paramNode, _))

    val annotationAsts = astsForAttributeGroups(param.attributeGroups)
    Ast(paramNode).withChildren(annotationAsts)
  end astForParam

  /** Build CPG annotation ASTs for PHP 8.0+ attribute groups (`#[Attr(args)]`), flattening every
    * group's attributes into a single sequence. Mirrors the javasrc2cpg annotation convention: one
    * NewAnnotation per attribute with its argument ASTs parented as annotation-assignment children.
    * Additive: an empty `attributeGroups` list yields no annotations, so previously-annotated-free
    * declarations are unaffected. Attribute groups get explicit handling here rather than degrading
    * to Nop.
    */
  private def astsForAttributeGroups(groups: List[PhpAttributeGroup]): List[Ast] =
      groups.flatMap(_.attrs).map(astForAttribute)

  private def astForAttribute(attr: PhpAttribute): Ast =
    val name     = attr.name.name
    val fullName = attr.name.name
    val argsCode = attr.args.collect { case arg: PhpArg => arg }
        .map(arg => astForExpr(arg.expr).rootCodeOrEmpty)
        .mkString(",")
    val code = if attr.args.isEmpty then s"#[$name]" else s"#[$name($argsCode)]"
    val node = annotationNode(attr, code, name, fullName)
    val assignmentAsts = attr.args.zipWithIndex.collect { case (arg: PhpArg, idx) =>
        val valueAst  = astForExpr(arg.expr)
        val paramName = arg.parameterName.getOrElse(idx.toString)
        annotationAssignmentAst(paramName, valueAst.rootCodeOrEmpty, valueAst)
    }
    annotationAst(node, assignmentAsts)

  private def astForExpr(expr: PhpExpr): Ast =
      expr match
        case funcCallExpr: PhpCallExpr       => astForCall(funcCallExpr)
        case variableExpr: PhpVariable       => astForVariableExpr(variableExpr)
        case nameExpr: PhpNameExpr           => astForNameExpr(nameExpr)
        case assignExpr: PhpAssignment       => astForAssignment(assignExpr)
        case scalarExpr: PhpScalar           => astForScalar(scalarExpr)
        case binaryOp: PhpBinaryOp           => astForBinOp(binaryOp)
        case unaryOp: PhpUnaryOp             => astForUnaryOp(unaryOp)
        case castExpr: PhpCast               => astForCastExpr(castExpr)
        case isSetExpr: PhpIsset             => astForIsSetExpr(isSetExpr)
        case printExpr: PhpPrint             => astForPrintExpr(printExpr)
        case ternaryOp: PhpTernaryOp         => astForTernaryOp(ternaryOp)
        case throwExpr: PhpThrowExpr         => astForThrow(throwExpr)
        case cloneExpr: PhpCloneExpr         => astForClone(cloneExpr)
        case emptyExpr: PhpEmptyExpr         => astForEmpty(emptyExpr)
        case evalExpr: PhpEvalExpr           => astForEval(evalExpr)
        case exitExpr: PhpExitExpr           => astForExit(exitExpr)
        case arrayExpr: PhpArrayExpr         => astForArrayExpr(arrayExpr)
        case listExpr: PhpListExpr           => astForListExpr(listExpr)
        case newExpr: PhpNewExpr             => astForNewExpr(newExpr)
        case matchExpr: PhpMatchExpr         => astForMatchExpr(matchExpr)
        case yieldExpr: PhpYieldExpr         => astForYieldExpr(yieldExpr)
        case closure: PhpClosureExpr         => astForClosureExpr(closure)
        case yieldFromExpr: PhpYieldFromExpr => astForYieldFromExpr(yieldFromExpr)
        case classConstFetchExpr: PhpClassConstFetchExpr =>
            astForClassConstFetchExpr(classConstFetchExpr)
        case constFetchExpr: PhpConstFetchExpr => astForConstFetchExpr(constFetchExpr)
        case arrayDimFetchExpr: PhpArrayDimFetchExpr =>
            astForArrayDimFetchExpr(arrayDimFetchExpr)
        case errorSuppressExpr: PhpErrorSuppressExpr =>
            astForErrorSuppressExpr(errorSuppressExpr)
        case instanceOfExpr: PhpInstanceOfExpr => astForInstanceOfExpr(instanceOfExpr)
        case propertyFetchExpr: PhpPropertyFetchExpr =>
            astForPropertyFetchExpr(propertyFetchExpr)
        case includeExpr: PhpIncludeExpr     => astForIncludeExpr(includeExpr)
        case shellExecExpr: PhpShellExecExpr => astForShellExecExpr(shellExecExpr)
        case null =>
            logger.debug("expr was null")
            ???
        case other => throw new NotImplementedError(
              s"unexpected expression '$other' of type ${other.getClass}"
            )

  private def intToLiteralAst(num: Int): Ast =
      Ast(NewLiteral().code(num.toString).typeFullName(TypeConstants.Int))

  private def astForBreakStmt(breakStmt: PhpBreakStmt): Ast =
    val code      = breakStmt.num.map(num => s"break($num)").getOrElse("break")
    val breakNode = controlStructureNode(breakStmt, ControlStructureTypes.BREAK, code)

    val argument = breakStmt.num.map(intToLiteralAst)

    controlStructureAst(breakNode, None, argument.toList)

  private def astForContinueStmt(continueStmt: PhpContinueStmt): Ast =
    val code         = continueStmt.num.map(num => s"continue($num)").getOrElse("continue")
    val continueNode = controlStructureNode(continueStmt, ControlStructureTypes.CONTINUE, code)

    val argument = continueStmt.num.map(intToLiteralAst)

    controlStructureAst(continueNode, None, argument.toList)

  private def astForWhileStmt(whileStmt: PhpWhileStmt): Ast =
    val condition  = astForExpr(whileStmt.cond)
    val lineNumber = line(whileStmt)
    val code       = s"while (${condition.rootCodeOrEmpty})"
    val body       = stmtBodyBlockAst(whileStmt)

    whileAst(
      Option(condition),
      List(body),
      Option(code),
      lineNumber,
      columnNumber = column(whileStmt)
    )

  private def astForDoStmt(doStmt: PhpDoStmt): Ast =
    val condition  = astForExpr(doStmt.cond)
    val lineNumber = line(doStmt)
    val code       = s"do {...} while (${condition.rootCodeOrEmpty})"
    val body       = stmtBodyBlockAst(doStmt)

    doWhileAst(
      Option(condition),
      List(body),
      Option(code),
      lineNumber,
      columnNumber = column(doStmt)
    )

  private def astForForStmt(stmt: PhpForStmt): Ast =
    val lineNumber = line(stmt)

    val initAsts      = stmt.inits.map(astForExpr)
    val conditionAsts = stmt.conditions.map(astForExpr)
    val loopExprAsts  = stmt.loopExprs.map(astForExpr)

    val bodyAst = stmtBodyBlockAst(stmt)

    val initCode      = initAsts.map(_.rootCodeOrEmpty).mkString(",")
    val conditionCode = conditionAsts.map(_.rootCodeOrEmpty).mkString(",")
    val loopExprCode  = loopExprAsts.map(_.rootCodeOrEmpty).mkString(",")
    val forCode       = s"for ($initCode;$conditionCode;$loopExprCode)"

    val forNode = controlStructureNode(stmt, ControlStructureTypes.FOR, forCode)
    forAst(forNode, Nil, initAsts, conditionAsts, loopExprAsts, bodyAst)

  private def astForIfStmt(ifStmt: PhpIfStmt): Ast =
    val condition = astForExpr(ifStmt.cond)

    val thenAst = stmtBodyBlockAst(ifStmt)

    val elseAst = ifStmt.elseIfs match
      case Nil => ifStmt.elseStmt.map(els => stmtBodyBlockAst(els)).toList

      case elseIf :: rest =>
          val newIfStmt =
              PhpIfStmt(elseIf.cond, elseIf.stmts, rest, ifStmt.elseStmt, elseIf.attributes)
          val wrappingBlock = blockNode(elseIf)
          val wrappedAst    = Ast(wrappingBlock).withChild(astForIfStmt(newIfStmt)) :: Nil
          wrappedAst

    val conditionCode = condition.rootCodeOrEmpty
    val ifNode = controlStructureNode(ifStmt, ControlStructureTypes.IF, s"if ($conditionCode)")

    controlStructureAst(ifNode, Option(condition), thenAst :: elseAst)
  end astForIfStmt

  private def astForSwitchStmt(stmt: PhpSwitchStmt): Ast =
    val conditionAst = astForExpr(stmt.condition)

    val switchNode =
        controlStructureNode(
          stmt,
          ControlStructureTypes.SWITCH,
          s"switch (${conditionAst.rootCodeOrEmpty})"
        )

    val switchBodyBlock = blockNode(stmt)
    val entryAsts       = stmt.cases.flatMap(astsForSwitchCase)
    val switchBody      = Ast(switchBodyBlock).withChildren(entryAsts)

    controlStructureAst(switchNode, Option(conditionAst), switchBody :: Nil)

  private def astForTryStmt(stmt: PhpTryStmt): Ast =
    val tryBody     = stmtBodyBlockAst(stmt)
    val catches     = stmt.catches.map(astForCatchStmt)
    val finallyBody = stmt.finallyStmt.map(fin => stmtBodyBlockAst(fin))

    val tryNode = controlStructureNode(stmt, ControlStructureTypes.TRY, "try { ... }")

    tryCatchAst(tryNode, tryBody, catches, finallyBody)

  private def astForReturnStmt(stmt: PhpReturnStmt): Ast =
    val maybeExprAst = stmt.expr.map(astForExpr)
    val code         = s"return ${maybeExprAst.map(_.rootCodeOrEmpty).getOrElse("")}"

    val node = returnNode(stmt, code)

    returnAst(node, maybeExprAst.toList)

  private def astForClassLikeStmt(stmt: PhpClassLikeStmt): Ast =
      stmt.name match
        case None       => astForAnonymousClass(stmt)
        case Some(name) => astForNamedClass(stmt, name)

  private def astForGotoStmt(stmt: PhpGotoStmt): Ast =
    val label = stmt.label.name
    val code  = s"goto $label"

    val gotoNode = controlStructureNode(stmt, ControlStructureTypes.GOTO, code)

    val jumpLabel = NewJumpLabel()
        .name(label)
        .code(label)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))

    controlStructureAst(gotoNode, condition = None, children = Ast(jumpLabel) :: Nil)

  private def astForLabelStmt(stmt: PhpLabelStmt): Ast =
    val label = stmt.label.name

    val jumpTarget = NewJumpTarget()
        .name(label)
        .code(label)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))

    Ast(jumpTarget)

  private def astForNamespaceStmt(stmt: PhpNamespaceStmt): Ast =
    val name     = stmt.name.map(_.name).getOrElse(NameConstants.Unknown)
    val fullName = s"$filename:$name"

    val namespaceBlock = NewNamespaceBlock()
        .name(name)
        .fullName(fullName)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))

    scope.pushNewScope(namespaceBlock)
    val bodyStmts = astsForClassLikeBody(stmt, stmt.stmts, createDefaultConstructor = false)
    scope.popScope()

    Ast(namespaceBlock).withChildren(bodyStmts)

  private def astForDeclareStmt(stmt: PhpDeclareStmt): Ast =
    val declareAssignAsts = stmt.declares.map(astForDeclareItem)
    val declareCode =
        s"${PhpOperators.declareFunc}(${declareAssignAsts.map(_.rootCodeOrEmpty).mkString(",")})"
    val declareNode =
        newOperatorCallNode(
          PhpOperators.declareFunc,
          declareCode,
          line = line(stmt),
          column = column(stmt)
        )
    val declareAst = callAst(declareNode, declareAssignAsts)

    stmt.stmts match
      case Some(stmtList) =>
          val stmtAsts = stmtList.flatMap(astsForStmt)
          Ast(blockNode(stmt))
              .withChild(declareAst)
              .withChildren(stmtAsts)

      case None => declareAst
  end astForDeclareStmt

  private def astForDeclareItem(item: PhpDeclareItem): Ast =
    val key   = identifierNode(item, item.key.name, item.key.name, "ANY")
    val value = astForExpr(item.value)
    val code  = s"${key.name}=${value.rootCodeOrEmpty}"

    val declareAssignment = newOperatorCallNode(
      Operators.assignment,
      code,
      line = line(item),
      column = column(item)
    )
    callAst(declareAssignment, Ast(key) :: value :: Nil)

  private def astForHaltCompilerStmt(stmt: PhpHaltCompilerStmt): Ast =
    val call = newOperatorCallNode(
      NameConstants.HaltCompiler,
      s"${NameConstants.HaltCompiler}()",
      Some(TypeConstants.Void),
      line(stmt),
      column(stmt)
    )

    Ast(call)

  private def astForUnsetStmt(stmt: PhpUnsetStmt): Ast =
    val name = PhpOperators.unset
    val args = stmt.vars.map(astForExpr)
    val code = s"$name(${args.map(_.rootCodeOrEmpty).mkString(", ")})"
    val callNode = newOperatorCallNode(
      name,
      code,
      typeFullName = Some(TypeConstants.Void),
      line = line(stmt),
      column = column(stmt)
    )
        .methodFullName(PhpOperators.unset)
    callAst(callNode, args)

  private def astForGlobalStmt(stmt: PhpGlobalStmt): Ast =
    // This isn't an accurater representation of what `global` does, but with things like `global $$x` being possible,
    // it's very difficult to figure out correct scopes for global variables.

    val varsAsts = stmt.vars.map(astForExpr)
    val code     = s"${PhpOperators.global} ${varsAsts.map(_.rootCodeOrEmpty).mkString(", ")}"

    val globalCallNode =
        newOperatorCallNode(
          PhpOperators.global,
          code,
          Some(TypeConstants.Void),
          line(stmt),
          column(stmt)
        )

    callAst(globalCallNode, varsAsts)

  private def astForUseStmt(stmt: PhpUseStmt): Ast =
    // TODO Use useType + scope to get better name info
    val imports = stmt.uses.map(astForUseUse(_))
    wrapMultipleInBlock(imports, line(stmt), column(stmt))

  private def astForGroupUseStmt(stmt: PhpGroupUseStmt): Ast =
    // TODO Use useType + scope to get better name info
    val groupPrefix = s"${stmt.prefix.name}\\"
    val imports     = stmt.uses.map(astForUseUse(_, groupPrefix))
    wrapMultipleInBlock(imports, line(stmt), column(stmt))

  private def astForKeyValPair(
    key: PhpExpr,
    value: PhpExpr,
    lineNo: Option[Integer],
    colNo: Option[Integer]
  ): Ast =
    val keyAst   = astForExpr(key)
    val valueAst = astForExpr(value)

    val code = s"${keyAst.rootCodeOrEmpty} => ${valueAst.rootCodeOrEmpty}"
    val callNode =
        newOperatorCallNode(PhpOperators.doubleArrow, code, line = lineNo, column = colNo)
    callAst(callNode, keyAst :: valueAst :: Nil)

  private def astForForeachStmt(stmt: PhpForeachStmt): Ast =
    val iteratorAst    = astForExpr(stmt.iterExpr)
    val iterIdentifier = getTmpIdentifier(stmt, maybeTypeFullName = None, prefix = "iter_")

    val assignItemTargetAst = stmt.keyVar match
      case Some(key) => astForKeyValPair(key, stmt.valueVar, line(stmt), column(stmt))
      case None      => astForExpr(stmt.valueVar)

    // Initializer asts
    // - Iterator assign
    val iterValue = astForExpr(stmt.iterExpr)
    val iteratorAssignAst =
        simpleAssignAst(Ast(iterIdentifier), iterValue, line(stmt), column(stmt))

    // - Assigned item assign
    val itemInitAst = getItemAssignAstForForeach(stmt, assignItemTargetAst, iterIdentifier.copy)

    // Condition ast
    val isNullName = PhpOperators.isNull
    val valueAst   = astForExpr(stmt.valueVar)
    val isNullCode = s"$isNullName(${valueAst.rootCodeOrEmpty})"
    val isNullCall =
        newOperatorCallNode(
          isNullName,
          isNullCode,
          Some(TypeConstants.Bool),
          line(stmt),
          column(stmt)
        )
            .methodFullName(PhpOperators.isNull)
    val notIsNull =
        newOperatorCallNode(
          Operators.logicalNot,
          s"!$isNullCode",
          line = line(stmt),
          column = column(stmt)
        )
    tagSynthetic(isNullCall)
    val isNullAst    = callAst(isNullCall, valueAst :: Nil)
    val conditionAst = callAst(notIsNull, isNullAst :: Nil)

    // Update asts
    val nextIterIdent = Ast(iterIdentifier.copy)
    val nextSignature = "void()"
    val nextCallCode  = s"${nextIterIdent.rootCodeOrEmpty}->next()"
    val nextCallNode = callNode(
      stmt,
      nextCallCode,
      "next",
      "Iterator.next",
      DispatchTypes.DYNAMIC_DISPATCH,
      Some(nextSignature),
      Some(TypeConstants.Any)
    )
    tagSynthetic(nextCallNode)
    val nextCallAst = callAst(nextCallNode, base = Option(nextIterIdent))
    val itemUpdateAst = itemInitAst.root match
      case Some(initRoot: AstNodeNew) => itemInitAst.subTreeCopy(initRoot)
      case _ =>
          logger.debug(s"Could not copy foreach init ast in $filename")
          Ast()

    // the copy of the item assignment holds a copy of the `current` call
    itemUpdateAst.nodes.collect {
        case c: NewCall if c.methodFullName == "Iterator.current" => tagSynthetic(c)
    }

    val bodyAst = stmtBodyBlockAst(stmt)

    val ampPrefix = if stmt.assignByRef then "&" else ""
    val foreachCode =
        s"foreach (${iteratorAst.rootCodeOrEmpty} as $ampPrefix${assignItemTargetAst.rootCodeOrEmpty})"
    val foreachNode = controlStructureNode(stmt, ControlStructureTypes.FOR, foreachCode)
    Ast(foreachNode)
        .withChild(wrapMultipleInBlock(
          iteratorAssignAst :: itemInitAst :: Nil,
          line(stmt),
          column(stmt)
        ))
        .withChild(conditionAst)
        .withChild(wrapMultipleInBlock(
          nextCallAst :: itemUpdateAst :: Nil,
          line(stmt),
          column(stmt)
        ))
        .withChild(bodyAst)
        .withConditionEdges(foreachNode, conditionAst.root.toList)
  end astForForeachStmt

  private def getItemAssignAstForForeach(
    stmt: PhpForeachStmt,
    assignItemTargetAst: Ast,
    iteratorIdentifier: NewIdentifier
  ): Ast =
    val iteratorIdentifierAst = Ast(iteratorIdentifier)
    val currentCallSignature  = s"$UnresolvedSignature(0)"
    val currentCallCode       = s"${iteratorIdentifierAst.rootCodeOrEmpty}->current()"
    val currentCallNode = callNode(
      stmt,
      currentCallCode,
      "current",
      "Iterator.current",
      DispatchTypes.DYNAMIC_DISPATCH,
      Some(currentCallSignature),
      Some(TypeConstants.Any)
    );
    tagSynthetic(currentCallNode)
    val currentCallAst = callAst(currentCallNode, base = Option(iteratorIdentifierAst))

    val valueAst = if stmt.assignByRef then
      val addressOfCode = s"&${currentCallAst.rootCodeOrEmpty}"
      val addressOfCall =
          newOperatorCallNode(
            Operators.addressOf,
            addressOfCode,
            line = line(stmt),
            column = column(stmt)
          )
      callAst(addressOfCall, currentCallAst :: Nil)
    else
      currentCallAst

    simpleAssignAst(assignItemTargetAst, valueAst, line(stmt), column(stmt))
  end getItemAssignAstForForeach

  private def simpleAssignAst(
    target: Ast,
    source: Ast,
    lineNo: Option[Integer],
    colNo: Option[Integer]
  ): Ast =
    val code = s"${target.rootCodeOrEmpty} = ${source.rootCodeOrEmpty}"
    val callNode =
        newOperatorCallNode(Operators.assignment, code, line = lineNo, column = colNo)
    callAst(callNode, target :: source :: Nil)

  // A class's trait names are lowered with its heritage (see astForNamedClass); the adaptations
  // (`insteadof`, `as`) rename methods and create no node of their own.
  private def astforTraitUseStmt(stmt: PhpTraitUseStmt): Ast =
      Ast()

  private def astForUseUse(stmt: PhpUseUse, namePrefix: String = ""): Ast =
    val originalName = s"$namePrefix${stmt.originalName.name}"
    val aliasCode    = stmt.alias.map(alias => s" as ${alias.name}").getOrElse("")
    val typeCode = stmt.useType match
      case PhpUseType.Function => s"function "
      case PhpUseType.Constant => s"const "
      case _                   => ""
    val code = s"use $typeCode$originalName$aliasCode"
    val importNode = NewImport()
        .importedEntity(originalName)
        .importedAs(stmt.alias.map(_.name))
        .isExplicit(true)
        .code(code)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))

    Ast(importNode)

  private def astsForStaticStmt(stmt: PhpStaticStmt): List[Ast] =
      stmt.vars.flatMap { staticVarDecl =>
        val variableAst   = astForVariableExpr(staticVarDecl.variable)
        val maybeValueAst = staticVarDecl.defaultValue.map(astForExpr)

        val code = variableAst.rootCode.getOrElse(NameConstants.Unknown)
        val name = variableAst.root match
          case Some(identifier: NewIdentifier) => identifier.name
          case _                               => code

        val local = localNode(
          stmt,
          name,
          s"static $code",
          variableAst.rootType.getOrElse(TypeConstants.Any)
        )
        scope.addToScope(local.name, local)

        variableAst.root.collect { case identifier: NewIdentifier =>
            diffGraph.addEdge(identifier, local, EdgeTypes.REF)
        }

        val defaultAssignAst = maybeValueAst.map { valueAst =>
          val valueCode = s"static $code = ${valueAst.rootCodeOrEmpty}"
          val assignNode =
              newOperatorCallNode(
                Operators.assignment,
                valueCode,
                line = line(stmt),
                column = column(stmt)
              )
          callAst(assignNode, variableAst :: valueAst :: Nil)
        }

        Ast(local) :: defaultAssignAst.toList
      }

  private def astForAnonymousClass(stmt: PhpClassLikeStmt): Ast =
      // TODO
      Ast()

  def codeForClassStmt(stmt: PhpClassLikeStmt, name: PhpNameExpr): String =
    // TODO Extend for anonymous classes
    val extendsString = stmt.extendsNames match
      case Nil   => ""
      case names => s" extends ${names.map(_.name).mkString(", ")}"
    val implementsString =
        if stmt.implementedInterfaces.isEmpty then
          ""
        else
          s" implements ${stmt.implementedInterfaces.map(_.name).mkString(", ")}"

    s"${stmt.classLikeType} ${name.name}$extendsString$implementsString"

  private def astForNamedClass(stmt: PhpClassLikeStmt, name: PhpNameExpr): Ast =
    val traitNames   = stmt.stmts.collect { case use: PhpTraitUseStmt => use.traits }.flatten
    val inheritsFrom = (stmt.extendsNames ++ stmt.implementedInterfaces ++ traitNames).map(_.name)
    val code         = codeForClassStmt(stmt, name)

    val fullName =
        if name.name == NamespaceTraversal.globalNamespaceName then
          globalNamespace.fullName
        else
          prependNamespacePrefix(name.name)

    val typeDecl =
        typeDeclNode(stmt, name.name, fullName, filename, code, inherits = inheritsFrom)
    // the class sits at its name, not at the first of its attributes the statement starts with
    if name.attributes.lineNumber.isDefined then
      typeDecl.lineNumber(name.attributes.lineNumber)
      typeDecl.columnNumber(column(name))
    // a type declaration cannot carry tags, so the file's own method does
    fileMethod.foreach { method =>
      tagWrittenNames(method, stmt.extendsNames, "extends")
      tagWrittenNames(method, stmt.implementedInterfaces, "implements")
      tagWrittenNames(method, traitNames, "use")
    }

    val createDefaultConstructor = stmt.hasConstructor

    val outerPropertyTypes = propertyTypes
    propertyTypes = propertyTypesOf(stmt)
    scope.pushNewScope(typeDecl)
    val bodyStmts = astsForClassLikeBody(stmt, stmt.stmts, createDefaultConstructor)
    val modifiers = stmt.modifiers.map(newModifierNode).map(Ast(_))
    scope.popScope()
    propertyTypes = outerPropertyTypes

    val annotationAsts = astsForAttributeGroups(stmt.attributeGroups)
    Ast(typeDecl)
        .withChildren(modifiers)
        .withChildren(annotationAsts)
        .withChildren(bodyStmts)
  end astForNamedClass

  /** The class each typed property of `stmt` declares, with the constructor's promoted parameters.
    */
  private def propertyTypesOf(stmt: PhpClassLikeStmt): Map[String, String] =
    val declared = stmt.stmts.collect { case p: PhpPropertyStmt => p }.flatMap { p =>
        VariableTypes.singleClass(p.typeName).toList.flatMap(cls =>
            p.variables.map(_.name.name -> cls)
        )
    }
    val promoted = stmt.stmts.collect {
        case m: PhpMethodDecl if m.name.name == ConstructorMethodName => m.params
    }.flatten.filter(_.flags != 0).flatMap { param =>
        VariableTypes.singleClass(param.paramType).map(param.name -> _)
    }
    (declared ++ promoted).toMap

  private def astForStaticAndConstInits: Option[Ast] =
      scope.getConstAndStaticInits match
        case Nil => None

        case inits =>
            val signature = s"${TypeConstants.Void}()"
            val fullName  = composeMethodFullName(StaticInitMethodName, isStatic = true)
            val ast = staticInitMethodAst(
              inits,
              fullName,
              Option(signature),
              TypeConstants.Void,
              fileName = Some(filename)
            )
            Option(ast)

  private def astsForClassLikeBody(
    classLike: PhpStmt,
    bodyStmts: List[PhpStmt],
    createDefaultConstructor: Boolean
  ): List[Ast] =
    val classConsts =
        bodyStmts.collect { case cs: PhpConstStmt => cs }.flatMap(astsForConstStmt)
    val properties =
        bodyStmts.collect { case cp: PhpPropertyStmt => cp }.flatMap(astsForPropertyStmt)

    val explicitConstructorAst = bodyStmts.collectFirst {
        case m: PhpMethodDecl if m.name.name == ConstructorMethodName => astForConstructor(m)
    }

    val constructorAst =
        explicitConstructorAst.orElse(
          Option.when(createDefaultConstructor)(defaultConstructorAst(classLike))
        )

    val otherBodyStmts = bodyStmts.flatMap {
        case _: PhpConstStmt => Nil // Handled above

        case _: PhpPropertyStmt => Nil // Handled above

        case method: PhpMethodDecl if method.name.name == ConstructorMethodName =>
            Nil // Handled above

        // Not all statements are supported in class bodies, but since this is re-used for namespaces
        // we allow that here.
        case stmt => astsForStmt(stmt)
    }

    val clinitAst           = astForStaticAndConstInits
    val anonymousMethodAsts = scope.getAndClearAnonymousMethods

    List(
      classConsts,
      properties,
      clinitAst,
      constructorAst,
      anonymousMethodAsts,
      otherBodyStmts
    ).flatten
  end astsForClassLikeBody

  private def astForConstructor(constructorDecl: PhpMethodDecl): Ast =
    val fieldInits = scope.getFieldInits
    astForMethodDecl(constructorDecl, fieldInits, isConstructor = true)

  private def prependNamespacePrefix(name: String): String =
      scope.getEnclosingNamespaceNames.filterNot(
        _ == NamespaceTraversal.globalNamespaceName
      ) match
        case Nil   => name
        case names => names.appended(name).mkString(NamespaceDelimiter)

  private def getTypeDeclPrefix: Option[String] =
      scope.getEnclosingTypeDeclTypeName
          .filterNot(_ == NamespaceTraversal.globalNamespaceName)

  private def defaultConstructorAst(originNode: PhpNode): Ast =
    val fullName = composeMethodFullName(ConstructorMethodName, isStatic = false)

    val signature = s"$UnresolvedSignature(0)"

    val modifiers = List(
      ModifierTypes.VIRTUAL,
      ModifierTypes.PUBLIC,
      ModifierTypes.CONSTRUCTOR
    ).map(newModifierNode)

    val thisParam = thisParamAstForMethod(originNode)

    val method = methodNode(
      originNode,
      ConstructorMethodName,
      fullName,
      fullName,
      Some(signature),
      filename
    )

    val methodBody = blockAst(blockNode(originNode), scope.getFieldInits)

    val methodReturn = newMethodReturnNode(TypeConstants.Any, line = None, column = None)

    methodAstWithAnnotations(method, thisParam :: Nil, methodBody, methodReturn, modifiers)
  end defaultConstructorAst

  private def astForMemberAssignment(
    memberNode: NewMember,
    valueExpr: PhpExpr,
    isField: Boolean
  ): Ast =
    val targetAst = if isField then
      val code = s"$$this->${memberNode.name}"
      val fieldAccessNode =
          newOperatorCallNode(Operators.fieldAccess, code, line = memberNode.lineNumber)
      val identifier      = thisIdentifier(memberNode.lineNumber)
      val thisParam       = scope.lookupVariable(NameConstants.This)
      val fieldIdentifier = newFieldIdentifierNode(memberNode.name, memberNode.lineNumber)
      callAst(fieldAccessNode, List(identifier, fieldIdentifier).map(Ast(_))).withRefEdges(
        identifier,
        thisParam.toList
      )
    else
      val identifierCode = memberNode.code.replaceAll("const ", "").replaceAll("case ", "")
      val typeFullName   = Option(memberNode.typeFullName)
      val identifier = newIdentifierNode(memberNode.name, typeFullName.getOrElse("ANY"))
          .code(identifierCode)
      Ast(identifier).withRefEdge(identifier, memberNode)
    val value = astForExpr(valueExpr)

    val assignmentCode = s"${targetAst.rootCodeOrEmpty} = ${value.rootCodeOrEmpty}"
    val callNode =
        newOperatorCallNode(Operators.assignment, assignmentCode, line = memberNode.lineNumber)

    callAst(callNode, List(targetAst, value))
  end astForMemberAssignment

  private def astsForConstStmt(stmt: PhpConstStmt): List[Ast] =
      stmt.consts.map { constDecl =>
        val finalModifier = Ast(newModifierNode(ModifierTypes.FINAL))
        // `final const` is not allowed, so this is a safe way to represent constants in the CPG
        val modifierAsts = finalModifier :: stmt.modifiers.map(newModifierNode).map(Ast(_))

        val name      = constDecl.name.name
        val code      = s"const $name"
        val someValue = Option(constDecl.value)
        val member = astForConstOrFieldValue(
          stmt,
          name,
          code,
          someValue,
          scope.addConstOrStaticInitToScope,
          isField = false
        )
        member.root.foreach(tagWrittenNames(_, stmt.typeName.toList.flatMap(_.members), "decltype"))
        member
            .withChildren(modifierAsts)
            .withChildren(astsForAttributeGroups(stmt.attributeGroups))
      }

  private def astForEnumCase(stmt: PhpEnumCaseStmt): Ast =
    val finalModifier = Ast(newModifierNode(ModifierTypes.FINAL))

    val name = stmt.name.name
    val code = s"case $name"

    val annotationAsts = astsForAttributeGroups(stmt.attributeGroups)
    astForConstOrFieldValue(
      stmt,
      name,
      code,
      stmt.expr,
      scope.addConstOrStaticInitToScope,
      isField = false
    )
        .withChild(finalModifier)
        .withChildren(annotationAsts)

  private def astsForPropertyStmt(stmt: PhpPropertyStmt): List[Ast] =
    // PHP 8.0+ attribute groups map to CPG annotations; PHP 8.4 asymmetric visibility (e.g.
    // `private(set)`) maps to an extra modifier so it is not dropped; PHP 8.4 property hooks
    // (get/set) have their bodies emitted as child ASTs so hook logic survives downstream.
    val asymVisModifier =
        stmt.asymmetricVisibility.map(vis => Ast(newModifierNode(vis))).toList
    stmt.variables.map { varDecl =>
      val modifierAsts = stmt.modifiers.map(newModifierNode).map(Ast(_))

      val name = varDecl.name.name
      val member = astForConstOrFieldValue(
        stmt,
        name,
        s"$$$name",
        varDecl.defaultValue,
        scope.addFieldInitToScope,
        isField = true
      )
      member.root.foreach(tagWrittenNames(_, stmt.typeName.toList.flatMap(_.members), "decltype"))
      // each hook is a method of the class, so the calls in its body have an enclosing method
      stmt.hooks.foreach(hook => astForPropertyHook(name, hook).foreach(scope.addAnonymousMethod))
      member
          .withChildren(modifierAsts)
          .withChildren(asymVisModifier)
          .withChildren(astsForAttributeGroups(stmt.attributeGroups))
    }
  end astsForPropertyStmt

  /** A PHP 8.4 property hook (`get`/`set`) is a method of its class, named `$property::get`, so the
    * statements of its body (a block, or the expression of the arrow form) have an enclosing method
    * like any other. The arrow form of a `get` returns its expression, and a `set` hook without a
    * parameter list takes the implicit `$value`. An abstract hook has no body and no method.
    */
  private def astForPropertyHook(property: String, hook: PhpPropertyHook): Option[Ast] =
      hook.body.map { stmts =>
        val body = stmts match
          case (expr: PhpExpr) :: Nil if hook.name == "get" =>
              List(PhpReturnStmt(Some(expr), expr.attributes))
          case other => other
        val params =
            if hook.name == "set" && hook.params.isEmpty then
              List(PhpParam("value", None, false, false, None, 0, Nil, hook.attributes))
            else hook.params
        val decl = PhpMethodDecl(
          PhpNameExpr(s"$$$property::${hook.name}", hook.attributes),
          params,
          List(ModifierTypes.PUBLIC),
          None,
          body,
          hook.byRef,
          hook.attributeGroups,
          None,
          isClassMethod = true,
          hook.attributes
        )
        astForMethodDecl(decl)
      }

  private def astForConstOrFieldValue(
    originNode: PhpNode,
    name: String,
    code: String,
    value: Option[PhpExpr],
    addToScope: Ast => Unit,
    isField: Boolean
  ): Ast =
    val member = memberNode(originNode, name, code, TypeConstants.Any)

    value match
      case Some(v) =>
          val assignAst = astForMemberAssignment(member, v, isField)
          addToScope(assignAst)
      case None => // Nothing to do here
    Ast(member)

  private def astForCatchStmt(stmt: PhpCatchStmt): Ast =
    // TODO Add variable at some point. Current implementation is consistent with C++.
    // The caught classes are references of their own, kept first in the handler's block.
    val typeRefs = stmt.types.map(astForClassNameRef)
    Ast(blockNode(stmt)).withChildren(typeRefs ++ stmt.stmts.flatMap(astsForStmt))

  private def astsForSwitchCase(caseStmt: PhpCaseStmt): List[Ast] =
    val maybeConditionAst = caseStmt.condition.map(astForExpr)
    val jumpTarget = maybeConditionAst match
      case Some(conditionAst) =>
          NewJumpTarget().name("case").code(s"case ${conditionAst.rootCodeOrEmpty}")
      case None => NewJumpTarget().name("default").code("default")
    jumpTarget.lineNumber(line(caseStmt)).columnNumber(column(caseStmt))

    val stmtAsts = caseStmt.stmts.flatMap(astsForStmt)

    Ast(jumpTarget) :: stmtAsts

  private def codeForMethodCall(call: PhpCallExpr, targetAst: Ast, name: String): String =
    val callOperator = if call.isNullSafe then "?->" else "->"
    s"${targetAst.rootCodeOrEmpty}$callOperator$name"

  private def codeForStaticMethodCall(call: PhpCallExpr, name: String): String =
    val className =
        call.target
            .map(astForExpr)
            .map(_.rootCode.getOrElse(UnresolvedNamespace))
            .getOrElse(UnresolvedNamespace)
    s"$className::$name"

  /** The class an instance call's receiver is declared to hold: a typed or promoted property of the
    * enclosing class (`$this->p`), `new Foo` written in place, or a variable whose class
    * `variableTypesOf` recovered. `$this` itself is the project's own class and stays unnamed.
    */
  private def receiverClass(call: PhpCallExpr, receiver: PhpExpr): Option[String] =
      if !call.methodName.isInstanceOf[PhpNameExpr] then None
      else
        receiver match
          case PhpVariable(PhpNameExpr(name, _, _), _) if name != NameConstants.This =>
              variableTypes.get(name)
          case PhpNewExpr(name: PhpNameExpr, _, _) => writtenClass(name)
          case PhpPropertyFetchExpr(
                PhpVariable(PhpNameExpr(NameConstants.This, _, _), _),
                PhpNameExpr(property, _, _),
                _,
                false,
                _
              ) => propertyTypes.get(property)
          case _ => None

  private def astForCall(call: PhpCallExpr): Ast =
    val arguments = call.args.map(astForCallArg)

    val targetAst = Option.unless(call.isStatic)(call.target.map(astForExpr)).flatten

    val nameAst =
        Option.unless(call.methodName.isInstanceOf[PhpNameExpr])(astForExpr(call.methodName))
    val name =
        nameAst
            .map(_.rootCodeOrEmpty)
            .getOrElse(call.methodName match
              case nameExpr: PhpNameExpr => nameExpr.name
              case other =>
                  logger.debug(
                    s"Found unexpected call target type: Crash for now to handle properly later: $other"
                  )
                  ???
            )

    // an unpacked argument's own code is `...$xs` and a named one's is its value
    val argsCode = arguments
        .zip(call.args)
        .map {
            case (arg, PhpArg(_, Some(name), _, _, _)) => s"$name: ${arg.rootCodeOrEmpty}"
            case (arg, _)                              => arg.rootCodeOrEmpty
        }
        .mkString(",")

    val codePrefix =
        if !call.isStatic && targetAst.isDefined then
          codeForMethodCall(call, targetAst.get, name)
        else if call.isStatic then
          codeForStaticMethodCall(call, name)
        else
          name

    val code = s"$codePrefix($argsCode)"

    val dispatchType =
        if call.isStatic || call.target.isEmpty then
          DispatchTypes.STATIC_DISPATCH
        else
          DispatchTypes.DYNAMIC_DISPATCH

    val fullName = call.target match
      // Static method call with a known class name
      case Some(nameExpr: PhpNameExpr) if call.isStatic =>
          if nameExpr.name == "self" then composeMethodFullName(name, call.isStatic)
          else s"${nameExpr.name}${StaticMethodDelimiter}$name"

      // an instance call on a receiver whose class is declared: the class's method
      case Some(receiver) if !call.isStatic && receiverClass(call, receiver).isDefined =>
          s"${receiverClass(call, receiver).get}$InstanceMethodDelimiter$name"

      case Some(expr) =>
          s"$UnresolvedNamespace\\$codePrefix"

      case None if PhpBuiltins.FuncNames.contains(name) =>
          // No signature/namespace for MFN for builtin functions to ensure stable names as type info improves.
          name

      // a function the source names absolutely (`\Foo\bar()`, or through `use function`)
      case None if call.absolute => name

      // A function call is named by its namespace alone: a class that calls `helper()` calls the
      // function, never one of its own methods.
      case None if call.methodName.isInstanceOf[PhpNameExpr] => prependNamespacePrefix(name)

      // Function call
      case None =>
          composeMethodFullName(name, call.isStatic)

    // Use method signature for methods that can be linked to avoid varargs issue.
    val signature = s"$UnresolvedSignature(${call.args.size})"
    // `use function Foo\bar` makes the call `bar`, with the function's full name `Foo\bar`
    val callName =
        if call.absolute && call.methodName.isInstanceOf[PhpNameExpr] then
          name.substring(name.lastIndexOf('\\') + 1)
        else name
    val callRoot = callNode(
      call,
      code,
      callName,
      fullName,
      dispatchType,
      Some(signature),
      Some(TypeConstants.Any)
    )

    // A call's own position is where its expression starts, the receiver of a chain; the use of
    // a call named after its receiver's class is the method's name, which a fluent chain writes
    // on a line of its own.
    (call.methodName, call.target) match
      case (name: PhpNameExpr, Some(receiver))
          if !call.isStatic && receiverClass(call, receiver).isDefined =>
          for ln <- name.attributes.lineNumber do
            val tag = NewTag().name(AstCreator.NamePositionTag).value(
              ujson.Obj(
                "line" -> ln.intValue,
                "col"  -> column(name).map(_.intValue).getOrElse(-1)
              ).render()
            )
            diffGraph.addNode(tag)
            diffGraph.addEdge(callRoot, tag, EdgeTypes.TAGGED_BY)
      case _ => ()

    // PHP calls the namespace's function when there is one and the global one otherwise; the
    // global name rides along for the consumer that knows which functions the program declares
    if call.globalFallback && fullName != name then callRoot.dynamicTypeHintFullName(Seq(name))

    val receiverAst = (targetAst, nameAst) match
      case (Some(target), Some(n)) =>
          val fieldAccess =
              newOperatorCallNode(
                Operators.fieldAccess,
                codePrefix,
                line = line(call),
                column = column(call)
              )
          Option(callAst(fieldAccess, target :: n :: Nil))
      case (Some(target), None) => Option(target)
      case (None, Some(n))      => Option(n)
      case (None, None)         => None

    callAst(callRoot, arguments, base = receiverAst)
  end astForCall

  /** A named argument (`f(cmd: $x)`) keeps its position as index and is named after the parameter
    * it binds; an unpacked one (`f(...$xs)`) is an `<operator>.unpack` of the iterable (see
    * ArgumentBinding).
    */
  private def astForCallArg(arg: PhpArgument): Ast =
      arg match
        case PhpArg(expr, parameterName, _, unpack, _) =>
            val valueAst = astForExpr(expr)
            val argAst =
                if unpack then
                  val unpackCall = newOperatorCallNode(
                    PhpOperators.unpack,
                    s"...${valueAst.rootCodeOrEmpty}",
                    line = line(arg),
                    column = column(arg)
                  )
                  callAst(unpackCall, valueAst :: Nil)
                else valueAst
            parameterName.foreach { name =>
                argAst.root.collect { case argument: ExpressionNew =>
                    argument.argumentName = Option(name)
                }
            }
            argAst

        case _: PhpVariadicPlaceholder =>
            val identifier =
                identifierNode(arg, "...", "...", TypeConstants.VariadicPlaceholder)
            Ast(identifier)

  private def astForVariableExpr(variable: PhpVariable): Ast =
    // TODO Need to figure out variable variables. Maybe represent as some kind of call?
    val valueAst = astForExpr(variable.value)

    valueAst.root.collect { case root: ExpressionNew =>
        root.code = s"$$${root.code}"
    }

    valueAst.root.collect { case root: NewIdentifier =>
        root.lineNumber = line(variable)
        root.columnNumber = column(variable)
    }

    valueAst

  private def astForNameExpr(expr: PhpNameExpr): Ast =
    val identifier = identifierNode(expr, expr.name, expr.name, TypeConstants.Any)

    scope.lookupVariable(identifier.name).foreach { declaringNode =>
        diffGraph.addEdge(identifier, declaringNode, EdgeTypes.REF)
    }

    Ast(identifier)

  /** This is used to rewrite the short form $xs[] = <value_expr> as array_push($xs, <value_expr>)
    * to avoid having to handle the empty array access operator as a special case in the dataflow
    * engine.
    *
    * This representation is technically wrong in the case where the shorthand is used to initialise
    * a new array (since PHP expects the first argument to array_push to be an existing array). This
    * shouldn't affect dataflow, however.
    */
  private def astForEmptyArrayDimAssign(
    assignment: PhpAssignment,
    arrayDimFetch: PhpArrayDimFetchExpr
  ): Ast =
    val attrs         = assignment.attributes
    val arrayPushArgs = List(arrayDimFetch.variable, assignment.source).map(PhpArg(_))
    val arrayPushCall = PhpCallExpr(
      target = None,
      methodName = PhpNameExpr("array_push", attrs),
      args = arrayPushArgs,
      isNullSafe = false,
      isStatic = true,
      attributes = attrs
    )
    val arrayPushAst = astForCall(arrayPushCall)
    arrayPushAst.root.collect { case astRoot: NewCall =>
        val args =
            arrayPushAst.argEdges
                .filter(_.src == astRoot)
                .map(_.dst)
                .collect { case arg: ExpressionNew => arg }
                .sortBy(_.argumentIndex)

        if args.size != 2 then
          val position = s"${line(assignment).getOrElse("")}:${filename}"
          logger.debug(
            s"Expected 2 call args for emptyArrayDimAssign. Not resetting code: ${position}"
          )
        else
          val codeOverride = s"${args.head.code}[] = ${args.last.code}"
          astRoot.code(codeOverride)
        tagSynthetic(astRoot)
    }
    arrayPushAst
  end astForEmptyArrayDimAssign

  private def astForAssignment(assignment: PhpAssignment): Ast =
      assignment.target match
        case arrayDimFetch: PhpArrayDimFetchExpr if arrayDimFetch.dimension.isEmpty =>
            // Rewrite `$xs[] = <value_expr>` as `array_push($xs, <value_expr>)` to simplify finding dataflows.
            astForEmptyArrayDimAssign(assignment, arrayDimFetch)

        case _ =>
            val operatorName = assignment.assignOp

            val targetAst = astForExpr(assignment.target)
            val sourceAst = astForExpr(assignment.source)

            // TODO Handle ref assigns properly (if needed).
            val refSymbol = if assignment.isRefAssign then "&" else ""
            val symbol    = operatorSymbols.getOrElse(assignment.assignOp, assignment.assignOp)
            val code =
                s"${targetAst.rootCodeOrEmpty} $symbol $refSymbol${sourceAst.rootCodeOrEmpty}"

            val callNode = newOperatorCallNode(
              operatorName,
              code,
              line = line(assignment),
              column = column(assignment)
            )
            callAst(callNode, List(targetAst, sourceAst))

  private def astForEncapsed(encapsed: PhpEncapsed): Ast =
    val args = encapsed.parts.map(astForExpr)
    val code = args.map(_.rootCodeOrEmpty).mkString(" . ")

    args match
      case singleArg :: Nil => singleArg
      case _ =>
          val callNode = newOperatorCallNode(
            PhpOperators.encaps,
            code,
            Some(TypeConstants.String),
            line(encapsed),
            column = column(encapsed)
          )
          callAst(callNode, args)

  private def astForScalar(scalar: PhpScalar): Ast =
      scalar match
        case encapsed: PhpEncapsed => astForEncapsed(encapsed)
        case simpleScalar: PhpSimpleScalar =>
            Ast(literalNode(scalar, simpleScalar.value, simpleScalar.typeFullName))
        case null =>
            logger.debug("scalar was null")
            ???

  private def astForBinOp(binOp: PhpBinaryOp): Ast =
    val leftAst  = astForExpr(binOp.left)
    val rightAst = astForExpr(binOp.right)

    val symbol = operatorSymbols.getOrElse(binOp.operator, binOp.operator)
    val code   = s"${leftAst.rootCodeOrEmpty} $symbol ${rightAst.rootCodeOrEmpty}"

    val callNode =
        newOperatorCallNode(binOp.operator, code, line = line(binOp), column = column(binOp))

    callAst(callNode, List(leftAst, rightAst))

  private def isPostfixOperator(operator: String): Boolean =
      Set(Operators.postDecrement, Operators.postIncrement).contains(operator)

  private def astForUnaryOp(unaryOp: PhpUnaryOp): Ast =
    val exprAst = astForExpr(unaryOp.expr)

    val symbol = operatorSymbols.getOrElse(unaryOp.operator, unaryOp.operator)
    val code =
        if isPostfixOperator(unaryOp.operator) then
          s"${exprAst.rootCodeOrEmpty}$symbol"
        else
          s"$symbol${exprAst.rootCodeOrEmpty}"

    val callNode = newOperatorCallNode(
      unaryOp.operator,
      code,
      line = line(unaryOp),
      column = column(unaryOp)
    )

    callAst(callNode, exprAst :: Nil)

  private def astForCastExpr(castExpr: PhpCast): Ast =
    val typeFullName = castExpr.typ
    val typ          = typeRefNode(castExpr, typeFullName, typeFullName)

    val expr    = astForExpr(castExpr.expr)
    val codeStr = s"($typeFullName) ${expr.rootCodeOrEmpty}"

    val callNode =
        newOperatorCallNode(
          name = Operators.cast,
          codeStr,
          Some(typeFullName),
          line(castExpr),
          column = column(castExpr)
        )

    callAst(callNode, Ast(typ) :: expr :: Nil)

  private def astForIsSetExpr(isSetExpr: PhpIsset): Ast =
    val name = PhpOperators.issetFunc
    val args = isSetExpr.vars.map(astForExpr)
    val code = s"$name(${args.map(_.rootCodeOrEmpty).mkString(",")})"

    val callNode =
        newOperatorCallNode(
          name,
          code,
          typeFullName = Some(TypeConstants.Bool),
          line = line(isSetExpr),
          column = column(isSetExpr)
        )
            .methodFullName(PhpOperators.issetFunc)

    callAst(callNode, args)
  private def astForPrintExpr(printExpr: PhpPrint): Ast =
    val name = PhpOperators.printFunc
    val arg  = astForExpr(printExpr.expr)
    val code = s"$name(${arg.rootCodeOrEmpty})"

    val callNode =
        newOperatorCallNode(
          name,
          code,
          typeFullName = Some(TypeConstants.Int),
          line = line(printExpr),
          column = column(printExpr)
        )
            .methodFullName(PhpOperators.printFunc)

    callAst(callNode, arg :: Nil)

  private def astForTernaryOp(ternaryOp: PhpTernaryOp): Ast =
    val conditionAst = astForExpr(ternaryOp.condition)
    val maybeThenAst = ternaryOp.thenExpr.map(astForExpr)
    val elseAst      = astForExpr(ternaryOp.elseExpr)

    val operatorName =
        if maybeThenAst.isDefined then Operators.conditional else PhpOperators.elvisOp
    val code = maybeThenAst match
      case Some(thenAst) =>
          s"${conditionAst.rootCodeOrEmpty} ? ${thenAst.rootCodeOrEmpty} : ${elseAst.rootCodeOrEmpty}"
      case None => s"${conditionAst.rootCodeOrEmpty} ?: ${elseAst.rootCodeOrEmpty}"

    val callNode = newOperatorCallNode(
      operatorName,
      code,
      line = line(ternaryOp),
      column = column(ternaryOp)
    )

    val args = List(Option(conditionAst), maybeThenAst, Option(elseAst)).flatten
    callAst(callNode, args)
  end astForTernaryOp

  private def astForThrow(expr: PhpThrowExpr): Ast =
    val thrownExpr = astForExpr(expr.expr)
    val code       = s"throw ${thrownExpr.rootCodeOrEmpty}"

    val throwNode = controlStructureNode(expr, ControlStructureTypes.THROW, code)

    Ast(throwNode).withChild(thrownExpr)

  private def astForClone(expr: PhpCloneExpr): Ast =
    val name    = PhpOperators.cloneFunc
    val argAst  = astForExpr(expr.expr)
    val argType = argAst.rootType.orElse(Some(TypeConstants.Any))
    val code    = s"$name ${argAst.rootCodeOrEmpty}"

    val callNode = newOperatorCallNode(name, code, argType, line(expr), column = column(expr))
        .methodFullName(PhpOperators.cloneFunc)

    callAst(callNode, argAst :: Nil)

  private def astForEmpty(expr: PhpEmptyExpr): Ast =
    val name   = PhpOperators.emptyFunc
    val argAst = astForExpr(expr.expr)
    val code   = s"$name(${argAst.rootCodeOrEmpty})"

    val callNode =
        newOperatorCallNode(
          name,
          code,
          typeFullName = Some(TypeConstants.Bool),
          line = line(expr),
          column = column(expr)
        )
            .methodFullName(PhpOperators.emptyFunc)

    callAst(callNode, argAst :: Nil)

  private def astForEval(expr: PhpEvalExpr): Ast =
    val name   = PhpOperators.evalFunc
    val argAst = astForExpr(expr.expr)
    val code   = s"$name(${argAst.rootCodeOrEmpty})"

    val callNode =
        newOperatorCallNode(
          name,
          code,
          typeFullName = Some(TypeConstants.Bool),
          line = line(expr),
          column = column(expr)
        )
            .methodFullName(PhpOperators.evalFunc)

    callAst(callNode, argAst :: Nil)

  private def astForExit(expr: PhpExitExpr): Ast =
    val name = PhpOperators.exitFunc
    val args = expr.expr.map(astForExpr)
    val code = s"$name(${args.map(_.rootCodeOrEmpty).getOrElse("")})"

    val callNode = newOperatorCallNode(
      name,
      code,
      Some(TypeConstants.Void),
      line(expr),
      column = column(expr)
    )
        .methodFullName(PhpOperators.exitFunc)

    callAst(callNode, args.toList)

  private def getTmpIdentifier(
    originNode: PhpNode,
    maybeTypeFullName: Option[String],
    prefix: String = ""
  ): NewIdentifier =
    val name         = s"$prefix${getNewTmpName()}"
    val typeFullName = maybeTypeFullName.getOrElse(TypeConstants.Any)
    identifierNode(originNode, name, s"$$$name", typeFullName)

  private def astForArrayExpr(expr: PhpArrayExpr): Ast =
    val idxTracker = new ArrayIndexTracker

    val tmpIdentifier = getTmpIdentifier(expr, Some(TypeConstants.Array))

    val itemAssignments = expr.items.flatMap {
        case Some(item) => Option(assignForArrayItem(item, tmpIdentifier.name, idxTracker))
        case None =>
            idxTracker.next // Skip an index
            None
    }
    val arrayBlock = blockNode(expr)

    Ast(arrayBlock)
        .withChildren(itemAssignments)
        .withChild(Ast(tmpIdentifier))

  private def astForListExpr(expr: PhpListExpr): Ast =
    /* TODO: Handling list in a way that will actually work with dataflow tracking is somewhat more complicated than
     *  this and will likely need a fairly ugly lowering.
     *
     * In short, the case:
     *   list($a, $b) = $arr;
     * can be lowered to:
     *   $a = $arr[0];
     *   $b = $arr[1];
     *
     * the case:
     *   list("id" => $a, "name" => $b) = $arr;
     * can be lowered to:
     *   $a = $arr["id"];
     *   $b = $arr["name"];
     *
     * and the case:
     *   foreach ($arr as list($a, $b)) { ... }
     * can be lowered as above for each $arr[i];
     *
     * The below is just a placeholder to prevent crashes while figuring out the cleanest way to
     * implement the above lowering or to think of a better way to do it.
     */

    val name     = PhpOperators.listFunc
    val args     = expr.items.flatten.map { item => astForExpr(item.value) }
    val listCode = s"$name(${args.map(_.rootCodeOrEmpty).mkString(",")})"
    val listNode = newOperatorCallNode(name, listCode, line = line(expr), column = column(expr))
        .methodFullName(PhpOperators.listFunc)

    callAst(listNode, args)
  end astForListExpr

  private def astForNewExpr(expr: PhpNewExpr): Ast =
      expr.className match
        case classLikeStmt: PhpClassLikeStmt =>
            astForAnonymousClassInstantiation(expr, classLikeStmt)

        case classNameExpr: PhpExpr =>
            astForSimpleNewExpr(expr, classNameExpr)

        case other =>
            throw new NotImplementedError(
              s"unexpected expression '$other' of type ${other.getClass}"
            )

  private def astForMatchExpr(expr: PhpMatchExpr): Ast =
    val conditionAst = astForExpr(expr.condition)

    val matchNode = controlStructureNode(
      expr,
      ControlStructureTypes.MATCH,
      s"match (${conditionAst.rootCodeOrEmpty})"
    )

    val matchBodyBlock = blockNode(expr)
    val armsAsts       = expr.matchArms.flatMap(astsForMatchArm)
    val matchBody      = Ast(matchBodyBlock).withChildren(armsAsts)

    controlStructureAst(matchNode, Option(conditionAst), matchBody :: Nil)

  private def astsForMatchArm(matchArm: PhpMatchArm): List[Ast] =
    // TODO Don't just throw away the condition asts here (also for switch cases)
    val targets = matchArm.conditions.map { condition =>
      val conditionAst = astForExpr(condition)
      // In PHP cases aren't labeled with `case`, but this is used by the CFG creator to differentiate between
      // case/default labels and other labels.
      val code = s"case ${conditionAst.rootCode.getOrElse(NameConstants.Unknown)}"
      NewJumpTarget().name(code).code(code).lineNumber(line(condition)).columnNumber(column(
        condition
      ))
    }
    val defaultLabel = Option.when(matchArm.isDefault)(
      NewJumpTarget().name(NameConstants.Default).code(NameConstants.Default).lineNumber(line(
        matchArm
      )).columnNumber(column(matchArm))
    )
    val targetAsts = (targets ++ defaultLabel.toList).map(Ast(_))

    val bodyAst = astForExpr(matchArm.body)

    targetAsts :+ bodyAst
  end astsForMatchArm

  private def astForYieldExpr(expr: PhpYieldExpr): Ast =
    val maybeKey = expr.key.map(astForExpr)
    val maybeVal = expr.value.map(astForExpr)

    val code = (maybeKey, maybeVal) match
      case (Some(key), Some(value)) =>
          s"yield ${key.rootCodeOrEmpty} => ${value.rootCodeOrEmpty}"

      case _ =>
          s"yield ${maybeKey.map(_.rootCodeOrEmpty)
                  .getOrElse("")}${maybeVal.map(_.rootCodeOrEmpty).getOrElse("")}".trim

    val yieldNode = controlStructureNode(expr, ControlStructureTypes.YIELD, code)

    Ast(yieldNode)
        .withChildren(maybeKey.toList)
        .withChildren(maybeVal.toList)

  private def astForClosureExpr(closureExpr: PhpClosureExpr): Ast =
    val methodName = scope.getScopedClosureName
    val methodRef  = methodRefNode(closureExpr, methodName, methodName, TypeConstants.Any)

    val localsForUses = closureExpr.uses.flatMap { closureUse =>
      val variableAst = astForExpr(closureUse.variable)
      val codePref    = if closureUse.byRef then "&" else ""

      variableAst.root match
        case Some(identifier: NewIdentifier) =>
            // This is the expected case and is handled well
            Some(localNode(
              closureExpr,
              identifier.name,
              codePref ++ identifier.code,
              TypeConstants.Any
            ))
        case Some(expr: ExpressionNew) =>
            // Results here may be bad, but its' the best we're likely to do
            Some(localNode(
              closureExpr,
              expr.code,
              codePref ++ expr.code,
              TypeConstants.Any
            ))
        case Some(other) =>
            // This should never happen
            logger.debug(s"Found ast '$other' for closure use in $filename")
            None
        case None =>
            // This should never happen
            logger.debug(s"Found empty ast for closure use in $filename")
            None
      end match
    }

    // Add closure bindings to diffgraph
    localsForUses.foreach { local =>
      val closureBindingId = s"$filename:$methodName:${local.name}"
      local.closureBindingId(closureBindingId)
      scope.addToScope(local.name, local)

      val closureBindingNode = NewClosureBinding()
          .closureBindingId(closureBindingId)
          .closureOriginalName(local.name)
          .evaluationStrategy(EvaluationStrategies.BY_SHARING)

      // The ref edge to the captured local is added in the ClosureRefPass
      diffGraph.addNode(closureBindingNode)
      diffGraph.addEdge(methodRef, closureBindingNode, EdgeTypes.CAPTURE)
    }

    // Create method for closure
    val name = PhpNameExpr(methodName, closureExpr.attributes)
    // TODO Check for static modifier
    val modifiers =
        "LAMBDA" :: (if closureExpr.isStatic then ModifierTypes.STATIC :: Nil else Nil)
    val methodDecl = PhpMethodDecl(
      name,
      closureExpr.params,
      modifiers,
      closureExpr.returnType,
      closureExpr.stmts,
      closureExpr.returnByRef,
      namespacedName = None,
      isClassMethod = closureExpr.isStatic,
      attributes = closureExpr.attributes
    )
    // a closure sees its by-value captures, an arrow function the whole enclosing scope
    val inherited =
        if closureExpr.isArrowFunc then variableTypes
        else
          val captured = closureExpr.uses.filterNot(_.byRef).collect {
              case PhpClosureUse(PhpVariable(PhpNameExpr(name, _, _), _), _, _) => name
          }.toSet
          variableTypes.filter((name, _) => captured.contains(name))
    val methodAst = astForMethodDecl(
      methodDecl,
      localsForUses.map(Ast(_)),
      Option(methodName),
      inheritedTypes = inherited
    )

    val usesCode = localsForUses match
      case Nil    => ""
      case locals => s" use(${locals.map(_.code).mkString(", ")})"
    methodAst.root.collect { case method: NewMethod => method }.foreach { methodNode =>
        methodNode.code(methodNode.code ++ usesCode)
    }

    // Add method to scope to be attached to typeDecl later
    scope.addAnonymousMethod(methodAst)

    Ast(methodRef)
  end astForClosureExpr

  private def astForYieldFromExpr(expr: PhpYieldFromExpr): Ast =
    // TODO This is currently only distinguishable from yield by the code field. Decide whether to treat YIELD_FROM
    //  separately or whether to lower this to a foreach with regular yields.
    val exprAst = astForExpr(expr.expr)

    val code = s"yield from ${exprAst.rootCodeOrEmpty}"

    val yieldNode = controlStructureNode(expr, ControlStructureTypes.YIELD, code)

    Ast(yieldNode)
        .withChild(exprAst)

  /** `new class(...) extends B { ... }`: a type declaration of its own, named after its position
    * (PHP names it `class@anonymous` and the file position), hung under the enclosing class like a
    * closure's method, and the `new` of that class with the arguments written.
    */
  private def astForAnonymousClassInstantiation(
    expr: PhpNewExpr,
    classLikeStmt: PhpClassLikeStmt
  ): Ast =
    val position = classLikeStmt.attributes.columnNumber.map(_.intValue).getOrElse(0) // file offset
    val name     = PhpNameExpr(s"class@anonymous#$position", classLikeStmt.attributes)
    val pending  = scope.getAndClearAnonymousMethods
    val typeDeclAst = astForNamedClass(classLikeStmt, name)
    pending.foreach(scope.addAnonymousMethod)
    scope.addAnonymousMethod(typeDeclAst)
    astForSimpleNewExpr(expr, PhpNameExpr(prependNamespacePrefix(name.name), expr.attributes))

  private def astForSimpleNewExpr(expr: PhpNewExpr, classNameExpr: PhpExpr): Ast =
    val (maybeNameAst, className) = classNameExpr match
      case nameExpr: PhpNameExpr =>
          (None, nameExpr.name)

      case expr: PhpExpr =>
          val ast = astForExpr(expr)
          // The name doesn't make sense in this case, but the AST will be more useful
          val name = ast.rootCode.getOrElse(NameConstants.Unknown)
          (Option(ast), name)

    val tmpIdentifier = getTmpIdentifier(expr, Option(className))

    // Alloc assign
    val allocCode = s"$className.<alloc>()"
    val allocNode =
        newOperatorCallNode(
          Operators.alloc,
          allocCode,
          Option(className),
          line(expr),
          column = column(expr)
        )
    val allocAst        = callAst(allocNode, base = maybeNameAst)
    val allocAssignCode = s"${tmpIdentifier.code} = ${allocAst.rootCodeOrEmpty}"
    val allocAssignNode = newOperatorCallNode(
      Operators.assignment,
      allocAssignCode,
      Option(className),
      line(expr),
      column = column(expr)
    )
    val allocAssignAst = callAst(allocAssignNode, Ast(tmpIdentifier) :: allocAst :: Nil)

    // Init node
    val initArgs      = expr.args.map(astForCallArg)
    val initSignature = s"$UnresolvedSignature(${initArgs.size})"
    val initFullName  = s"$className$InstanceMethodDelimiter${ConstructorMethodName}"
    val initCode      = s"$initFullName(${initArgs.map(_.rootCodeOrEmpty).mkString(",")})"
    val initCallNode = callNode(
      expr,
      initCode,
      ConstructorMethodName,
      initFullName,
      DispatchTypes.DYNAMIC_DISPATCH,
      Some(initSignature),
      Some(TypeConstants.Any)
    )
    classNameExpr match
      case name: PhpNameExpr =>
          // the use of the class is its name, not the `new` before it
          name.attributes.lineNumber.foreach { ln =>
            initCallNode.lineNumber(ln)
            initCallNode.columnNumber(column(name))
          }
      case _ => ()
    val initReceiver = Ast(tmpIdentifier.copy)
    val initCallAst  = callAst(initCallNode, initArgs, base = Option(initReceiver))

    // Return identifier
    val returnIdentifierAst = Ast(tmpIdentifier.copy)

    Ast(blockNode(expr, "", TypeConstants.Any))
        .withChild(allocAssignAst)
        .withChild(initCallAst)
        .withChild(returnIdentifierAst)
  end astForSimpleNewExpr

  private def dimensionFromSimpleScalar(
    scalar: PhpSimpleScalar,
    idxTracker: ArrayIndexTracker
  ): PhpExpr =
    val maybeIntValue = scalar match
      case string: PhpString =>
          string.value
              .drop(1)
              .dropRight(1)
              .toIntOption

      case number => number.value.toIntOption

    maybeIntValue match
      case Some(intValue) =>
          idxTracker.updateValue(intValue)
          PhpInt(intValue.toString, scalar.attributes)

      case None =>
          scalar
  end dimensionFromSimpleScalar
  private def assignForArrayItem(
    item: PhpArrayItem,
    name: String,
    idxTracker: ArrayIndexTracker
  ): Ast =
    // It's perhaps a bit clumsy to reconstruct PhpExpr nodes here, but reuse astForArrayDimExpr for consistency
    val variable = PhpVariable(PhpNameExpr(name, item.attributes), item.attributes)

    val dimension = item.key match
      case Some(key: PhpSimpleScalar) => dimensionFromSimpleScalar(key, idxTracker)
      case Some(key)                  => key
      case None                       => PhpInt(idxTracker.next, item.attributes)

    val dimFetchNode = PhpArrayDimFetchExpr(variable, Option(dimension), item.attributes)
    val dimFetchAst  = astForArrayDimFetchExpr(dimFetchNode)

    val valueAst = astForArrayItemValue(item)

    val assignCode = s"${dimFetchAst.rootCodeOrEmpty} = ${valueAst.rootCodeOrEmpty}"

    val assignNode = newOperatorCallNode(
      Operators.assignment,
      assignCode,
      line = line(item),
      column = column(item)
    )

    callAst(assignNode, dimFetchAst :: valueAst :: Nil)
  end assignForArrayItem

  private def astForArrayItemValue(item: PhpArrayItem): Ast =
    val exprAst   = astForExpr(item.value)
    val valueCode = exprAst.rootCodeOrEmpty

    if item.byRef then
      val parentCall =
          newOperatorCallNode(
            Operators.addressOf,
            s"&$valueCode",
            line = line(item),
            column = column(item)
          )
      callAst(parentCall, exprAst :: Nil)
    else if item.unpack then
      val parentCall =
          newOperatorCallNode(
            PhpOperators.unpack,
            s"...$valueCode",
            line = line(item),
            column = column(item)
          )
      callAst(parentCall, exprAst :: Nil)
    else
      exprAst
    end if
  end astForArrayItemValue

  private def astForArrayDimFetchExpr(expr: PhpArrayDimFetchExpr): Ast =
    val variableAst  = astForExpr(expr.variable)
    val variableCode = variableAst.rootCodeOrEmpty

    expr.dimension match
      case Some(dimension) =>
          val dimensionAst = astForExpr(dimension)
          val code         = s"$variableCode[${dimensionAst.rootCodeOrEmpty}]"
          val accessNode = newOperatorCallNode(
            Operators.indexAccess,
            code,
            line = line(expr),
            column = column(expr)
          )
          callAst(accessNode, variableAst :: dimensionAst :: Nil)

      case None =>
          val errorPosition = s"${variableCode}:${line(expr).getOrElse("")}:${filename}"
          logger.debug(
            s"ArrayDimFetchExpr without dimensions should be handled in assignment: ${errorPosition}"
          )
          Ast()
  end astForArrayDimFetchExpr

  private def astForErrorSuppressExpr(expr: PhpErrorSuppressExpr): Ast =
    val childAst = astForExpr(expr.expr)

    val code = s"@${childAst.rootCodeOrEmpty}"
    val suppressNode = newOperatorCallNode(
      PhpOperators.errorSuppress,
      code,
      line = line(expr),
      column = column(expr)
    )
    childAst.rootType.foreach(typ => suppressNode.typeFullName(typ))

    callAst(suppressNode, childAst :: Nil)

  private def astForInstanceOfExpr(expr: PhpInstanceOfExpr): Ast =
    val exprAst  = astForExpr(expr.expr)
    val classAst = astForClassNameRef(expr.className)

    val code = s"${exprAst.rootCodeOrEmpty} instanceof ${classAst.rootCodeOrEmpty}"
    val instanceOfNode =
        newOperatorCallNode(
          Operators.instanceOf,
          code,
          Some(TypeConstants.Bool),
          line(expr),
          column = column(expr)
        )

    callAst(instanceOfNode, exprAst :: classAst :: Nil)

  private def astForPropertyFetchExpr(expr: PhpPropertyFetchExpr): Ast =
    val objExprAst =
        if expr.isStatic then astForClassNameRef(expr.expr) else astForExpr(expr.expr)

    val fieldAst = expr.name match
      case name: PhpNameExpr =>
          Ast(newFieldIdentifierNode(name.name, line(expr), column = column(expr)))
      case other => astForExpr(other)

    val accessSymbol =
        if expr.isStatic then
          "::"
        else if expr.isNullsafe then
          "?->"
        else
          "->"

    val code = s"${objExprAst.rootCodeOrEmpty}$accessSymbol${fieldAst.rootCodeOrEmpty}"
    val fieldAccessNode = newOperatorCallNode(
      Operators.fieldAccess,
      code,
      line = line(expr),
      column = column(expr)
    )

    callAst(fieldAccessNode, objExprAst :: fieldAst :: Nil)
  end astForPropertyFetchExpr

  private def astForIncludeExpr(expr: PhpIncludeExpr): Ast =
    val exprAst = astForExpr(expr.expr)
    val code    = s"${expr.includeType} ${exprAst.rootCodeOrEmpty}"
    val callNode =
        newOperatorCallNode(expr.includeType, code, line = line(expr), column = column(expr))

    callAst(callNode, exprAst :: Nil)

  private def astForShellExecExpr(expr: PhpShellExecExpr): Ast =
    val args = astForEncapsed(expr.parts)
    val code = "`" + args.rootCodeOrEmpty + "`"

    val callNode = newOperatorCallNode(
      PhpOperators.shellExec,
      code,
      line = line(expr),
      column = column(expr)
    )

    callAst(callNode, args :: Nil)

  private def astForMagicClassConstant(expr: PhpClassConstFetchExpr): Ast =
    val classAst = astForExpr(expr.className)
    val typeFullName = expr.className match
      case nameExpr: PhpNameExpr =>
          scope
              .lookupVariable(nameExpr.name)
              .flatMap(_.properties.get(PropertyNames.TYPE_FULL_NAME).map(_.toString))
              .getOrElse(nameExpr.name)

      case expr =>
          classAst.rootType.orElse(classAst.rootName).getOrElse(UnresolvedNamespace)

    Ast(typeRefNode(expr, classAst.rootCodeOrEmpty, typeFullName))

  private def astForClassConstFetchExpr(expr: PhpClassConstFetchExpr): Ast =
      expr.constantName match
        // Foo::class should be a TypeRef and not a field access
        case Some(constNameExpr) if constNameExpr.name == NameConstants.Class =>
            astForMagicClassConstant(expr)

        case _ =>
            val targetAst = astForClassNameRef(expr.className)
            val fieldIdentifierName =
                expr.constantName.map(_.name).getOrElse(NameConstants.Unknown)
            val fieldIdentifier =
                newFieldIdentifierNode(fieldIdentifierName, line(expr), column = column(expr))
            val fieldAccessCode = s"${targetAst.rootCodeOrEmpty}::${fieldIdentifier.code}"
            val fieldAccessCall =
                newOperatorCallNode(
                  Operators.fieldAccess,
                  fieldAccessCode,
                  line = line(expr),
                  column = column(expr)
                )
            callAst(fieldAccessCall, List(targetAst, Ast(fieldIdentifier)))

  private def astForConstFetchExpr(expr: PhpConstFetchExpr): Ast =
    val constName = expr.name.name

    if NameConstants.isBoolean(constName) then
      Ast(literalNode(expr, constName, TypeConstants.Bool))
    else if NameConstants.isNull(constName) then
      Ast(literalNode(expr, constName, TypeConstants.NullType))
    else
      val namespaceName = NamespaceTraversal.globalNamespaceName
      val identifier    = identifierNode(expr, namespaceName, namespaceName, "ANY")
      val fieldIdentifier =
          newFieldIdentifierNode(constName, line = line(expr), column = column(expr))

      val fieldAccessNode =
          newOperatorCallNode(
            Operators.fieldAccess,
            code = constName,
            line = line(expr),
            column = column(expr)
          )
      val args = List(identifier, fieldIdentifier).map(Ast(_))

      callAst(fieldAccessNode, args)
    end if
  end astForConstFetchExpr

  protected def line(phpNode: PhpNode): Option[Integer] = phpNode.attributes.lineNumber
  protected def column(phpNode: PhpNode): Option[Integer] =
      phpNode.attributes.columnNumber.map(pos => Integer.valueOf(columnOf(pos.intValue)))

  /** The parser positions a node by its byte offset in the file; the column is the offset from the
    * start of the node's line. Without the file's line starts the offset stays as it is.
    */
  private def columnOf(offset: Int): Int =
      if lineStarts.isEmpty then offset
      else
        val found = java.util.Arrays.binarySearch(lineStarts, offset)
        val index = if found >= 0 then found else -found - 2
        offset - lineStarts(math.max(index, 0))

  protected def lineEnd(phpNode: PhpNode): Option[Integer]   = None
  protected def columnEnd(phpNode: PhpNode): Option[Integer] = None
  protected def code(phpNode: PhpNode): String =
      "" // Sadly, the Php AST does not carry any code fields
end AstCreator

object AstCreator:
  /** The byte offsets at which each line of a file starts, the first being 0. */
  def lineStartsOf(path: String): Array[Int] =
      scala.util.Try {
          val bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path))
          (0 +: bytes.indices.collect { case i if bytes(i) == '\n'.toByte => i + 1 }).toArray
      }.getOrElse(Array.empty)

  /** The tag that carries a written class name with its position (see `tagWrittenNames`). */
  val WrittenNameTag: String = "callsites-type"

  /** The tag on an instance call named after its receiver's class, with the method name's own
    * position.
    */
  val NamePositionTag: String = "callsites-name"

  /** The tag on a call the frontend synthesizes (see `tagSynthetic`). */
  val SyntheticCallTag: String = "callsites-synthetic"

  object TypeConstants:
    val String: String              = "string"
    val Int: String                 = "int"
    val Float: String               = "float"
    val Bool: String                = "bool"
    val Void: String                = "void"
    val Any: String                 = "ANY"
    val Array: String               = "array"
    val NullType: String            = "null"
    val VariadicPlaceholder: String = "PhpVariadicPlaceholder"

  object NameConstants:
    val Default: String      = "default"
    val HaltCompiler: String = "__halt_compiler"
    val This: String         = "this"
    val Unknown: String      = "UNKNOWN"
    val Closure: String      = "__closure"
    val Class: String        = "class"
    val True: String         = "true";
    val False: String        = "false";
    val NullName: String     = "null";

    def isBoolean(name: String): Boolean =
        List(True, False).contains(name)

    def isNull(name: String): Boolean =
        name.toLowerCase == NullName

  val operatorSymbols: Map[String, String] = Map(
    Operators.and                            -> "&",
    Operators.or                             -> "|",
    Operators.xor                            -> "^",
    Operators.logicalAnd                     -> "&&",
    Operators.logicalOr                      -> "||",
    PhpOperators.coalesceOp                  -> "??",
    PhpOperators.concatOp                    -> ".",
    Operators.division                       -> "/",
    Operators.equals                         -> "==",
    Operators.greaterEqualsThan              -> ">=",
    Operators.greaterThan                    -> ">",
    PhpOperators.identicalOp                 -> "===",
    PhpOperators.logicalXorOp                -> "xor",
    Operators.minus                          -> "-",
    Operators.modulo                         -> "%",
    Operators.multiplication                 -> "*",
    Operators.notEquals                      -> "!=",
    PhpOperators.notIdenticalOp              -> "!==",
    Operators.plus                           -> "+",
    Operators.exponentiation                 -> "**",
    Operators.shiftLeft                      -> "<<",
    Operators.arithmeticShiftRight           -> ">>",
    Operators.lessEqualsThan                 -> "<=",
    Operators.lessThan                       -> "<",
    PhpOperators.spaceshipOp                 -> "<=>",
    Operators.not                            -> "~",
    Operators.logicalNot                     -> "!",
    Operators.postDecrement                  -> "--",
    Operators.postIncrement                  -> "++",
    Operators.preDecrement                   -> "--",
    Operators.preIncrement                   -> "++",
    Operators.minus                          -> "-",
    Operators.plus                           -> "+",
    Operators.assignment                     -> "=",
    Operators.assignmentAnd                  -> "&=",
    Operators.assignmentOr                   -> "|=",
    Operators.assignmentXor                  -> "^=",
    PhpOperators.assignmentCoalesceOp        -> "??=",
    PhpOperators.assignmentConcatOp          -> ".=",
    Operators.assignmentDivision             -> "/=",
    Operators.assignmentMinus                -> "-=",
    Operators.assignmentModulo               -> "%=",
    Operators.assignmentMultiplication       -> "*=",
    Operators.assignmentPlus                 -> "+=",
    Operators.assignmentExponentiation       -> "**=",
    Operators.assignmentShiftLeft            -> "<<=",
    Operators.assignmentArithmeticShiftRight -> ">>="
  )
end AstCreator
