package io.appthreat.javasrc2cpg.passes

import com.github.javaparser.ast.`type`.TypeParameter
import com.github.javaparser.ast.{CompilationUnit, Node, NodeList, PackageDeclaration}
import com.github.javaparser.ast.body.{
    AnnotationDeclaration,
    BodyDeclaration,
    CallableDeclaration,
    ClassOrInterfaceDeclaration,
    ConstructorDeclaration,
    EnumConstantDeclaration,
    FieldDeclaration,
    InitializerDeclaration,
    MethodDeclaration,
    Parameter,
    RecordDeclaration,
    TypeDeclaration,
    VariableDeclarator
}
import com.github.javaparser.ast.expr.AssignExpr.Operator
import com.github.javaparser.ast.expr.{
    AnnotationExpr,
    ArrayAccessExpr,
    ArrayCreationExpr,
    ArrayInitializerExpr,
    AssignExpr,
    BinaryExpr,
    BooleanLiteralExpr,
    CastExpr,
    CharLiteralExpr,
    ClassExpr,
    ConditionalExpr,
    DoubleLiteralExpr,
    EnclosedExpr,
    Expression,
    FieldAccessExpr,
    InstanceOfExpr,
    IntegerLiteralExpr,
    LambdaExpr,
    LiteralExpr,
    LongLiteralExpr,
    MarkerAnnotationExpr,
    MethodCallExpr,
    MethodReferenceExpr,
    NameExpr,
    NormalAnnotationExpr,
    NullLiteralExpr,
    ObjectCreationExpr,
    PatternExpr,
    RecordPatternExpr,
    SingleMemberAnnotationExpr,
    StringLiteralExpr,
    SuperExpr,
    SwitchExpr,
    TextBlockLiteralExpr,
    ThisExpr,
    TypePatternExpr,
    UnaryExpr,
    VariableDeclarationExpr
}
import com.github.javaparser.ast.nodeTypes.{NodeWithName, NodeWithSimpleName}
import com.github.javaparser.ast.stmt.{
    AssertStmt,
    BlockStmt,
    BreakStmt,
    CatchClause,
    ContinueStmt,
    DoStmt,
    EmptyStmt,
    ExplicitConstructorInvocationStmt,
    ExpressionStmt,
    ForEachStmt,
    ForStmt,
    IfStmt,
    LabeledStmt,
    LocalClassDeclarationStmt,
    LocalRecordDeclarationStmt,
    ReturnStmt,
    Statement,
    SwitchEntry,
    SwitchStmt,
    SynchronizedStmt,
    ThrowStmt,
    TryStmt,
    WhileStmt,
    YieldStmt
}
import com.github.javaparser.resolution.UnsolvedSymbolException
import com.github.javaparser.resolution.declarations.{
    ResolvedFieldDeclaration,
    ResolvedMethodDeclaration,
    ResolvedMethodLikeDeclaration,
    ResolvedReferenceTypeDeclaration,
    ResolvedTypeParameterDeclaration
}
import com.github.javaparser.resolution.types.parametrization.ResolvedTypeParametersMap
import com.github.javaparser.resolution.types.{
    ResolvedReferenceType,
    ResolvedType,
    ResolvedTypeVariable
}
import com.github.javaparser.symbolsolver.JavaSymbolSolver
import io.appthreat.javasrc2cpg.typesolvers.TypeInfoCalculator.{
    ObjectMethodSignatures,
    TypeConstants
}
import io.appthreat.javasrc2cpg.util.BindingTable.createBindingTable
import io.appthreat.x2cpg.utils.NodeBuilders.{
    newAnnotationLiteralNode,
    newBindingNode,
    newCallNode,
    newClosureBindingNode,
    newFieldIdentifierNode,
    newIdentifierNode,
    newMethodReturnNode,
    newModifierNode,
    newOperatorCallNode
}
import io.appthreat.javasrc2cpg.scope.Scope.*
import io.appthreat.javasrc2cpg.util.{
    BindingTable,
    BindingTableAdapterForJavaparser,
    BindingTableAdapterForLambdas,
    BindingTableEntry,
    LambdaBindingInfo,
    NameConstants
}
import io.appthreat.javasrc2cpg.typesolvers.TypeInfoCalculator.{
    ObjectMethodSignatures,
    TypeConstants
}
import io.appthreat.javasrc2cpg.util.Util.{
    composeMethodFullName,
    composeMethodLikeSignature,
    composeUnresolvedSignature
}
import io.appthreat.x2cpg.Defines.*
import io.shiftleft.codepropertygraph.generated.{
    ControlStructureTypes,
    DispatchTypes,
    EdgeTypes,
    EvaluationStrategies,
    ModifierTypes,
    NodeTypes,
    Operators
}
import io.shiftleft.codepropertygraph.generated.nodes.{
    AstNodeNew,
    NewAnnotation,
    NewArrayInitializer,
    NewBlock,
    NewCall,
    NewClosureBinding,
    NewControlStructure,
    NewFieldIdentifier,
    NewIdentifier,
    NewImport,
    NewJumpTarget,
    NewLiteral,
    NewLocal,
    NewMember,
    NewMethod,
    NewMethodParameterIn,
    NewMethodRef,
    NewMethodReturn,
    NewModifier,
    NewNamespaceBlock,
    NewNode,
    NewReturn,
    NewTypeDecl,
    NewTypeRef
}
import io.appthreat.x2cpg.{Ast, AstCreatorBase, Defines, ValidationMode}
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.passes.frontend.TypeNodePass
import io.appthreat.x2cpg.utils.AstPropertiesUtil.*
import io.appthreat.x2cpg.utils.NodeBuilders
import io.appthreat.x2cpg.AstNodeBuilder
import io.shiftleft.codepropertygraph.generated.nodes.AstNode.PropertyDefaults
import io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn.PropertyDefaults as ParameterDefaults
import io.shiftleft.passes.IntervalKeyPool
import org.slf4j.LoggerFactory
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.jdk.OptionConverters.RichOptional
import scala.language.{existentials, implicitConversions}
import scala.util.{Failure, Success, Try}
import com.github.javaparser.ast.stmt.LocalClassDeclarationStmt
import io.appthreat.javasrc2cpg.passes
import io.appthreat.javasrc2cpg.scope.{NodeTypeInfo, Scope}
import io.appthreat.javasrc2cpg.scope.Scope.ScopeVariable
import io.appthreat.javasrc2cpg.typesolvers.TypeInfoCalculator
import io.appthreat.javasrc2cpg.util.{
    BindingTable,
    BindingTableAdapterForJavaparser,
    BindingTableAdapterForLambdas,
    BindingTableEntry,
    LambdaBindingInfo,
    NameConstants
}
import io.appthreat.x2cpg.Defines.StaticInitMethodName
import io.shiftleft.codepropertygraph.generated.nodes.NewTypeParameter

case class ClosureBindingEntry(node: ScopeVariable, binding: NewClosureBinding)

case class LambdaImplementedInfo(
  implementedInterface: Option[ResolvedReferenceType],
  implementedMethod: Option[ResolvedMethodDeclaration]
)

case class PartialConstructor(initNode: NewCall, initArgs: Seq[Ast], blockAst: Ast)

case class ExpectedType(fullName: Option[String], resolvedType: Option[ResolvedType] = None)
object ExpectedType:
  def empty: ExpectedType   = ExpectedType(None, None)
  val Int: ExpectedType     = ExpectedType(Some(TypeConstants.Int))
  val Boolean: ExpectedType = ExpectedType(Some(TypeConstants.Boolean))
  val Void: ExpectedType    = ExpectedType(Some(TypeConstants.Void))

case class AstWithStaticInit(ast: Seq[Ast], staticInits: Seq[Ast])

object AstWithStaticInit:
  val empty: AstWithStaticInit = AstWithStaticInit(Seq.empty, Seq.empty)

  def apply(ast: Ast): AstWithStaticInit =
      AstWithStaticInit(Seq(ast), staticInits = Seq.empty)

/** Translate a Java Parser AST into a CPG AST
  */
class AstCreator(
  filename: String,
  javaParserAst: CompilationUnit,
  global: Global,
  symbolSolver: JavaSymbolSolver,
  packagesJarMappings: mutable.Map[String, mutable.Set[String]]
)(implicit withSchemaValidation: ValidationMode)
    extends AstCreatorBase(filename)
    with AstNodeBuilder[Node, AstCreator]:

  private val logger = LoggerFactory.getLogger(this.getClass)

  private val scope = Scope()

  private val typeInfoCalc: TypeInfoCalculator = TypeInfoCalculator(global, symbolSolver)
  private val partialConstructorQueue: mutable.ArrayBuffer[PartialConstructor] =
      mutable.ArrayBuffer.empty
  private val bindingTableCache = mutable.HashMap.empty[String, BindingTable]

  // TODO: Perhaps move this to a NameProvider or some such? Look at kt2cpg to see if some unified representation
  // makes sense.
  private val LambdaNamePrefix   = "lambda$"
  private val lambdaKeyPool      = new IntervalKeyPool(first = 0, last = Long.MaxValue)
  private val IndexNamePrefix    = "$idx"
  private val indexKeyPool       = new IntervalKeyPool(first = 0, last = Long.MaxValue)
  private val IterableNamePrefix = "$iterLocal"
  private val iterableKeyPool    = new IntervalKeyPool(first = 0, last = Long.MaxValue)

  /** Entry point of AST creation. Translates a compilation unit created by JavaParser into a
    * DiffGraph containing the corresponding CPG AST.
    */
  def createAst(): DiffGraphBuilder =
    val ast = astForTranslationUnit(javaParserAst)
    storeInDiffGraph(ast)
    diffGraph

  /** Copy nodes/edges of given `AST` into the diff graph
    */
  def storeInDiffGraph(ast: Ast): Unit =
      Ast.storeInDiffGraph(ast, diffGraph)

  protected def line(node: Node): Option[Integer] =
      node.getBegin.map(x => Integer.valueOf(x.line)).toScala
  protected def column(node: Node): Option[Integer] =
      node.getBegin.map(x => Integer.valueOf(x.column)).toScala
  protected def lineEnd(node: Node): Option[Integer] =
      node.getEnd.map(x => Integer.valueOf(x.line)).toScala
  protected def columnEnd(node: Node): Option[Integer] =
      node.getEnd.map(x => Integer.valueOf(x.line)).toScala
  protected def code(node: Node): String = ""

  // TODO: Handle static imports correctly.
  private def addImportsToScope(compilationUnit: CompilationUnit): Seq[NewImport] =
    val (asteriskImports, specificImports) =
        compilationUnit.getImports.asScala.toList.partition(_.isAsterisk)
    val specificImportNodes = specificImports.map { importStmt =>
      val name         = importStmt.getName.getIdentifier
      val typeFullName = importStmt.getNameAsString // fully qualified name
      typeInfoCalc.registerType(typeFullName)
      val importNode = NewImport()
          .importedAs(name)
          .importedEntity(typeFullName)

      if importStmt.isStatic then
        scope.addStaticImport(importNode)
      else
        scope.addType(name, typeFullName)
      importNode
    }

    val asteriskImportNodes = asteriskImports match
      case imp :: Nil =>
          val name         = NameConstants.WildcardImportName
          val typeFullName = imp.getNameAsString
          val importNode = NewImport()
              .importedAs(name)
              .importedEntity(typeFullName)
              .isWildcard(true)
          scope.addWildcardImport(typeFullName)
          Seq(importNode)
      case _ => // Only try to guess a wildcard import if exactly one is defined
          Seq.empty
    specificImportNodes ++ asteriskImportNodes
  end addImportsToScope

  /** Translate compilation unit into AST
    */
  private def astForTranslationUnit(compilationUnit: CompilationUnit): Ast =
      try
        val namespaceBlock =
            namespaceBlockForPackageDecl(compilationUnit.getPackageDeclaration.toScala)

        scope.pushNamespaceScope(namespaceBlock)

        val importNodes = addImportsToScope(compilationUnit).map(Ast(_))

        val typeDeclAsts = compilationUnit.getTypes.asScala.map { typ =>
            astForTypeDecl(
              typ,
              astParentType = NodeTypes.NAMESPACE_BLOCK,
              astParentFullName = namespaceBlock.fullName
            )
        }

        // TODO: Add ASTs
        scope.popScope()
        Ast(namespaceBlock).withChildren(typeDeclAsts).withChildren(importNodes)
      catch
        case t: UnsolvedSymbolException =>
            Ast()
        case t: Throwable =>
            Ast()

  /** Translate package declaration into AST consisting of a corresponding namespace block.
    */
  private def namespaceBlockForPackageDecl(packageDecl: Option[PackageDeclaration])
    : NewNamespaceBlock =
      packageDecl match
        case Some(decl) =>
            val packageName = decl.getName.toString
            val fullName    = s"$filename:$packageName"
            NewNamespaceBlock()
                .name(packageName)
                .fullName(fullName)
                .filename(filename)
        case None =>
            globalNamespaceBlock()

  private def tryWithSafeStackOverflow[T](expr: => T): Try[T] =
      try
        Try(expr)
      catch
        // This is really, really ugly, but there's a bug in the JavaParser symbol solver that can lead to
        // unterminated recursion in some cases where types cannot be resolved.
        // Update: This must be fixed with https://github.com/javaparser/javaparser/pull/4236
        case e: StackOverflowError =>
            Failure(e)

  private def composeSignature(
    maybeReturnType: Option[String],
    maybeParameterTypes: Option[List[String]],
    parameterCount: Int
  ): String =
      (maybeReturnType, maybeParameterTypes) match
        case (Some(returnType), Some(parameterTypes)) =>
            composeMethodLikeSignature(returnType, parameterTypes)

        case _ =>
            composeUnresolvedSignature(parameterCount)

  private def methodSignature(
    method: ResolvedMethodDeclaration,
    typeParamValues: ResolvedTypeParametersMap
  ): String =
    val maybeParameterTypes = calcParameterTypes(method, typeParamValues)

    val maybeReturnType =
        Try(method.getReturnType).toOption
            .flatMap(returnType => typeInfoCalc.fullName(returnType, typeParamValues))

    composeSignature(maybeReturnType, maybeParameterTypes, method.getNumberOfParams)

  private def toOptionList[T](items: collection.Seq[Option[T]]): Option[List[T]] =
      items.foldLeft[Option[List[T]]](Some(Nil)) {
          case (Some(acc), Some(value)) => Some(acc :+ value)
          case _                        => None
      }

  private def calcParameterTypes(
    methodLike: ResolvedMethodLikeDeclaration,
    typeParamValues: ResolvedTypeParametersMap
  ): Option[List[String]] =
    val parameterTypes =
        Range(0, methodLike.getNumberOfParams)
            .flatMap { index =>
                Try(methodLike.getParam(index)).toOption
            }
            .map { param =>
                Try(param.getType).toOption
                    .flatMap(paramType => typeInfoCalc.fullName(paramType, typeParamValues))
            }

    toOptionList(parameterTypes)

  def getBindingTable(typeDecl: ResolvedReferenceTypeDeclaration): BindingTable =
    val fullName = typeInfoCalc.fullName(typeDecl).getOrElse {
        val qualifiedName = typeDecl.getQualifiedName
        qualifiedName
    }
    bindingTableCache.getOrElseUpdate(
      fullName,
      createBindingTable(
        fullName,
        typeDecl,
        getBindingTable,
        new BindingTableAdapterForJavaparser(methodSignature)
      )
    )

  private def getLambdaBindingTable(lambdaBindingInfo: LambdaBindingInfo): BindingTable =
    val fullName = lambdaBindingInfo.fullName

    bindingTableCache.getOrElseUpdate(
      fullName,
      createBindingTable(
        fullName,
        lambdaBindingInfo,
        getBindingTable,
        new BindingTableAdapterForLambdas(methodSignature)
      )
    )

  private def createBindingNodes(typeDeclNode: NewTypeDecl, bindingTable: BindingTable): Unit =
    // We only sort to get stable output.
    val sortedEntries =
        bindingTable.getEntries.toBuffer.sortBy((entry: BindingTableEntry) =>
            s"${entry.name}${entry.signature}"
        )

    sortedEntries.foreach { entry =>
      val bindingNode =
          newBindingNode(entry.name, entry.signature, entry.implementingMethodFullName)

      diffGraph.addNode(bindingNode)
      diffGraph.addEdge(typeDeclNode, bindingNode, EdgeTypes.BINDS)
    }

  private def astForTypeDeclMember(
    member: BodyDeclaration[?],
    astParentFullName: String
  ): AstWithStaticInit =
      member match
        case constructor: ConstructorDeclaration =>
            val ast = astForConstructor(constructor)

            AstWithStaticInit(ast)

        case method: MethodDeclaration =>
            val ast = astForMethod(method)

            AstWithStaticInit(ast)

        case typeDeclaration: TypeDeclaration[?] =>
            AstWithStaticInit(astForTypeDecl(
              typeDeclaration,
              NodeTypes.TYPE_DECL,
              astParentFullName
            ))

        case fieldDeclaration: FieldDeclaration =>
            val memberAsts = fieldDeclaration.getVariables.asScala.toList.map { variable =>
                astForFieldVariable(variable, fieldDeclaration)
            }

            val assignments = assignmentsForVarDecl(
              fieldDeclaration.getVariables.asScala.toList,
              line(fieldDeclaration),
              column(fieldDeclaration)
            )

            val staticInitAsts = if fieldDeclaration.isStatic then assignments else Nil
            if !fieldDeclaration.isStatic then scope.addMemberInitializers(assignments)

            AstWithStaticInit(memberAsts, staticInitAsts)

        case initDeclaration: InitializerDeclaration =>
            val stmts = initDeclaration.getBody.getStatements
            val asts  = stmts.asScala.flatMap(astsForStatement).toList
            AstWithStaticInit(ast = Seq.empty, staticInits = asts)

        case unhandled =>
            // AnnotationMemberDeclarations and InitializerDeclarations as children of typeDecls are the
            // expected cases.
            AstWithStaticInit.empty

  private def identifierForResolvedTypeParameter(typeParameter: ResolvedTypeParameterDeclaration)
    : NewIdentifier =
    val name = typeParameter.getName
    val typeFullName = Try(typeParameter.getUpperBound).toOption
        .flatMap(typeInfoCalc.fullName)
        .getOrElse(TypeConstants.Object)
    typeInfoCalc.registerType(typeFullName)
    newIdentifierNode(name, typeFullName)

  private def clinitAstFromStaticInits(staticInits: Seq[Ast]): Option[Ast] =
      Option.when(staticInits.nonEmpty) {
          val signature = composeMethodLikeSignature(TypeConstants.Void, Nil)
          val enclosingDeclName =
              scope.enclosingTypeDeclFullName.getOrElse(Defines.UnresolvedNamespace)
          val fullName =
              composeMethodFullName(enclosingDeclName, Defines.StaticInitMethodName, signature)
          staticInitMethodAst(staticInits.toList, fullName, Some(signature), TypeConstants.Void)
      }

  private def codeForTypeDecl(typ: TypeDeclaration[?], isInterface: Boolean): String =
    val codeBuilder = new mutable.StringBuilder()
    if typ.isPublic then
      codeBuilder.append("public ")
    else if typ.isPrivate then
      codeBuilder.append("private ")
    else if typ.isProtected then
      codeBuilder.append("protected ")

    if typ.isStatic then
      codeBuilder.append("static ")

    val classPrefix =
        if isInterface then
          "interface "
        else if typ.isEnumDeclaration then
          "enum "
        else
          "class "
    codeBuilder.append(classPrefix)
    codeBuilder.append(typ.getNameAsString)

    codeBuilder.toString()
  end codeForTypeDecl

  private def modifiersForTypeDecl(
    typ: TypeDeclaration[?],
    isInterface: Boolean
  ): List[NewModifier] =
    val accessModifierType = if typ.isPublic then
      Some(ModifierTypes.PUBLIC)
    else if typ.isPrivate then
      Some(ModifierTypes.PRIVATE)
    else if typ.isProtected then
      Some(ModifierTypes.PROTECTED)
    else
      None
    val accessModifier = accessModifierType.map(newModifierNode)

    val abstractModifier =
        Option.when(isInterface || typ.getMethods.asScala.exists(_.isAbstract))(newModifierNode(
          ModifierTypes.ABSTRACT
        ))

    List(accessModifier, abstractModifier).flatten
  end modifiersForTypeDecl

  private def createTypeDeclNode(
    typ: TypeDeclaration[?],
    astParentType: String,
    astParentFullName: String,
    isInterface: Boolean
  ): NewTypeDecl =
    val baseTypeFullNames = if typ.isClassOrInterfaceDeclaration then
      val decl             = typ.asClassOrInterfaceDeclaration()
      val extendedTypes    = decl.getExtendedTypes.asScala
      val implementedTypes = decl.getImplementedTypes.asScala
      val inheritsFromTypeNames =
          (extendedTypes ++ implementedTypes).flatMap { typ =>
              typeInfoCalc.fullName(typ).orElse(scope.lookupType(typ.getNameAsString))
          }
      val maybeJavaObjectType = if extendedTypes.isEmpty then
        typeInfoCalc.registerType(TypeConstants.Object)
        Seq(TypeConstants.Object)
      else
        Seq()
      maybeJavaObjectType ++ inheritsFromTypeNames
    else
      List.empty[String]

    val resolvedType    = tryWithSafeStackOverflow(typ.resolve()).toOption
    val defaultFullName = s"${Defines.UnresolvedNamespace}.${typ.getNameAsString}"
    val name            = resolvedType.flatMap(typeInfoCalc.name).getOrElse(typ.getNameAsString)
    val typeFullName    = resolvedType.flatMap(typeInfoCalc.fullName).getOrElse(defaultFullName)
    val code            = codeForTypeDecl(typ, isInterface)
    val typeDecl = NewTypeDecl()
        .name(name)
        .fullName(typeFullName)
        .lineNumber(line(typ))
        .columnNumber(column(typ))
        .inheritsFromTypeFullName(baseTypeFullNames)
        .filename(filename)
        .code(code)
        .astParentType(astParentType)
        .astParentFullName(astParentFullName)
    if packagesJarMappings.contains(typeFullName) then
      typeDecl.aliasTypeFullName(packagesJarMappings.getOrElse(
        typeFullName,
        mutable.Set.empty
      ).headOption)
    typeDecl
  end createTypeDeclNode

  private def addTypeDeclTypeParamsToScope(typ: TypeDeclaration[?]): Unit =
      tryWithSafeStackOverflow(typ.resolve()).map(_.getTypeParameters.asScala) match
        case Success(resolvedTypeParams) =>
            resolvedTypeParams
                .map(identifierForResolvedTypeParameter)
                .foreach { typeParamIdentifier =>
                    scope.addType(typeParamIdentifier.name, typeParamIdentifier.typeFullName)
                }

        case _ => // Nothing to do here
  private def astForTypeDecl(
    typ: TypeDeclaration[?],
    astParentType: String,
    astParentFullName: String
  ): Ast =
    val isInterface = typ match
      case classDeclaration: ClassOrInterfaceDeclaration => classDeclaration.isInterface
      case _                                             => false

    val typeDeclNode = createTypeDeclNode(typ, astParentType, astParentFullName, isInterface)

    scope.pushTypeDeclScope(typeDeclNode)
    addTypeDeclTypeParamsToScope(typ)

    val enumEntryAsts = if typ.isEnumDeclaration then
      typ.asEnumDeclaration().getEntries.asScala.map(astForEnumEntry).toList
    else
      List.empty

    val staticInits: mutable.Buffer[Ast] = mutable.Buffer()
    val memberAsts = typ.getMembers.asScala.flatMap { member =>
      val astWithInits =
          astForTypeDeclMember(member, astParentFullName = NodeTypes.TYPE_DECL)
      staticInits.appendAll(astWithInits.staticInits)
      astWithInits.ast
    }

    val defaultConstructorAst = if !isInterface && typ.getConstructors.isEmpty then
      Some(astForDefaultConstructor())
    else
      None

    val annotationAsts = typ.getAnnotations.asScala.map(astForAnnotationExpr)

    val clinitAst = clinitAstFromStaticInits(staticInits.toSeq)

    val localDecls    = scope.localDeclsInScope
    val lambdaMethods = scope.lambdaMethodsInScope

    val modifiers = modifiersForTypeDecl(typ, isInterface)

    val typeDeclAst = Ast(typeDeclNode)
        .withChildren(enumEntryAsts)
        .withChildren(memberAsts)
        .withChildren(defaultConstructorAst.toList)
        .withChildren(annotationAsts)
        .withChildren(clinitAst.toSeq)
        .withChildren(localDecls)
        .withChildren(lambdaMethods)
        .withChildren(modifiers.map(Ast(_)))

    val defaultConstructorBindingEntry =
        defaultConstructorAst
            .flatMap(_.root)
            .collect { case defaultConstructor: NewMethod =>
                BindingTableEntry(
                  io.appthreat.x2cpg.Defines.ConstructorMethodName,
                  defaultConstructor.signature,
                  defaultConstructor.fullName
                )
            }

    // Annotation declarations need no binding table as objects of this
    // typ never get called from user code.
    // Furthermore the parser library throws an exception when trying to
    // access e.g. the declared methods of an annotation declaration.
    if !typ.isInstanceOf[AnnotationDeclaration] then
      tryWithSafeStackOverflow(typ.resolve()).toOption.foreach { resolvedTypeDecl =>
        val bindingTable = getBindingTable(resolvedTypeDecl)
        defaultConstructorBindingEntry.foreach(bindingTable.add)
        createBindingNodes(typeDeclNode, bindingTable)
      }

    scope.popScope()

    typeDeclAst
  end astForTypeDecl

  private def astForDefaultConstructor(): Ast =
    val typeFullName = scope.enclosingTypeDeclFullName
    val signature    = s"${TypeConstants.Void}()"
    val fullName = composeMethodFullName(
      typeFullName.getOrElse(Defines.UnresolvedNamespace),
      Defines.ConstructorMethodName,
      signature
    )
    val constructorNode = NewMethod()
        .name(io.appthreat.x2cpg.Defines.ConstructorMethodName)
        .fullName(fullName)
        .signature(signature)
        .filename(filename)
        .isExternal(false)

    val thisAst = Ast(thisNodeForMethod(typeFullName, lineNumber = None))
    val bodyAst = Ast(NewBlock()).withChildren(scope.memberInitializers)

    val returnNode = newMethodReturnNode(TypeConstants.Void, line = None, column = None)

    val modifiers =
        List(newModifierNode(ModifierTypes.CONSTRUCTOR), newModifierNode(ModifierTypes.PUBLIC))

    methodAstWithAnnotations(constructorNode, Seq(thisAst), bodyAst, returnNode, modifiers)
  end astForDefaultConstructor

  private def astForEnumEntry(entry: EnumConstantDeclaration): Ast =
    // TODO Fix enum entries in general
    val typeFullName =
        tryWithSafeStackOverflow(entry.resolve().getType).toOption.flatMap(
          typeInfoCalc.fullName
        )

    val entryNode =
        memberNode(entry, entry.getNameAsString, entry.toString, typeFullName.getOrElse("ANY"))

    val name =
        s"${typeFullName.getOrElse(Defines.UnresolvedNamespace)}.${Defines.ConstructorMethodName}"

    Ast(entryNode)

  private def modifiersForFieldDeclaration(decl: FieldDeclaration): Seq[Ast] =
    val staticModifier =
        Option.when(decl.isStatic)(newModifierNode(ModifierTypes.STATIC))

    val accessModifierType =
        if decl.isPublic then
          Some(ModifierTypes.PUBLIC)
        else if decl.isPrivate then
          Some(ModifierTypes.PRIVATE)
        else if decl.isProtected then
          Some(ModifierTypes.PROTECTED)
        else
          None

    val accessModifier = accessModifierType.map(newModifierNode)

    List(staticModifier, accessModifier).flatten.map(Ast(_))

  private def astForFieldVariable(
    v: VariableDeclarator,
    fieldDeclaration: FieldDeclaration
  ): Ast =
    // TODO: Should be able to find expected type here
    val annotations = fieldDeclaration.getAnnotations

    // variable can be declared with generic type, so we need to get rid of the <> part of it to get the package information
    // and append the <> when forming the typeFullName again
    // Ex - private Consumer<String, Integer> consumer;
    // From Consumer<String, Integer> we need to get to Consumer so splitting it by '<' and then combining with '<' to
    // form typeFullName as Consumer<String, Integer>
    val typeFullNameWithoutGenericSplit = typeInfoCalc
        .fullName(v.getType)
        .orElse(scope.lookupType(v.getTypeAsString))
        .getOrElse(guessTypeFullName(v.getTypeAsString))
    val typeFullName =
        // Check if the typeFullName is unresolved and if it has generic information to resolve the typeFullName
        if
          typeFullNameWithoutGenericSplit
              .contains(Defines.UnresolvedNamespace) && v.getTypeAsString.contains(
            Defines.LeftAngularBracket
          )
        then
          val splitByLeftAngular = v.getTypeAsString.split(Defines.LeftAngularBracket)
          scope.lookupType(splitByLeftAngular.head) match
            case Some(fullName) =>
                fullName + splitByLeftAngular
                    .slice(1, splitByLeftAngular.size)
                    .mkString(Defines.LeftAngularBracket, Defines.LeftAngularBracket, "")
            case None => typeFullNameWithoutGenericSplit
        else if typeFullNameWithoutGenericSplit.nonEmpty then typeFullNameWithoutGenericSplit
        else v.getTypeAsString
    val name           = v.getName.toString
    val node           = memberNode(v, name, s"$typeFullName $name", typeFullName)
    val memberAst      = Ast(node)
    val annotationAsts = annotations.asScala.map(astForAnnotationExpr)

    val fieldDeclModifiers = modifiersForFieldDeclaration(fieldDeclaration)

    scope.addMember(node, fieldDeclaration.isStatic)

    memberAst
        .withChildren(annotationAsts)
        .withChildren(fieldDeclModifiers)
  end astForFieldVariable

  private def astForConstructor(constructorDeclaration: ConstructorDeclaration): Ast =
    val constructorNode = createPartialMethod(constructorDeclaration)
        .name(io.appthreat.x2cpg.Defines.ConstructorMethodName)

    scope.pushMethodScope(constructorNode, ExpectedType.Void)
    val maybeResolved = tryWithSafeStackOverflow(constructorDeclaration.resolve())

    val parameterAsts = astsForParameterList(constructorDeclaration.getParameters).toList
    val paramTypes    = argumentTypesForMethodLike(maybeResolved)
    val signature     = composeSignature(Some(TypeConstants.Void), paramTypes, parameterAsts.size)
    val typeFullName  = scope.enclosingTypeDeclFullName
    val fullName =
        composeMethodFullName(
          typeFullName.getOrElse(Defines.UnresolvedNamespace),
          Defines.ConstructorMethodName,
          signature
        )
    val typeNameLookup = fullName.takeWhile(_ != ':').split("\\.").dropRight(1).mkString(".")
    constructorNode
        .fullName(fullName)
        .signature(signature)
    if packagesJarMappings.contains(typeNameLookup) then
      constructorNode.astParentType(packagesJarMappings.getOrElse(
        typeNameLookup,
        mutable.Set.empty
      ).head)

    parameterAsts.foreach { ast =>
        ast.root match
          case Some(parameter: NewMethodParameterIn) => scope.addParameter(parameter)
          case _                                     => // This should never happen
    }

    val thisNode = thisNodeForMethod(typeFullName, line(constructorDeclaration))
    scope.addParameter(thisNode)
    val thisAst = Ast(thisNode)

    val bodyAst      = astForConstructorBody(Some(constructorDeclaration.getBody))
    val methodReturn = constructorReturnNode(constructorDeclaration)

    val annotationAsts =
        constructorDeclaration.getAnnotations.asScala.map(astForAnnotationExpr).toList

    val modifiers =
        NewModifier().modifierType(ModifierTypes.CONSTRUCTOR) :: modifiersForMethod(
          constructorDeclaration
        ).filterNot(
          _.modifierType == ModifierTypes.VIRTUAL
        )

    scope.popScope()

    methodAstWithAnnotations(
      constructorNode,
      thisAst :: parameterAsts,
      bodyAst,
      methodReturn,
      modifiers,
      annotationAsts
    )
  end astForConstructor

  private def thisNodeForMethod(
    maybeTypeFullName: Option[String],
    lineNumber: Option[Integer]
  ): NewMethodParameterIn =
    val typeFullName = typeInfoCalc.registerType(maybeTypeFullName.getOrElse(TypeConstants.Any))
    NodeBuilders.newThisParameterNode(
      typeFullName = typeFullName,
      dynamicTypeHintFullName = maybeTypeFullName.toSeq,
      line = lineNumber
    )

  private def convertAnnotationValueExpr(expr: Expression): Option[Ast] =
      expr match
        case arrayInit: ArrayInitializerExpr =>
            val arrayInitNode = NewArrayInitializer()
                .code(arrayInit.toString)
            val initElementAsts = arrayInit.getValues.asScala.toList.map { value =>
                convertAnnotationValueExpr(value)
            }

            setArgumentIndices(initElementAsts.flatten)

            val returnAst = initElementAsts.foldLeft(Ast(arrayInitNode)) {
                case (ast, Some(elementAst)) =>
                    ast.withChild(elementAst)
                case (ast, _) => ast
            }
            Some(returnAst)

        case annotationExpr: AnnotationExpr =>
            Some(astForAnnotationExpr(annotationExpr))

        case literalExpr: LiteralExpr =>
            Some(astForAnnotationLiteralExpr(literalExpr))

        case _: ClassExpr =>
            // TODO: Implement for known case
            None

        case _: FieldAccessExpr =>
            // TODO: Implement for known case
            None

        case _: BinaryExpr =>
            // TODO: Implement for known case
            None

        case _: NameExpr =>
            // TODO: Implement for known case
            None

        case _ =>
            None

  private def astForAnnotationLiteralExpr(literalExpr: LiteralExpr): Ast =
    val valueNode =
        literalExpr match
          case literal: StringLiteralExpr  => newAnnotationLiteralNode(literal.getValue)
          case literal: IntegerLiteralExpr => newAnnotationLiteralNode(literal.getValue)
          case literal: BooleanLiteralExpr =>
              newAnnotationLiteralNode(java.lang.Boolean.toString(literal.getValue))
          case literal: CharLiteralExpr      => newAnnotationLiteralNode(literal.getValue)
          case literal: DoubleLiteralExpr    => newAnnotationLiteralNode(literal.getValue)
          case literal: LongLiteralExpr      => newAnnotationLiteralNode(literal.getValue)
          case _: NullLiteralExpr            => newAnnotationLiteralNode("null")
          case literal: TextBlockLiteralExpr => newAnnotationLiteralNode(literal.getValue)

    Ast(valueNode)

  private def exprNameFromStack(expr: Expression): Option[String] = expr match
    case annotation: AnnotationExpr =>
        scope.lookupType(annotation.getNameAsString)
    case namedExpr: NodeWithName[?] =>
        scope.lookupVariableOrType(namedExpr.getNameAsString)
    case namedExpr: NodeWithSimpleName[?] =>
        scope.lookupVariableOrType(namedExpr.getNameAsString)
    // JavaParser doesn't handle literals well for some reason
    case _: BooleanLiteralExpr   => Some("boolean")
    case _: CharLiteralExpr      => Some("char")
    case _: DoubleLiteralExpr    => Some("double")
    case _: IntegerLiteralExpr   => Some("int")
    case _: LongLiteralExpr      => Some("long")
    case _: NullLiteralExpr      => Some("null")
    case _: StringLiteralExpr    => Some("java.lang.String")
    case _: TextBlockLiteralExpr => Some("java.lang.String")
    case _                       => None

  private def expressionReturnTypeFullName(expr: Expression): Option[String] =

    val resolvedTypeOption = tryWithSafeStackOverflow(expr.calculateResolvedType()) match
      case Failure(ex) =>
          ex match
            // If ast parser fails to resolve type, try resolving locally by using name
            // Precaution when resolving by name, we only want to resolve for case when the expr is solely a MethodCallExpr
            // and doesn't have a scope to it
            case symbolException: UnsolvedSymbolException =>
                expr match
                  case callExpr: MethodCallExpr =>
                      callExpr.getScope.toScala match
                        case Some(_: Expression) => None
                        case _                   => scope.lookupType(symbolException.getName)
                  case _ => None
            case _ => None
      case Success(resolvedType) => typeInfoCalc.fullName(resolvedType)
    resolvedTypeOption.orElse(exprNameFromStack(expr))

  private def guessTypeFullName(initString: String): String =
      initString match
        case x
            if Seq(
              "Override",
              "Deprecated",
              "SuppressWarnings",
              "SafeVarargs",
              "FunctionalInterface",
              "Native"
            ).contains(x) => s"java.lang.$x"
        case y if y.startsWith("java.") => y
        case z
            if Seq(
              "byte",
              "short",
              "int",
              "long",
              "float",
              "double",
              "char",
              "boolean",
              "java.lang.Byte",
              "java.lang.Short",
              "java.lang.Integer",
              "java.lang.Long",
              "java.lang.Float",
              "java.lang.Double",
              "java.lang.Character",
              "java.lang.Boolean"
            ).equals(z) => z
        case _ => s"${Defines.UnresolvedNamespace}.${initString}"

  private def astForAnnotationExpr(annotationExpr: AnnotationExpr): Ast =
    val fallbackType = guessTypeFullName(annotationExpr.getNameAsString)
    val fullName     = expressionReturnTypeFullName(annotationExpr).getOrElse(fallbackType)
    val code         = annotationExpr.toString
    val name         = annotationExpr.getName.getIdentifier
    val node         = annotationNode(annotationExpr, code, name, fullName)

    /** A string-valued member additionally lowers to a real LITERAL under the parameter assignment.
      * The ANNOTATION_LITERAL value node keeps its historic shape (pinned by AnnotationTests) but
      * cannot carry TAGGED_BY edges or be reached by literal traversals, and a route
      * (`@GetMapping("/users")`) or statement (`@Query("SELECT ...")`) that exists only there is
      * invisible to the framework taggers and to every literal-based consumer. The duplicate
      * LITERAL makes the value a first-class expression node.
      */
    def withStringLiteral(assignmentAst: Ast, value: Expression): Ast =
        value match
          case str: StringLiteralExpr =>
              assignmentAst.withChild(Ast(
                NewLiteral()
                    .code(s"\"${str.getValue}\"")
                    .typeFullName("java.lang.String")
                    .lineNumber(line(str))
                    .columnNumber(column(str))
              ))
          case block: TextBlockLiteralExpr =>
              assignmentAst.withChild(Ast(
                NewLiteral()
                    .code(s"\"${block.getValue}\"")
                    .typeFullName("java.lang.String")
                    .lineNumber(line(block))
                    .columnNumber(column(block))
              ))
          case _ => assignmentAst

    annotationExpr match
      case _: MarkerAnnotationExpr =>
          annotationAst(node, List.empty)
      case normal: NormalAnnotationExpr =>
          val assignmentAsts = normal.getPairs.asScala.toList.map { pair =>
              withStringLiteral(
                annotationAssignmentAst(
                  pair.getName.getIdentifier,
                  pair.toString,
                  convertAnnotationValueExpr(pair.getValue).getOrElse(Ast())
                ),
                pair.getValue
              )
          }
          annotationAst(node, assignmentAsts)
      case single: SingleMemberAnnotationExpr =>
          val assignmentAsts = List(
            withStringLiteral(
              annotationAssignmentAst(
                "value",
                single.getMemberValue.toString,
                convertAnnotationValueExpr(single.getMemberValue).getOrElse(Ast())
              ),
              single.getMemberValue
            )
          )
          annotationAst(node, assignmentAsts)
    end match
  end astForAnnotationExpr

  private def abstractModifierForCallable(
    callableDeclaration: CallableDeclaration[?],
    isInterfaceMethod: Boolean
  ): Option[NewModifier] =
      callableDeclaration match
        case methodDeclaration: MethodDeclaration =>
            Option.when(
              methodDeclaration.isAbstract || (isInterfaceMethod && !methodDeclaration.isDefault)
            ) {
                newModifierNode(ModifierTypes.ABSTRACT)
            }

        case _ => None

  private def modifiersForMethod(methodDeclaration: CallableDeclaration[?]): List[NewModifier] =
    val isInterfaceMethod = scope.enclosingTypeDecl.exists(_.code.contains("interface "))

    val abstractModifier = abstractModifierForCallable(methodDeclaration, isInterfaceMethod)

    val staticVirtualModifierType =
        if methodDeclaration.isStatic then ModifierTypes.STATIC else ModifierTypes.VIRTUAL
    val staticVirtualModifier = Some(newModifierNode(staticVirtualModifierType))

    // `native` methods (JNI) keep their NATIVE modifier - the framework taggers key on it to
    // mark the JNI boundary.
    val nativeModifier = methodDeclaration match
      case method: MethodDeclaration
          if method.getModifiers.asScala.exists(
            _.getKeyword.asString().equalsIgnoreCase("native")
          ) =>
          Some(newModifierNode(ModifierTypes.NATIVE))
      case _ => None

    val accessModifierType = if methodDeclaration.isPublic then
      Some(ModifierTypes.PUBLIC)
    else if methodDeclaration.isPrivate then
      Some(ModifierTypes.PRIVATE)
    else if methodDeclaration.isProtected then
      Some(ModifierTypes.PROTECTED)
    else if isInterfaceMethod then
      // TODO: more robust interface check
      Some(ModifierTypes.PUBLIC)
    else
      None
    val accessModifier = accessModifierType.map(newModifierNode)

    List(accessModifier, abstractModifier, staticVirtualModifier, nativeModifier).flatten
  end modifiersForMethod

  private def getIdentifiersForTypeParameters(methodDeclaration: MethodDeclaration)
    : List[NewIdentifier] =
      methodDeclaration.getTypeParameters.asScala.map { typeParameter =>
        val name = typeParameter.getNameAsString
        val typeFullName = typeParameter.getTypeBound.asScala.headOption
            .flatMap(typeInfoCalc.fullName)
            .getOrElse(TypeConstants.Object)
        typeInfoCalc.registerType(typeFullName)

        NewIdentifier().name(name).typeFullName(typeFullName)
      }.toList

  private def astForMethod(methodDeclaration: MethodDeclaration): Ast =
    val methodNode = createPartialMethod(methodDeclaration)

    val typeParameters = getIdentifiersForTypeParameters(methodDeclaration)

    val maybeResolved = tryWithSafeStackOverflow(methodDeclaration.resolve())
    val expectedReturnType = Try(symbolSolver.toResolvedType(
      methodDeclaration.getType,
      classOf[ResolvedType]
    )).toOption
    val simpleMethodReturnType = methodDeclaration.getTypeAsString()
    val returnTypeFullName = expectedReturnType
        .flatMap(typeInfoCalc.fullName)
        .orElse(scope.lookupType(simpleMethodReturnType))
        .orElse(typeParameters.find(_.name == simpleMethodReturnType).map(_.typeFullName))

    scope.pushMethodScope(methodNode, ExpectedType(returnTypeFullName, expectedReturnType))
    typeParameters.foreach { typeParameter =>
        scope.addType(typeParameter.name, typeParameter.typeFullName)
    }

    val parameterAsts  = astsForParameterList(methodDeclaration.getParameters)
    val parameterTypes = argumentTypesForMethodLike(maybeResolved)
    val signature      = composeSignature(returnTypeFullName, parameterTypes, parameterAsts.size)
    val namespaceName  = scope.enclosingTypeDeclFullName.getOrElse(Defines.UnresolvedNamespace)
    val methodFullName =
        composeMethodFullName(namespaceName, methodDeclaration.getNameAsString, signature)

    methodNode
        .fullName(methodFullName)
        .signature(signature)
    val typeNameLookup =
        methodFullName.takeWhile(_ != ':').split("\\.").dropRight(1).mkString(".")
    if packagesJarMappings != null && packagesJarMappings.contains(typeNameLookup) then
      methodNode.astParentType(packagesJarMappings.getOrElse(
        typeNameLookup,
        mutable.Set.empty
      ).head)
    val thisNode = Option.when(!methodDeclaration.isStatic) {
        val typeFullName = scope.enclosingTypeDeclFullName
        thisNodeForMethod(typeFullName, line(methodDeclaration))
    }
    val thisAst = thisNode.map(Ast(_)).toList

    thisNode.foreach { node =>
        scope.addParameter(node)
    }

    val bodyAst = methodDeclaration.getBody.toScala.map(astForBlockStatement(_)).getOrElse(Ast(
      NewBlock()
    ))
    // Pattern-binding locals synthesized while lowering the body (type patterns in `instanceof`
    // and pattern `case` labels) attach here - see [[Scope.registerPatternLocalAst]].
    val patternLocals = scope.takePatternLocalAsts
    val bodyAstWithPatternLocals =
        if patternLocals.isEmpty then bodyAst else bodyAst.withChildren(patternLocals)
    val methodReturn = newMethodReturnNode(
      returnTypeFullName.getOrElse(TypeConstants.Any),
      None,
      line(methodDeclaration.getType),
      column(methodDeclaration.getType)
    )

    val annotationAsts =
        methodDeclaration.getAnnotations.asScala.map(astForAnnotationExpr).toSeq

    val modifiers = modifiersForMethod(methodDeclaration)

    scope.popScope()

    methodAstWithAnnotations(
      methodNode,
      thisAst ++ parameterAsts,
      bodyAstWithPatternLocals,
      methodReturn,
      modifiers,
      annotationAsts
    )
  end astForMethod

  private def constructorReturnNode(constructorDeclaration: ConstructorDeclaration)
    : NewMethodReturn =
    val line   = constructorDeclaration.getEnd.map(x => Integer.valueOf(x.line)).toScala
    val column = constructorDeclaration.getEnd.map(x => Integer.valueOf(x.column)).toScala
    newMethodReturnNode(TypeConstants.Void, None, line, column)

  /** Constructor and Method declarations share a lot of fields, so this method adds the fields they
    * have in common. `fullName` and `signature` are omitted
    */
  private def createPartialMethod(declaration: CallableDeclaration[?]): NewMethod =
    val code         = declaration.getDeclarationAsString.trim
    val columnNumber = declaration.getBegin.map(x => Integer.valueOf(x.column)).toScala
    val endLine      = declaration.getEnd.map(x => Integer.valueOf(x.line)).toScala
    val endColumn    = declaration.getEnd.map(x => Integer.valueOf(x.column)).toScala

    val methodNode = NewMethod()
        .name(declaration.getNameAsString)
        .code(code)
        .isExternal(false)
        .filename(filename)
        .lineNumber(line(declaration))
        .columnNumber(columnNumber)
        .lineNumberEnd(endLine)
        .columnNumberEnd(endColumn)

    methodNode

  private def astForConstructorBody(body: Option[BlockStmt]): Ast =
    val containsThisInvocation =
        body
            .flatMap(_.getStatements.asScala.headOption)
            .collect { case e: ExplicitConstructorInvocationStmt => e }
            .exists(_.isThis)

    val memberInitializers =
        if containsThisInvocation then
          Seq.empty
        else
          scope.memberInitializers

    body match
      case Some(b) => astForBlockStatement(b, prefixAsts = memberInitializers)

      case None => Ast(NewBlock()).withChildren(memberInitializers)

  private def astsForLabeledStatement(stmt: LabeledStmt): Seq[Ast] =
    val jumpTargetAst = Ast(NewJumpTarget().name(stmt.getLabel.toString))
    val stmtAst       = astsForStatement(stmt.getStatement).toList

    jumpTargetAst :: stmtAst

  private def astForThrow(stmt: ThrowStmt): Ast =
    val throwNode = NewCall()
        .name("<operator>.throw")
        .methodFullName("<operator>.throw")
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))
        .code(stmt.toString())
        .dispatchType(DispatchTypes.STATIC_DISPATCH)

    val args = astsForExpression(stmt.getExpression, ExpectedType.empty)

    callAst(throwNode, args)

  private def astForCatchClause(catchClause: CatchClause): Ast =
      astForBlockStatement(catchClause.getBody)

  private def astsForTry(stmt: TryStmt): Seq[Ast] =
    val tryNode = NewControlStructure()
        .controlStructureType(ControlStructureTypes.TRY)
        .code("try")
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))

    val resources = stmt.getResources.asScala.flatMap(astsForExpression(
      _,
      expectedType = ExpectedType.empty
    )).toList
    val tryAst    = astForBlockStatement(stmt.getTryBlock, codeStr = "try")
    val catchAsts = stmt.getCatchClauses.asScala.map(astForCatchClause)
    val catchBlock = Option
        .when(catchAsts.nonEmpty) {
            Ast(NewBlock().code("catch")).withChildren(catchAsts)
        }
        .toList
    val finallyAst =
        stmt.getFinallyBlock.toScala.map(astForBlockStatement(_, "finally")).toList

    val controlStructureAst = Ast(tryNode)
        .withChild(tryAst)
        .withChildren(catchBlock)
        .withChildren(finallyAst)

    resources.appended(controlStructureAst)
  end astsForTry

  private def astsForStatement(statement: Statement): Seq[Ast] =
      statement match
        case x: ExplicitConstructorInvocationStmt =>
            Seq(astForExplicitConstructorInvocation(x))
        case x: AssertStmt     => Seq(astForAssertStatement(x))
        case x: BlockStmt      => Seq(astForBlockStatement(x))
        case x: BreakStmt      => Seq(astForBreakStatement(x))
        case x: ContinueStmt   => Seq(astForContinueStatement(x))
        case x: DoStmt         => Seq(astForDo(x))
        case _: EmptyStmt      => Seq() // Intentionally skipping this
        case x: ExpressionStmt => astsForExpression(x.getExpression, ExpectedType.Void)
        case x: ForEachStmt    => astForForEach(x)
        case x: ForStmt        => Seq(astForFor(x))
        case x: IfStmt         => Seq(astForIf(x))
        case x: LabeledStmt    => astsForLabeledStatement(x)
        case x: LocalClassDeclarationStmt => astForLocalTypeDeclaration(
              x.getClassDeclaration,
              x
            )
        case x: LocalRecordDeclarationStmt => astForLocalTypeDeclaration(
              x.getRecordDeclaration,
              x
            )
        case x: ReturnStmt       => astForReturnNode(x)
        case x: SwitchStmt       => Seq(astForSwitchStatement(x))
        case x: SynchronizedStmt => Seq(astForSynchronizedStatement(x))
        case x: ThrowStmt        => Seq(astForThrow(x))
        case x: TryStmt          => astsForTry(x)
        case x: WhileStmt        => Seq(astForWhile(x))
        case x: YieldStmt        => Seq(astForYieldStatement(x))
        case x =>
            logger.debug(
              s"Attempting to generate AST for unknown statement of type ${x.getClass}"
            )
            Seq(unknownAst(x))

  private def astForElse(maybeStmt: Option[Statement]): Option[Ast] =
      maybeStmt.map { stmt =>
        val elseAsts = astsForStatement(stmt)

        val elseNode =
            NewControlStructure()
                .controlStructureType(ControlStructureTypes.ELSE)
                .lineNumber(line(stmt))
                .columnNumber(column(stmt))
                .code("else")

        Ast(elseNode).withChildren(elseAsts)
      }

  def astForIf(stmt: IfStmt): Ast =
    val ifNode =
        NewControlStructure()
            .controlStructureType(ControlStructureTypes.IF)
            .lineNumber(line(stmt))
            .columnNumber(column(stmt))
            .code(s"if (${stmt.getCondition.toString})")

    // A condition with type patterns (`o instanceof String s`) lowers to several ASTs - the
    // boolean test first, then the pattern bindings. All of them belong before the branches;
    // only the boolean test gets the CONDITION edge.
    val conditionAsts = astsForExpression(stmt.getCondition, ExpectedType.Boolean).toList

    val thenAsts = astsForStatement(stmt.getThenStmt)
    val elseAst  = astForElse(stmt.getElseStmt.toScala).toList

    val ast = Ast(ifNode)
        .withChildren(conditionAsts)
        .withChildren(thenAsts)
        .withChildren(elseAst)

    conditionAsts.headOption.flatMap(_.root) match
      case Some(r) =>
          ast.withConditionEdge(ifNode, r)
      case None =>
          ast
  end astForIf

  /** All condition ASTs, with the boolean test (the first) singled out for the CONDITION edge.
    * Mirrors [[astForIf]]: a pattern-carrying condition contributes binding ASTs after the test.
    *
    * Loop conditions keep only the boolean test: a pattern bound in a `while`/`do` condition has no
    * definite assignment that outlives the test (`JLS 6.3` scopes it to the condition itself when
    * the loop is not unrolled), so lowering its binding would fabricate a taint step.
    */
  private def conditionAstsFor(condition: Expression): Option[Ast] =
      astsForExpression(condition, ExpectedType.Boolean).headOption

  def astForWhile(stmt: WhileStmt): Ast =
    val conditionAst = conditionAstsFor(stmt.getCondition)
    val stmtAsts     = astsForStatement(stmt.getBody)
    val code         = s"while (${stmt.getCondition.toString})"
    val lineNumber   = line(stmt)
    val columnNumber = column(stmt)

    whileAst(conditionAst, stmtAsts, Some(code), lineNumber, columnNumber)

  private def astForDo(stmt: DoStmt): Ast =
    val conditionAst = conditionAstsFor(stmt.getCondition)
    val stmtAsts     = astsForStatement(stmt.getBody)
    val code         = s"do {...} while (${stmt.getCondition.toString})"
    val lineNumber   = line(stmt)
    val columnNumber = column(stmt)

    doWhileAst(conditionAst, stmtAsts, Some(code), lineNumber, columnNumber)

  private def astForBreakStatement(stmt: BreakStmt): Ast =
    val node = NewControlStructure()
        .controlStructureType(ControlStructureTypes.BREAK)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))
        .code(stmt.toString)
    Ast(node)

  private def astForContinueStatement(stmt: ContinueStmt): Ast =
    val node = NewControlStructure()
        .controlStructureType(ControlStructureTypes.CONTINUE)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))
        .code(stmt.toString)
    Ast(node)

  private def getForCode(stmt: ForStmt): String =
    val init    = stmt.getInitialization.asScala.map(_.toString).mkString(", ")
    val compare = stmt.getCompare.toScala.map(_.toString)
    val update  = stmt.getUpdate.asScala.map(_.toString).mkString(", ")
    s"for ($init; $compare; $update)"
  def astForFor(stmt: ForStmt): Ast =
    val forNode =
        NewControlStructure()
            .controlStructureType(ControlStructureTypes.FOR)
            .code(getForCode(stmt))
            .lineNumber(line(stmt))
            .columnNumber(column(stmt))

    val initAsts =
        stmt.getInitialization.asScala.flatMap(astsForExpression(
          _,
          expectedType = ExpectedType.empty
        ))

    val compareAsts = stmt.getCompare.toScala.toList.flatMap {
        astsForExpression(_, ExpectedType.Boolean)
    }

    val updateAsts = stmt.getUpdate.asScala.toList.flatMap {
        astsForExpression(_, ExpectedType.empty)
    }

    val stmtAsts =
        astsForStatement(stmt.getBody)

    val ast = Ast(forNode)
        .withChildren(initAsts)
        .withChildren(compareAsts)
        .withChildren(updateAsts)
        .withChildren(stmtAsts)

    compareAsts.flatMap(_.root) match
      case c :: Nil =>
          ast.withConditionEdge(forNode, c)
      case _ => ast
  end astForFor

  private def iterableAssignAstsForNativeForEach(
    iterableExpression: Expression,
    iterableType: Option[String]
  ): (NodeTypeInfo, Seq[Ast]) =
    val lineNo       = line(iterableExpression)
    val expectedType = ExpectedType(iterableType)

    val iterableAst = astsForExpression(iterableExpression, expectedType = expectedType) match
      case Nil =>
          logger.debug(
            s"Could not create AST for iterable expr $iterableExpression: $filename:l$lineNo"
          )
          Ast()
      case iterableAstHead :: Nil => iterableAstHead
      case iterableAsts =>
          logger.debug(
            s"Found multiple ASTS for iterable expr $iterableExpression: $filename:l$lineNo\nDropping all but the first!"
          )
          iterableAsts.head

    val iterableName = nextIterableName()
    val iterableLocalNode =
        localNode(iterableExpression, iterableName, iterableName, iterableType.getOrElse("ANY"))
    val iterableLocalAst = Ast(iterableLocalNode)

    val iterableAssignNode =
        newOperatorCallNode(
          Operators.assignment,
          code = "",
          line = lineNo,
          typeFullName = iterableType
        )
    val iterableAssignIdentifier =
        identifierNode(
          iterableExpression,
          iterableName,
          iterableName,
          iterableType.getOrElse("ANY")
        )
    val iterableAssignArgs = List(Ast(iterableAssignIdentifier), iterableAst)
    val iterableAssignAst =
        callAst(iterableAssignNode, iterableAssignArgs)
            .withRefEdge(iterableAssignIdentifier, iterableLocalNode)

    (
      NodeTypeInfo(
        iterableLocalNode,
        iterableLocalNode.name,
        Some(iterableLocalNode.typeFullName)
      ),
      List(iterableLocalAst, iterableAssignAst)
    )
  end iterableAssignAstsForNativeForEach

  private def nativeForEachIdxLocalNode(lineNo: Option[Integer]): NewLocal =
    val idxName      = nextIndexName()
    val typeFullName = TypeConstants.Int
    val idxLocal =
        NewLocal()
            .name(idxName)
            .typeFullName(typeFullName)
            .code(idxName)
            .lineNumber(lineNo)
    scope.addLocal(idxLocal)
    idxLocal

  private def nativeForEachIdxInitializerAst(lineNo: Option[Integer], idxLocal: NewLocal): Ast =
    val idxName = idxLocal.name
    val idxInitializerCallNode = newOperatorCallNode(
      Operators.assignment,
      code = s"int $idxName = 0",
      line = lineNo,
      typeFullName = Some(TypeConstants.Int)
    )
    val idxIdentifierArg = newIdentifierNode(idxName, idxLocal.typeFullName)
    val zeroLiteral =
        NewLiteral()
            .code("0")
            .typeFullName(TypeConstants.Int)
            .lineNumber(lineNo)
    val idxInitializerArgAsts = List(Ast(idxIdentifierArg), Ast(zeroLiteral))
    callAst(idxInitializerCallNode, idxInitializerArgAsts)
        .withRefEdge(idxIdentifierArg, idxLocal)

  private def nativeForEachCompareAst(
    lineNo: Option[Integer],
    iterableSource: NodeTypeInfo,
    idxLocal: NewLocal
  ): Ast =
    val idxName = idxLocal.name

    val compareNode = newOperatorCallNode(
      Operators.lessThan,
      code = s"$idxName < ${iterableSource.name}.length",
      typeFullName = Some(TypeConstants.Boolean),
      line = lineNo
    )
    val comparisonIdxIdentifier = newIdentifierNode(idxName, idxLocal.typeFullName)
    val comparisonFieldAccess = newOperatorCallNode(
      Operators.fieldAccess,
      code = s"${iterableSource.name}.length",
      typeFullName = Some(TypeConstants.Int),
      line = lineNo
    )
    val fieldAccessIdentifier =
        newIdentifierNode(iterableSource.name, iterableSource.typeFullName.getOrElse("ANY"))
    val fieldAccessFieldIdentifier = newFieldIdentifierNode("length", lineNo)
    val fieldAccessArgs = List(fieldAccessIdentifier, fieldAccessFieldIdentifier).map(Ast(_))
    val fieldAccessAst  = callAst(comparisonFieldAccess, fieldAccessArgs)
    val compareArgs     = List(Ast(comparisonIdxIdentifier), fieldAccessAst)

    // TODO: This is a workaround for a crash when looping over statically imported members. Handle those properly.
    val iterableSourceNode = localParamOrMemberFromNode(iterableSource)

    callAst(compareNode, compareArgs)
        .withRefEdge(comparisonIdxIdentifier, idxLocal)
        .withRefEdges(fieldAccessIdentifier, iterableSourceNode.toList)
  end nativeForEachCompareAst

  private def nativeForEachIncrementAst(lineNo: Option[Integer], idxLocal: NewLocal): Ast =
    val incrementNode = newOperatorCallNode(
      Operators.postIncrement,
      code = s"${idxLocal.name}++",
      typeFullName = Some(TypeConstants.Int),
      line = lineNo
    )
    val incrementArg    = newIdentifierNode(idxLocal.name, idxLocal.typeFullName)
    val incrementArgAst = Ast(incrementArg)
    callAst(incrementNode, List(incrementArgAst))
        .withRefEdge(incrementArg, idxLocal)

  private def variableLocalForForEachBody(stmt: ForEachStmt): NewLocal =
    val lineNo = line(stmt)
    // Create item local
    val maybeVariable = stmt.getVariable.getVariables.asScala.toList match
      case Nil =>
          None
      case variable :: Nil => Some(variable)
      case variable :: _ =>
          Some(variable)

    val partialLocalNode = NewLocal().lineNumber(lineNo)

    maybeVariable match
      case Some(variable) =>
          val name         = variable.getNameAsString
          val typeFullName = typeInfoCalc.fullName(variable.getType).getOrElse("ANY")
          val localNode = partialLocalNode
              .name(name)
              .code(variable.getNameAsString)
              .typeFullName(typeFullName)

          scope.addLocal(localNode)
          localNode

      case None =>
          // Returning partialLocalNode here is fine since getting to this case means everything is broken anyways :)
          partialLocalNode
  end variableLocalForForEachBody

  private def localParamOrMemberFromNode(nodeTypeInfo: NodeTypeInfo): Option[NewNode] =
      nodeTypeInfo.node match
        case localNode: NewLocal                 => Some(localNode)
        case memberNode: NewMember               => Some(memberNode)
        case parameterNode: NewMethodParameterIn => Some(parameterNode)
        case _                                   => None
  private def variableAssignForNativeForEachBody(
    variableLocal: NewLocal,
    idxLocal: NewLocal,
    iterable: NodeTypeInfo
  ): Ast =
    // Everything will be on the same line as the `for` statement, but this is the most useful
    // solution for debugging.
    val lineNo = variableLocal.lineNumber
    val varAssignNode =
        newOperatorCallNode(
          Operators.assignment,
          PropertyDefaults.Code,
          Some(variableLocal.typeFullName),
          lineNo
        )

    val targetNode = newIdentifierNode(variableLocal.name, variableLocal.typeFullName)

    val indexAccessTypeFullName = iterable.typeFullName.map(_.replaceAll(raw"\[]", ""))
    val indexAccess =
        newOperatorCallNode(
          Operators.indexAccess,
          PropertyDefaults.Code,
          indexAccessTypeFullName,
          lineNo
        )

    val indexAccessIdentifier =
        newIdentifierNode(iterable.name, iterable.typeFullName.getOrElse("ANY"))
    val indexAccessIndex = newIdentifierNode(idxLocal.name, idxLocal.typeFullName)

    val indexAccessArgsAsts = List(indexAccessIdentifier, indexAccessIndex).map(Ast(_))
    val indexAccessAst      = callAst(indexAccess, indexAccessArgsAsts)

    val iterableSourceNode = localParamOrMemberFromNode(iterable)

    val assignArgsAsts = List(Ast(targetNode), indexAccessAst)
    callAst(varAssignNode, assignArgsAsts)
        .withRefEdge(targetNode, variableLocal)
        .withRefEdges(indexAccessIdentifier, iterableSourceNode.toList)
        .withRefEdge(indexAccessIndex, idxLocal)
  end variableAssignForNativeForEachBody

  private def nativeForEachBodyAst(
    stmt: ForEachStmt,
    idxLocal: NewLocal,
    iterable: NodeTypeInfo
  ): Ast =
    val variableLocal    = variableLocalForForEachBody(stmt)
    val variableLocalAst = Ast(variableLocal)
    val variableAssignAst =
        variableAssignForNativeForEachBody(variableLocal, idxLocal, iterable)

    stmt.getBody match
      case block: BlockStmt =>
          astForBlockStatement(block, prefixAsts = List(variableLocalAst, variableAssignAst))
      case statement =>
          val stmtAsts  = astsForStatement(statement)
          val blockNode = NewBlock().lineNumber(variableLocal.lineNumber)
          Ast(blockNode)
              .withChild(variableLocalAst)
              .withChild(variableAssignAst)
              .withChildren(stmtAsts)
  end nativeForEachBodyAst

  private def astsForNativeForEach(stmt: ForEachStmt, iterableType: Option[String]): Seq[Ast] =

    // This is ugly, but for a case like `for (int x : new int[] { ... })` this creates a new LOCAL
    // with the assignment `int[] $iterLocal0 = new int[] { ... }` before the FOR loop.
    // TODO: Fix this
    val (iterableSource: NodeTypeInfo, tempIterableInitAsts) = stmt.getIterable match
      case nameExpr: NameExpr =>
          scope.lookupVariable(nameExpr.getNameAsString).asNodeInfoOption match
            // If this is not the case, then the code is broken (iterable not in scope).
            case Some(nodeTypeInfo) => (nodeTypeInfo, Nil)
            case _                  => iterableAssignAstsForNativeForEach(nameExpr, iterableType)
      case iterableExpr => iterableAssignAstsForNativeForEach(iterableExpr, iterableType)

    val forNode = NewControlStructure()
        .controlStructureType(ControlStructureTypes.FOR)

    val lineNo = line(stmt)

    val idxLocal          = nativeForEachIdxLocalNode(lineNo)
    val idxInitializerAst = nativeForEachIdxInitializerAst(lineNo, idxLocal)
    // TODO next: pass NodeTypeInfo around
    val compareAst   = nativeForEachCompareAst(lineNo, iterableSource, idxLocal)
    val incrementAst = nativeForEachIncrementAst(lineNo, idxLocal)
    val bodyAst      = nativeForEachBodyAst(stmt, idxLocal, iterableSource)

    val forAst = Ast(forNode)
        .withChild(Ast(idxLocal))
        .withChild(idxInitializerAst)
        .withChild(compareAst)
        .withChild(incrementAst)
        .withChild(bodyAst)
        .withConditionEdges(forNode, compareAst.root.toList)

    tempIterableInitAsts ++ Seq(forAst)
  end astsForNativeForEach

  private def iteratorLocalForForEach(lineNumber: Option[Integer]): NewLocal =
    val iteratorLocalName = nextIterableName()
    NewLocal()
        .name(iteratorLocalName)
        .code(iteratorLocalName)
        .typeFullName(TypeConstants.Iterator)
        .lineNumber(lineNumber)

  private def iteratorAssignAstForForEach(
    iterExpr: Expression,
    iteratorLocalNode: NewLocal,
    iterableType: Option[String],
    lineNo: Option[Integer]
  ): Ast =
    val iteratorAssignNode =
        newOperatorCallNode(
          Operators.assignment,
          code = "",
          typeFullName = Some(TypeConstants.Iterator),
          line = lineNo
        )
    val iteratorAssignIdentifier =
        identifierNode(
          iterExpr,
          iteratorLocalNode.name,
          iteratorLocalNode.name,
          iteratorLocalNode.typeFullName
        )

    val iteratorCallNode =
        newCallNode(
          "iterator",
          iterableType,
          TypeConstants.Iterator,
          DispatchTypes.DYNAMIC_DISPATCH,
          lineNumber = lineNo
        )

    val actualIteratorAst =
        astsForExpression(iterExpr, expectedType = ExpectedType.empty).toList match
          case Nil =>
              logger.debug(s"Could not create receiver ast for iterator $iterExpr")
              None

          case ast :: Nil => Some(ast)

          case ast :: _ =>
              logger.debug(
                s"Created multiple receiver asts for $iterExpr. Dropping all but the first."
              )
              Some(ast)

    val iteratorCallAst =
        callAst(iteratorCallNode, base = actualIteratorAst)

    callAst(iteratorAssignNode, List(Ast(iteratorAssignIdentifier), iteratorCallAst))
        .withRefEdge(iteratorAssignIdentifier, iteratorLocalNode)
  end iteratorAssignAstForForEach

  private def hasNextCallAstForForEach(
    iteratorLocalNode: NewLocal,
    lineNo: Option[Integer]
  ): Ast =
    val iteratorHasNextCallNode =
        newCallNode(
          "hasNext",
          Some(TypeConstants.Iterator),
          TypeConstants.Boolean,
          DispatchTypes.DYNAMIC_DISPATCH,
          lineNumber = lineNo
        )
    val iteratorHasNextCallReceiver =
        newIdentifierNode(iteratorLocalNode.name, iteratorLocalNode.typeFullName)

    callAst(iteratorHasNextCallNode, base = Some(Ast(iteratorHasNextCallReceiver)))
        .withRefEdge(iteratorHasNextCallReceiver, iteratorLocalNode)

  private def astForIterableForEachItemAssign(
    iteratorLocalNode: NewLocal,
    variableLocal: NewLocal
  ): Ast =
    val lineNo          = variableLocal.lineNumber
    val forVariableType = variableLocal.typeFullName
    val varLocalAssignNode =
        newOperatorCallNode(
          Operators.assignment,
          PropertyDefaults.Code,
          Some(forVariableType),
          lineNo
        )
    val varLocalAssignIdentifier =
        newIdentifierNode(variableLocal.name, variableLocal.typeFullName)

    val iterNextCallNode =
        newCallNode(
          "next",
          Some(TypeConstants.Iterator),
          TypeConstants.Object,
          DispatchTypes.DYNAMIC_DISPATCH,
          lineNumber = lineNo
        )
    val iterNextCallReceiver =
        newIdentifierNode(iteratorLocalNode.name, iteratorLocalNode.typeFullName)
    val iterNextCallAst =
        callAst(iterNextCallNode, base = Some(Ast(iterNextCallReceiver)))
            .withRefEdge(iterNextCallReceiver, iteratorLocalNode)

    callAst(varLocalAssignNode, List(Ast(varLocalAssignIdentifier), iterNextCallAst))
        .withRefEdge(varLocalAssignIdentifier, variableLocal)
  end astForIterableForEachItemAssign

  private def astForIterableForEach(stmt: ForEachStmt, iterableType: Option[String]): Seq[Ast] =
    val lineNo = line(stmt)

    val iteratorLocalNode = iteratorLocalForForEach(lineNo)
    val iteratorAssignAst =
        iteratorAssignAstForForEach(stmt.getIterable, iteratorLocalNode, iterableType, lineNo)
    val iteratorHasNextCallAst = hasNextCallAstForForEach(iteratorLocalNode, lineNo)
    val variableLocal          = variableLocalForForEachBody(stmt)
    val variableAssignAst      = astForIterableForEachItemAssign(iteratorLocalNode, variableLocal)

    val bodyPrefixAsts = Seq(Ast(variableLocal), variableAssignAst)
    val bodyAst = stmt.getBody match
      case block: BlockStmt =>
          astForBlockStatement(block, prefixAsts = bodyPrefixAsts)

      case bodyStmt =>
          val bodyBlockNode = NewBlock().lineNumber(lineNo)
          val bodyStmtAsts  = astsForStatement(bodyStmt)
          Ast(bodyBlockNode)
              .withChildren(bodyPrefixAsts)
              .withChildren(bodyStmtAsts)

    val forNode =
        NewControlStructure()
            .controlStructureType(ControlStructureTypes.WHILE)
            .code(ControlStructureTypes.FOR)
            .lineNumber(lineNo)
            .columnNumber(column(stmt))

    val forAst = controlStructureAst(forNode, Some(iteratorHasNextCallAst), List(bodyAst))

    Seq(Ast(iteratorLocalNode), iteratorAssignAst, forAst)
  end astForIterableForEach

  private def astForForEach(stmt: ForEachStmt): Seq[Ast] =
    scope.pushBlockScope()

    val ast = expressionReturnTypeFullName(stmt.getIterable) match
      case Some(typeFullName) if typeFullName.endsWith("[]") =>
          astsForNativeForEach(stmt, Some(typeFullName))

      case maybeType =>
          astForIterableForEach(stmt, maybeType)

    scope.popScope()
    ast

  private def astForSwitchStatement(stmt: SwitchStmt): Ast =
    val switchNode =
        NewControlStructure()
            .controlStructureType(ControlStructureTypes.SWITCH)
            .code(s"switch(${stmt.getSelector.toString})")

    val selectorAsts = astsForExpression(stmt.getSelector, ExpectedType.empty)
    val selectorNode = selectorAsts.head.root.get

    val entryAsts = stmt.getEntries.asScala.flatMap(entry =>
        astsForSwitchEntry(entry, selectorAsts, asExpressionValue = false)
    )

    val switchBodyAst = Ast(NewBlock()).withChildren(entryAsts)

    Ast(switchNode)
        .withChildren(selectorAsts)
        .withChild(switchBodyAst)
        .withConditionEdge(switchNode, selectorNode)

  /** A switch expression (Java 14+), lowered to nested `<operator>.conditional` calls.
    *
    * `switch (sel) { case A -> v1; case B -> v2; default -> v3 }` becomes `conditional(equals(sel,
    * A), v1, conditional(equals(sel, B), v2, v3))`, which gives the construct its `JLS 14.11.2`
    * dataflow for free: `<operator>.conditional` already propagates arguments 2 and 3 to its
    * result, so taint in any arm value flows to the expression's value, and the CFG treats each arm
    * value as a branch join.
    *
    * Pattern labels (`case Circle c`, Java 21) lower their test to an `instanceof` condition and
    * their bindings to locals assigned from the selector (see [[patternBindingAsts]]); a `when`
    * guard is ANDed into the arm condition. Block arms keep their non-yield statements - those run
    * before the arm's value is produced - and `yield e` contributes `e` as the arm value.
    *
    * The returned sequence carries the synthesized binding/side-effect ASTs first and the value
    * expression last, so callers that flatten the sequence into statement position keep source
    * order.
    */
  private def astsForSwitchExpr(expr: SwitchExpr, expectedType: ExpectedType): Seq[Ast] =
    val selectorAsts = astsForExpression(expr.getSelector, ExpectedType.empty)
    val entries      = expr.getEntries.asScala.toList

    val typeFullName = expressionReturnTypeFullName(expr)
        .orElse(expectedType.fullName)
        .getOrElse(TypeConstants.Any)

    /** A fresh copy of the selector expression, for the (one per arm) equality/instanceof tests.
      * The arms are mutually exclusive tests of the same value, so each test needs its own copy of
      * the selector's nodes rather than sharing one node across arms.
      */
    def selectorCopy: Ast = selectorAsts.headOption
        .flatMap { ast =>
            ast.root.collectFirst { case copyable: AstNodeNew => ast.subTreeCopy(copyable) }
        }
        .getOrElse(Ast())

    // Per entry: (conditionAst, valueAst, bindingAndSideEffectAsts). The default entry (no
    // labels) has no condition and lands innermost.
    case class Arm(condition: Option[Ast], value: Ast, prefix: Seq[Ast])

    val armValues = entries.map { entry =>
      val prefix = mutable.Buffer.empty[Ast]

      // Bindings of every pattern label of this entry alias the selector.
      entry.getLabels.asScala.foreach {
          case pattern: PatternExpr =>
              prefix.appendAll(
                patternBindingAsts(pattern, matchedExprAsts = selectorAsts, anchor = entry)
              )
          case _ =>
      }

      val conditionParts = entry.getLabels.asScala.toList.flatMap { label =>
          label match
            case pattern: PatternExpr => patternLabelTestAst(pattern, selectorAsts)
            case _                    =>
                // A constant label compares the selector for equality.
                val labelAsts = astsForExpression(label, ExpectedType.empty)
                val equalsCall = newOperatorCallNode(
                  Operators.equals,
                  code = s"${selectorAsts.rootCodeOrEmpty} == ${labelAsts.rootCodeOrEmpty}",
                  typeFullName = Some(TypeConstants.Boolean),
                  line = line(label),
                  column = column(label)
                )
                Some(callAst(equalsCall, Seq(selectorCopy) ++ labelAsts))
      }

      // `case A, B -> ...` matches either label; the guard narrows further.
      val withGuard = entry.getGuard.toScala.map { guard =>
        val guardAsts = astsForExpression(guard, ExpectedType.Boolean)
        val andCall = newOperatorCallNode(
          Operators.logicalAnd,
          code = guardAsts.rootCodeOrEmpty,
          typeFullName = Some(TypeConstants.Boolean),
          line = line(entry),
          column = column(entry)
        )
        callAst(andCall, guardAsts)
      }

      val condition = (conditionParts, withGuard) match
        case (Nil, None)        => None
        case (parts, None)      => Some(orTogether(parts))
        case (Nil, Some(guard)) => Some(guard)
        case (parts, Some(guard)) =>
            val or = orTogether(parts)
            val andCall = newOperatorCallNode(
              Operators.logicalAnd,
              code = s"${or.rootCodeOrEmpty} && ${guard.rootCodeOrEmpty}",
              typeFullName = Some(TypeConstants.Boolean),
              line = line(entry),
              column = column(entry)
            )
            Some(callAst(andCall, Seq(or, guard)))

      // The arm value: an EXPRESSION entry's single statement expression, or the yielded
      // expression of a BLOCK / STATEMENT_GROUP arm.
      val valueAst: Ast = entry.getType match
        case SwitchEntry.Type.EXPRESSION =>
            entry.getStatements.asScala.headOption
                .collect { case exprStmt: ExpressionStmt =>
                    astsForExpression(exprStmt.getExpression, expectedType)
                }
                .getOrElse(Seq.empty)
                .headOption
                .getOrElse(Ast())
        case SwitchEntry.Type.THROWS_STATEMENT =>
            entry.getStatements.asScala.headOption
                .map(stmt => astsForStatement(stmt))
                .getOrElse(Seq.empty)
                .headOption.getOrElse(Ast())
        case _ =>
            // A BLOCK arm (`case 1 -> { ... }`) carries its statements wrapped in a single
            // BlockStmt; a STATEMENT_GROUP colon arm carries them directly. Unwrap the block
            // so the arm's side effects land in the prefix and `yield` is found as the value.
            val statements = entry.getStatements.asScala.toList.flatMap {
                case block: BlockStmt => block.getStatements.asScala.toList
                case other            => List(other)
            }
            statements.foreach {
                case stmt: YieldStmt => // the value, extracted below
                case other           => prefix.appendAll(astsForStatement(other))
            }
            statements
                .collectFirst { case yieldStmt: YieldStmt => yieldStmt }
                .map(yieldStmt => astsForExpression(yieldStmt.getExpression, expectedType))
                .getOrElse(Seq.empty)
                .headOption.getOrElse(Ast())

      Arm(condition, valueAst, prefix.toList)
    }

    val defaultArm = armValues.find(_.condition.isEmpty)
    val casedArms  = armValues.filter(_.condition.isDefined)

    val nested = casedArms.foldRight(defaultArm.map(_.value).getOrElse(Ast())) { (arm, elseAst) =>
      val conditionalCall = newOperatorCallNode(
        Operators.conditional,
        code = s"switch (${expr.getSelector.toString})",
        typeFullName = Some(typeFullName),
        line = line(expr),
        column = column(expr)
      )
      callAst(conditionalCall, Seq(arm.condition.get, arm.value, elseAst))
    }

    val prefixes = armValues.flatMap(_.prefix)

    // The pattern bindings and block-arm side effects must NOT hang off the value expression:
    // an expression-position switch (`String v = switch ...`, `return switch ...`) funnels its
    // value into an ARGUMENT slot, and ARGUMENT edges into LOCAL/BLOCK nodes violate the schema
    // (see [[Scope.registerPatternLocalAst]]). Statements tucked under the conditional call are
    // also invisible to reaching definitions, because the declared `<operator>.conditional`
    // semantic only maps the value arms - a binding def inside the condition subtree never
    // reaches an arm's use of the binding. The binding LOCAL therefore goes to the scope
    // channel (direct child of the body BLOCK), and the binding assignments and arm side
    // effects are returned as LEADING ASTs, which [[astsForVariableDecl]] and
    // [[astForReturnNode]] hoist into statement position before their expression.
    prefixes.foreach { prefix =>
        if prefix.root.exists(_.isInstanceOf[NewLocal]) then scope.registerPatternLocalAst(prefix)
    }
    val hoisted = prefixes.filterNot(p => p.root.exists(_.isInstanceOf[NewLocal]))
    hoisted :+ nested
  end astsForSwitchExpr

  /** `yield e;` reached in statement position (Java 14 switch expressions).
    *
    * The switch-expression lowering extracts yield values directly from arm blocks, so this path is
    * only reached for malformed or future positions. The value expression is preserved as the
    * argument of a `yield` call so its calls, identifiers and taint steps survive.
    */
  private def astForYieldStatement(stmt: YieldStmt): Ast =
    val valueAsts =
        astsForExpression(
          stmt.getExpression,
          scope.enclosingMethodReturnType.getOrElse(
            ExpectedType.empty
          )
        )
    val callNode = newOperatorCallNode(
      "<operator>.yield",
      code = stmt.toString,
      typeFullName = valueAsts.headOption.flatMap(_.rootType),
      line = line(stmt),
      column = column(stmt)
    )
    callAst(callNode, valueAsts)

  /** `orTogether`: a chain of `<operator>.logicalOr` calls over the conditions of a multi-label
    * `case A, B ->` entry.
    */
  private def orTogether(conditions: Seq[Ast]): Ast =
      conditions match
        case Nil           => Ast()
        case single +: Nil => single
        case head +: tail =>
            val orCall = newOperatorCallNode(
              Operators.logicalOr,
              code = (head +: tail).map(_.rootCodeOrEmpty).mkString(" || "),
              typeFullName = Some(TypeConstants.Boolean),
              line = None,
              column = None
            )
            callAst(orCall, head +: tail)

  /** A method reference (`System.out::println`, `this::handler`, Java 8).
    *
    * Lowered to a METHOD_REF node - the same shape a lambda lowers to - so a framework registration
    * that takes a functional interface (`.handler(this::handle)`, gRPC `StreamObserver::onNext`)
    * exposes the referenced method for call-graph and route resolution. Resolution is best effort:
    * without the declaring type on the classpath the symbol solver cannot qualify the method, and
    * the node then carries the source form as its code with the identifier as the name hint.
    */
  private def astForMethodReferenceExpr(expr: MethodReferenceExpr): Ast =
    val maybeResolved = tryWithSafeStackOverflow(expr.resolve()).toOption
    val code          = expr.toString
    val methodFullName = maybeResolved.map { resolved =>
      val signature = composeUnresolvedSignature(resolved.getNumberOfParams)
      composeMethodFullName(
        resolved.declaringType().getQualifiedName,
        resolved.getName,
        signature
      )
    }.orElse(Option(code))
    val typeFullName = maybeResolved
        .flatMap(resolved =>
            tryWithSafeStackOverflow(typeInfoCalc.fullName(resolved.getReturnType)).toOption
                .flatten
        )
        .orElse(Option(TypeConstants.Any))
    Ast(
      NewMethodRef()
          .methodFullName(methodFullName.getOrElse(code))
          .typeFullName(typeFullName.getOrElse(TypeConstants.Any))
          .code(code)
    )
  end astForMethodReferenceExpr

  /** A class or record declared inside a method body (Java 16 local classes/records).
    *
    * The declaration is lowered with the shared type-decl machinery and attached to the enclosing
    * METHOD, so its methods, fields and constructors are first-class graph citizens and calls such
    * as `new Point(1, 2).x()` resolve.
    */
  private def astForLocalTypeDeclaration(
    declaration: TypeDeclaration[?],
    stmt: Statement
  ): Seq[Ast] =
    val astParentFullName = scope.enclosingTypeDeclFullName.getOrElse(
      Defines.UnresolvedNamespace
    )
    Seq(astForTypeDecl(declaration, NodeTypes.METHOD, astParentFullName))

  private def astForSynchronizedStatement(stmt: SynchronizedStmt): Ast =
    val parentNode =
        NewBlock()
            .lineNumber(line(stmt))
            .columnNumber(column(stmt))

    val modifier = Ast(newModifierNode("SYNCHRONIZED"))

    val exprAsts = astsForExpression(stmt.getExpression, ExpectedType.empty)
    val bodyAst  = astForBlockStatement(stmt.getBody)

    Ast(parentNode)
        .withChild(modifier)
        .withChildren(exprAsts)
        .withChild(bodyAst)

  /** The case labels of one switch entry, as JUMP_TARGET markers plus label expressions.
    *
    * A constant label (`case 1`) keeps its expression as before. A pattern label (Java 21, `case
    * Circle c` / `case Rect(double w, double h)`) has no runtime constant to compare, so the jump
    * target alone carries the label text and the pattern's bindings are lowered by
    * [[astsForSwitchEntry]] as selector aliases; the pattern's `instanceof` test is part of the arm
    * condition when the enclosing switch lowers as an expression.
    */
  private def astsForSwitchCases(entry: SwitchEntry, selectorAsts: Seq[Ast]): Seq[Ast] =
      entry.getLabels.asScala.toList match
        case Nil =>
            val target = NewJumpTarget()
                .name("default")
                .code("default")
            Seq(Ast(target))

        case labels =>
            labels.flatMap { label =>
              val jumpTarget = NewJumpTarget()
                  .name("case")
                  .code(label.toString)
              label match
                // A pattern's bindings are locals aliased to the selector; the pattern's own
                // expression node must not be lowered as an ordinary expression (it is not
                // one - `Circle c` is a declaration).
                case pattern: PatternExpr =>
                    Seq(Ast(jumpTarget)) ++ patternBindingAsts(
                      pattern,
                      matchedExprAsts = selectorAsts,
                      anchor = pattern
                    )
                case _ =>
                    val labelAsts = astsForExpression(label, ExpectedType.empty).toList
                    Seq(Ast(jumpTarget)) ++ labelAsts
            }

  /** One switch entry of a STATEMENT-form switch: labels (with pattern bindings), then the `when`
    * guard condition, then the entry statements.
    */
  private def astsForSwitchEntry(
    entry: SwitchEntry,
    selectorAsts: Seq[Ast],
    asExpressionValue: Boolean
  ): Seq[Ast] =
    val labelAsts = astsForSwitchCases(entry, selectorAsts)

    val guardAsts = entry.getGuard.toScala.toList.flatMap { guard =>
        astsForExpression(guard, ExpectedType.Boolean)
    }

    val statementAsts = entry.getStatements.asScala.flatMap(astsForStatement)

    labelAsts ++ guardAsts ++ statementAsts

  private def astForAssertStatement(stmt: AssertStmt): Ast =
    val callNode = NewCall()
        .name("assert")
        .methodFullName("assert")
        .dispatchType(DispatchTypes.STATIC_DISPATCH)
        .code(stmt.toString)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))

    val args = astsForExpression(stmt.getCheck, ExpectedType.Boolean)
    callAst(callNode, args)

  private def astForBlockStatement(
    stmt: BlockStmt,
    codeStr: String = "<empty>",
    prefixAsts: Seq[Ast] = Seq.empty
  ): Ast =

    val block = NewBlock()
        .code(codeStr)
        .lineNumber(line(stmt))
        .columnNumber(column(stmt))

    scope.pushBlockScope()

    val stmtAsts = stmt.getStatements.asScala.flatMap(astsForStatement)

    scope.popScope()
    Ast(block)
        .withChildren(prefixAsts)
        .withChildren(stmtAsts)
  end astForBlockStatement

  private def astForReturnNode(ret: ReturnStmt): Seq[Ast] =
    val returnNode = NewReturn()
        .lineNumber(line(ret))
        .columnNumber(column(ret))
        .code(ret.toString)
    if ret.getExpression.isPresent then
      val expectedType = scope.enclosingMethodReturnType.getOrElse(ExpectedType.empty)
      val exprAsts     = astsForExpression(ret.getExpression.get(), expectedType)
      // A `return switch (...)` with pattern/block arms carries leading statements; they run
      // before the return's value is produced.
      val (leading, valueAsts) = hoistExpressionAsts(exprAsts)
      leading ++ List(returnAst(returnNode, valueAsts))
    else
      List(Ast(returnNode))

  private def astForUnaryExpr(expr: UnaryExpr, expectedType: ExpectedType): Ast =
    val operatorName = expr.getOperator match
      case UnaryExpr.Operator.LOGICAL_COMPLEMENT => Operators.logicalNot
      case UnaryExpr.Operator.POSTFIX_DECREMENT  => Operators.postDecrement
      case UnaryExpr.Operator.POSTFIX_INCREMENT  => Operators.postIncrement
      case UnaryExpr.Operator.PREFIX_DECREMENT   => Operators.preDecrement
      case UnaryExpr.Operator.PREFIX_INCREMENT   => Operators.preIncrement
      case UnaryExpr.Operator.BITWISE_COMPLEMENT => Operators.not
      case UnaryExpr.Operator.PLUS               => Operators.plus
      case UnaryExpr.Operator.MINUS              => Operators.minus

    val argsAsts = astsForExpression(expr.getExpression, expectedType)

    val typeFullName =
        expressionReturnTypeFullName(expr)
            .orElse(argsAsts.headOption.flatMap(_.rootType))
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)

    val callNode = newOperatorCallNode(
      operatorName,
      code = expr.toString,
      typeFullName = Some(typeFullName),
      line = line(expr),
      column = column(expr)
    )

    callAst(callNode, argsAsts)
  end astForUnaryExpr

  private def astForArrayAccessExpr(expr: ArrayAccessExpr, expectedType: ExpectedType): Ast =
    val typeFullName =
        expressionReturnTypeFullName(expr)
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)
    val callNode = newOperatorCallNode(
      Operators.indexAccess,
      code = expr.toString,
      typeFullName = Some(typeFullName),
      line = line(expr),
      column = column(expr)
    )

    val arrayExpectedType = expectedType.copy(fullName = expectedType.fullName.map(_ ++ "[]"))
    val nameAst           = astsForExpression(expr.getName, arrayExpectedType)
    val indexAst          = astsForExpression(expr.getIndex, ExpectedType.Int)
    val args              = nameAst ++ indexAst
    callAst(callNode, args)

  private def astForArrayCreationExpr(expr: ArrayCreationExpr, expectedType: ExpectedType): Ast =
    val elementType = tryWithSafeStackOverflow(expr.getElementType.resolve()).map(elementType =>
        ExpectedType(typeInfoCalc.fullName(elementType).map(_ ++ "[]"), Option(elementType))
    )
    val maybeInitializerAst =
        expr.getInitializer.toScala.map(astForArrayInitializerExpr(
          _,
          elementType.getOrElse(expectedType)
        ))

    maybeInitializerAst.flatMap(_.root) match
      case Some(initializerRoot: NewCall) => initializerRoot.code(expr.toString)
      case _                              => // This should never happen
    maybeInitializerAst.getOrElse {
        val typeFullName = expressionReturnTypeFullName(expr).orElse(
          expectedType.fullName
        ).getOrElse(TypeConstants.Any)
        val callNode = newOperatorCallNode(
          Operators.alloc,
          code = expr.toString,
          typeFullName = Some(typeFullName)
        )
        val levelAsts = expr.getLevels.asScala.flatMap { lvl =>
            lvl.getDimension.toScala match
              case Some(dimension) => astsForExpression(dimension, ExpectedType.Int)

              case None => Seq.empty
        }.toSeq
        callAst(callNode, levelAsts)
    }
  end astForArrayCreationExpr

  private def astForArrayInitializerExpr(
    expr: ArrayInitializerExpr,
    expectedType: ExpectedType
  ): Ast =
    val typeFullName = expectedType.fullName
        .map(typeInfoCalc.registerType)
        .getOrElse(TypeConstants.Any)
    val callNode = newOperatorCallNode(
      Operators.arrayInitializer,
      code = expr.toString,
      typeFullName = Some(typeFullName),
      line = line(expr),
      column = column(expr)
    )

    val MAX_INITIALIZERS = 1000

    val expectedValueType = expr.getValues.asScala.headOption.map { value =>
      // typeName and resolvedType may represent different types since typeName can fall
      // back to known information or primitive types. While this certainly isn't ideal,
      // it shouldn't cause issues since resolvedType is only used where the extra type
      // information not available in typeName is necessary.
      val typeName     = expressionReturnTypeFullName(value)
      val resolvedType = tryWithSafeStackOverflow(value.calculateResolvedType()).toOption
      ExpectedType(typeName, resolvedType)
    }
    val args = expr.getValues.asScala
        .slice(0, MAX_INITIALIZERS)
        .flatMap(astsForExpression(_, expectedValueType.getOrElse(ExpectedType.empty)))
        .toSeq

    val ast = callAst(callNode, args)

    if expr.getValues.size() > MAX_INITIALIZERS then
      val placeholder = NewLiteral()
          .typeFullName(TypeConstants.Any)
          .code("<too-many-initializers>")
          .lineNumber(line(expr))
          .columnNumber(column(expr))
      ast.withChild(Ast(placeholder)).withArgEdge(callNode, placeholder)
    else
      ast
  end astForArrayInitializerExpr

  def astForBinaryExpr(expr: BinaryExpr, expectedType: ExpectedType): Ast =
    val operatorName = expr.getOperator match
      case BinaryExpr.Operator.OR                   => Operators.logicalOr
      case BinaryExpr.Operator.AND                  => Operators.logicalAnd
      case BinaryExpr.Operator.BINARY_OR            => Operators.or
      case BinaryExpr.Operator.BINARY_AND           => Operators.and
      case BinaryExpr.Operator.DIVIDE               => Operators.division
      case BinaryExpr.Operator.EQUALS               => Operators.equals
      case BinaryExpr.Operator.GREATER              => Operators.greaterThan
      case BinaryExpr.Operator.GREATER_EQUALS       => Operators.greaterEqualsThan
      case BinaryExpr.Operator.LESS                 => Operators.lessThan
      case BinaryExpr.Operator.LESS_EQUALS          => Operators.lessEqualsThan
      case BinaryExpr.Operator.LEFT_SHIFT           => Operators.shiftLeft
      case BinaryExpr.Operator.SIGNED_RIGHT_SHIFT   => Operators.logicalShiftRight
      case BinaryExpr.Operator.UNSIGNED_RIGHT_SHIFT => Operators.arithmeticShiftRight
      case BinaryExpr.Operator.XOR                  => Operators.xor
      case BinaryExpr.Operator.NOT_EQUALS           => Operators.notEquals
      case BinaryExpr.Operator.PLUS                 => Operators.addition
      case BinaryExpr.Operator.MINUS                => Operators.subtraction
      case BinaryExpr.Operator.MULTIPLY             => Operators.multiplication
      case BinaryExpr.Operator.REMAINDER            => Operators.modulo

    val args =
        astsForExpression(expr.getLeft, expectedType) ++ astsForExpression(
          expr.getRight,
          expectedType
        )

    val typeFullName =
        expressionReturnTypeFullName(expr)
            .orElse(args.headOption.flatMap(_.rootType))
            .orElse(args.lastOption.flatMap(_.rootType))
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)

    val callNode = newOperatorCallNode(
      operatorName,
      code = expr.toString,
      typeFullName = Some(typeFullName),
      line = line(expr),
      column = column(expr)
    )

    callAst(callNode, args)
  end astForBinaryExpr

  private def astForCastExpr(expr: CastExpr, expectedType: ExpectedType): Ast =
    val typeFullName =
        typeInfoCalc
            .fullName(expr.getType)
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)

    val callNode = newOperatorCallNode(
      Operators.cast,
      code = expr.toString,
      typeFullName = Some(typeFullName),
      line = line(expr),
      column = column(expr)
    )

    val typeNode = NewTypeRef()
        .code(expr.getType.toString)
        .lineNumber(line(expr))
        .columnNumber(column(expr))
        .typeFullName(typeFullName)
    val typeAst = Ast(typeNode)

    val exprAst = astsForExpression(expr.getExpression, ExpectedType.empty)

    callAst(callNode, Seq(typeAst) ++ exprAst)
  end astForCastExpr

  private def astsForAssignExpr(expr: AssignExpr, expectedExprType: ExpectedType): Seq[Ast] =
    val operatorName = expr.getOperator match
      case Operator.ASSIGN               => Operators.assignment
      case Operator.PLUS                 => Operators.assignmentPlus
      case Operator.MINUS                => Operators.assignmentMinus
      case Operator.MULTIPLY             => Operators.assignmentMultiplication
      case Operator.DIVIDE               => Operators.assignmentDivision
      case Operator.BINARY_AND           => Operators.assignmentAnd
      case Operator.BINARY_OR            => Operators.assignmentOr
      case Operator.XOR                  => Operators.assignmentXor
      case Operator.REMAINDER            => Operators.assignmentModulo
      case Operator.LEFT_SHIFT           => Operators.assignmentShiftLeft
      case Operator.SIGNED_RIGHT_SHIFT   => Operators.assignmentArithmeticShiftRight
      case Operator.UNSIGNED_RIGHT_SHIFT => Operators.assignmentLogicalShiftRight

    val maybeResolvedType = Try(expr.getTarget.calculateResolvedType()).toOption
    val expectedType = maybeResolvedType
        .map { resolvedType =>
            ExpectedType(typeInfoCalc.fullName(resolvedType), Some(resolvedType))
        }
        .getOrElse(expectedExprType) // resolved target type should be more accurate
    val targetAst = astsForExpression(expr.getTarget, expectedType)
    val argsAsts  = astsForExpression(expr.getValue, expectedType)
    val valueType = argsAsts.headOption.flatMap(_.rootType)

    val typeFullName =
        targetAst.headOption
            .flatMap(_.rootType)
            .orElse(valueType)
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)

    val code =
        s"${targetAst.rootCodeOrEmpty} ${expr.getOperator.asString} ${argsAsts.rootCodeOrEmpty}"

    val callNode =
        newOperatorCallNode(operatorName, code, Some(typeFullName), line(expr), column(expr))

    if partialConstructorQueue.isEmpty then
      val assignAst = callAst(callNode, targetAst ++ argsAsts)
      Seq(assignAst)
    else
      val partialConstructor = partialConstructorQueue.head
      partialConstructorQueue.clear()

      targetAst.flatMap(_.root).toList match
        case List(identifier: NewIdentifier) =>
            // In this case we have a simple assign. No block needed.
            // e.g. Foo f = new Foo();
            val initAst =
                completeInitForConstructor(partialConstructor, Ast(identifier.copy))
            Seq(callAst(callNode, targetAst ++ argsAsts), initAst)

        case _ =>
            // In this case the left hand side is more complex than an identifier, so
            // we need to contain the constructor in a block.
            // e.g. items[10] = new Foo();
            val valueAst = partialConstructor.blockAst
            Seq(callAst(callNode, targetAst ++ Seq(valueAst)))
    end if
  end astsForAssignExpr

  private def localsForVarDecl(varDecl: VariableDeclarationExpr): List[NewLocal] =
      varDecl.getVariables.asScala.map { variable =>
        val name = variable.getName.toString
        val initialTypeFullName =
            tryWithSafeStackOverflow(typeInfoCalc.fullName(variable.getType))
                .toOption
                .flatten
                .orElse(scope.lookupType(variable.getTypeAsString))
                .getOrElse(TypeConstants.Any)
        val typeFullName =
            if initialTypeFullName.isEmpty then variable.getTypeAsString
            else initialTypeFullName
        val code = s"${variable.getTypeAsString} $name"
        NewLocal()
            .name(name)
            .code(code)
            .typeFullName(typeFullName)
            .lineNumber(line(varDecl))
            .columnNumber(column(varDecl))
      }.toList

  private def copyAstForVarDeclInit(targetAst: Ast): Ast =
      targetAst.root match
        case Some(identifier: NewIdentifier) => Ast(identifier.copy)

        case Some(fieldAccess: NewCall) if fieldAccess.name == Operators.fieldAccess =>
            val maybeIdentifier = targetAst.nodes.collectFirst {
                case node if node.isInstanceOf[NewIdentifier] => node
            }
            val maybeField = targetAst.nodes.collectFirst {
                case node if node.isInstanceOf[NewFieldIdentifier] => node
            }

            (maybeIdentifier, maybeField) match
              case (Some(identifier), Some(fieldIdentifier)) =>
                  val args = List(identifier, fieldIdentifier).map(node => Ast(node.copy))
                  callAst(fieldAccess.copy, args)

              case _ =>
                  Ast()

        case Some(root) =>
            Ast()

        case None =>
            Ast()

  private def assignmentsForVarDecl(
    variables: Iterable[VariableDeclarator],
    lineNumber: Option[Integer],
    columnNumber: Option[Integer]
  ): Seq[Ast] =
    val variablesWithInitializers =
        variables.filter(_.getInitializer.toScala.isDefined)
    val assignments = variablesWithInitializers.flatMap { variable =>
      val name        = variable.getName.toString
      val initializer = variable.getInitializer.toScala.get // Won't crash because of filter
      val initializerTypeFullName =
          variable.getInitializer.toScala.flatMap(expressionReturnTypeFullName)
      val javaParserVarType = variable.getTypeAsString
      val variableTypeFullName =
          tryWithSafeStackOverflow(typeInfoCalc.fullName(variable.getType)).toOption.flatten
              // TODO: Surely the variable being declared can't already be in scope?
              .orElse(scope.lookupVariable(name).typeFullName)
              .orElse(scope.lookupType(javaParserVarType))
      val (typeFullName, typeName) =
        val initialTypeFullName = variableTypeFullName.orElse(initializerTypeFullName)
        val initialTypeName = initialTypeFullName
            .map(TypeNodePass.fullToShortName)
            .getOrElse(guessTypeFullName(variable.getTypeAsString))

        if initialTypeName.isEmpty && variable.getTypeAsString.nonEmpty then
          (Some(variable.getTypeAsString), variable.getTypeAsString)
        else
          (initialTypeFullName, initialTypeName)
      // Need the actual resolvedType here for when the RHS is a lambda expression.
      val resolvedExpectedType =
          tryWithSafeStackOverflow(symbolSolver.toResolvedType(
            variable.getType,
            classOf[ResolvedType]
          )).toOption
      val initializerAsts =
          astsForExpression(initializer, ExpectedType(typeFullName, resolvedExpectedType))
      val code = s"$typeName $name = ${initializerAsts.rootCodeOrEmpty}"
      val callNode = newOperatorCallNode(
        Operators.assignment,
        code,
        typeFullName,
        lineNumber,
        columnNumber
      )

      val targetAst = scope.lookupVariable(name).getVariable() match
        // TODO: This definitely feels like a bug. Why is the found member not being used for anything?
        case Some(ScopeMember(_, false)) =>
            val thisType = scope.enclosingTypeDeclFullName
            fieldAccessAst(
              NameConstants.This,
              thisType,
              name,
              typeFullName,
              line(variable),
              column(variable)
            )

        case maybeCorrespNode =>
            val identifier = identifierNode(
              variable,
              name,
              name,
              typeFullName.getOrElse(TypeConstants.Any)
            )
            Ast(identifier).withRefEdges(identifier, maybeCorrespNode.map(_.node).toList)

      // Since all partial constructors will be dealt with here, don't pass them up. A switch
      // expression initializer with pattern/block arms carries leading statements (`k = sel`),
      // which belong before the assignment in statement position.
      val (leadingInitializerAsts, valueAsts) = hoistExpressionAsts(initializerAsts)
      val declAst                             = callAst(callNode, Seq(targetAst) ++ valueAsts)

      val constructorAsts = partialConstructorQueue.map(completeInitForConstructor(
        _,
        copyAstForVarDeclInit(targetAst)
      ))
      partialConstructorQueue.clear()

      leadingInitializerAsts ++ (Seq(declAst) ++ constructorAsts)
    }

    assignments.toList
  end assignmentsForVarDecl

  private def completeInitForConstructor(
    partialConstructor: PartialConstructor,
    targetAst: Ast
  ): Ast =
    val initNode = partialConstructor.initNode
    val args     = partialConstructor.initArgs

    targetAst.root match
      case Some(identifier: NewIdentifier) =>
          scope.lookupVariable(identifier.name).variableNode.foreach { variableNode =>
              diffGraph.addEdge(identifier, variableNode, EdgeTypes.REF)
          }

      case _ => // Nothing to do in this case
    callAst(initNode, args.toList, Some(targetAst))

  private def astsForVariableDecl(varDecl: VariableDeclarationExpr): Seq[Ast] =
    val locals    = localsForVarDecl(varDecl)
    val localAsts = locals.map { Ast(_) }

    locals.foreach { local =>
        scope.addLocal(local)
    }

    val assignments =
        assignmentsForVarDecl(varDecl.getVariables.asScala, line(varDecl), column(varDecl))

    localAsts ++ assignments

  private def astForClassExpr(expr: ClassExpr): Ast =
    val someTypeFullName = Some(TypeConstants.Class)
    val callNode = newOperatorCallNode(
      Operators.fieldAccess,
      expr.toString,
      someTypeFullName,
      line(expr),
      column(expr)
    )

    val identifierType = typeInfoCalc.fullName(expr.getType)
    val identifier = identifierNode(
      expr,
      expr.getTypeAsString,
      expr.getTypeAsString,
      identifierType.getOrElse("ANY")
    )
    val idAst = Ast(identifier)

    val fieldIdentifier = NewFieldIdentifier()
        .canonicalName("class")
        .code("class")
        .lineNumber(line(expr))
        .columnNumber(column(expr))
    val fieldIdAst = Ast(fieldIdentifier)

    callAst(callNode, Seq(idAst, fieldIdAst))
  end astForClassExpr

  private def astForConditionalExpr(expr: ConditionalExpr, expectedType: ExpectedType): Ast =
    val condAst = astsForExpression(expr.getCondition, ExpectedType.Boolean)
    val thenAst = astsForExpression(expr.getThenExpr, expectedType)
    val elseAst = astsForExpression(expr.getElseExpr, expectedType)

    val typeFullName =
        expressionReturnTypeFullName(expr)
            .orElse(thenAst.headOption.flatMap(_.rootType))
            .orElse(elseAst.headOption.flatMap(_.rootType))
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)

    val callNode =
        newOperatorCallNode(
          Operators.conditional,
          expr.toString,
          Some(typeFullName),
          line(expr),
          column(expr)
        )

    callAst(callNode, condAst ++ thenAst ++ elseAst)
  end astForConditionalExpr

  private def astForEnclosedExpression(expr: EnclosedExpr, expectedType: ExpectedType): Seq[Ast] =
      astsForExpression(expr.getInner, expectedType)

  private def astForFieldAccessExpr(expr: FieldAccessExpr, expectedType: ExpectedType): Ast =
    val typeFullName =
        expressionReturnTypeFullName(expr)
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)

    val callNode =
        newOperatorCallNode(
          Operators.fieldAccess,
          expr.toString,
          Some(typeFullName),
          line(expr),
          column(expr)
        )

    val fieldIdentifier = expr.getName
    val identifierAsts  = astsForExpression(expr.getScope, ExpectedType.empty)
    val fieldIdentifierNode = NewFieldIdentifier()
        .canonicalName(fieldIdentifier.toString)
        .lineNumber(line(fieldIdentifier))
        .columnNumber(column(fieldIdentifier))
        .code(fieldIdentifier.toString)
    val fieldIdAst = Ast(fieldIdentifierNode)

    callAst(callNode, identifierAsts ++ Seq(fieldIdAst))
  end astForFieldAccessExpr

  /** `instanceof` with an optional type pattern (Java 16+).
    *
    * Without a pattern this is the plain type test. With a pattern - `o instanceof String s` - the
    * binding `s` is definitely assigned when the test succeeds (`JLS 6.3`), so in addition to the
    * type-test call the pattern binding is lowered as a local plus an assignment from the tested
    * expression: a tainted tested value therefore taints the binding, which is exactly the taint
    * relation the source program has.
    */
  private def astForInstanceOfExpr(expr: InstanceOfExpr): Ast =
    val booleanTypeFullName = Some(TypeConstants.Boolean)
    val callNode =
        newOperatorCallNode(
          Operators.instanceOf,
          expr.toString,
          booleanTypeFullName,
          line(expr),
          column(expr)
        )

    val exprAst      = astsForExpression(expr.getExpression, ExpectedType.empty)
    val typeFullName = typeInfoCalc.fullName(expr.getType).getOrElse(TypeConstants.Any)
    val typeNode =
        NewTypeRef()
            .code(expr.getType.toString)
            .lineNumber(line(expr))
            .columnNumber(column(expr.getType))
            .typeFullName(typeFullName)
    val typeAst = Ast(typeNode)

    val testAst = callAst(callNode, exprAst ++ Seq(typeAst))
    expr.getPattern.toScala match
      case Some(pattern) =>
          // The binding ASTs (local + assignment) attach as children of the type-test call:
          // keeping them separate would put LOCAL nodes into ARGUMENT slots wherever the
          // `instanceof` itself sits in expression position (`sink(o instanceof String s)`).
          patternBindingAsts(
            pattern,
            matchedExprAsts = exprAst,
            anchor = expr.getExpression
          ).foldLeft(testAst)((acc, binding) => acc.withChild(binding))
      case None =>
          testAst
  end astForInstanceOfExpr

  /** Pattern bindings of a [[PatternExpr]], as local declarations plus assignments from the matched
    * value.
    *
    * A type pattern (`String s`) binds one variable of the pattern's type. A record pattern
    * (`Box(String content)`, Java 21) binds one variable per nested pattern; each component is an
    * alias of the matched record's component, and since components are retrieved positionally from
    * the matched value each binding aliases the matched value itself - conservative for taint (a
    * tainted record taints every bound component) and precise enough for definite assignment,
    * because the pattern only binds when the whole record matches.
    *
    * @param pattern
    *   the pattern to lower.
    * @param matchedExprAsts
    *   the AST(s) of the matched expression; when empty (a bare pattern in expression position,
    *   which the grammar does not produce) only the local declarations are emitted.
    * @param anchor
    *   a node used for line/column metadata of the synthesized local nodes.
    */
  private def patternBindingAsts(
    pattern: PatternExpr,
    matchedExprAsts: Seq[Ast],
    anchor: Node
  ): Seq[Ast] =
    def localFor(name: String, typeName: String, typeFullName: String): (NewLocal, Ast) =
      val local = NewLocal()
          .name(name)
          .code(s"$typeName $name")
          .typeFullName(typeFullName)
          .lineNumber(line(anchor))
          .columnNumber(column(anchor))
      scope.addLocal(local)
      (local, Ast(local))

    def assignmentFor(localAst: Ast, name: String, typeName: Option[String]): Option[Ast] =
        matchedExprAsts.headOption.flatMap { matchedAst =>
            matchedAst.root.collectFirst { case copyable: AstNodeNew => copyable }.map {
                matchedRoot =>
                  val identifier = newIdentifierNode(name, typeName.getOrElse(TypeConstants.Any))
                  val identifierAstWithRef =
                      Ast(identifier).withRefEdge(identifier, localAst.root.get)
                  val matchedCopy = matchedAst.subTreeCopy(matchedRoot)
                  val assignCall = newOperatorCallNode(
                    Operators.assignment,
                    code = s"$name = ${matchedExprAsts.rootCodeOrEmpty}",
                    typeFullName = typeName,
                    line = line(anchor),
                    column = column(anchor)
                  )
                  callAst(assignCall, Seq(identifierAstWithRef, matchedCopy))
            }
        }

    pattern match
      case typePattern: TypePatternExpr =>
          val name = typePattern.getNameAsString
          val typeFullName = tryWithSafeStackOverflow(
            typeInfoCalc.fullName(typePattern.getType)
          ).toOption.flatten.getOrElse(TypeConstants.Any)
          val (_, localAst) = localFor(name, typePattern.getTypeAsString, typeFullName)
          scope.registerPatternLocalAst(localAst)
          assignmentFor(localAst, name, Some(typeFullName)).toList

      case recordPattern: RecordPatternExpr =>
          recordPattern.getPatternList.asScala.flatMap { nested =>
              nested match
                case nestedTypePattern: TypePatternExpr =>
                    val name = nestedTypePattern.getNameAsString
                    val nestedTypeFullName = tryWithSafeStackOverflow(
                      typeInfoCalc.fullName(nestedTypePattern.getType)
                    ).toOption.flatten.getOrElse(TypeConstants.Any)
                    val (_, localAst) =
                        localFor(name, nestedTypePattern.getTypeAsString, nestedTypeFullName)
                    scope.registerPatternLocalAst(localAst)
                    assignmentFor(localAst, name, Some(nestedTypeFullName)).toList
                case nestedRecord: RecordPatternExpr =>
                    patternBindingAsts(nestedRecord, matchedExprAsts, anchor)
                case _ => Seq.empty
          }.toSeq

      case _ => Seq.empty
    end match
  end patternBindingAsts

  /** The type-test condition of a pattern `case` label, for use as the arm condition of a lowered
    * pattern switch: `<operator>.instanceOf(selector, <TypeRef>)`. Boolean patterns (`case null`)
    * and `default` labels have no test and the caller treats them specially.
    */
  private def patternLabelTestAst(
    label: Expression,
    selectorAsts: Seq[Ast]
  ): Option[Ast] =
      label match
        case pattern: PatternExpr =>
            val patternType = pattern match
              case typePattern: TypePatternExpr     => typePattern.getType
              case recordPattern: RecordPatternExpr => recordPattern.getType
              case _                                => null
            if patternType == null then None
            else
              val typeFullName =
                  tryWithSafeStackOverflow(typeInfoCalc.fullName(patternType))
                      .toOption.flatten.getOrElse(TypeConstants.Any)
              val callNode = newOperatorCallNode(
                Operators.instanceOf,
                code = s"${selectorAsts.rootCodeOrEmpty} instanceof ${patternType.toString}",
                typeFullName = Some(TypeConstants.Boolean),
                line = line(pattern),
                column = column(pattern)
              )
              val typeNode = NewTypeRef()
                  .code(patternType.toString)
                  .lineNumber(line(pattern))
                  .columnNumber(column(pattern))
                  .typeFullName(typeFullName)
              val selectorCopy = selectorAsts.headOption
                  .flatMap { ast =>
                      ast.root.collectFirst { case copyable: AstNodeNew =>
                          ast.subTreeCopy(copyable)
                      }
                  }
                  .getOrElse(Ast())
              Some(callAst(callNode, Seq(selectorCopy, Ast(typeNode))))
            end if
        case _ => None

  private def fieldAccessAst(
    identifierName: String,
    identifierType: Option[String],
    fieldIdentifierName: String,
    returnType: Option[String],
    lineNo: Option[Integer],
    columnNo: Option[Integer]
  ): Ast =
    val typeFullName =
        identifierType.orElse(Some(TypeConstants.Any)).map(typeInfoCalc.registerType)
    val identifier       = newIdentifierNode(identifierName, typeFullName.getOrElse("ANY"))
    val maybeCorrespNode = scope.lookupVariable(identifierName).variableNode

    val fieldIdentifier = NewFieldIdentifier()
        .code(fieldIdentifierName)
        .canonicalName(fieldIdentifierName)
        .lineNumber(lineNo)
        .columnNumber(columnNo)

    val fieldAccessCode = s"$identifierName.$fieldIdentifierName"
    val fieldAccess =
        newOperatorCallNode(
          Operators.fieldAccess,
          fieldAccessCode,
          returnType.orElse(Some(TypeConstants.Any)),
          lineNo,
          columnNo
        )

    val identifierAst = Ast(identifier)
    val fieldIdentAst = Ast(fieldIdentifier)

    callAst(fieldAccess, Seq(identifierAst, fieldIdentAst))
        .withRefEdges(identifier, maybeCorrespNode.toList)
  end fieldAccessAst

  private def astForNameExpr(nameExpr: NameExpr, expectedType: ExpectedType): Ast =
    val name = nameExpr.getName.toString
    val typeFullName = expressionReturnTypeFullName(nameExpr)
        .orElse(expectedType.fullName)
        .map(typeInfoCalc.registerType)

    tryWithSafeStackOverflow(nameExpr.resolve()) match
      case Success(value) if value.isField =>
          val identifierName = if value.asField.isStatic then
            // A static field represented by a NameExpr must belong to the class in which it's used. Static fields
            // from other classes are represented by a FieldAccessExpr instead.
            scope.enclosingTypeDecl.map(_.name).getOrElse(
              guessTypeFullName(name)
            )
          else
            NameConstants.This

          val identifierTypeFullName =
              value match
                case fieldDecl: ResolvedFieldDeclaration =>
                    // TODO It is not quite correct to use the declaring classes type.
                    // Instead we should take the using classes type which is either the same or a
                    // sub class of the declaring class.
                    typeInfoCalc.fullName(fieldDecl.declaringType())

          fieldAccessAst(
            identifierName,
            identifierTypeFullName,
            name,
            typeFullName,
            line(nameExpr),
            column(nameExpr)
          )

      case _ =>
          val identifier =
              identifierNode(nameExpr, name, name, typeFullName.getOrElse(TypeConstants.Any))

          val variableOption = scope
              .lookupVariable(name)
              .variableNode
              .collect {
                  case parameter: NewMethodParameterIn => parameter

                  case local: NewLocal => local
              }

          variableOption.foldLeft(Ast(identifier))((ast, variableNode) =>
              ast.withRefEdge(identifier, variableNode)
          )
    end match
  end astForNameExpr

  private def argumentTypesForMethodLike(
    maybeResolvedMethodLike: Try[ResolvedMethodLikeDeclaration]
  ): Option[List[String]] =
      maybeResolvedMethodLike.toOption
          .flatMap(calcParameterTypes(_, ResolvedTypeParametersMap.empty()))

  private def returnTypeForAstMethod(methodDecl: MethodDeclaration): Option[String] =
      typeInfoCalc
          .fullName(methodDecl.getType)
          .orElse(scope.lookupType(methodDecl.getTypeAsString))

  private def parameterTypesForAstMethod(methodDecl: MethodDeclaration): Option[List[String]] =
    val parameterTypes = methodDecl.getParameters.asScala.toList.map { parameter =>
        typeInfoCalc
            .fullName(parameter.getType)
            .orElse(scope.lookupType(parameter.getTypeAsString))
    }
    toOptionList(parameterTypes)

  private lazy val typeDeclsInUnitByName: Map[String, List[TypeDeclaration[?]]] =
      javaParserAst
          .findAll(classOf[TypeDeclaration[?]])
          .asScala
          .toList
          .groupBy(_.getNameAsString)

  private def findTypeDeclInUnit(typeName: String): Option[TypeDeclaration[?]] =
      typeDeclsInUnitByName.get(typeName).flatMap(_.headOption)

  private def findMethodInTypeHierarchy(
    typeDecl: TypeDeclaration[?],
    methodName: String,
    arity: Int
  ): Option[MethodDeclaration] =
    val localMatch =
        typeDecl
            .getMethodsByName(methodName)
            .asScala
            .find(_.getParameters.size == arity)

    localMatch.orElse {
        typeDecl match
          case classOrInterface: ClassOrInterfaceDeclaration =>
              classOrInterface.getExtendedTypes.asScala.toList
                  .flatMap(typ => findTypeDeclInUnit(typ.getNameAsString))
                  .view
                  .flatMap(findMethodInTypeHierarchy(_, methodName, arity))
                  .headOption
          case _ => None
    }
  end findMethodInTypeHierarchy

  private def unresolvedImplicitThisMethod(call: MethodCallExpr): Option[MethodDeclaration] =
      call.getScope.toScala match
        case Some(_) => None
        case None =>
            call.findAncestor(classOf[TypeDeclaration[?]]).toScala.flatMap { enclosingType =>
                findMethodInTypeHierarchy(
                  enclosingType,
                  call.getNameAsString,
                  call.getArguments.size
                )
            }

  private def initNode(
    namespaceName: Option[String],
    argumentTypes: Option[List[String]],
    argsSize: Int,
    code: String,
    lineNumber: Option[Integer] = None,
    columnNumber: Option[Integer] = None
  ): NewCall =
    val initSignature = argumentTypes match
      case Some(tpe)          => composeMethodLikeSignature(TypeConstants.Void, tpe)
      case _ if argsSize == 0 => composeMethodLikeSignature(TypeConstants.Void, Nil)
      case _                  => composeUnresolvedSignature(argsSize)
    val namespace = namespaceName.getOrElse(Defines.UnresolvedNamespace)
    val initMethodFullName =
        composeMethodFullName(namespace, Defines.ConstructorMethodName, initSignature)
    NewCall()
        .name(Defines.ConstructorMethodName)
        .methodFullName(initMethodFullName)
        .signature(initSignature)
        .typeFullName(TypeConstants.Void)
        .code(code)
        .dispatchType(DispatchTypes.STATIC_DISPATCH)
        .lineNumber(lineNumber)
        .columnNumber(columnNumber)
  end initNode

  /** The below representation for constructor invocations and object creations was chosen for the
    * sake of consistency with the Java frontend. It follows the bytecode approach of splitting a
    * constructor call into separate `alloc` and `init` calls.
    *
    * There are two cases to consider. The first is a constructor invocation in an assignment, for
    * example:
    *
    * Foo f = new Foo(42);
    *
    * is represented as
    *
    * Foo f = <operator>.alloc() f.init(42);
    *
    * The second case is a constructor invocation not in an assignment, for example as an argument
    * to a method call. In this case, the representation does not stay as close to Java as in case
    *   1. In particular, a new BLOCK is introduced to contain the constructor invocation. For
    *      example:
    *
    * foo(new Foo(42));
    *
    * is represented as
    *
    * foo({ Foo temp = alloc(); temp.init(42); temp })
    *
    * This is not valid Java code, but this representation is a decent compromise between staying
    * faithful to Java and being consistent with the Java bytecode frontend.
    */
  private def astForObjectCreationExpr(
    expr: ObjectCreationExpr,
    expectedType: ExpectedType
  ): Ast =
    val maybeResolvedExpr = tryWithSafeStackOverflow(expr.resolve())
    val argumentAsts      = argAstsForCall(expr, maybeResolvedExpr, expr.getArguments)

    val typeFullName =
        tryWithSafeStackOverflow(typeInfoCalc.fullName(expr.getType)).toOption.flatten
            .orElse(scope.lookupType(expr.getTypeAsString))
            .orElse(expectedType.fullName)

    val argumentTypes = argumentTypesForMethodLike(maybeResolvedExpr)

    val allocNode = newOperatorCallNode(
      Operators.alloc,
      expr.toString,
      typeFullName.orElse(Some(TypeConstants.Any)),
      line(expr),
      column(expr)
    )

    val initCall = initNode(
      typeFullName.orElse(Some(TypeConstants.Any)),
      argumentTypes,
      argumentAsts.size,
      expr.toString,
      line(expr)
    )

    // Assume that a block ast is required, since there isn't enough information to decide otherwise.
    // This simplifies logic elsewhere, and unnecessary blocks will be garbage collected soon.
    val blockAst = blockAstForConstructorInvocation(
      line(expr),
      column(expr),
      allocNode,
      initCall,
      argumentAsts
    )

    expr.getParentNode.toScala match
      case Some(parent)
          if parent.isInstanceOf[VariableDeclarator] || parent.isInstanceOf[AssignExpr] =>
          val partialConstructor = PartialConstructor(initCall, argumentAsts, blockAst)
          partialConstructorQueue.append(partialConstructor)
          Ast(allocNode)

      case _ =>
          blockAst
  end astForObjectCreationExpr

  private var tempConstCount = 0
  private def blockAstForConstructorInvocation(
    lineNumber: Option[Integer],
    columnNumber: Option[Integer],
    allocNode: NewCall,
    initNode: NewCall,
    args: Seq[Ast]
  ): Ast =
    val blockNode = NewBlock()
        .lineNumber(lineNumber)
        .columnNumber(columnNumber)
        .typeFullName(allocNode.typeFullName)

    val tempName = "$obj" ++ tempConstCount.toString
    tempConstCount += 1
    val identifier    = newIdentifierNode(tempName, allocNode.typeFullName)
    val identifierAst = Ast(identifier)

    val allocAst = Ast(allocNode)

    val assignmentNode = newOperatorCallNode(
      Operators.assignment,
      PropertyDefaults.Code,
      Some(allocNode.typeFullName)
    )

    val assignmentAst = callAst(assignmentNode, List(identifierAst, allocAst))

    val identifierWithDefaultOrder = identifier.copy.order(PropertyDefaults.Order)
    val identifierForInit          = identifierWithDefaultOrder.copy
    val initWithDefaultOrder       = initNode.order(PropertyDefaults.Order)
    val initAst = callAst(initWithDefaultOrder, args, Some(Ast(identifierForInit)))

    val returnAst = Ast(identifierWithDefaultOrder.copy)

    Ast(blockNode)
        .withChild(assignmentAst)
        .withChild(initAst)
        .withChild(returnAst)
  end blockAstForConstructorInvocation

  private def astForThisExpr(expr: ThisExpr, expectedType: ExpectedType): Ast =
    val typeFullName =
        expressionReturnTypeFullName(expr)
            .orElse(expectedType.fullName)

    val identifier =
        identifierNode(expr, expr.toString, expr.toString, typeFullName.getOrElse("ANY"))
    val thisParam = scope.lookupVariable(NameConstants.This).variableNode

    thisParam.foreach { thisNode =>
        diffGraph.addEdge(identifier, thisNode, EdgeTypes.REF)
    }

    Ast(identifier)

  private def astForExplicitConstructorInvocation(stmt: ExplicitConstructorInvocationStmt): Ast =
    val maybeResolved = tryWithSafeStackOverflow(stmt.resolve())
    val args          = argAstsForCall(stmt, maybeResolved, stmt.getArguments)
    val argTypes      = argumentTypesForMethodLike(maybeResolved)

    val typeFullName = maybeResolved.toOption
        .map(_.declaringType())
        .flatMap(typeInfoCalc.fullName)

    val callRoot = initNode(
      typeFullName.orElse(Some(TypeConstants.Any)),
      argTypes,
      args.size,
      stmt.toString,
      line(stmt),
      column(stmt)
    )

    val thisNode =
        newIdentifierNode(NameConstants.This, typeFullName.getOrElse(TypeConstants.Any))
    scope.lookupVariable(NameConstants.This).variableNode.foreach { thisParam =>
        diffGraph.addEdge(thisNode, thisParam, EdgeTypes.REF)
    }
    val thisAst = Ast(thisNode)

    callAst(callRoot, args, Some(thisAst))
  end astForExplicitConstructorInvocation

  /** Splits the ASTs of an expression into leading statement-position ASTs and the value ASTs.
    *
    * A switch expression with pattern arms (Java 21) or block arms lowers to leading statements -
    * the pattern bindings (`k = selector`) and the arm side effects - followed by the value
    * expression itself. Only the value ASTs may take ARGUMENT slots of the enclosing construct; the
    * leading statements belong immediately before it, in statement position, where reaching
    * definitions can connect the binding's def to its uses inside the arms.
    */
  private def hoistExpressionAsts(asts: Seq[Ast]): (Seq[Ast], Seq[Ast]) =
      asts match
        case init :+ last if init.nonEmpty => (init, List(last))
        case other                         => (List.empty, other)

  private def astsForExpression(expression: Expression, expectedType: ExpectedType): Seq[Ast] =
      expression match
        case _: AnnotationExpr       => Seq()
        case x: ArrayAccessExpr      => Seq(astForArrayAccessExpr(x, expectedType))
        case x: ArrayCreationExpr    => Seq(astForArrayCreationExpr(x, expectedType))
        case x: ArrayInitializerExpr => Seq(astForArrayInitializerExpr(x, expectedType))
        case x: AssignExpr           => astsForAssignExpr(x, expectedType)
        case x: BinaryExpr           => Seq(astForBinaryExpr(x, expectedType))
        case x: CastExpr             => Seq(astForCastExpr(x, expectedType))
        case x: ClassExpr            => Seq(astForClassExpr(x))
        case x: ConditionalExpr      => Seq(astForConditionalExpr(x, expectedType))
        case x: EnclosedExpr         => astForEnclosedExpression(x, expectedType)
        case x: FieldAccessExpr      => Seq(astForFieldAccessExpr(x, expectedType))
        case x: InstanceOfExpr       => Seq(astForInstanceOfExpr(x))
        case x: LambdaExpr           => Seq(astForLambdaExpr(x, expectedType))
        case x: LiteralExpr          => Seq(astForLiteralExpr(x))
        case x: MethodCallExpr       => Seq(astForMethodCall(x, expectedType))
        case x: MethodReferenceExpr  => Seq(astForMethodReferenceExpr(x))
        case x: NameExpr             => Seq(astForNameExpr(x, expectedType))
        case x: ObjectCreationExpr   => Seq(astForObjectCreationExpr(x, expectedType))
        case x: PatternExpr => patternBindingAsts(x, matchedExprAsts = Seq.empty, anchor = x)
        case x: SuperExpr   => Seq(astForSuperExpr(x, expectedType))
        case x: SwitchExpr  => astsForSwitchExpr(x, expectedType)
        case x: ThisExpr    => Seq(astForThisExpr(x, expectedType))
        case x: UnaryExpr   => Seq(astForUnaryExpr(x, expectedType))
        case x: VariableDeclarationExpr => astsForVariableDecl(x)
        case x                          => Seq(unknownAst(x))

  private def unknownAst(node: Node): Ast = Ast(unknownNode(node, node.toString))

  private def someWithDotSuffix(prefix: String): Option[String] = Some(s"$prefix.")

  private def codeForScopeExpr(
    scopeExpr: Expression,
    isScopeForStaticCall: Boolean
  ): Option[String] =
      scopeExpr match
        case scope: NameExpr => someWithDotSuffix(scope.getNameAsString)

        case fieldAccess: FieldAccessExpr =>
            val maybeScopeString =
                codeForScopeExpr(fieldAccess.getScope, isScopeForStaticCall = false)
            val name = fieldAccess.getNameAsString
            maybeScopeString
                .map { scopeString =>
                    s"$scopeString$name"
                }
                .orElse(Some(name))
                .flatMap(someWithDotSuffix)

        case _: SuperExpr => someWithDotSuffix(NameConstants.Super)

        case _: ThisExpr => someWithDotSuffix(NameConstants.This)

        case scopeMethodCall: MethodCallExpr =>
            codePrefixForMethodCall(scopeMethodCall) match
              case "" => Some("")
              case prefix =>
                  val argumentsCode = getArgumentCodeString(scopeMethodCall.getArguments)
                  someWithDotSuffix(
                    s"$prefix${scopeMethodCall.getNameAsString}($argumentsCode)"
                  )

        case objectCreationExpr: ObjectCreationExpr =>
            val typeName        = objectCreationExpr.getTypeAsString
            val argumentsString = getArgumentCodeString(objectCreationExpr.getArguments)
            someWithDotSuffix(s"new $typeName($argumentsString)")

        case _ => None

  private def codePrefixForMethodCall(call: MethodCallExpr): String =
      tryWithSafeStackOverflow(call.resolve()) match
        case Success(resolvedCall) =>
            call.getScope.toScala
                .flatMap(codeForScopeExpr(_, resolvedCall.isStatic))
                .getOrElse(if resolvedCall.isStatic then "" else s"${NameConstants.This}.")

        case _ =>
            // If the call is unresolvable, we cannot make a good guess about what the prefix should be
            ""

  private def createObjectNode(
    typeFullName: Option[String],
    call: MethodCallExpr,
    dispatchType: String
  ): Option[NewIdentifier] =
    val maybeScope = call.getScope.toScala

    Option.when(maybeScope.isDefined || dispatchType == DispatchTypes.DYNAMIC_DISPATCH) {
        val name = maybeScope.map(_.toString).getOrElse(NameConstants.This)
        identifierNode(call, name, name, typeFullName.getOrElse("ANY"))
    }

  private def nextLambdaName(): String =
      s"$LambdaNamePrefix${lambdaKeyPool.next}"

  private def nextIndexName(): String =
      s"$IndexNamePrefix${indexKeyPool.next}"

  private def nextIterableName(): String =
      s"$IterableNamePrefix${iterableKeyPool.next}"

  private def genericParamTypeMapForLambda(expectedType: ExpectedType): ResolvedTypeParametersMap =
      expectedType.resolvedType
          // This should always be true for correct code
          .collect { case r: ResolvedReferenceType => r }
          .map(_.typeParametersMap())
          .getOrElse(new ResolvedTypeParametersMap.Builder().build())

  private def buildParamListForLambda(
    expr: LambdaExpr,
    maybeBoundMethod: Option[ResolvedMethodDeclaration],
    expectedTypeParamTypes: ResolvedTypeParametersMap
  ): Seq[Ast] =
    val lambdaParameters = expr.getParameters.asScala.toList
    val paramTypesList = maybeBoundMethod match
      case Some(resolvedMethod) =>
          val resolvedParameters =
              (0 until resolvedMethod.getNumberOfParams).map(resolvedMethod.getParam)

          // Substitute generic typeParam with the expected type if it can be found; leave unchanged otherwise.
          resolvedParameters.map(param => Try(param.getType)).map {
              case Success(resolvedType: ResolvedTypeVariable) =>
                  val typ = expectedTypeParamTypes.getValue(resolvedType.asTypeParameter)
                  typeInfoCalc.fullName(typ)

              case Success(resolvedType) => typeInfoCalc.fullName(resolvedType)

              case Failure(_) => None
          }

      case None =>
          // Unless types are explicitly specified in the lambda definition,
          // this will yield the erased types which is why the actual lambda
          // expression parameters are only used as a fallback.
          lambdaParameters
              .map(_.getType)
              .map(typeInfoCalc.fullName)

    if paramTypesList.sizeIs != lambdaParameters.size then
      logger.debug(
        s"Found different number lambda params and param types for $expr. Some parameters will be missing."
      )

    val parameterNodes = lambdaParameters
        .zip(paramTypesList)
        .zipWithIndex
        .map { case ((param, maybeType), idx) =>
            val name         = param.getNameAsString
            val typeFullName = maybeType.getOrElse(TypeConstants.Any)
            val code         = s"$typeFullName $name"
            val evalStrat =
                if param.getType.isPrimitiveType then EvaluationStrategies.BY_VALUE
                else EvaluationStrategies.BY_SHARING
            val paramNode = NewMethodParameterIn()
                .name(name)
                .index(idx + 1)
                .order(idx + 1)
                .code(code)
                .evaluationStrategy(evalStrat)
                .typeFullName(typeFullName)
                .lineNumber(line(expr))
                .columnNumber(column(expr))
            typeInfoCalc.registerType(typeFullName)
            paramNode
        }

    parameterNodes.foreach { paramNode =>
        scope.addParameter(paramNode)
    }

    parameterNodes.map(Ast(_))
  end buildParamListForLambda

  private def getLambdaReturnType(
    maybeResolvedLambdaType: Option[ResolvedType],
    maybeBoundMethod: Option[ResolvedMethodDeclaration],
    expectedTypeParamTypes: ResolvedTypeParametersMap
  ): Option[String] =
    val maybeBoundMethodReturnType = maybeBoundMethod.flatMap { boundMethod =>
        Try(boundMethod.getReturnType).collect {
            case returnType: ResolvedTypeVariable =>
                expectedTypeParamTypes.getValue(returnType.asTypeParameter)
            case other => other
        }.toOption
    }

    val returnType = maybeBoundMethodReturnType.orElse(maybeResolvedLambdaType)
    returnType.flatMap(typeInfoCalc.fullName)

  private def closureBindingsForCapturedNodes(lambdaMethodName: String): List[ClosureBindingEntry] =
      scope.capturedVariables.map { capturedNode =>
        val closureBindingId = s"$filename:$lambdaMethodName:${capturedNode.name}"
        val closureBindingNode =
            newClosureBindingNode(
              closureBindingId,
              capturedNode.name,
              EvaluationStrategies.BY_SHARING
            )
        passes.ClosureBindingEntry(capturedNode, closureBindingNode)
      }

  private def localsForCapturedNodes(closureBindingEntries: List[ClosureBindingEntry])
    : List[NewLocal] =
    val localsForCaptured =
        closureBindingEntries.map { case ClosureBindingEntry(node, binding) =>
            val local = NewLocal()
                .name(node.name)
                .code(node.name)
                .closureBindingId(binding.closureBindingId)
                .typeFullName(node.typeFullName)
            local
        }
    localsForCaptured.foreach { local => scope.addLocal(local) }
    localsForCaptured

  private def astForLambdaBody(
    body: Statement,
    localsForCapturedVars: Seq[NewLocal],
    returnType: Option[String]
  ): Ast =
      body match
        case block: BlockStmt =>
            astForBlockStatement(block, prefixAsts = localsForCapturedVars.map(Ast(_)))

        case stmt =>
            val blockAst = Ast(NewBlock().lineNumber(line(body)))
            val bodyAst = if returnType.contains(TypeConstants.Void) then
              astsForStatement(stmt)
            else
              val returnNode =
                  NewReturn()
                      .code(s"return ${body.toString}")
                      .lineNumber(line(body))
              val returnArgs = astsForStatement(stmt)
              Seq(returnAst(returnNode, returnArgs))

            // A lambda body lowering type patterns (`x instanceof String s` inside the lambda)
            // registers its pattern locals on the scope; drain them into this body block so they
            // are direct children of a BLOCK like any other local - see
            // [[Scope.registerPatternLocalAst]].
            val patternLocals = scope.takePatternLocalAsts

            blockAst
                .withChildren(localsForCapturedVars.map(Ast(_)))
                .withChildren(patternLocals)
                .withChildren(bodyAst)

  private def lambdaMethodSignature(returnType: Option[String], parameters: Seq[Ast]): String =
    val maybeParameterTypes = toOptionList(parameters.map(_.rootType))
    val containsEmptyType =
        maybeParameterTypes.exists(_.contains(ParameterDefaults.TypeFullName))

    (returnType, maybeParameterTypes) match
      case (Some(returnTpe), Some(parameterTpes)) if !containsEmptyType =>
          composeMethodLikeSignature(returnTpe, parameterTpes)

      case _ => composeUnresolvedSignature(parameters.size)

  private def createLambdaMethodNode(
    lambdaName: String,
    parameters: Seq[Ast],
    returnType: Option[String]
  ): NewMethod =
    val enclosingTypeName =
        scope.enclosingTypeDeclFullName.getOrElse(Defines.UnresolvedNamespace)
    val signature      = lambdaMethodSignature(returnType, parameters)
    val lambdaFullName = composeMethodFullName(enclosingTypeName, lambdaName, signature)

    NewMethod()
        .name(lambdaName)
        .fullName(lambdaFullName)
        .signature(signature)
        .filename(filename)
        .code("<lambda>")

  private def addClosureBindingsToDiffGraph(
    bindingEntries: Iterable[ClosureBindingEntry],
    methodRef: NewMethodRef
  ): Unit =
      bindingEntries.foreach { case ClosureBindingEntry(nodeTypeInfo, closureBinding) =>
          diffGraph.addNode(closureBinding)
          diffGraph.addEdge(closureBinding, nodeTypeInfo.node, EdgeTypes.REF)
          diffGraph.addEdge(methodRef, closureBinding, EdgeTypes.CAPTURE)
      }

  private def createAndPushLambdaMethod(
    expr: LambdaExpr,
    lambdaMethodName: String,
    implementedInfo: LambdaImplementedInfo,
    localsForCaptured: Seq[NewLocal],
    expectedLambdaType: ExpectedType
  ): NewMethod =
    val implementedMethod    = implementedInfo.implementedMethod
    val implementedInterface = implementedInfo.implementedInterface

    // We need to get this information from the expected type as the JavaParser
    // symbol solver returns the erased types when resolving the lambda itself.
    val expectedTypeParamTypes = genericParamTypeMapForLambda(expectedLambdaType)
    val parametersWithoutThis =
        buildParamListForLambda(expr, implementedMethod, expectedTypeParamTypes)

    val returnType =
        getLambdaReturnType(implementedInterface, implementedMethod, expectedTypeParamTypes)

    val lambdaMethodBody = astForLambdaBody(expr.getBody, localsForCaptured, returnType)

    val thisParam = lambdaMethodBody.nodes
        .collect { case identifier: NewIdentifier => identifier }
        .find { identifier =>
            identifier.name == NameConstants.This || identifier.name == NameConstants.Super
        }
        .map { _ =>
          val typeFullName = scope.enclosingTypeDeclFullName
          Ast(thisNodeForMethod(typeFullName, line(expr)))
        }
        .toList

    val parameters = thisParam ++ parametersWithoutThis

    val lambdaMethodNode =
        createLambdaMethodNode(lambdaMethodName, parametersWithoutThis, returnType)
    val returnNode = newMethodReturnNode(
      returnType.getOrElse(TypeConstants.Any),
      None,
      line(expr),
      column(expr)
    )
    val virtualModifier = Some(newModifierNode(ModifierTypes.VIRTUAL))
    val staticModifier  = Option.when(thisParam.isEmpty)(newModifierNode(ModifierTypes.STATIC))
    val privateModifier = Some(newModifierNode(ModifierTypes.PRIVATE))

    val modifiers = List(virtualModifier, staticModifier, privateModifier).flatten.map(Ast(_))

    val lambdaParameterNamesToNodes =
        parameters
            .flatMap(_.root)
            .collect { case param: NewMethodParameterIn => param }
            .map { param => param.name -> param }
            .toMap

    val identifiersMatchingParams = lambdaMethodBody.nodes
        .collect { case identifier: NewIdentifier => identifier }
        .filter { identifier => lambdaParameterNamesToNodes.contains(identifier.name) }

    val lambdaMethodAstWithoutRefs =
        Ast(lambdaMethodNode)
            .withChildren(parameters)
            .withChild(lambdaMethodBody)
            .withChild(Ast(returnNode))
            .withChildren(modifiers)

    val lambdaMethodAst =
        identifiersMatchingParams.foldLeft(lambdaMethodAstWithoutRefs)((ast, identifier) =>
            ast.withRefEdge(identifier, lambdaParameterNamesToNodes(identifier.name))
        )

    scope.addLambdaMethod(lambdaMethodAst)

    lambdaMethodNode
  end createAndPushLambdaMethod

  private def createAndPushLambdaTypeDecl(
    lambdaMethodNode: NewMethod,
    implementedInfo: LambdaImplementedInfo
  ): NewTypeDecl =
    val inheritsFromTypeFullName =
        implementedInfo.implementedInterface
            .flatMap(typeInfoCalc.fullName)
            .orElse(Some(TypeConstants.Object))
            .toList

    typeInfoCalc.registerType(lambdaMethodNode.fullName)
    val lambdaTypeDeclNode =
        NewTypeDecl()
            .fullName(lambdaMethodNode.fullName)
            .name(lambdaMethodNode.name)
            .inheritsFromTypeFullName(inheritsFromTypeFullName)
    scope.addLocalDecl(Ast(lambdaTypeDeclNode))

    lambdaTypeDeclNode
  end createAndPushLambdaTypeDecl

  private def getLambdaImplementedInfo(
    expr: LambdaExpr,
    expectedType: ExpectedType
  ): LambdaImplementedInfo =
    val maybeImplementedType =
      val maybeResolved = tryWithSafeStackOverflow(expr.calculateResolvedType())
      maybeResolved.toOption
          .orElse(expectedType.resolvedType)
          .collect { case refType: ResolvedReferenceType => refType }

    val maybeImplementedInterface = maybeImplementedType.flatMap(_.getTypeDeclaration.toScala)

    if maybeImplementedInterface.isEmpty then
      val location = s"$filename:${line(expr)}:${column(expr)}"
      logger.debug(
        s"Could not resolve the interface implemented by a lambda. Type info may be missing: $location. Type info may be missing."
      )

    val maybeBoundMethod = maybeImplementedInterface.flatMap { interface =>
        interface.getDeclaredMethods.asScala
            .filter(_.isAbstract)
            .filterNot { method =>
                // Filter out java.lang.Object methods re-declared by the interface as these are also considered abstract.
                // See https://docs.oracle.com/javase/8/docs/api/java/lang/FunctionalInterface.html for details.
                Try(method.getSignature) match
                  case Success(signature) => ObjectMethodSignatures.contains(signature)
                  case Failure(_) =>
                      false // If the signature could not be calculated, it's probably not a standard object method.
            }
            .headOption
    }

    LambdaImplementedInfo(maybeImplementedType, maybeBoundMethod)
  end getLambdaImplementedInfo

  // TODO: All of this will be thrown out, probably
  private def astForLambdaExpr(expr: LambdaExpr, expectedType: ExpectedType): Ast =
    scope.pushMethodScope(NewMethod(), expectedType)

    val lambdaMethodName = nextLambdaName()

    val closureBindingsForCapturedVars = closureBindingsForCapturedNodes(lambdaMethodName)
    val localsForCaptured              = localsForCapturedNodes(closureBindingsForCapturedVars)
    val implementedInfo                = getLambdaImplementedInfo(expr, expectedType)
    val lambdaMethodNode =
        createAndPushLambdaMethod(
          expr,
          lambdaMethodName,
          implementedInfo,
          localsForCaptured,
          expectedType
        )
    val typeNameLookup =
        lambdaMethodNode.fullName.takeWhile(_ != ':').split("\\.").dropRight(1).mkString(".")
    val methodRef =
        NewMethodRef()
            .methodFullName(lambdaMethodNode.fullName)
            .typeFullName(lambdaMethodNode.fullName)
            .code(lambdaMethodNode.fullName)
            .dynamicTypeHintFullName(packagesJarMappings.getOrElse(
              typeNameLookup,
              mutable.Set.empty
            ).toSeq)

    addClosureBindingsToDiffGraph(closureBindingsForCapturedVars, methodRef)

    val interfaceBinding = implementedInfo.implementedMethod.map { implementedMethod =>
        newBindingNode(
          implementedMethod.getName,
          lambdaMethodNode.signature,
          lambdaMethodNode.fullName
        )
    }

    val bindingTable = getLambdaBindingTable(
      LambdaBindingInfo(
        lambdaMethodNode.fullName,
        implementedInfo.implementedInterface,
        interfaceBinding
      )
    )

    val lambdaTypeDeclNode = createAndPushLambdaTypeDecl(lambdaMethodNode, implementedInfo)
    createBindingNodes(lambdaTypeDeclNode, bindingTable)

    scope.popScope()
    Ast(methodRef)
  end astForLambdaExpr

  private def astForLiteralExpr(expr: LiteralExpr): Ast =
    val typeFullName = expressionReturnTypeFullName(expr).getOrElse(TypeConstants.Any)
    val literalNode =
        NewLiteral()
            .code(expr.toString)
            .lineNumber(line(expr))
            .columnNumber(column(expr))
            .typeFullName(typeFullName)
    Ast(literalNode)

  private def getExpectedParamType(
    maybeResolvedCall: Try[ResolvedMethodLikeDeclaration],
    idx: Int
  ): ExpectedType =
      maybeResolvedCall.toOption
          .map { methodDecl =>
            val paramCount = methodDecl.getNumberOfParams

            val resolvedType = if idx < paramCount then
              Some(methodDecl.getParam(idx).getType)
            else if paramCount > 0 && methodDecl.getParam(paramCount - 1).isVariadic then
              Some(methodDecl.getParam(paramCount - 1).getType)
            else
              None

            val typeName = resolvedType.flatMap(typeInfoCalc.fullName)
            ExpectedType(typeName, resolvedType)
          }
          .getOrElse(ExpectedType.empty)

  private def dispatchTypeForCall(
    maybeDecl: Try[ResolvedMethodDeclaration],
    maybeScope: Option[Expression]
  ): String =
      maybeScope match
        case Some(_: SuperExpr) =>
            DispatchTypes.STATIC_DISPATCH
        case _ =>
            maybeDecl match
              case Success(decl) =>
                  if decl.isStatic then DispatchTypes.STATIC_DISPATCH
                  else DispatchTypes.DYNAMIC_DISPATCH

              case _ =>
                  DispatchTypes.DYNAMIC_DISPATCH

  private def targetTypeForCall(callExpr: MethodCallExpr): Option[String] =
    val maybeType = callExpr.getScope.toScala match
      case Some(callScope: ThisExpr) =>
          expressionReturnTypeFullName(callScope)
              .orElse(scope.enclosingTypeDeclFullName)

      case Some(callScope: SuperExpr) =>
          expressionReturnTypeFullName(callScope)
              .orElse(scope.enclosingTypeDecl.flatMap(_.inheritsFromTypeFullName.headOption))

      case Some(scope) => expressionReturnTypeFullName(scope)

      case None =>
          tryWithSafeStackOverflow(callExpr.resolve()).toOption
              .flatMap { methodDeclOption =>
                  if methodDeclOption.isStatic then
                    typeInfoCalc.fullName(methodDeclOption.declaringType())
                  else scope.enclosingTypeDeclFullName
              }
              .orElse(scope.enclosingTypeDeclFullName)

    maybeType.map(typeInfoCalc.registerType)
  end targetTypeForCall

  private def argAstsForCall(
    call: Node,
    tryResolvedDecl: Try[ResolvedMethodLikeDeclaration],
    args: NodeList[Expression]
  ): Seq[Ast] =
    val hasVariadicParameter = tryResolvedDecl.map(_.hasVariadicParameter).getOrElse(false)
    val paramCount           = tryResolvedDecl.map(_.getNumberOfParams).getOrElse(-1)

    val argsAsts = args.asScala.zipWithIndex.flatMap { case (arg, idx) =>
        val expectedType = getExpectedParamType(tryResolvedDecl, idx)
        astsForExpression(arg, expectedType)
    }.toList

    tryResolvedDecl match
      case Success(_) if hasVariadicParameter =>
          val expectedVariadicTypeFullName =
              getExpectedParamType(tryResolvedDecl, paramCount - 1).fullName
          val (regularArgs, varargs) = argsAsts.splitAt(paramCount - 1)
          val arrayInitializer = newOperatorCallNode(
            Operators.arrayInitializer,
            Operators.arrayInitializer,
            expectedVariadicTypeFullName,
            line(call),
            column(call)
          )

          val arrayInitializerAst = callAst(arrayInitializer, varargs)

          regularArgs ++ Seq(arrayInitializerAst)

      case _ => argsAsts
  end argAstsForCall

  private def getArgumentCodeString(args: NodeList[Expression]): String =
      args.asScala
          .map {
              case _: LambdaExpr => "<lambda>"
              case other         => other.toString
          }
          .mkString(", ")

  private def astForMethodCall(call: MethodCallExpr, expectedReturnType: ExpectedType): Ast =
    val maybeResolvedCall = tryWithSafeStackOverflow(call.resolve())
    // Fallback used when JavaParser cannot resolve a local implicit-this call through external types.
    val unresolvedMethod =
        maybeResolvedCall.failed.toOption.flatMap(_ => unresolvedImplicitThisMethod(call))
    val argumentAsts = argAstsForCall(call, maybeResolvedCall, call.getArguments)

    val expressionTypeFullName =
        expressionReturnTypeFullName(call).orElse(expectedReturnType.fullName)

    val argumentTypes =
        argumentTypesForMethodLike(maybeResolvedCall)
            .orElse(unresolvedMethod.flatMap(parameterTypesForAstMethod))
    val returnType = maybeResolvedCall
        .map { resolvedCall =>
            typeInfoCalc.fullName(resolvedCall.getReturnType, ResolvedTypeParametersMap.empty())
        }
        .toOption
        .flatten
        .orElse(unresolvedMethod.flatMap(returnTypeForAstMethod))
        .orElse(expressionTypeFullName)
    val dispatchType = dispatchTypeForCall(maybeResolvedCall, call.getScope.toScala)

    val receiverTypeOption = targetTypeForCall(call)
    val scopeAsts = call.getScope.toScala match
      case Some(scope) => astsForExpression(scope, ExpectedType(receiverTypeOption))

      case None =>
          val objectNode =
              createObjectNode(receiverTypeOption, call, dispatchType)
          for
            obj       <- objectNode
            thisParam <- scope.lookupVariable(NameConstants.This).variableNode
          do diffGraph.addEdge(obj, thisParam, EdgeTypes.REF)
          objectNode.map(Ast(_)).toList

    val receiverType =
        receiverTypeOption.orElse(scopeAsts.rootType).filter(_ != TypeConstants.Any)

    val argumentsCode = getArgumentCodeString(call.getArguments)
    val codePrefix    = codePrefixForMethodCall(call)
    val callCode      = s"$codePrefix${call.getNameAsString}($argumentsCode)"

    val callName       = call.getNameAsString
    val namespace      = receiverType.getOrElse(Defines.UnresolvedNamespace)
    val signature      = composeSignature(returnType, argumentTypes, argumentAsts.size)
    val methodFullName = composeMethodFullName(namespace, callName, signature)
    val typeFullNameStr = (expressionTypeFullName, expectedReturnType.resolvedType) match
      case (Some(name), _) if name.nonEmpty => name
      case (_, Some(resolved)) if resolved.isPrimitive =>
          resolved.asPrimitive().name().toLowerCase()
      case _ => TypeConstants.Any
    val callRoot = NewCall()
        .name(callName)
        .methodFullName(methodFullName)
        .signature(signature)
        .code(callCode)
        .dispatchType(dispatchType)
        .lineNumber(line(call))
        .columnNumber(column(call))
        .typeFullName(typeFullNameStr)
    callRoot.dynamicTypeHintFullName(
      packagesJarMappings
          .getOrElse(
            methodFullName.takeWhile(_ != ':').split("\\.").dropRight(1).mkString("."),
            mutable.Set.empty
          )
          .toSeq
    )
    callAst(callRoot, argumentAsts, scopeAsts.headOption)
  end astForMethodCall

  private def astForSuperExpr(superExpr: SuperExpr, expectedType: ExpectedType): Ast =
    val typeFullName =
        expressionReturnTypeFullName(superExpr)
            .orElse(expectedType.fullName)
            .getOrElse(TypeConstants.Any)

    typeInfoCalc.registerType(typeFullName)

    val identifier =
        identifierNode(superExpr, NameConstants.This, NameConstants.Super, typeFullName)
    Ast(identifier)

  private def astsForParameterList(parameters: NodeList[Parameter]): Seq[Ast] =
      parameters.asScala.toList.zipWithIndex.map { case (param, idx) =>
          astForParameter(param, idx + 1)
      }

  private def astForParameter(parameter: Parameter, childNum: Int): Ast =
    val maybeArraySuffix = if parameter.isVarArgs then "[]" else ""
    val typeFullName =
        typeInfoCalc
            .fullName(parameter.getType)
            .orElse(scope.lookupType(parameter.getTypeAsString))
            .map(_ ++ maybeArraySuffix)
            .getOrElse(guessTypeFullName(parameter.getTypeAsString))
    val evalStrat =
        if parameter.getType.isPrimitiveType then EvaluationStrategies.BY_VALUE
        else EvaluationStrategies.BY_SHARING
    typeInfoCalc.registerType(typeFullName)
    val parameterNode = NewMethodParameterIn()
        .name(parameter.getName.toString)
        .code(parameter.toString)
        .lineNumber(line(parameter))
        .columnNumber(column(parameter))
        .evaluationStrategy(evalStrat)
        .typeFullName(typeFullName)
        .index(childNum)
        .order(childNum)
    val annotationAsts = parameter.getAnnotations.asScala.map(astForAnnotationExpr)
    val ast            = Ast(parameterNode)

    scope.addParameter(parameterNode)

    ast.withChildren(annotationAsts)
  end astForParameter
end AstCreator
