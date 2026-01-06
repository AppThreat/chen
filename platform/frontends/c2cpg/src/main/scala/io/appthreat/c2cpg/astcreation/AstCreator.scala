package io.appthreat.c2cpg.astcreation

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.passes.AstCreationPass
import io.appthreat.x2cpg.datastructures.Scope
import io.appthreat.x2cpg.datastructures.Stack.*
import io.appthreat.x2cpg.{
    Ast,
    AstCreatorBase,
    ValidationMode,
    AstNodeBuilder as X2CpgAstNodeBuilder
}
import io.shiftleft.codepropertygraph.generated.NodeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.types.structure.NamespaceTraversal
import org.eclipse.cdt.core.dom.ast.{IASTNode, IASTTranslationUnit}
import org.slf4j.{Logger, LoggerFactory}
import overflowdb.BatchedUpdate.DiffGraphBuilder

import java.io.*
import java.nio.file.{Files, Paths, StandardCopyOption}
import java.util.concurrent.ConcurrentHashMap
import scala.collection.mutable
import scala.util.Using

/** Translates the Eclipse CDT AST into a CPG AST.
  */
class AstCreator(
  val filename: String,
  val config: Config,
  val cdtAst: IASTTranslationUnit,
  val file2OffsetTable: ConcurrentHashMap[String, Array[Int]],
  val fileHash: Option[String] = None
)(implicit withSchemaValidation: ValidationMode)
    extends AstCreatorBase(filename)
    with AstForTypesCreator
    with AstForFunctionsCreator
    with AstForPrimitivesCreator
    with AstForStatementsCreator
    with AstForExpressionsCreator
    with AstNodeBuilder
    with AstCreatorHelper
    with MacroHandler
    with X2CpgAstNodeBuilder[IASTNode, AstCreator]:

  protected val logger: Logger = LoggerFactory.getLogger(classOf[AstCreator])

  protected val scope: Scope[String, (NewNode, String), NewNode] = new Scope()

  protected val usingDeclarationMappings: mutable.Map[String, String] = mutable.HashMap.empty

  // TypeDecls with their bindings (with their refs) for lambdas and methods are not put in the AST
  // where the respective nodes are defined. Instead we put them under the parent TYPE_DECL in which they are defined.
  // To achieve this we need this extra stack.
  protected val methodAstParentStack: Stack[NewNode] = new Stack()

  def createAst(): DiffGraphBuilder =
    val ast = astForTranslationUnit(cdtAst)
    if config.enableAstCache && fileHash.isDefined then
      saveToCache(ast, fileHash.get)
    if !config.onlyAstCache then
      Ast.storeInDiffGraph(ast, diffGraph)
    diffGraph

  private def saveToCache(ast: Ast, hash: String): Unit =
    val finalPath = Paths.get(config.cacheDir, s"$hash.json")
    val tmpPath   = Paths.get(config.cacheDir, s"$hash.json.tmp")

    try
      val cachedModel = AstCreationPass.Serialization.toCached(ast)
      val bytes       = upickle.default.writeBinary(cachedModel)
      Files.write(tmpPath, bytes)
      Files.move(tmpPath, finalPath, StandardCopyOption.REPLACE_EXISTING)
    catch
      case e: Exception =>
          logger.warn(s"Critical error saving AST cache for $filename: ${e.getMessage}")
          Files.deleteIfExists(tmpPath)

  def generateAst(iASTTranslationUnit: IASTTranslationUnit): Ast =
    val namespaceBlock = globalNamespaceBlock()
    methodAstParentStack.push(namespaceBlock)
    val translationUnitAst =
        astInFakeMethod(
          namespaceBlock.fullName,
          fileName(iASTTranslationUnit),
          iASTTranslationUnit
        )
    val depsAndImportsAsts = astsForDependenciesAndImports(iASTTranslationUnit)
    val commentsAsts       = astsForComments(iASTTranslationUnit)
    val childrenAsts       = depsAndImportsAsts ++ Seq(translationUnitAst) ++ commentsAsts
    setArgumentIndices(childrenAsts)
    Ast(namespaceBlock).withChildren(childrenAsts)

  private def astForTranslationUnit(iASTTranslationUnit: IASTTranslationUnit): Ast =
      generateAst(iASTTranslationUnit)

  /** Creates an AST of all declarations found in the translation unit - wrapped in a fake method.
    */
  private def astInFakeMethod(
    fullName: String,
    path: String,
    iASTTranslationUnit: IASTTranslationUnit
  ): Ast =
    val allDecls = iASTTranslationUnit.getDeclarations.toList.filterNot(isIncludedNode)
    val name     = NamespaceTraversal.globalNamespaceName

    val fakeGlobalTypeDecl =
        typeDeclNode(
          iASTTranslationUnit,
          name,
          fullName,
          filename,
          name,
          NodeTypes.NAMESPACE_BLOCK,
          fullName
        )
    methodAstParentStack.push(fakeGlobalTypeDecl)

    val fakeGlobalMethod =
        methodNode(
          iASTTranslationUnit,
          name,
          name,
          fullName,
          None,
          path,
          Option(NodeTypes.TYPE_DECL),
          Option(fullName)
        )
    methodAstParentStack.push(fakeGlobalMethod)
    scope.pushNewScope(fakeGlobalMethod)

    val blockNode_ = blockNode(iASTTranslationUnit)

    val declsAsts = allDecls.flatMap(astsForDeclaration)
    setArgumentIndices(declsAsts)

    val methodReturn = newMethodReturnNode(iASTTranslationUnit, Defines.anyTypeName)
    Ast(fakeGlobalTypeDecl).withChild(
      methodAst(fakeGlobalMethod, Seq.empty, blockAst(blockNode_, declsAsts), methodReturn)
    )
  end astInFakeMethod
end AstCreator
