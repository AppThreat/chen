package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.astcreation.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, NodeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.appthreat.x2cpg.passes.frontend.MetaDataPass
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.appthreat.x2cpg.utils.NodeBuilders.newMethodReturnNode
import io.shiftleft.semanticcpg.language.types.structure.NamespaceTraversal

/** Stub type declarations for the types the graph uses but no parsed file defines, carrying the
  * member layouts the AST pass recorded for them (`members`: owner -> (order, name, type)) - a
  * struct or class defined in a header.
  */
class TypeDeclNodePass(
  cpg: Cpg,
  members: Map[String, List[(Int, String, String)]] = Map.empty
)(implicit withSchemaValidation: ValidationMode)
    extends CpgPass(cpg):

  private val filename: String   = "<includes>"
  private val globalName: String = NamespaceTraversal.globalNamespaceName
  private val fullName: String   = MetaDataPass.getGlobalNamespaceBlockFullName(Option(filename))

  private val typeDeclFullNames: Set[String] = cpg.typeDecl.fullName.toSetImmutable

  private def createGlobalAst(): Ast =
    val includesFile = NewFile().name(filename)
    val namespaceBlock = NewNamespaceBlock()
        .name(globalName)
        .fullName(fullName)
        .filename(filename)
    val fakeGlobalIncludesMethod =
        NewMethod()
            .name(globalName)
            .code(globalName)
            .fullName(fullName)
            .filename(filename)
            .lineNumber(1)
            .astParentType(NodeTypes.NAMESPACE_BLOCK)
            .astParentFullName(fullName)
    val blockNode    = NewBlock().typeFullName(Defines.anyTypeName)
    val methodReturn = newMethodReturnNode(Defines.anyTypeName, line = None, column = None)
    Ast(includesFile).withChild(
      Ast(namespaceBlock)
          .withChild(
            Ast(fakeGlobalIncludesMethod).withChild(Ast(blockNode)).withChild(Ast(methodReturn))
          )
    )
  end createGlobalAst

  private def typeNeedsTypeDeclStub(t: Type): Boolean =
      !typeDeclFullNames.contains(t.typeDeclFullName)

  override def run(dstGraph: DiffGraphBuilder): Unit =
    var hadMissingTypeDecl = false
    val stubbed            = scala.collection.mutable.HashSet.empty[String]
    def stub(name: String, typeDeclFullName: String): Unit =
        if stubbed.add(typeDeclFullName) then
          val newTypeDecl = NewTypeDecl()
              .name(name)
              .fullName(typeDeclFullName)
              .code(name)
              .isExternal(true)
              .filename(filename)
              .astParentType(NodeTypes.NAMESPACE_BLOCK)
              .astParentFullName(fullName)
          dstGraph.addNode(newTypeDecl)
          members.getOrElse(typeDeclFullName, Nil).foreach { (order, memberName, tpe) =>
            val member = NewMember()
                .name(memberName)
                .code(s"$tpe $memberName")
                .typeFullName(tpe)
                .order(order)
            dstGraph.addNode(member)
            dstGraph.addEdge(newTypeDecl, member, EdgeTypes.AST)
          }
          hadMissingTypeDecl = true
    cpg.typ.filter(typeNeedsTypeDeclStub).foreach(t => stub(t.name, t.typeDeclFullName))
    // a recorded layout whose type no Type node names (the struct behind a pointer)
    members.keys.filterNot(typeDeclFullNames.contains).foreach(owner =>
        stub(owner.split('.').lastOption.getOrElse(owner), owner)
    )
    if hadMissingTypeDecl then Ast.storeInDiffGraph(createGlobalAst(), dstGraph)
  end run
end TypeDeclNodePass
