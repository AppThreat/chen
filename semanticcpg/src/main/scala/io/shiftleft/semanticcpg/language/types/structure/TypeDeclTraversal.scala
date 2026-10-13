package io.shiftleft.semanticcpg.language.types.structure

import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** Type declaration - possibly a template that requires instantiation
  */
class TypeDeclTraversal(val traversal: Iterator[TypeDecl]) extends AnyVal:
  import TypeDeclTraversal.*

  /** Annotations of the type declaration
    */
  def annotation: Iterator[nodes.Annotation] =
      traversal.flatMap(_._annotationViaAstOut)

  /** Types referencing to this type declaration.
    */
  def referencingType: Iterator[Type] =
      traversal.flatMap(_.refIn)

  /** Namespace in which this type declaration is defined
    */
  def namespace: Iterator[Namespace] =
      traversal.flatMap(_.namespaceBlock).namespace

  /** Methods defined as part of this type
    */
  def method: Iterator[Method] =
      canonicalType.flatMap(_._methodViaAstOut)

  /** Filter for type declarations contained in the analyzed code.
    */
  def internal: Iterator[TypeDecl] =
      canonicalType.isExternal(false)

  /** Filter for type declarations not contained in the analyzed code.
    */
  def external: Iterator[TypeDecl] =
      canonicalType.isExternal(true)

  /** Member variables
    */
  def member: Iterator[Member] =
      canonicalType.flatMap(_._memberViaAstOut)

  /** Direct base types in the inheritance graph.
    */
  def baseType: Iterator[Type] =
      canonicalType.flatMap(_._typeViaInheritsFromOut)

  /** Direct base type declaration.
    */
  def derivedTypeDecl: Iterator[TypeDecl] =
      referencingType.derivedTypeDecl

  /** Direct and transitive base type declaration.
    */
  def derivedTypeDeclTransitive: Iterator[TypeDecl] =
      traversal.repeat(_.derivedTypeDecl)(using _.emitAllButFirst.dedup)

  /** Direct base type declaration.
    */
  def baseTypeDecl: Iterator[TypeDecl] =
      traversal.baseType.referencedTypeDecl

  /** Direct and transitive base type declaration.
    */
  def baseTypeDeclTransitive: Iterator[TypeDecl] =
      traversal.repeat(_.baseTypeDecl)(using _.emitAllButFirst.dedup)

  /** Traverse to alias type declarations.
    */
  def isAlias: Iterator[TypeDecl] =
      traversal.filter(_.aliasTypeFullName.isDefined)

  /** Traverse to canonical type declarations.
    */
  def isCanonical: Iterator[TypeDecl] =
      traversal.filter(_.aliasTypeFullName.isEmpty)

  /** If this is an alias type declaration, go to its underlying type declaration else unchanged.
    */
  def unravelAlias: Iterator[TypeDecl] =
      traversal.map { typeDecl =>
          typeDecl.aliasedType.nextOption()
              .flatMap(tpe => preferredDeclaration(tpe.referencedTypeDecl.l))
              .getOrElse(typeDecl)
      }

  /** Traverse to canonical type which means unravel aliases until we find a non alias type
    * declaration.
    */
  def canonicalType: Iterator[TypeDecl] =
      traversal.repeat(_.unravelAlias)(using _.until(_.isCanonical).maxDepth(maxAliasExpansions))

  /** Direct alias type declarations.
    */
  def aliasTypeDecl: Iterator[TypeDecl] =
      referencingType.aliasTypeDecl

  /** Direct and transitive alias type declarations.
    */
  def aliasTypeDeclTransitive: Iterator[TypeDecl] =
      traversal.repeat(_.aliasTypeDecl)(using _.emitAllButFirst.dedup)
end TypeDeclTraversal

object TypeDeclTraversal:
  private val maxAliasExpansions = 100

  /** The declaration a type stands for when several declare it - in C, a header's forward
    * declaration (`typedef struct s S;` declares `s` too) and the definition in one source file. A
    * declaration that is not an alias wins, then one with members (the definition), a parsed one
    * over a stub, and then a content-stable order. The first edge or index entry would be whichever
    * file a parallel frontend happened to write first, so a type's members could differ from one
    * run to the next.
    */
  def preferredDeclaration(decls: List[TypeDecl]): Option[TypeDecl] =
      if decls.sizeIs <= 1 then decls.headOption
      else
        decls.minByOption(d =>
            (
              d.aliasTypeFullName.isDefined,
              d._memberViaAstOut.isEmpty,
              d.isExternal,
              d.filename,
              d.lineNumber.map(_.intValue).getOrElse(Int.MaxValue),
              d.code
            )
        )
end TypeDeclTraversal
