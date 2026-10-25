package io.appthreat.jssrc2cpg.passes

import io.appthreat.x2cpg.Defines as XDefines
import io.appthreat.x2cpg.Defines.ConstructorMethodName
import io.appthreat.x2cpg.passes.frontend.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Operators, PropertyNames}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.operatorextension.OpNodes.{Assignment, FieldAccess}
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable

class JavaScriptTypeRecoveryPass(cpg: Cpg, config: XTypeRecoveryConfig = XTypeRecoveryConfig())
    extends XTypeRecoveryPass[File](cpg, config):
  override protected def generateRecoveryPass(state: XTypeRecoveryState): XTypeRecovery[File] =
      new JavaScriptTypeRecovery(cpg, state)

private class JavaScriptTypeRecovery(cpg: Cpg, state: XTypeRecoveryState)
    extends XTypeRecovery[File](cpg, state):

  override def compilationUnit: Iterator[File] = cpg.file.iterator

  /** TYPE_DECL full names grouped by their (short) name, computed once per recovery iteration and
    * shared by all per-file tasks. This replaces a `cpg.typeDecl.nameExact(...)` whole-graph scan
    * that was previously performed once per symbol during symbol-table prepopulation - the dominant
    * cost of JS type recovery on large projects.
    */
  private lazy val typeDeclFullNamesByName: Map[String, Set[String]] =
    val acc = mutable.HashMap.empty[String, mutable.LinkedHashSet[String]]
    cpg.typeDecl.foreach { td =>
        acc.getOrElseUpdate(td.name, mutable.LinkedHashSet.empty) += td.fullName
    }
    acc.view.mapValues(_.toSet).toMap

  override def generateRecoveryForCompilationUnitTask(
    unit: File,
    builder: DiffGraphBuilder
  ): RecoverForXCompilationUnit[File] =
    val newConfig = state.config.copy(enabledDummyTypes =
        state.isFinalIteration && state.config.enabledDummyTypes
    )
    new RecoverForJavaScriptFile(
      cpg,
      unit,
      builder,
      state.copy(config = newConfig),
      typeDeclFullNamesByName
    )
end JavaScriptTypeRecovery

private class RecoverForJavaScriptFile(
  cpg: Cpg,
  cu: File,
  builder: DiffGraphBuilder,
  state: XTypeRecoveryState,
  typeDeclFullNamesByName: Map[String, Set[String]]
) extends RecoverForXCompilationUnit[File](cpg, cu, builder, state):

  private lazy val exportedIdentifiers = cu.method
      .nameExact(":program")
      .flatMap(_._callViaContainsOut)
      .nameExact(Operators.assignment)
      .filter(_.code.startsWith("exports.*"))
      .argument
      .isIdentifier
      .name
      .toSet
  override protected val pathSep = ':'

  /** A heuristic method to determine if a call is a constructor or not.
    */
  override protected def isConstructor(c: Call): Boolean =
      c.name.endsWith("factory") && c.inCall.astParent.headOption.exists(_.isInstanceOf[Block])

  override protected def isConstructor(name: String): Boolean =
      !name.isBlank && (name.charAt(0).isUpper || name.endsWith("factory"))

  override protected def prepopulateSymbolTableEntry(x: AstNode): Unit = x match
    case x @ (_: Identifier | _: Local | _: MethodParameterIn)
        if x.property(PropertyNames.TYPE_FULL_NAME, Defines.Any) != Defines.Any =>
        val typeFullName = x.property(PropertyNames.TYPE_FULL_NAME, Defines.Any)
        val typeHints = symbolTable.get(LocalVar(x.property(
          PropertyNames.TYPE_FULL_NAME,
          Defines.Any
        ))) - typeFullName
        lazy val cpgTypeFullName = typeDeclFullNamesByName.getOrElse(typeFullName, Set.empty)
        val resolvedTypeHints =
            if typeHints.nonEmpty then symbolTable.put(x, typeHints)
            else if cpgTypeFullName.nonEmpty then symbolTable.put(x, cpgTypeFullName)
            else symbolTable.put(x, x.getKnownTypes)
        if !resolvedTypeHints.contains(typeFullName) && resolvedTypeHints.sizeIs == 1 then
          builder.setNodeProperty(x, PropertyNames.TYPE_FULL_NAME, resolvedTypeHints.head)
    case x @ (_: Identifier | _: Local | _: MethodParameterIn) =>
        symbolTable.put(x, x.getKnownTypes)
    case x: Call => symbolTable.put(x, (x.methodFullName +: x.dynamicTypeHintFullName).toSet)
    case _       =>

  override protected def prepopulateSymbolTable(): Unit =
    super.prepopulateSymbolTable()
    cu.ast.isMethod.foreach(f =>
        symbolTable.put(CallAlias(f.name, Option("this")), Set(f.fullName))
    )
    (cu.ast.isParameter.whereNot(_.nameExact("this")) ++ cu.ast.isMethod.methodReturn).filter(
      hasTypes
    ).foreach { p =>
      val resolvedHints = p.getKnownTypes
          .map { t =>
              t.split("\\.").headOption match
                case Some(base) if symbolTable.contains(LocalVar(base)) =>
                    (
                      t,
                      symbolTable.get(LocalVar(base)).map(x => s"$x${t.stripPrefix(base)}")
                    )
                case _ => (t, Set(t))
          }
          .flatMap {
              case (t, ts) if Set(t) == ts => Set(t)
              case (_, ts) => ts.map(_.replaceAll("\\.(?!js::program)", pathSep.toString))
          }
      p match
        case _: MethodParameterIn => symbolTable.put(p, resolvedHints)
        case _: MethodReturn if resolvedHints.sizeIs == 1 =>
            builder.setNodeProperty(p, PropertyNames.TYPE_FULL_NAME, resolvedHints.head)
        case _: MethodReturn =>
            builder.setNodeProperty(p, PropertyNames.TYPE_FULL_NAME, Defines.Any)
            builder.setNodeProperty(
              p,
              PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME,
              resolvedHints
            )
        case _ =>
    }
  end prepopulateSymbolTable

  override protected def isField(i: Identifier): Boolean =
      state.isFieldCache.getOrElseUpdate(
        i.id(),
        exportedIdentifiers.contains(i.name) || super.isField(i)
      )

  override protected def visitIdentifierAssignedToConstructor(
    i: Identifier,
    c: Call
  ): Set[String] =
    val constructorPaths = if c.methodFullName.endsWith(".alloc") then
      val newOp       = c.inAssignment.astSiblings.isCall.nameExact("<operator>.new").headOption
      val newChildren = newOp.astChildren.l
      val possibleImportIdentifier = newChildren.isIdentifier.headOption match
        case Some(i) if GlobalBuiltins.builtins.contains(i.name) => Set(s"__ecma.${i.name}")
        case Some(i) =>
            val typs = symbolTable.get(CallAlias(i.name, Option("this")))
            if typs.nonEmpty then newOp.foreach(symbolTable.put(_, typs))
            symbolTable.get(i)
        case None => Set.empty[String]
      lazy val possibleConstructorPointer =
          newChildren.astChildren.isFieldIdentifier.map(f =>
              CallAlias(f.canonicalName, Some("this"))
          ).headOption match
            case Some(fi) => symbolTable.get(fi)
            case None     => Set.empty[String]

      if possibleImportIdentifier.nonEmpty then possibleImportIdentifier
      else if possibleConstructorPointer.nonEmpty then possibleConstructorPointer
      else Set.empty[String]
    else (symbolTable.get(c) + c.methodFullName).map(t => t.stripSuffix(".factory"))
    associateTypes(i, constructorPaths)
  end visitIdentifierAssignedToConstructor

  override protected def visitIdentifierAssignedToOperator(
    i: Identifier,
    c: Call,
    operation: String
  ): Set[String] =
      operation match
        case "<operator>.new" =>
            c.astChildren.l match
              case ::(fa: Call, ::(i: Identifier, _)) if fa.name == Operators.fieldAccess =>
                  symbolTable.append(
                    c,
                    visitIdentifierAssignedToFieldLoad(i, new FieldAccess(fa)).map(t =>
                        s"$t$pathSep$ConstructorMethodName"
                    )
                  )
              case _ => Set.empty
        case _ => super.visitIdentifierAssignedToOperator(i, c, operation)

  override protected def associateInterproceduralTypes(
    i: Identifier,
    fieldFullName: String,
    fieldName: String,
    globalTypes: Set[String],
    baseTypes: Set[String]
  ): Set[String] =
      if symbolTable.contains(LocalVar(fieldName)) then
        val fieldTypes = symbolTable.get(LocalVar(fieldName))
        symbolTable.append(i, fieldTypes)
      else if symbolTable.contains(CallAlias(fieldName, Option("this"))) then
        symbolTable.get(CallAlias(fieldName, Option("this")))
      else
        super.associateInterproceduralTypes(
          i: Identifier,
          fieldFullName: String,
          fieldName: String,
          globalTypes: Set[String],
          baseTypes: Set[String]
        )

  override protected def visitIdentifierAssignedToCall(i: Identifier, c: Call): Set[String] =
      // Instead of returning empty, this must visit and identify the default export
      if c.name == "require" || c.name == "import" then Set.empty
      else super.visitIdentifierAssignedToCall(i, c)

  override protected def visitIdentifierAssignedToMethodRef(
    i: Identifier,
    m: MethodRef,
    rec: Option[String] = None
  ): Set[String] =
      super.visitIdentifierAssignedToMethodRef(i, m, Option("this"))

  /** Field writes, which is also how class fields are lowered (`x = v` is `this.x = v`):
    *   - `this.x = class X {}` stores the class under the field, as a field assigned a function
    *     reference already is;
    *   - `this.x = f(...)` stores what the call returns, as an identifier assigned the call does.
    *     The base visit stores the callee's own types, so `http = inject(HttpClient)` typed the
    *     field as the function `inject` and `this.http.get()` as `@angular/core:inject:get`.
    */
  override protected def visitAssignments(a: Assignment): Set[String] =
      a.argumentOut.l match
        case List(c: Call, t: TypeRef) if c.name == Operators.fieldAccess =>
            assignTypesToCall(c, Set(t.typeFullName))
        case List(c: Call, v: Call)
            if c.name == Operators.fieldAccess && !v.name.startsWith("<operator>") =>
            // a return nothing is known about is no type: the field keeps the type it has (the
            // declared one, with TypeScript types), as a field written nowhere else does
            assignTypesToCall(
              c,
              returnTypesOf(v).filterNot(_.endsWith(XTypeRecovery.DummyReturnType))
            )
        case _ => super.visitAssignments(a)

  /** The classes whose member a field access names. `this.f` is a field of the class the method
    * belongs to (or of an ancestor that declares it), not of every class with a member called `f`:
    * with field initialisers lowered as `this.f = v`, `@Output() delete = new EventEmitter()` in
    * one component typed the `delete` method of every other class.
    */
  override protected def getFieldParents(fa: FieldAccess): Set[String] =
    val byName = super.getFieldParents(fa)
    fa.argumentOption(1) match
      // the frontend gives `this` the class it belongs to as its type hint, which becomes its type
      // once the first iteration has set types from hints
      case Some(base: Identifier) if base.name == "this" =>
          (base.typeFullName +: base.dynamicTypeHintFullName)
              .filterNot(t => t == Defines.Any || t == "this")
              .flatMap(t => cpg.typeDecl.fullNameExact(t).l) match
            case td +: _ =>
                val ancestors = td.inheritsFromTypeFullName.map(_.split("[:.]").last).toSet
                byName.filter(t =>
                    t == td.fullName || ancestors.contains(t.split("[:.]").last)
                )
            case _ => byName
      case _ => byName

  /** The types a call returns, by the rules `visitIdentifierAssignedToCall` applies to a local. */
  private def returnTypesOf(c: Call): Set[String] =
      if symbolTable.contains(c) then methodReturnValues(symbolTable.get(c).toSeq)
      else if c.argument.argumentIndex(0).headOption.exists(symbolTable.contains) then
        setCallMethodFullNameFromBase(c)
        if symbolTable.contains(c) then methodReturnValues(symbolTable.get(c).toSeq)
        else Set(s"${c.name}$pathSep${XTypeRecovery.DummyReturnType}")
      else Set(s"${c.name}$pathSep${XTypeRecovery.DummyReturnType}")

  override protected def visitIdentifierAssignedToTypeRef(
    i: Identifier,
    t: TypeRef,
    rec: Option[String] = None
  ): Set[String] =
      super.visitIdentifierAssignedToTypeRef(i, t, Option("this"))

  override protected def postSetTypeInformation(): Unit =
      // often there are "this" identifiers with type hints but this can be set to a type hint if they meet the criteria
      cu.method
          .flatMap(_._identifierViaContainsOut)
          .nameExact("this")
          .where(_.typeFullNameExact(Defines.Any))
          .filterNot(_.dynamicTypeHintFullName.isEmpty)
          .foreach(setTypeFromTypeHints)

  protected override def storeIdentifierTypeInfo(i: Identifier, types: Seq[String]): Unit =
      super.storeIdentifierTypeInfo(
        i,
        types.map(_.stripSuffix(s"$pathSep${XDefines.ConstructorMethodName}"))
      )

  protected override def storeLocalTypeInfo(i: Local, types: Seq[String]): Unit =
      super.storeLocalTypeInfo(
        i,
        types.map(_.stripSuffix(s"$pathSep${XDefines.ConstructorMethodName}"))
      )
end RecoverForJavaScriptFile
