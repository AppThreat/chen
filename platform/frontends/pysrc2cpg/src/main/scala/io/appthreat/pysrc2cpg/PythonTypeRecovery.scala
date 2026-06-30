package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.passes.frontend.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Operators, PropertyNames}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.operatorextension.OpNodes
import io.shiftleft.semanticcpg.language.operatorextension.OpNodes.FieldAccess
import overflowdb.BatchedUpdate.DiffGraphBuilder

class PythonTypeRecoveryPass(cpg: Cpg, config: XTypeRecoveryConfig = XTypeRecoveryConfig())
    extends XTypeRecoveryPass[File](cpg, config):

  override protected def generateRecoveryPass(state: XTypeRecoveryState): XTypeRecovery[File] =
      new PythonTypeRecovery(cpg, state)

private class PythonTypeRecovery(cpg: Cpg, state: XTypeRecoveryState)
    extends XTypeRecovery[File](cpg, state):

  override def compilationUnit: Iterator[File] = cpg.file.iterator

  override def generateRecoveryForCompilationUnitTask(
    unit: File,
    builder: DiffGraphBuilder
  ): RecoverForXCompilationUnit[File] =
    val newConfig = state.config.copy(enabledDummyTypes =
        state.isFinalIteration && state.config.enabledDummyTypes
    )
    new RecoverForPythonFile(cpg, unit, builder, state.copy(config = newConfig))

/** Performs type recovery from the root of a compilation unit level
  */
private class RecoverForPythonFile(
  cpg: Cpg,
  cu: File,
  builder: DiffGraphBuilder,
  state: XTypeRecoveryState
) extends RecoverForXCompilationUnit[File](cpg, cu, builder, state):

  override val symbolTable: SymbolTable[LocalKey] =
      new SymbolTable[LocalKey](fromNodeToLocalPythonKey)

  override def visitImport(i: Import): Unit =
      if i.importedAs.isDefined && i.importedEntity.isDefined then
        import io.appthreat.x2cpg.passes.frontend.ImportsPass.*

        val entityName = i.importedAs.get
        i.call.tag.flatMap(ResolvedImport.tagToResolvedImport).foreach {
            case ResolvedMethod(fullName, alias, receiver, _) =>
                symbolTable.put(CallAlias(alias, receiver), fullName)
            case ResolvedTypeDecl(fullName, _) =>
                symbolTable.put(LocalVar(entityName), fullName)
            case ResolvedMember(basePath, memberName, _) =>
                val memberTypes = cpg.typeDecl
                    .fullNameExact(basePath)
                    .member
                    .nameExact(memberName)
                    .flatMap(m => m.typeFullName +: m.dynamicTypeHintFullName)
                    .filterNot(_ == "ANY")
                    .toSet
                symbolTable.put(LocalVar(entityName), memberTypes)
            case UnknownMethod(fullName, alias, receiver, _) =>
                symbolTable.put(CallAlias(alias, receiver), fullName)
            case UnknownTypeDecl(fullName, _) =>
                symbolTable.put(LocalVar(entityName), fullName)
            case UnknownImport(path, _) =>
                symbolTable.put(CallAlias(entityName), path)
                symbolTable.put(LocalVar(entityName), path)
        }

  override def visitAssignments(a: OpNodes.Assignment): Set[String] =
      a.argumentOut.l match
        case List(i: Identifier, c: Call) if c.name.isBlank && c.signature.isBlank =>
            // This is usually some decorator wrapper
            c.argument.isMethodRef.headOption match
              case Some(mRef) => visitIdentifierAssignedToMethodRef(i, mRef)
              case None       => super.visitAssignments(a)
        case _ => super.visitAssignments(a)

  /** Determines if a function call is a constructor by following the heuristic that Python classes
    * are typically camel-case and start with an upper-case character.
    */
  override def isConstructor(c: Call): Boolean =
      isConstructor(c.name) && c.code.endsWith(")")

  /** If the parent method is module then it can be used as a field.
    */
  override def isField(i: Identifier): Boolean =
      state.isFieldCache.getOrElseUpdate(
        i.id(),
        i.method.name.matches("(<module>|__init__)") || super.isField(i)
      )

  override def visitIdentifierAssignedToOperator(
    i: Identifier,
    c: Call,
    operation: String
  ): Set[String] =
      operation match
        case "<operator>.listLiteral" =>
            associateTypes(i, Set(s"${PythonAstVisitor.builtinPrefix}list"))
        case "<operator>.tupleLiteral" =>
            associateTypes(i, Set(s"${PythonAstVisitor.builtinPrefix}tuple"))
        case "<operator>.dictLiteral" =>
            associateTypes(i, Set(s"${PythonAstVisitor.builtinPrefix}dict"))
        case "<operator>.setLiteral" =>
            associateTypes(i, Set(s"${PythonAstVisitor.builtinPrefix}set"))
        case Operators.conditional =>
            associateTypes(i, Set(s"${PythonAstVisitor.builtinPrefix}bool"))
        case Operators.indexAccess =>
            c.argument.argumentIndex(1).isCall.foreach(setCallMethodFullNameFromBase)
            visitIdentifierAssignedToIndexAccess(i, c)
        case _ => super.visitIdentifierAssignedToOperator(i, c, operation)

  override def visitIdentifierAssignedToConstructor(i: Identifier, c: Call): Set[String] =
    val constructorPaths = symbolTable.get(c).map(_.stripSuffix(s"${pathSep}__init__"))
    associateTypes(i, constructorPaths)

  override def visitIdentifierAssignedToCall(i: Identifier, c: Call): Set[String] =
      // Ignore legacy import representation
      if c.name.equals("import") then Set.empty
      // Stop custom annotation representation from hitting superclass
      else if c.name.isBlank then Set.empty
      // For-loop element typing: `for x in coll` lowers to
      //   tmp = coll.__iter__(); x = tmp.__next__()
      // so the iterator's type encodes the collection (`coll[E].__iter__.<returnValue>`).
      // Unwrap the element type `E` so `x.method()` resolves.
      else if c.name.equals("__next__") then
        val elemTypes = iterationElementTypes(c)
        if elemTypes.nonEmpty then associateTypes(i, elemTypes)
        else super.visitIdentifierAssignedToCall(i, c)
      // `super().method()` lowers to `tmp = super(); tmp.method()`. Type `tmp` as the
      // base class(es) of the enclosing method's class so the subsequent call on `tmp`
      // resolves to the inherited method (via the hierarchy lookup in
      // `createCallFromIdentifierTypeFullName`).
      else if c.name.equals("super") then
        val baseTypes = superBaseTypes(c)
        if baseTypes.nonEmpty then associateTypes(i, baseTypes)
        else super.visitIdentifierAssignedToCall(i, c)
      else super.visitIdentifierAssignedToCall(i, c)

  /** The direct base-class full names of the class enclosing a `super()` call. */
  private def superBaseTypes(c: Call): Set[String] =
      c.method.typeDecl.inheritsFromTypeFullName.toSet
          .filterNot(_.matches("(?i)(any|object)"))
          .flatMap(resolveBareTypeName)

  override def visitIdentifierAssignedToFieldLoad(i: Identifier, fa: FieldAccess): Set[String] =
    val fieldParents = getFieldParents(fa)
    fa.astChildren.l match
      case List(base: Identifier, fi: FieldIdentifier)
          if base.name.equals("self") && fieldParents.nonEmpty =>
          val referencedFields = cpg.typeDecl.fullNameExact(
            fieldParents.toSeq*
          ).member.nameExact(fi.canonicalName)
          val globalTypes =
              referencedFields.flatMap(m =>
                  m.typeFullName +: m.dynamicTypeHintFullName
              ).filterNot(_ == Constants.ANY).toSet
          associateTypes(i, globalTypes)
      case _ => super.visitIdentifierAssignedToFieldLoad(i, fa)

  override def getFieldParents(fa: FieldAccess): Set[String] =
      if fa.method.name == "<module>" then
        Set(fa.method.fullName)
      else if fa.method.typeDecl.nonEmpty then
        val parentTypes = fa.method.typeDecl.fullName.toSet
        val baseTypeFullNames =
            cpg.typeDecl.fullNameExact(parentTypes.toSeq*).inheritsFromTypeFullName.toSet
        (parentTypes ++ baseTypeFullNames).filterNot(_.matches("(?i)(any|object)"))
      else
        super.getFieldParents(fa)

  override def getLiteralType(l: Literal): Set[String] =
      (l.code match
        case code if code.toIntOption.isDefined => Some(s"${PythonAstVisitor.builtinPrefix}int")
        case code if code.toDoubleOption.isDefined =>
            Some(s"${PythonAstVisitor.builtinPrefix}float")
        case code if "True".equals(code) || "False".equals(code) =>
            Some(s"${PythonAstVisitor.builtinPrefix}bool")
        case code if code.equals("None") => Some(s"${PythonAstVisitor.builtinPrefix}None")
        case code if isPyString(code)    => Some(s"${PythonAstVisitor.builtinPrefix}str")
        case _                           => None
      ).toSet

  private def isPyString(s: String): Boolean =
      (s.startsWith("\"") || s.startsWith("'")) && (s.endsWith("\"") || s.endsWith("'"))

  override def createCallFromIdentifierTypeFullName(
    typeFullName: String,
    callName: String
  ): String =
    lazy val tName = typeFullName.split("\\.").lastOption.getOrElse(typeFullName)
    typeFullName match
      case t if t.matches(".*(<\\w+>)$") =>
          super.createCallFromIdentifierTypeFullName(typeFullName, callName)
      case t if t.matches(".*\\.<(member|returnValue|indexAccess)>(\\(.*\\))?") =>
          super.createCallFromIdentifierTypeFullName(typeFullName, callName)
      case t if isConstructor(tName) =>
          // `t` is an instance of a (capitalised) class. Bind to the nearest class
          // in the inheritance chain that actually defines `callName`, so
          // `self.method()` resolves to an inherited method (e.g. `Child(Base)`
          // calling a method defined on `Base`). Fall back to the direct
          // `t.callName` when the method isn't found in the hierarchy.
          resolveMethodInHierarchy(t, callName)
              .getOrElse(Seq(t, callName).mkString(pathSep.toString))
      case _ => super.createCallFromIdentifierTypeFullName(typeFullName, callName)
  end createCallFromIdentifierTypeFullName

  /** Walk `typeFullName` and its (transitive) base classes, returning the fullName of the first
    * type that declares a method named `callName`, suffixed with `callName`. Returns `None` when no
    * class in the hierarchy declares it.
    */
  private def resolveMethodInHierarchy(
    typeFullName: String,
    callName: String
  ): Option[String] =
    val visited = scala.collection.mutable.HashSet.empty[String]
    val queue   = scala.collection.mutable.Queue(typeFullName)
    var result  = Option.empty[String]
    while result.isEmpty && queue.nonEmpty do
      val current = queue.dequeue()
      if visited.add(current) then
        // Look the method up by fullName rather than `typeDecl.method`: pysrc2cpg
        // does not reliably reach a class's methods via the TypeDecl traversal.
        val candidate = Seq(current, callName).mkString(pathSep.toString)
        val typeDecls = cpg.typeDecl.fullNameExact(current).l
        if cpg.method.fullNameExact(candidate).nonEmpty then
          result = Some(candidate)
        else
          typeDecls.iterator
              .flatMap(_.inheritsFromTypeFullName)
              .filterNot(b => b.matches("(?i)(any|object)"))
              .foreach(queue.enqueue)
    result
  end resolveMethodInHierarchy

  override protected def isConstructor(name: String): Boolean =
      name.nonEmpty && name.charAt(0).isUpper

  override def prepopulateSymbolTable(): Unit =
    // Factory return-types are committed through a *separate* diff applied
    // immediately, so `methodReturnValues` (which reads the live graph) sees them
    // within this same iteration. Committing the framework's shared `builder`
    // mid-pass would consume it before the framework applies it.
    val factoryDiff = new DiffGraphBuilder
    cu.ast.isMethodRef.where(
      _.astSiblings.isIdentifier.nameExact("classmethod")
    ).referencedMethod.foreach {
        classMethod =>
          val clsPath = classMethod.typeDecl.fullName.toSet
          classMethod.parameter
              .nameExact("cls")
              .foreach { cls =>
                symbolTable.put(LocalVar(cls.name), clsPath)
                if cls.typeFullName == "ANY" then
                  builder.setNodeProperty(
                    cls,
                    PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME,
                    clsPath.toSeq
                  )
              }
          // Factory idiom: a classmethod that returns `cls(...)` produces an
          // instance of the enclosing class. Seed its return type so callers
          // (`x = Cls.create(...)`) recover `x`'s type and resolve `x.method()`.
          val returnsClsInstance =
              classMethod.ast.isReturn.code.exists(_.matches("""return\s+cls\(.*"""))
          if returnsClsInstance && clsPath.nonEmpty
            && classMethod.methodReturn.dynamicTypeHintFullName.isEmpty
          then
            factoryDiff.setNodeProperty(
              classMethod.methodReturn,
              PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME,
              clsPath.toSeq
            )
    }
    overflowdb.BatchedUpdate.applyDiff(cpg.graph, factoryDiff)
    cu.ast.isIdentifier.filterNot(_.typeFullName.matches("(?i)(any|null|void|unknown)"))
        .foreach { id => symbolTable.put(LocalVar(id.name), id.typeFullName) }
    cu.ast.isLocal.filterNot(_.typeFullName.matches("(?i)(any|null|void|unknown)"))
        .foreach { local => symbolTable.put(LocalVar(local.name), local.typeFullName) }
    cu.ast.isParameter.filterNot(_.typeFullName.matches("(?i)(any|null|void|unknown)"))
        .foreach { param => symbolTable.put(LocalVar(param.name), param.typeFullName) }
    super.prepopulateSymbolTable()
  end prepopulateSymbolTable

  override protected def associateTypes(i: Identifier, types: Set[String]): Set[String] =
    val existingTypes = symbolTable.get(i)
    val filteredTypes = types.filter { t =>
        if t == s"${PythonAstVisitor.builtinPrefix}list" && existingTypes.exists(
            _.startsWith(s"${PythonAstVisitor.builtinPrefix}list[")
          )
        then false
        else if t == s"${PythonAstVisitor.builtinPrefix}dict" && existingTypes.exists(
            _.startsWith(s"${PythonAstVisitor.builtinPrefix}dict[")
          )
        then false
        else if t == s"${PythonAstVisitor.builtinPrefix}set" && existingTypes.exists(
            _.startsWith(s"${PythonAstVisitor.builtinPrefix}set[")
          )
        then false
        else if t == s"${PythonAstVisitor.builtinPrefix}tuple" && existingTypes.exists(
            _.startsWith(s"${PythonAstVisitor.builtinPrefix}tuple[")
          )
        then false
        else true
    }
    if filteredTypes.isEmpty && existingTypes.nonEmpty then existingTypes
    else super.associateTypes(i, filteredTypes)
  end associateTypes

  override protected def postSetTypeInformation(): Unit =
      cu.typeDecl
          .map(t =>
              t -> t.inheritsFromTypeFullName.partition(itf =>
                  symbolTable.contains(LocalVar(itf))
              )
          )
          .foreach { case (t, (identifierTypes, otherTypes)) =>
              val existingTypes = (identifierTypes ++ otherTypes).distinct
              val resolvedTypes = identifierTypes.map(LocalVar.apply).flatMap(symbolTable.get)
              if existingTypes != resolvedTypes && resolvedTypes.nonEmpty then
                state.changesWereMade.compareAndExchange(false, true)
                builder.setNodeProperty(
                  t,
                  PropertyNames.INHERITS_FROM_TYPE_FULL_NAME,
                  resolvedTypes
                )
          }

  override protected def visitIdentifierAssignedToTypeRef(
    i: Identifier,
    t: TypeRef,
    rec: Option[String]
  ): Set[String] =
      t.typ.referencedTypeDecl
          .map(_.fullName.stripSuffix("<meta>"))
          .map(td => symbolTable.append(CallAlias(i.name, rec), Set(td)))
          .headOption
          .getOrElse(super.visitIdentifierAssignedToTypeRef(i, t, rec))

  /** Element types yielded by iterating the collection behind a `__next__` call. The receiver of
    * `__next__` is the synthetic iterator whose type is `<collectionType>.__iter__.<returnValue>`;
    * we strip that suffix, unwrap the collection's generic element, and resolve bare class names to
    * their compilation-unit-qualified full names.
    */
  private def iterationElementTypes(nextCall: Call): Set[String] =
    val iterSuffix = s"${pathSep}__iter__${pathSep}${XTypeRecovery.DummyReturnType}"
    val recvTypes = nextCall.argument.argumentIndex(0).headOption match
      case Some(id: Identifier) =>
          symbolTable.get(id) ++ Option(id.typeFullName).filterNot(_ == Constants.ANY).toSet
      case Some(call: Call) => symbolTable.get(call)
      case _                => Set.empty[String]
    recvTypes.collect { case t if t.endsWith(iterSuffix) => t.stripSuffix(iterSuffix) }
        .flatMap(elementTypesOf)
        .flatMap(resolveBareTypeName)

  /** Unwrap the element type(s) from a generic collection type string such as `list[AppConfig]`,
    * `typing.List[AppConfig]`, `dict[str, AppConfig]` (iteration yields keys) or `tuple[A, B]`.
    * Returns empty when the type is not a recognised parametrised collection.
    */
  private def elementTypesOf(collType: String): Set[String] =
      if !(collType.contains("[") && collType.endsWith("]")) then Set.empty
      else
        val container = collType.substring(0, collType.indexOf('['))
        val inner     = collType.substring(collType.indexOf('[') + 1, collType.length - 1)
        val parts     = splitGenericParts(inner)
        container.split("[.:]").lastOption.map(_.toLowerCase) match
          case Some("dict" | "mapping" | "defaultdict" | "ordereddict" | "counter") =>
              parts.headOption.toSet
          case Some(
                "list" | "set" | "frozenset" | "sequence" | "iterable" | "iterator" |
                "generator" | "deque" | "tuple"
              ) =>
              parts.toSet
          case _ => parts.toSet
  end elementTypesOf

  /** Resolve a possibly-bare class name (e.g. `AppConfig`) to a qualified type full name by
    * consulting the symbol table (import aliases) and then matching declared types by short name.
    * Already-qualified names (and builtins/ANY) are returned as-is.
    */
  private def resolveBareTypeName(name: String): Set[String] =
      if name.isEmpty || name == Constants.ANY then Set.empty
      else if name.contains(":") || name.startsWith(PythonAstVisitor.builtinPrefix) then Set(name)
      else
        val viaSymbols = symbolTable.get(LocalVar(name)).filterNot(_ == Constants.ANY)
        if viaSymbols.nonEmpty then viaSymbols
        else
          val short    = name.split("[.]").lastOption.getOrElse(name)
          val declared = cpg.typeDecl.nameExact(short).fullName.toSet
          if declared.nonEmpty then declared else Set(name)
  end resolveBareTypeName

  private def splitGenericParts(s: String): List[String] =
    val result  = scala.collection.mutable.ListBuffer[String]()
    var current = new StringBuilder()
    var depth   = 0
    for c <- s do
      if c == '[' then depth += 1
      else if c == ']' then depth -= 1

      if c == ',' && depth == 0 then
        result += current.toString().trim
        current = new StringBuilder()
      else
        current.append(c)
    if current.nonEmpty then
      result += current.toString().trim
    result.toList

  override protected def getIndexAccessTypes(ia: Call): Set[String] =
    val baseTypes = ia.argument.argumentIndex(1).headOption match
      case Some(c: Call)        => getTypesFromCall(c)
      case Some(id: Identifier) => symbolTable.get(id)
      case _                    => Set.empty[String]
    val resolvedTypes = baseTypes.flatMap {
        case t if t.startsWith(s"${PythonAstVisitor.builtinPrefix}list[") && t.endsWith("]") =>
            val element = t.stripPrefix(s"${PythonAstVisitor.builtinPrefix}list[").stripSuffix("]")
            Set(element)
        case t if t.startsWith(s"${PythonAstVisitor.builtinPrefix}dict[") && t.endsWith("]") =>
            val inner = t.stripPrefix(s"${PythonAstVisitor.builtinPrefix}dict[").stripSuffix("]")
            val parts = splitGenericParts(inner)
            if parts.length == 2 then Set(parts(1)) else Set(Constants.ANY)
        case t if t.startsWith(s"${PythonAstVisitor.builtinPrefix}tuple[") && t.endsWith("]") =>
            val inner = t.stripPrefix(s"${PythonAstVisitor.builtinPrefix}tuple[").stripSuffix("]")
            splitGenericParts(inner).toSet
        case t if t.contains("[") && t.endsWith("]") =>
            val inner = t.substring(t.indexOf('[') + 1, t.length - 1)
            splitGenericParts(inner).toSet
        case _ => Set.empty[String]
    }
    if resolvedTypes.nonEmpty then resolvedTypes
    else
      ia.argument.argumentIndex(1).isCall.headOption match
        case Some(c) =>
            getTypesFromCall(c).map(x => s"$x$pathSep${XTypeRecovery.DummyIndexAccess}")
        case _ => super.getIndexAccessTypes(ia)
  end getIndexAccessTypes

  override def getTypesFromCall(c: Call): Set[String] =
      c.name match
        case "<operator>.listLiteral"  => Set(s"${PythonAstVisitor.builtinPrefix}list")
        case "<operator>.tupleLiteral" => Set(s"${PythonAstVisitor.builtinPrefix}tuple")
        case "<operator>.dictLiteral"  => Set(s"${PythonAstVisitor.builtinPrefix}dict")
        case "<operator>.setLiteral"   => Set(s"${PythonAstVisitor.builtinPrefix}set")
        case _ =>
            val base = super.getTypesFromCall(c)
            if base.nonEmpty then base
            else returnTypeOfResolvedCall(c)

  /** Fallback used by RHS type extraction (`getTypesFromCall`): when the symbol table holds no
    * direct type for a call, resolve the callee and take its *return* type. This lets `self.attr =
    * Factory.create()` propagate the factory return onto the member — the constructor case
    * (`self.attr = Cls()`) already works. Mirrors `visitIdentifierAssignedToCallRetVal`: during
    * recovery the resolved callee lives in the symbol table (the node's methodFullName is only set
    * later by the linker), keyed either on the call or on its receiver + call name.
    */
  private def returnTypeOfResolvedCall(c: Call): Set[String] =
    val calleeFullNames =
        if symbolTable.contains(c) then symbolTable.get(c).toSeq
        else
          c.argument.find(_.argumentIndex == 0) match
            case Some(recv: Identifier) if symbolTable.contains(LocalVar(recv.name)) =>
                symbolTable.get(LocalVar(recv.name)).map(_.concat(s"$pathSep${c.name}")).toSeq
            case Some(recv: Identifier) if symbolTable.contains(CallAlias(recv.name)) =>
                symbolTable.get(CallAlias(recv.name)).map(_.concat(s"$pathSep${c.name}")).toSeq
            case _ => Seq.empty
    if calleeFullNames.isEmpty then Set.empty
    else
      methodReturnValues(calleeFullNames).filterNot(t =>
          t == Constants.ANY || XTypeRecovery.isDummyType(t)
      )

  /** Replaces the `this` prefix with the Pythonic `self` prefix for instance methods of functions
    * local to this compilation unit.
    */
  private def fromNodeToLocalPythonKey(node: AstNode): Option[LocalKey] =
      node match
        case n: Method => Option(CallAlias(n.name, Option("self")))
        case _         => SBKey.fromNodeToLocalKey(node)
end RecoverForPythonFile
