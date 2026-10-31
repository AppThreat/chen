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

  /** Types the author declared via PEP 484/526 annotations, keyed by variable name. Annotations are
    * declarations: they must win over naming-convention heuristics (but never over real dataflow).
    * Populated from nodes that carry a frontend-derived type before recovery starts.
    */
  private val declaredTypes = scala.collection.mutable.HashMap.empty[String, Set[String]]

  private def recordDeclaredType(name: String, types: Set[String]): Unit =
      if name.nonEmpty && types.nonEmpty then
        declaredTypes.updateWith(name) {
            case Some(ts) => Some(ts ++ types)
            case None     => Some(types)
        }

  /** Import aliases whose entity the resolver could not verify (an unknown type declaration, or a
    * whole unknown module). Their resolved path names a namespace, not the type of the values
    * bound to them, so it must not propagate onto other variables (a `value = SKIP_HEADER`
    * assignment is what named `value.strip()` `urllib3.util.SKIP_HEADER.strip`).
    */
  private val unknownValueAliases = scala.collection.mutable.HashSet.empty[String]

  /** The declaration a captured local stands for, one CLOSURE_BINDING level at a time: the binding
    * sharing the local's `closureBindingId` hangs off the capturing method's method reference and
    * refers to the next declaration out.
    */
  private val outermostOfLocal = scala.collection.mutable.HashMap.empty[Long, Declaration]

  private def outermostDeclaration(l: Local): Declaration =
      outermostOfLocal.getOrElseUpdate(
        l.id(), {
            var current: Declaration = l
            var depth                = 0
            var following            = true
            while following && depth < 32 do
              depth += 1
              following = false
              current match
                case cur: Local if cur.closureBindingId.isDefined =>
                    val cbid = cur.closureBindingId.get
                    val next = cur.method._refIn.collectAll[MethodRef]
                        .flatMap(_._captureOut)
                        .collectAll[ClosureBinding]
                        .find(_.closureBindingId.contains(cbid))
                        .flatMap(_._refOut.collectFirst { case d: Declaration => d })
                    next.foreach { d =>
                        if d.id() != cur.id() then
                          current = d
                          following = true
                    }
                case _ =>
            current
        }
      )

  /** The scopes whose variables share the module-wide name: the module method itself, and the
    * synthetic `<body>` method the front end lowers each class body into (class-level variables
    * are the class's fields, not locals of a method body).
    */
  private def isNamespaceScope(d: Declaration): Boolean =
      enclosingMethodOf(d).exists(m => m.name == "<module>" || m.name == "<body>")

  private def enclosingMethodOf(d: Declaration): Option[Method] = d match
    case l: Local             => l.method.headOption
    case p: MethodParameterIn => Some(p.method)
    case _                    => None

  /** The symbol key for a declaration's scope: the method's full name plus the name. Keeps each
    * method's locals and parameters apart from the module binding of the same name, which keeps
    * its plain name.
    */
  private def scopedKey(scope: String, name: String): LocalKey =
      LocalVar(s"$scope$pathSep$name")

  private def keyOfDeclaration(n: AstNode, fallbackName: String): LocalKey =
      n match
        case p: MethodParameterIn => scopedKey(p.method.fullName, p.name)
        case l: Local =>
            outermostDeclaration(l) match
              case outer if isNamespaceScope(outer) => LocalVar(l.name)
              case outer =>
                  scopedKey(enclosingMethodOf(outer).map(_.fullName).getOrElse(""), l.name)
        case id: Identifier =>
            id._refOut.collectFirst { case d: Declaration => d } match
              case Some(p: MethodParameterIn) => scopedKey(p.method.fullName, p.name)
              case Some(l: Local)             => keyOfDeclaration(l, fallbackName)
              case _                          => LocalVar(fallbackName)
        case _ => LocalVar(fallbackName)

  private def fromNodeToLocalPythonKey(node: AstNode): Option[LocalKey] =
      node match
        case n: Method            => Option(CallAlias(n.name, Option("self")))
        case n: MethodParameterIn => Some(scopedKey(n.method.fullName, n.name))
        case n: Identifier        => Some(keyOfDeclaration(n, n.name))
        case n: Local             => Some(keyOfDeclaration(n, n.name))
        case _                    => SBKey.fromNodeToLocalKey(node)

  /** The key of the local an import lowers to: the target identifier's declaration. A module-level
    * import binds the module scope (the plain name); a function-level import binds inside its
    * method, so its uses resolve under that method's scoped key.
    */
  private def bindingKeyOf(i: Import): Option[LocalKey] =
      i.call.headOption.flatMap { importCall =>
          val assignment = importCall._astIn.collectFirst {
              case a: Call if a.name == Operators.assignment => a
          }.orElse(
              // several aliases of one import statement lower to a block of assignments
              importCall._astIn.collectFirst { case b: Block => b }.flatMap(
                _.astChildren.isCall.nameExact(Operators.assignment)
                    .find(_.argumentOut.exists(_.id() == importCall.id()))
              )
          )
          assignment.flatMap(
            _.argument.collectFirst { case id: Identifier if id.argumentIndex == 1 => id }
          ).map(lhs => keyOfDeclaration(lhs, lhs.name))
      }

  private def putImportBinding(i: Import, name: String, types: Set[String]): Unit =
      if types.nonEmpty then
        symbolTable.put(LocalVar(name), types)
        bindingKeyOf(i).foreach(k => symbolTable.put(k, types))
        // A plain dotted import binds the top-level package (`import os.path` binds `os`), but
        // member loads of the full path (`tmp0 = os.path` in the callee lowering) resolve through
        // the path's own name, so it keeps an entry of its own.
        types.toList match
          case List(entity) if entity.startsWith(s"$name.") => symbolTable.put(LocalVar(entity), types)
          case _                                            =>

  override def visitImport(i: Import): Unit =
      if i.importedAs.isDefined && i.importedEntity.isDefined then
        import io.appthreat.x2cpg.passes.frontend.ImportsPass.*

        val entityName = i.importedAs.get
        i.call.tag.flatMap(ResolvedImport.tagToResolvedImport).foreach {
            case ResolvedMethod(fullName, alias, receiver, _) =>
                symbolTable.put(CallAlias(alias, receiver), fullName)
            case ResolvedTypeDecl(fullName, _) =>
                putImportBinding(i, entityName, Set(fullName))
            case ResolvedMember(basePath, memberName, _) =>
                val memberTypes = cpg.typeDecl
                    .fullNameExact(basePath)
                    .member
                    .nameExact(memberName)
                    .flatMap(m => m.typeFullName +: m.dynamicTypeHintFullName)
                    .filterNot(_ == Constants.ANY)
                    .toSet
                putImportBinding(i, entityName, memberTypes)
            case UnknownMethod(fullName, alias, receiver, _) =>
                symbolTable.put(CallAlias(alias, receiver), fullName)
            case UnknownTypeDecl(fullName, _) =>
                unknownValueAliases += entityName
                putImportBinding(i, entityName, Set(fullName))
            case UnknownImport(path, _) =>
                unknownValueAliases += entityName
                symbolTable.put(CallAlias(entityName), path)
                putImportBinding(i, entityName, Set(path))
        }

  override def visitAssignments(a: OpNodes.Assignment): Set[String] =
      a.argumentOut.l match
        case List(i: Identifier, c: Call) if c.name.isBlank && c.signature.isBlank =>
            // This is usually some decorator wrapper
            c.argument.isMethodRef.headOption match
              case Some(mRef) => visitIdentifierAssignedToMethodRef(i, mRef)
              case None       => super.visitAssignments(a)
        case _ => super.visitAssignments(a)

  override protected def visitIdentifierAssignedToIdentifier(
    x: Identifier,
    y: Identifier
  ): Set[String] =
      // An alias whose entity the resolver could not verify keeps its namespace path as the
      // binding's entry (receiver resolution needs it), but that path is not the type of the
      // values assigned from it: it would name `value.strip()` after
      // `urllib3.util.SKIP_HEADER.strip`. Only this propagation is blocked.
      if unknownValueAliases.contains(y.name) && declarationIsNamespaceBound(y) then Set.empty
      else super.visitIdentifierAssignedToIdentifier(x, y)

  private def declarationIsNamespaceBound(id: Identifier): Boolean =
      id._refOut.collectFirst { case l: Local => l }
          .map(outermostDeclaration)
          .exists(isNamespaceScope)

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
    // The camel-case constructor guess must never override an author declaration:
    // `x: str = Foo()` keeps `str`. Declared types only win over this heuristic,
    // never over real dataflow.
    val existing = symbolTable.get(i)
    val declared = declaredTypes.getOrElse(i.name, Set.empty)
    if existing.nonEmpty && declared.exists(existing.contains) then existing
    else
      val constructorPaths = symbolTable.get(c).map(_.stripSuffix(s"${pathSep}__init__"))
      associateTypes(i, constructorPaths)

  override protected def visitIdentifierAssignedToCallRetVal(i: Identifier, c: Call): Set[String] =
      if symbolTable.contains(c) then super.visitIdentifierAssignedToCallRetVal(i, c)
      else if c.argument.exists(_.argumentIndex == 0) then
        val callFullNames = (c.argument(0) match
          case recv: Identifier =>
              // the receiver's own scope first (a parameter or a local of this method), then the
              // module-wide name (an import binding), then a call alias
              if symbolTable.contains(recv) then symbolTable.get(recv)
              else if symbolTable.contains(LocalVar(recv.name)) then
                symbolTable.get(LocalVar(recv.name))
              else if symbolTable.contains(CallAlias(recv.name)) then
                symbolTable.get(CallAlias(recv.name))
              else Set.empty
          case _ => Set.empty
        ).map(_.concat(s"$pathSep${c.name}")).toSeq
        associateTypes(i, methodReturnValues(callFullNames))
      else super.visitIdentifierAssignedToCallRetVal(i, c)

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
          val directTypes =
              referencedFields.flatMap(m =>
                  m.typeFullName +: m.dynamicTypeHintFullName
              ).filterNot(_ == Constants.ANY).toSet
          val globalTypes =
              if directTypes.nonEmpty then directTypes
              else fieldParents.flatMap(memberTypesInHierarchy(_, fi.canonicalName))
          associateTypes(i, globalTypes)
      case _ => super.visitIdentifierAssignedToFieldLoad(i, fa)

  /** Field loads through a receiver whose member lives on an inherited dependency base resolve
    * through the hierarchy walk; everything else keeps the base behaviour.
    */
  override protected def getFieldBaseType(baseName: String, fieldName: String): Set[String] =
    val direct = super.getFieldBaseType(baseName, fieldName)
    if direct.nonEmpty then direct
    else
      symbolTable
          .get(LocalVar(baseName))
          .flatMap(memberTypesInHierarchy(_, fieldName))
          .toSet

  /** Field loads through a base whose declaration is a parameter or a local of this method resolve
    * under that base's own scope key; the name-keyed base behaviour stays for module bindings.
    */
  override protected def getFieldBaseType(base: Identifier, fi: FieldIdentifier): Set[String] =
      if symbolTable.contains(base) then
        val baseTypes = symbolTable.get(base)
        val direct = baseTypes
            .flatMap(t => typeDeclIterator(t).member.nameExact(fi.canonicalName))
            .typeFullNameNot("ANY")
            .flatMap(m => m.typeFullName +: m.dynamicTypeHintFullName)
            .toSet
        if direct.nonEmpty then direct
        else baseTypes.flatMap(memberTypesInHierarchy(_, fi.canonicalName)).toSet
      else super.getFieldBaseType(base, fi)

  /** Member types for `memberName` as visible on `typeFullName` or inherited from a base class
    * whose TYPE_DECL is an ingested dependency (`isExternal`): `flask.Request`'s `args` lives on
    * werkzeug's `Request`, so a direct-member lookup alone cannot type a field load through a
    * dependency's class hierarchy. Members are read only from external type decls, and a graph
    * without ingested dependencies has none - so there the walk is a no-op and the base lookup
    * behaviour is untouched.
    *
    * A member that is a `@property` of an external class is a computed value: the field load
    * `request.args` reads the getter's declared return type, not the member stub. Ordinary methods
    * are left alone - `request.url_for` is a bound method, not `url_for`'s return.
    */
  private def memberTypesInHierarchy(typeFullName: String, memberName: String): Set[String] =
    val visited = scala.collection.mutable.HashSet.empty[String]
    val queue   = scala.collection.mutable.Queue(typeFullName)
    var types   = Set.empty[String]
    while queue.nonEmpty && types.isEmpty do
      val current = queue.dequeue()
      if visited.add(current) then
        val decls   = cpg.typeDecl.fullNameExact(current).toList
        val members = decls.iterator.filter(_.isExternal).member.nameExact(memberName).l
        types =
            if members.isEmpty then Set.empty
            else
              // A `@property` member is a computed value, so the getter's declared return is
              // the field's type; the member stub itself carries nothing useful.
              propertyReturnTypes(current, memberName).getOrElse {
                  members
                      .flatMap(m => m.typeFullName +: m.dynamicTypeHintFullName)
                      .filterNot(isValueTypeName)
                      .toSet
              }
        queue.enqueueAll(
          decls.iterator
              .flatMap(_.inheritsFromTypeFullName)
              .filterNot(isValueTypeName)
              .toSeq
        )
      end if
    end while
    types
  end memberTypesInHierarchy

  /** Names that carry no information: the placeholder, an invented dummy type, and the two
    * universal Python bases every hierarchy walk would otherwise terminate on.
    */
  private def isValueTypeName(t: String): Boolean =
      t.equalsIgnoreCase(Constants.ANY) || t.equalsIgnoreCase("object") ||
          XTypeRecovery.isDummyType(t)

  /** The declared return types of a `@property` getter `memberName` on the external class
    * `typeFullName`, when such a getter exists and its return is declared. Only declared,
    * non-placeholder returns count: a property the dependency never types stays untyped here.
    */
  private def propertyReturnTypes(typeFullName: String, memberName: String): Option[Set[String]] =
      cpg.method.fullNameExact(s"$typeFullName.$memberName").find { getter =>
          getter.annotation.name.exists(_.equalsIgnoreCase("property"))
      }.map { getter =>
        val mr = getter.methodReturn
        (mr.typeFullName +: mr.dynamicTypeHintFullName).filterNot(isValueTypeName).toSet
      }.filter(_.nonEmpty)
  end propertyReturnTypes

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

  override protected def setTypeForDynamicDispatchCall(call: Call, i: Identifier): Unit =
      // A call the frontend lowers with only a callee receiver (`handler(request)`) has no base:
      // its first real argument sits at index 1, and naming the call after that argument's type
      // invents a member that was never called (`aiohttp.web.Request.handler`). Member and
      // instance calls carry their base at argument index 0, which is what the base behaviour
      // expects.
      if i.argumentIndex != 0 then
        persistType(i, symbolTable.get(i))
        // The base leaves the call unnamed on this path; keep the source-text callee hint it
        // uses when no argument is in the table (`handler(a)` resolves to `handler`), so both
        // shapes agree.
        if symbolTable.get(call).isEmpty && !call.name.startsWith("<operator>") then
          storeCallTypeInfo(call, Seq(call.code.takeWhile(_ != '(')))
      // `self`/`this` is a file-scoped symbol in the base symbol table, so it accumulates the
      // type of *every* class defined in the file. The base then builds one `<Class>.method`
      // candidate per class, and the call linker — faced with several — refuses to pick,
      // leaving `self.method()` as `<unknownFullName>`. Scope `self` to the enclosing method's
      // own class (and its hierarchy) so a single, correct callee survives.
      else if (i.name == "self" || i.name == "this") && symbolTable.get(call).isEmpty
        && !call.name.startsWith("<operator>")
      then
        val enclosing =
            call.method.typeDecl.fullName.toSet.filterNot(_.matches("(?i)(any|object)"))
        val scoped = enclosing.map(t => createCallFromIdentifierTypeFullName(t, call.name))
        persistType(i, symbolTable.get(i))
        if scoped.nonEmpty then persistType(call, scoped)
        else super.setTypeForDynamicDispatchCall(call, i)
      else super.setTypeForDynamicDispatchCall(call, i)

  override protected def isConstructor(name: String): Boolean =
      name.nonEmpty && name.charAt(0).isUpper

  override protected def setTypeForFieldAccess(
    fieldAccess: Call,
    i: Identifier,
    f: FieldIdentifier
  ): Unit =
    // The base falls back to the module-wide call alias for an identifier it cannot find in the
    // table. A parameter or local of this method that shares an alias's name is not that alias
    // (a shadowing `requests` must not take `import requests`'s names), so the alias only applies
    // to identifiers bound at the module scope.
    if symbolTable.contains(i) || declarationIsNamespaceBound(i) then
      super.setTypeForFieldAccess(fieldAccess, i, f)
    else persistType(i, symbolTable.get(i))

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
    // Keyed by each node's own scope (see fromNodeToLocalPythonKey), so a concrete type written
    // onto a method's parameter or local does not leak onto the module binding of the same name.
    cu.ast.isIdentifier.filterNot(_.typeFullName.matches("(?i)(any|null|void|unknown)"))
        .foreach { id =>
          symbolTable.put(id, Set(id.typeFullName))
          recordDeclaredType(id.name, Set(id.typeFullName) ++ id.dynamicTypeHintFullName)
        }
    cu.ast.isLocal.filterNot(_.typeFullName.matches("(?i)(any|null|void|unknown)"))
        .foreach { local =>
          symbolTable.put(local, Set(local.typeFullName))
          recordDeclaredType(local.name, Set(local.typeFullName) ++ local.dynamicTypeHintFullName)
        }
    cu.ast.isParameter.filterNot(_.typeFullName.matches("(?i)(any|null|void|unknown)"))
        .foreach { param =>
          symbolTable.put(param, Set(param.typeFullName))
          recordDeclaredType(param.name, Set(param.typeFullName) ++ param.dynamicTypeHintFullName)
        }
    super.prepopulateSymbolTable()
  end prepopulateSymbolTable

  /** A bare container type: `__builtin.list` / `typing.List` without type arguments. */
  private def isBareContainer(t: String): Boolean =
      !t.contains("[") && PythonAstVisitor.containerTypes.contains(
        t.split("[.:]").lastOption.getOrElse(t).toLowerCase
      )

  /** A parametrised generic type: `list[str]`, `typing.Dict[str, Item]`, ... */
  private def isParametrised(t: String): Boolean = t.contains("[") && t.endsWith("]")

  override protected def associateTypes(i: Identifier, types: Set[String]): Set[String] =
    val existingTypes = symbolTable.get(i)
    // A parametrised type the variable already carries (annotation-derived or inferred
    // from a typed RHS) is strictly more precise than a bare container guess from a
    // literal (`x = {}`); the literal must not dilute or replace it.
    val filteredTypes = types.filter { t =>
        if isBareContainer(t) && existingTypes.exists(isParametrised) then false
        else if isBareContainer(t) && declaredTypes.get(i.name).exists(_.exists(isParametrised))
        then false
        else true
    }
    if filteredTypes.isEmpty && existingTypes.nonEmpty then existingTypes
    else super.associateTypes(i, filteredTypes)

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
    // Final flush: the recovery only persists types along assignment/receiver shapes, so
    // read-only occurrences (returns, bare reads, loop conditions) of variables the symbol
    // table already types stay ANY on the node. Write the symbol table's knowledge onto
    // those nodes; persistType keeps dummy and operator pseudo types out.
    cu.ast.isIdentifier.foreach { id =>
        if id.typeFullName == Constants.ANY && symbolTable.contains(id) then
          val ts = symbolTable.get(id)
          if ts.nonEmpty then persistType(id, ts)
    }
    cu.ast.isLocal.foreach { local =>
        if local.typeFullName == Constants.ANY && symbolTable.contains(local) then
          val ts = symbolTable.get(local)
          if ts.nonEmpty then persistType(local, ts)
    }
  end postSetTypeInformation

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
          val short = name.split("[.]").lastOption.getOrElse(name)
          val declared = state.typeDeclFullNamesByName.getOrElseUpdate(
            short,
            cpg.typeDecl.nameExact(short).fullName.toSet
          )
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
            case Some(recv: Identifier) if symbolTable.contains(recv) =>
                symbolTable.get(recv).map(_.concat(s"$pathSep${c.name}")).toSeq
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
end RecoverForPythonFile
