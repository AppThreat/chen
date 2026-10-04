package io.appthreat.edg2atom.astcreation

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.edg2atom.parser.{EdgaUnit, FileEntry, Pos}
import io.appthreat.edg2atom.parser.EdgaUnit.*
import io.appthreat.x2cpg.datastructures.Scope
import io.appthreat.x2cpg.{Ast, AstCreatorBase, AstNodeBuilder, ValidationMode}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{
    ControlStructureTypes,
    DispatchTypes,
    EvaluationStrategies,
    ModifierTypes,
    NodeTypes,
    Operators
}
import io.shiftleft.semanticcpg.language.types.structure.NamespaceTraversal
import overflowdb.BatchedUpdate.DiffGraphBuilder
import ujson.Value

import java.nio.file.{Files, Path, Paths}
import scala.collection.mutable

/** Builds the AST of one translation unit from edga's document, in the shapes the CDT-based C/C++
  * frontend gives the same code: the same node kinds, names, full names, type names and operator
  * names, so every pass and query that reads a C/C++ graph reads this one too.
  *
  * The front end resolved more than the CDT parser does, and that is kept where the graph has room
  * for it: pointer arithmetic, constant values and macro origins as the same tags.
  *
  * A header in the project is written by the first translation unit that includes it (`claim`), so
  * its functions, types and variables appear once.
  */
class AstCreator(
  val filename: String,
  val unit: EdgaUnit,
  val config: Config,
  val claim: String => Boolean
)(implicit withSchemaValidation: ValidationMode)
    extends AstCreatorBase(filename)
    with AstNodeBuilder[Value, AstCreator]
    with AstForExpressions
    with AstForCpp
    with MacroCalls:

  protected val types = new TypeNames(unit)

  protected val scope: Scope[String, (NewNode, String), NewNode] = new Scope()

  /** Variables in scope by id: their LOCAL or METHOD_PARAMETER_IN, for REF edges. */
  protected val variables = mutable.HashMap.empty[Long, NewNode]

  /** The `this` parameters of member functions, by variable id: the graph has no parameter for
    * them, as the CDT frontend has none.
    */
  protected val thisVariables = mutable.HashSet.empty[Long]

  /** The full names of the METHODs being built, innermost first. */
  private var methodStack: List[String] = Nil

  private var currentPath = filename

  protected def globalTypeDeclFullName: String =
      s"$currentPath:${NamespaceTraversal.globalNamespaceName}"

  /** The METHOD a lambda is written in, for the lambda's full name. */
  protected def enclosingMethodFullName: String =
      methodStack.headOption.getOrElse(globalTypeDeclFullName)

  protected val usedTypes = mutable.LinkedHashSet.empty[String]

  /** The type names this unit's AST uses, for the global type table. */
  def usedTypeNames: Seq[String] = usedTypes.toSeq

  /** The project root as the file system resolves it: edga names files by their real paths. */
  private val root = AstCreator.realPath(Paths.get(config.inputPath))

  private val sourceLines = mutable.HashMap.empty[Long, Option[Array[String]]]

  def createAst(): DiffGraphBuilder =
    val files   = filesToWrite
    val written = files.map(_.id).toSet
    files.foreach(f => Ast.storeInDiffGraph(fileAst(f, written), diffGraph))
    usedTypes.foreach(t => CGlobal.usedTypes.putIfAbsent(t, true))
    diffGraph

  /** The translation unit's own file, and the project headers that belong to it. */
  private def filesToWrite: Seq[FileEntry] =
    val primary = unit.primaryFile.toSeq
    val headers = unit.files.values.toSeq.sortBy(_.id).filter { f =>
        f.id != 0L && f.inRoot && !f.system && claim(f.path)
    }
    primary ++ headers

  // ---- files --------------------------------------------------------------------------------

  private def relativePath(f: FileEntry): String =
      if f.id == 0L then filename
      else
        val p = AstCreator.realPath(Paths.get(f.path))
        if p.startsWith(root) then root.relativize(p).toString else f.path

  private def fileAst(file: FileEntry, written: Set[Long]): Ast =
    val path = relativePath(file)
    currentPath = path
    val fullName = s"$path:${NamespaceTraversal.globalNamespaceName}"
    val namespace = NewNamespaceBlock()
        .name(NamespaceTraversal.globalNamespaceName)
        .fullName(fullName)
        .filename(path)
    val name = NamespaceTraversal.globalNamespaceName
    val globalTypeDecl = NewTypeDecl()
        .name(name)
        .fullName(fullName)
        .filename(path)
        .code(name)
        .astParentType(NodeTypes.NAMESPACE_BLOCK)
        .astParentFullName(fullName)
        .isExternal(false)
        .lineNumber(Integer.valueOf(1))
        .columnNumber(Integer.valueOf(1))
    val globalMethod = NewMethod()
        .name(name)
        .code(name)
        .fullName(fullName)
        .filename(path)
        .astParentType(NodeTypes.TYPE_DECL)
        .astParentFullName(fullName)
        .isExternal(false)
        .lineNumber(Integer.valueOf(1))
        .columnNumber(Integer.valueOf(1))
    scope.pushNewScope(globalMethod)
    val block = NewBlock().code("<empty>").typeFullName(registerType("<empty>"))
        .lineNumber(Integer.valueOf(1)).columnNumber(Integer.valueOf(1))

    val inFile = (v: Value) => v.position.exists(_.file == file.id)
    val typeDecls = unit.types.values.toSeq.sortBy(_("id").num).filter { t =>
        isDefinedRecordOrTypedef(t) && inFile(t) && !isClosure(t)
    }.flatMap(typeDeclAst(_, path))
    val globals = unit.globals.filter(inFile).flatMap(globalAst)
    // a member function defined in its class is written in the class's TYPE_DECL
    val routines = unit.routines.filter { r =>
        inFile(r) && !r.flag("implicit") && isWritten(r) && !definedInClass(r)
    }.flatMap(routineAst(_, path))
    val instances = if file.id == 0L then foreignInstanceAsts(written) else Seq.empty
    val lambdas   = lambdaAsts.toSeq
    lambdaAsts.clear()
    val children = typeDecls ++ globals ++ routines ++ instances ++ lambdas
    setArgumentIndices(children)
    scope.popScope()
    val methodReturn = NewMethodReturn().code("RET").typeFullName(registerType(X2CpgDefines.Any))
        .evaluationStrategy(EvaluationStrategies.BY_VALUE)
        .lineNumber(Integer.valueOf(1)).columnNumber(Integer.valueOf(1))
    Ast(namespace).withChild(
      Ast(globalTypeDecl).withChild(
        methodAst(globalMethod, Seq.empty, blockAst(block, children.toList), methodReturn)
      )
    )
  end fileAst

  /** The template instances this unit uses from project headers another unit writes. Which
    * instances a unit has depends on what it uses, so each unit writes its own and
    * DuplicateDefinitionPass keeps one copy of each. An instance class is written with its members,
    * its member functions on their own: the copy kept is the one with the most member functions.
    */
  private def foreignInstanceAsts(written: Set[Long]): Seq[Ast] =
    def foreignFile(v: Value): Option[FileEntry] =
        v.position.flatMap(p => unit.files.get(p.file)).filter(f =>
            f.id != 0L && f.inRoot && !f.system && !written.contains(f.id)
        )
    val types = unit.types.values.toSeq.sortBy(_("id").num).filter { t =>
        t.flag("templateInstance") && isDefinedRecordOrTypedef(t) && !isClosure(t)
    }.flatMap(t =>
        foreignFile(t).flatMap(f => typeDeclAst(t, relativePath(f), withMethods = false))
    )
    val routines = unit.routines.filter { r =>
        r.flag("templateInstance") && r.field("body").isDefined && !r.flag("implicit") &&
        isWritten(r)
    }.flatMap(r => foreignFile(r).flatMap(f => routineAst(r, relativePath(f))))
    types ++ routines

  /** A routine of the project, or a library routine the unit calls: lambda bodies belong to the
    * routine they are written in.
    */
  private def isWritten(r: Value): Boolean = !r.flag("lambda")

  // ---- routines -----------------------------------------------------------------------------

  protected def methodFullNameOf(r: Value): String =
    val name = r.string("name").getOrElse("")
    if !unit.isCpp || r.string("linkage").contains("external") && r.long("class").isEmpty &&
      !r.string("qualifiedName").exists(_.contains("::"))
    then name
    else s"${cppQualifiedName(dotted(r.string("qualifiedName").getOrElse(name)))}:${signatureOf(r)}"

  /** The signature in a METHOD's full name and a call's: C++ spells its types as the CDT frontend
    * does (`geo.Point(geo.Point &)`).
    */
  protected def signatureOf(r: Value): String =
      if unit.isCpp then signatureWith(r, types.signatureType, types.signatureType)
      else methodSignatureOf(r)

  /** The signature a METHOD itself carries: references are their referents (`geo.Point (geo.Point)`
    * for a definition).
    */
  protected def methodSignatureOf(r: Value): String =
      signatureWith(r, id => types(id), types.returnType)

  private def signatureWith(
    r: Value,
    param: Option[Long] => String,
    returned: Option[Long] => String
  ): String =
    val params = r.list("params").filterNot(_.flag("this")).map(p => param(p.long("type")))
    val all    = if r.flag("variadic") then params :+ "..." else params
    val ret = r.string("special") match
      case Some("constructor") | Some("destructor") => "void"
      case _                                        => returned(r.long("returnType"))
    s"$ret(${all.mkString(",")})"

  protected def dotted(name: String): String = types.dotted(name)

  /** A routine's METHOD. `parent` is the TYPE_DECL a member function defined in its class is
    * written in; a `stub` is a member function's declaration in its class, without the body.
    */
  private def routineAst(
    r: Value,
    path: String,
    parent: Option[String] = None,
    stub: Boolean = false,
    names: Option[(String, String)] = None,
    captures: Map[String, Long] = Map.empty
  ): Option[Ast] =
    val name     = names.map(_._1).getOrElse(cppName(r.string("name").getOrElse("")))
    val fullName = names.map(_._2).getOrElse(methodFullNameOf(r))
    val body     = if stub then None else r.field("body")
    // the CDT frontend writes a definition's signature with a space before its parameters
    val signature =
        if body.isDefined then
          val spaced = methodSignatureOf(r).replaceFirst("\\(", " (")
          if unit.isCpp then spaced
          else spaced.replace(" ()", if r.flag("prototyped") then " (void)" else " ()")
        else methodSignatureOf(r)
    val method = methodNode(r, name, methodCode(r, body), fullName, Some(signature), path)
        .astParentType(NodeTypes.TYPE_DECL)
        .astParentFullName(parent.getOrElse(s"$path:${NamespaceTraversal.globalNamespaceName}"))
    // a METHOD is where its declaration starts, and ends with its body
    r.field("start").flatMap(EdgaUnit.pos).filter(_ => !stub).foreach { p =>
        method.lineNumber(Integer.valueOf(p.line)).columnNumber(Integer.valueOf(p.column))
    }
    body.flatMap(_.field("end")).flatMap(EdgaUnit.pos).foreach { p =>
        method.lineNumberEnd(Integer.valueOf(p.line)).columnNumberEnd(Integer.valueOf(p.column))
    }
    scope.pushNewScope(method)
    methodStack = fullName :: methodStack
    // `f(void)`: the CDT frontend writes the empty parameter list as one `void` parameter
    val voidParam = Option.when(
      !unit.isCpp && r.list("params").isEmpty && r.flag("prototyped")
    ) {
        Ast(parameterInNode(
          r,
          "",
          "void",
          1,
          false,
          EvaluationStrategies.BY_VALUE,
          registerType("void")
        ))
    }
    r.list("params").filter(_.flag("this")).flatMap(_.long("id")).foreach { id =>
      thisVariables += id
      if r.flag("lambda") then closureThis(id) = captures
    }
    val params = voidParam.toSeq ++ r.list("params").filterNot(_.flag("this")).zipWithIndex.map {
        (p, i) =>
          val pname = p.string("name").getOrElse("")
          val tpe   = registerType(types(p.long("type")))
          // a parameter's code is its declaration as written
          val written =
              for
                start <- p.field("start").flatMap(EdgaUnit.pos)
                at    <- p.position.filter(_ => pname.nonEmpty)
                text  <- textOf(start, Pos(at.file, at.line, at.column + pname.length - 1))
              yield text
          val param = parameterInNode(
            p,
            pname,
            written.getOrElse(if pname.isEmpty then tpe else s"$tpe $pname"),
            i + 1,
            false,
            if types.isPointer(p.long("type").getOrElse(-1L)) then EvaluationStrategies.BY_SHARING
            else EvaluationStrategies.BY_VALUE,
            tpe
          )
          p.long("id").foreach(id => variables(id) = param)
          if pname.nonEmpty then scope.addToScope(pname, (param, tpe))
          Ast(param)
    }
    val returnType = registerType(r.string("special") match
      case Some("constructor") | Some("destructor") => "void"
      case _                                        => types.returnType(r.long("returnType"))
    )
    val methodReturn = methodReturnNode(r, returnType)
    val bodyAst = withFunctionScope(body) {
        body match
          case Some(b) if b.kind == "block" => blockStatementAst(b, constructorInitAsts(r))
          case Some(b)                      => statementAst(b)
          case None => Ast(NewBlock().code("<empty>").typeFullName(registerType("<empty>")))
    }
    methodStack = methodStack.drop(1)
    scope.popScope()
    Some(methodAst(method, params, bodyAst, methodReturn, modifiersOf(r)))
  end routineAst

  /** The modifiers the CDT frontend gives a function: a constructor is marked as one, and a
    * function with internal linkage outside a class (`static`, or in an unnamed namespace) is
    * `static`.
    */
  private def modifiersOf(r: Value): Seq[NewModifier] =
      if r.string("special").contains("constructor") then
        Seq(
          NewModifier().modifierType(ModifierTypes.CONSTRUCTOR),
          NewModifier().modifierType(ModifierTypes.PUBLIC)
        )
      else if r.long("class").isEmpty && r.string("linkage").contains("internal") then
        Seq(NewModifier().modifierType(ModifierTypes.STATIC))
      else Seq.empty

  /** A lambda's METHOD, written in the file's global block. `captures` are the outer variables its
    * closure's members copy or refer to, by member name.
    */
  protected def lambdaRoutineAst(
    r: Value,
    name: String,
    fullName: String,
    captures: Map[String, Long]
  ): Option[Ast] =
      routineAst(r, currentPath, names = Some((name, fullName)), captures = captures)

  /** A constructor's member initialisers, `data(new int[16])`, before its body: each the store of
    * its value into the member of the object being built, `this->data`.
    */
  private def constructorInitAsts(r: Value): Seq[Ast] =
    val classType = r.long("class")
    val fields    = classType.flatMap(unit.types.get).toSeq.flatMap(_.list("fields"))
    val thisType  = registerType(s"${types(classType)}*")
    r.list("ctorInits").filterNot(_.flag("implicit")).flatMap { ci =>
        for
          field <- ci.string("field")
          init  <- ci.field("init")
          value <- memberInitializerAst(init)
        yield
          val tpe = registerType(
            types(fields.find(_.string("name").contains(field)).flatMap(_.long("type")))
          )
          val at = init.field("expr").getOrElse(init)
          val access = callNode(
            at,
            s"this->$field",
            Operators.indirectFieldAccess,
            Operators.indirectFieldAccess,
            DispatchTypes.DYNAMIC_DISPATCH,
            None,
            Some(tpe)
          )
          val member =
              callAst(
                access,
                Seq(
                  Ast(literalNode(at, "this", thisType)),
                  Ast(fieldIdentifierNode(at, field, field))
                )
              )
          val call = callNode(
            at,
            s"$field(${codeOfAst(value)})",
            Operators.assignment,
            Operators.assignment,
            DispatchTypes.STATIC_DISPATCH,
            None,
            Some(tpe)
          )
          callAst(call, Seq(member, value))
    }
  end constructorInitAsts

  private def memberInitializerAst(init: Value): Option[Ast] =
      init.kind match
        case "expression" => init.field("expr").map(expressionAst)
        case "constructor" =>
            routineOf(init.long("routine")).filter(inProject) match
              case Some(ctor) =>
                  val tpe = types(ctor.long("class"))
                  Some(
                    linkedCallAst(init, ctor, tpe, None, init.list("args").map(expressionAst))._2
                  )
              case None => init.list("args").headOption.map(expressionAst)
        case _ => None

  /** A definition's code: its text from where its declaration starts to the end of its body. */
  private def methodCode(r: Value, body: Option[Value]): String =
      (for
        start <- r.field("start").flatMap(EdgaUnit.pos).orElse(r.position)
        end   <- body.flatMap(_.field("end")).flatMap(EdgaUnit.pos)
        text  <- textOf(start, end)
      yield text).getOrElse(r.string("name").getOrElse(""))

  /** Whether `r` is a member function defined inside its class's braces. */
  protected def definedInClass(r: Value): Boolean =
      r.long("class").flatMap(unit.types.get).exists { c =>
          classSpan(c) match
            case Some((start, end)) => r.position.exists(p => within(p, start, end))
            case None               => r.flag("inline") && r.field("body").isDefined
      }

  private def classSpan(t: Value): Option[(Pos, Pos)] =
      t.field("span").map(_.arr.toSeq.flatMap(EdgaUnit.pos)).filter(_.size == 2).map(s =>
          (s(0), s(1))
      )

  private def within(p: Pos, start: Pos, end: Pos): Boolean =
      p.file == start.file && p.file == end.file &&
          (p.line > start.line || p.line == start.line && p.column >= start.column) &&
          (p.line < end.line || p.line == end.line && p.column <= end.column)

  /** The function attributes the overlay reads from a declaration (`malloc`, `alloc_size`, ...). */
  private def attributeTags(r: Value, method: NewMethod): Unit = ()

  /** A declaration's code: its source text, when the front end gave its position. */
  private def codeOfDeclaration(r: Value): String =
      r.string("name").getOrElse("")

  // ---- globals ------------------------------------------------------------------------------

  private def globalAst(v: Value): Seq[Ast] =
    val name  = v.string("name").getOrElse("")
    val tpe   = registerType(types(v.long("type")))
    val local = localNode(v, name, s"$tpe $name", tpe)
    v.long("id").foreach(id => variables(id) = local)
    scope.addToScope(name, (local, tpe))
    if v.string("storage").contains("static") then
      tagNode(local, X2CpgDefines.StorageClassTag, X2CpgDefines.StorageClassStatic)
    val init = v.field("init").map(initializerAssignment(v, local, tpe, _)).toSeq
    Ast(local) +: init

  // ---- types --------------------------------------------------------------------------------

  private def isDefinedRecordOrTypedef(t: Value): Boolean =
      t.string("kind") match
        case Some("struct" | "class" | "union") => !t.flag("incomplete")
        case Some("typeref")                    => t.string("typedef").exists(_.nonEmpty)
        case _                                  => false

  private def isClosure(t: Value): Boolean = t.flag("closure")

  private def typeDeclAst(t: Value, path: String, withMethods: Boolean = true): Option[Ast] =
      t.string("kind") match
        case Some("typeref") =>
            val name  = t.string("typedef").getOrElse("")
            val alias = registerType(types(t.long("of")))
            Some(Ast(typeDeclNode(
              t,
              name,
              registerType(name),
              path,
              s"typedef $name",
              alias = Some(alias)
            )))
        case _ =>
            val name     = types(t("id").num.toLong)
            val fullName = registerType(name)
            val inherits = t.list("bases").flatMap(_.long("type")).map(b => registerType(types(b)))
            val decl =
                typeDeclNode(
                  t,
                  unqualifiedTypeName(name),
                  fullName,
                  path,
                  name,
                  inherits = inherits
                )
            val members = t.list("fields").map { f =>
              val fname = f.string("name").getOrElse("")
              Ast(memberNode(f, fname, fname, registerType(types(f.long("type")))))
            }
            // its member functions: those defined in its braces, and a declaration of each other
            val id = t("id").num.toLong
            val methods = unit.routines.filter { r =>
                withMethods && r.long("class").contains(id) && !r.flag("implicit") && isWritten(r)
            }.flatMap { r =>
                if definedInClass(r) then routineAst(r, path, parent = Some(fullName))
                else routineAst(r, path, parent = Some(fullName), stub = true)
            }
            Some(Ast(decl).withChildren(inSourceOrder(members ++ methods)))

  /** A class's members and member functions in the order they are written. */
  private def inSourceOrder(asts: Seq[Ast]): Seq[Ast] =
      asts.sortBy { a =>
          a.root.map(_.properties) match
            case Some(p) =>
                (
                  p.get("LINE_NUMBER").map(_.asInstanceOf[Integer].intValue).getOrElse(
                    Int.MaxValue
                  ),
                  p.get("COLUMN_NUMBER").map(_.asInstanceOf[Integer].intValue).getOrElse(0)
                )
            case None => (Int.MaxValue, 0)
      }

  // ---- statements -----------------------------------------------------------------------------

  protected def statementAst(s: Value): Ast = withMacroCall(s)(statementAstOf(s))

  private def statementAstOf(s: Value): Ast =
      s.kind match
        case "block" => blockStatementAst(s)
        case "expr"  => s.field("expr").map(expressionAst).getOrElse(Ast())
        case "decl"  => wrapped(s, declarationAsts(s))
        case "init"  => wrapped(s, initStatementAsts(s))
        // the front end's `return;` at the end of a function
        case "return" if s.flag("implicit") && s.field("expr").isEmpty => Ast()
        case "return"                                                  => returnStatementAst(s)
        case "if"                                                      => ifAst(s)
        case "while"                                                   => whileStatementAst(s)
        case "end_test_while"                                          => doWhileStatementAst(s)
        case "for"                                                     => forStatementAst(s)
        case "switch"                                                  => switchAst(s)
        case "switch_case" =>
            val name = if s.flag("default") then "default" else "case"
            val code = if s.flag("default") then "default:"
            else s"case ${s.string("value").getOrElse("")}:"
            Ast(jumpTargetNode(s, name, code, Some("CaseStatement")))
        case "label" =>
            s.string("label") match
              case Some(label) => Ast(jumpTargetNode(s, label, s"$label:", Some("LabelStatement")))
              case None        => Ast() // the front end's own labels for loops and switches
        case "goto"  => jumpAst(s)
        case "empty" => Ast()
        // the front end's bookkeeping for variable-length arrays
        case "vla_decl" | "set_vla_size" => Ast()
        case "try_block"                 => tryAst(s)
        case "range_based_for"           => rangeForAst(s)
        case "stmt_expr_result"          => s.field("expr").map(expressionAst).getOrElse(Ast())
        case _                           => Ast(unknownNode(s, code(s)))

  /** Statements that become several ASTs in a context that takes one. */
  private def wrapped(s: Value, asts: Seq[Ast]): Ast =
      asts match
        case Seq()       => Ast()
        case Seq(single) => single
        case many =>
            val block = blockNode(s, "<empty>", registerType(X2CpgDefines.Any))
            blockAst(block, many.toList)

  /** A block; `prelude` is what runs before its statements (a constructor's member initialisers).
    * The destructors of the objects it declares run where control falls out of it.
    */
  private def blockStatementAst(s: Value, prelude: Seq[Ast] = Seq.empty): Ast =
    val block = blockNode(s, code(s), registerType("void"))
    scope.pushNewScope(block)
    val children = withExitScope("block", s) {
        val stmts = s.list("stmts")
        prelude ++ stmts.flatMap(child => statementAsts(child)) ++
            scopeEndDestructorCalls(s, stmts)
    }
    scope.popScope()
    blockAst(block, children.toList)

  /** A statement in a block: a declaration is a LOCAL per variable and an assignment per
    * initialiser, flattened into the block as the CDT frontend does.
    */
  private def statementAsts(s: Value): Seq[Ast] =
      s.kind match
        // a block the front end made (around a loop or switch, for its labels) is not one
        case "block" if s.flag("implicit") => s.list("stmts").flatMap(statementAsts)
        case "decl"                        => declarationAsts(s)
        case "init"                        => initStatementAsts(s)
        case "switch_case" if !s.flag("default") =>
            val label = statementAst(s)
            val value = s.string("value").map(v => Ast(literalNode(s, v, registerType("int"))))
            label +: value.toSeq
        case "label"                               => Seq(statementAst(s)).filter(_.root.isDefined)
        case "empty" | "vla_decl" | "set_vla_size" => Seq.empty
        case _                                     => Seq(statementAst(s)).filter(_.root.isDefined)

  private def declarationAsts(s: Value): Seq[Ast] =
      s.list("decls").flatMap { d =>
          d.long("typeDecl") match
            case Some(_) => Seq.empty
            // a variable the front end made for itself
            case None if d.flag("implicit") => Seq.empty
            case None =>
                val name  = d.string("name").getOrElse("")
                val tpe   = registerType(types(d.long("type")))
                val local = localNode(d, name, s"$tpe $name", tpe)
                d.long("id").foreach(id => variables(id) = local)
                scope.addToScope(name, (local, tpe))
                if d.string("storage").contains("static") then
                  tagNode(local, X2CpgDefines.StorageClassTag, X2CpgDefines.StorageClassStatic)
                if d.field("init").isDefined then d.long("id").foreach(initializedAtDeclaration.add)
                val init = d.field("init").flatMap { i =>
                    if unit.isCpp && i.kind == "constructor" then
                      constructedVariableAst(d, local, tpe, i)
                    else Some(initializerAssignment(d, local, tpe, i))
                }
                for
                  id   <- d.long("id")
                  dtor <- d.field("init").flatMap(_.long("destructor"))
                do destroysAtScopeEnd(id, name, Some(dtor))
                Ast(local) +: init.toSeq
      }

  /** A local's initialisation the front end placed after other statements. */
  private def initStatementAsts(s: Value): Seq[Ast] =
      (s.long("var"), s.field("init")) match
        // written with the declaration already
        case (Some(id), _) if initializedAtDeclaration.contains(id) => Seq.empty
        case (Some(id), Some(init)) =>
            variables.get(id).collect { case local: NewLocal =>
                initializerAssignment(
                  ujson.Obj("name" -> local.name, "p" -> s.field("p").getOrElse(ujson.Null)),
                  local,
                  local.typeFullName,
                  init
                )
            }.toSeq
        case _ => Seq.empty

  /** Variables whose initialiser was written with their declaration. The front end also lists a
    * declaration's initialisation as a statement of its own when a statement precedes it.
    */
  private val initializedAtDeclaration = mutable.HashSet.empty[Long]

  private def returnStatementAst(s: Value): Ast =
    val expr = s.field("expr").orElse(s.field("init").flatMap(_.field("expr")))
    // a value the front end constructs in place (`return Point(x, y)`) is its initialiser
    val init  = s.field("init").filter(_ => expr.isEmpty)
    val value = expr.orElse(init)
    def plain: Ast =
      val ret = returnNode(s, code(s))
      val valueAst = expr.map(expressionAst).orElse(init.map { i =>
        val ast = initializerExpressionAst(i)
        ast.root.foreach {
            case c: NewCall if c.lineNumber.isEmpty =>
                c.lineNumber(line(s)).columnNumber(column(s))
            case _ =>
        }
        ast
      })
      valueAst match
        case Some(e) =>
            e.root.map(r => Ast(ret).withChild(e).withArgEdge(ret, r)).getOrElse(Ast(ret))
        case None => Ast(ret)
    returnLeavingScopes(s, value, plain)
  end returnStatementAst

  private def conditionAst(s: Value, key: String = "cond"): Ast =
      s.field(key).map(e => expressionAst(withoutImplicitTest(e))).getOrElse(Ast())

  private def branchAst(s: Option[Value]): Ast =
      s match
        case Some(b) if b.kind == "block" && !b.flag("implicit") => statementAst(b)
        // the front end's block around a loop's body, for its `continue` label
        case Some(b) if b.kind == "block" && soleBlock(b).isDefined =>
            statementAst(soleBlock(b).get)
        case Some(other) =>
            val block = blockNode(other, "<empty>", registerType("void"))
            scope.pushNewScope(block)
            val children = statementAsts(other)
            setArgumentIndices(children)
            scope.popScope()
            blockAst(block, children.toList)
        case None => Ast()

  private def soleBlock(b: Value): Option[Value] =
      b.list("stmts").filterNot(s => s.kind == "label" && s.string("label").isEmpty) match
        case Seq(inner) if inner.kind == "block" && !inner.flag("implicit") => Some(inner)
        case _                                                              => None

  private def ifAst(s: Value): Ast =
    val cond    = conditionAst(s)
    val ifNode  = controlStructureNode(s, ControlStructureTypes.IF, s"if (${codeOfAst(cond)})")
    val thenAst = branchAst(s.field("then"))
    val elseAst = s.field("else") match
      case Some(e) =>
          val elseNode = controlStructureNode(e, ControlStructureTypes.ELSE, "else")
          Ast(elseNode).withChild(branchAst(Some(e)))
      case None => Ast()
    controlStructureAst(ifNode, Some(cond), Seq(thenAst, elseAst))

  private def whileStatementAst(s: Value): Ast =
    val cond = conditionAst(s)
    whileAst(
      Some(cond),
      Seq(withExitScope("loop", s)(branchAst(s.field("body")))),
      Some(s"while (${codeOfAst(cond)})"),
      lineNumber = line(s),
      columnNumber = column(s)
    )

  private def doWhileStatementAst(s: Value): Ast =
    val cond   = conditionAst(s)
    val doNode = controlStructureNode(s, ControlStructureTypes.DO, code(s))
    controlStructureAst(
      doNode,
      Some(cond),
      Seq(withExitScope("loop", s)(branchAst(s.field("body")))),
      placeConditionLast = true
    )

  private def forStatementAst(s: Value): Ast = withExitScope("loop", s)(forLoopAst(s))

  private def forLoopAst(s: Value): Ast =
    val initBlock = blockNode(s, "<empty>", registerType("void"))
    scope.pushNewScope(initBlock)
    val initAsts = s.field("init").toSeq.flatMap(statementAsts)
    val initAst  = blockAst(initBlock, initAsts.toList)
    val cond     = conditionAst(s)
    cond.root.foreach { case e: ExpressionNew => e.argumentIndex = 2; case _ => }
    val update = s.field("inc").map(expressionAst).getOrElse(Ast())
    update.root.foreach { case e: ExpressionNew => e.argumentIndex = 3; case _ => }
    val body = branchAst(s.field("body"))
    body.root.foreach { case e: ExpressionNew => e.argumentIndex = 4; case _ => }
    scope.popScope()
    val forNode = controlStructureNode(s, ControlStructureTypes.FOR, code(s))
    forAst(forNode, Seq(), Seq(initAst), Seq(cond), Seq(update), Seq(body))

  private def switchAst(s: Value): Ast =
    val cond = conditionAst(s)
    val switchNode =
        controlStructureNode(s, ControlStructureTypes.SWITCH, s"switch(${codeOfAst(cond)})")
    val body = withExitScope("switch", s)(branchAst(s.field("body")))
    controlStructureAst(switchNode, Some(cond), Seq(body))

  private def jumpAst(s: Value): Ast =
    val jump = s.string("jump") match
      case Some("break") => Ast(controlStructureNode(s, ControlStructureTypes.BREAK, "break;"))
      case Some("continue") =>
          Ast(controlStructureNode(s, ControlStructureTypes.CONTINUE, "continue;"))
      case _ =>
          val label = s.string("label").getOrElse("")
          Ast(controlStructureNode(s, ControlStructureTypes.GOTO, s"goto $label;"))
    jumpLeavingScopes(s, jump)

  /** `for (T v : range) body`: the range, the loop variable's LOCAL and the body, as the CDT
    * frontend writes the loop; the iteration the front end spells out is not.
    */
  private def rangeForAst(s: Value): Ast = withExitScope("loop", s) {
      val block = blockNode(s, "<empty>", registerType("void"))
      scope.pushNewScope(block)
      val over    = s.field("over").flatMap(_.field("expr"))
      val overAst = over.map(expressionAst).getOrElse(Ast())
      val variable = s.field("variable").toSeq.map { v =>
        val name  = v.string("name").getOrElse("")
        val tpe   = registerType(types(v.long("type")))
        val local = localNode(v, name, s"$tpe $name", tpe)
        v.long("id").foreach(id => variables(id) = local)
        scope.addToScope(name, (local, tpe))
        (local, s"$tpe $name")
      }
      // a body that is not a block is the statement itself
      val body = s.field("body") match
        case Some(b) if b.kind == "block" && b.flag("implicit") && soleBlock(b).isEmpty =>
            statementAsts(b)
        case other => Seq(branchAst(other))
      scope.popScope()
      val written = s"for (${variable.map(_._2).mkString}:${codeOfAst(overAst)})"
      val forNode = controlStructureNode(s, ControlStructureTypes.FOR, written)
      controlStructureAst(forNode, None, Seq(overAst) ++ variable.map(v => Ast(v._1)) ++ body)
  }

  /** The try body, then one `catch` block that groups the handlers, each a block of its own. */
  private def tryAst(s: Value): Ast =
    val tryNode = controlStructureNode(s, ControlStructureTypes.TRY, "try")
    val body    = branchAst(s.field("body"))
    body.root.foreach { case e: ExpressionNew => e.argumentIndex = 1; e.order = 1; case _ => }
    val handlers = s.list("handlers").zipWithIndex.map { (h, i) =>
      val block = blockNode(h, "<empty>", registerType("void"))
      scope.pushNewScope(block)
      val param = h.field("param").toSeq.map { p =>
        val name  = p.string("name").getOrElse("")
        val tpe   = registerType(types(p.long("type")))
        val local = localNode(p, name, s"$tpe $name", tpe)
        p.long("id").foreach(id => variables(id) = local)
        scope.addToScope(name, (local, tpe))
        Ast(local)
      }
      val handlerBody = branchAst(h.field("body"))
      handlerBody.root.foreach {
          case e: ExpressionNew =>
              e.argumentIndex = param.size + 1
              e.order = param.size + 1
          case _ =>
      }
      scope.popScope()
      blockAst(block.order(i + 1).argumentIndex(i + 1), (param :+ handlerBody).toList)
    }
    val group = Option.when(handlers.nonEmpty) {
        val groupNode = NewBlock().code("catch").typeFullName(registerType("void"))
            .order(2).argumentIndex(2)
        blockAst(groupNode, handlers.toList)
    }
    Ast(tryNode).withChild(body).withChildren(group.toList)
  end tryAst

  // ---- positions and code -----------------------------------------------------------------

  protected def line(node: Value): Option[Integer] = startOf(node).map(p => Integer.valueOf(p.line))

  protected def column(node: Value): Option[Integer] =
      startOf(node).map(p => Integer.valueOf(p.column))

  /** Where a node starts: an expression where its text does (`a + b` at `a`), as the CDT frontend
    * places it, unless a macro wrote it.
    */
  private def startOf(node: Value): Option[Pos] =
    val p = node.position
    node.field("range").collect { case ujson.Arr(items) => items }.flatMap(_.headOption)
        .flatMap(EdgaUnit.pos).filter(r =>
            node.field("mi").isEmpty && p.forall(_.file == r.file)
        ).orElse(p)

  protected def lineEnd(node: Value): Option[Integer] =
      node.field("end").flatMap(EdgaUnit.pos).orElse(rangeEnd(node)).map(p =>
          Integer.valueOf(p.line)
      )

  protected def columnEnd(node: Value): Option[Integer] =
      node.field("end").flatMap(EdgaUnit.pos).orElse(rangeEnd(node))
          .map(p => Integer.valueOf(p.column))

  private def rangeEnd(node: Value): Option[Pos] =
      node.field("range").flatMap(r => r.arr.lift(1)).flatMap(EdgaUnit.pos)

  /** The node's source text, from its start to its end in one file. */
  protected def code(node: Value): String =
      sourceText(node).getOrElse(node.string("name").getOrElse(""))

  protected def sourceText(node: Value): Option[String] =
    val range = node.field("range").map(_.arr.toSeq.flatMap(EdgaUnit.pos))
        .filter(_.size == 2).map(r => (r(0), r(1)))
        .orElse(for
          start <- node.position
          end   <- node.field("end").flatMap(EdgaUnit.pos)
        yield (start, end))
    range.filter((s, e) => s.file == e.file && node.field("mi").isEmpty).flatMap { (s, e) =>
        linesOf(s.file).flatMap(textBetween(_, s, e))
    }

  /** The text from `start` to `end` in one file. */
  protected def textOf(start: Pos, end: Pos): Option[String] =
      if start.file != end.file then None
      else linesOf(start.file).flatMap(textBetween(_, start, end))

  protected def linesOf(file: Long): Option[Array[String]] =
      sourceLines.getOrElseUpdate(
        file,
        unit.files.get(file).flatMap { f =>
            scala.util.Try(Files.readAllLines(Paths.get(f.path)).toArray(Array.empty[String])).toOption
        }
      )

  /** The text from `start` to `end` (the end's character included). */
  private def textBetween(lines: Array[String], start: Pos, end: Pos): Option[String] =
      if start.line < 1 || end.line > lines.length || end.line < start.line then None
      else if start.line == end.line then
        val l = lines(start.line - 1)
        Option.when(start.column >= 1 && end.column <= l.length + 1 && end.column >= start.column)(
          l.substring(start.column - 1, math.min(l.length, end.column + tokenTail(l, end.column)))
        )
      else
        val first  = lines(start.line - 1).drop(start.column - 1)
        val middle = (start.line until end.line - 1).map(lines(_))
        val last   = lines(end.line - 1)
        Some((Seq(first) ++ middle :+ last.take(end.column + tokenTail(last, end.column - 1) - 1))
            .mkString("\n"))

  /** The rest of the identifier or number the end position starts. */
  private def tokenTail(line: String, column: Int): Int =
    var i = column
    while i < line.length && (line(i).isLetterOrDigit || line(i) == '_') do i += 1
    if column >= 1 && column <= line.length && (line(column - 1).isLetterOrDigit || line(
        column - 1
      ) == '_')
    then i - column
    else 0

  protected def codeOfAst(ast: Ast): String =
      ast.root.collect { case e: ExpressionNew => e.code }.getOrElse("")

  // ---- helpers ------------------------------------------------------------------------------

  protected def registerType(t: String): String =
    usedTypes += t
    t

  /** Tags for the frontend's own facts, flushed with the AST. */
  protected def tagNode(node: NewNode, name: String, value: String): Unit =
    val tag = NewTag().name(name).value(value)
    diffGraph.addNode(tag)
    diffGraph.addEdge(node, tag, io.shiftleft.codepropertygraph.generated.EdgeTypes.TAGGED_BY)
end AstCreator

object AstCreator:
  /** A path as the file system resolves it, links followed; normalised when it does not exist. */
  def realPath(path: Path): Path =
      scala.util.Try(path.toRealPath()).getOrElse(path.toAbsolutePath.normalize)
