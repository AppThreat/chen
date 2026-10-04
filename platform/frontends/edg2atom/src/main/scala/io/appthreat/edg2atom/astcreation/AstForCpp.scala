package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.parser.{EdgaUnit, Pos}
import io.appthreat.edg2atom.parser.EdgaUnit.*
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import ujson.Value

import scala.collection.mutable

/** The calls C++ makes without spelling them as calls, in the CDT frontend's shapes: overloaded
  * operators, constructors and destructors, `new` and `delete`, and calls through a lambda's
  * closure.
  *
  * A call is linked to a METHOD only when the graph holds one for its callee: a function declared
  * in a file of the project, not one the front end made itself (an implicit copy constructor). A
  * library operator keeps the shape of the built-in operator it is written with, whose data-flow
  * semantics summarise it better than a call to an unknown function would; a library constructor or
  * destructor is not a call at all.
  *
  * Destructors run where objects with automatic storage end their lifetime: where control falls out
  * of the block that declares them, and at every `return`, `break`, `continue` and `goto` that
  * leaves it early, innermost scope first and in the reverse order of construction. A `return`
  * whose value could observe a destroyed object stores the value in a local named `<return-value>`
  * first.
  */
trait AstForCpp(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  // ---- the graph's METHODs ------------------------------------------------------------------

  /** Whether the graph holds a METHOD for `r`. */
  protected def inProject(r: Value): Boolean =
      !r.flag("implicit") && r.position.flatMap(p => unit.files.get(p.file)).exists(_.inRoot)

  protected def routineOf(id: Option[Long]): Option[Value] = id.flatMap(unit.routinesById.get)

  /** `operator+` as the CDT frontend names it: `operator +`. */
  protected def cppName(name: String): String =
      if name.startsWith("operator") && name.length > 8 && !(name(8).isLetterOrDigit || name(
          8
        ) == '_' || name(8) == ' ')
      then s"operator ${name.drop(8)}"
      else name

  /** A qualified name with its operator function named as the CDT frontend names it. */
  protected def cppQualifiedName(qualified: String): String =
    val at = qualified.lastIndexOf("operator")
    if at < 0 || at > 0 && qualified.substring(0, at).takeRight(1) != "." then qualified
    else qualified.substring(0, at) + cppName(qualified.substring(at))

  /** A type's own name, without its scopes and template arguments: `lock_guard` for
    * `std.lock_guard<std.mutex>`.
    */
  protected def simpleTypeName(tpe: String): String =
      tpe.takeWhile(_ != '<').split('.').lastOption.filter(_.nonEmpty).getOrElse(tpe)

  /** A type's name without its scopes, template arguments kept: `vector<std.string>` for
    * `std.vector<std.string>`.
    */
  protected def unqualifiedTypeName(tpe: String): String =
    var depth = 0
    var last  = -1
    tpe.indices.foreach { i =>
        tpe(i) match
          case '<'               => depth += 1
          case '>'               => depth -= 1
          case '.' if depth == 0 => last = i
          case _                 =>
    }
    tpe.substring(last + 1)

  protected def isMember(r: Value): Boolean =
      r.long("class").isDefined && !r.string("storage").contains("static")

  private def isVirtual(r: Value): Boolean = r.flag("virtual") || r.flag("pureVirtual")

  /** A call as the CDT frontend builds one: the object of a member call is argument 0, and the
    * receiver of a dynamic dispatch.
    */
  protected def cppCallAst(
    call: NewCall,
    args: Seq[Ast],
    base: Option[Ast] = None,
    receiver: Option[Ast] = None
  ): Ast =
    setArgumentIndices(args)
    val baseRoot = base.flatMap(_.root).toList
    baseRoot.foreach { case e: ExpressionNew => e.argumentIndex = 0; case _ => }
    var ast = Ast(call).withChild(base.getOrElse(Ast()))
    receiver.filterNot(r => base.contains(r)).foreach { r =>
      r.root.foreach { case e: ExpressionNew => e.argumentIndex = -1; case _ => }
      ast = ast.withChild(r)
    }
    ast = ast.withChildren(args).withArgEdges(call, baseRoot).withArgEdges(
      call,
      args.flatMap(_.root)
    )
    receiver.flatMap(_.root).foreach(r => ast = ast.withReceiverEdge(call, r))
    ast
  end cppCallAst

  /** A call to `r`, the graph's METHOD for it, with `receiver` as the object of a member call. */
  protected def linkedCallAst(
    at: Value,
    r: Value,
    tpe: String,
    receiver: Option[Ast],
    args: Seq[Ast],
    callCode: Option[String] = None
  ): (NewCall, Ast) =
    val dispatch =
        if isVirtual(r) then DispatchTypes.DYNAMIC_DISPATCH else DispatchTypes.STATIC_DISPATCH
    val call = callNode(
      at,
      callCode.getOrElse(code(at)),
      cppName(r.string("name").getOrElse("")),
      methodFullNameOf(r),
      dispatch,
      Some(signatureOf(r)),
      Some(registerType(tpe))
    )
    val ast = receiver match
      case Some(self) =>
          cppCallAst(
            call,
            args,
            base = Some(self),
            receiver = Option.when(dispatch == DispatchTypes.DYNAMIC_DISPATCH)(self)
          )
      case None => cppCallAst(call, args)
    (call, ast)
  end linkedCallAst

  // ---- overloaded operators -----------------------------------------------------------------

  private val UnaryOperators: Map[String, String] = Map(
    "plus"      -> Operators.plus,
    "minus"     -> Operators.minus,
    "star"      -> Operators.indirection,
    "ampersand" -> Operators.addressOf,
    "compl"     -> Operators.not,
    "not"       -> Operators.logicalNot
  )

  private val BinaryOperators: Map[String, String] = Map(
    "plus"               -> Operators.addition,
    "minus"              -> Operators.subtraction,
    "star"               -> Operators.multiplication,
    "divide"             -> Operators.division,
    "remainder"          -> Operators.modulo,
    "excl_or"            -> Operators.xor,
    "ampersand"          -> Operators.and,
    "or"                 -> Operators.or,
    "assign"             -> Operators.assignment,
    "lt"                 -> Operators.lessThan,
    "gt"                 -> Operators.greaterThan,
    "le"                 -> Operators.lessEqualsThan,
    "ge"                 -> Operators.greaterEqualsThan,
    "eq"                 -> Operators.equals,
    "ne"                 -> Operators.notEquals,
    "plus_assign"        -> Operators.assignmentPlus,
    "minus_assign"       -> Operators.assignmentMinus,
    "times_assign"       -> Operators.assignmentMultiplication,
    "divide_assign"      -> Operators.assignmentDivision,
    "remainder_assign"   -> Operators.assignmentModulo,
    "excl_or_assign"     -> Operators.assignmentXor,
    "and_assign"         -> Operators.assignmentAnd,
    "or_assign"          -> Operators.assignmentOr,
    "shift_left"         -> Operators.shiftLeft,
    "shift_right"        -> Operators.arithmeticShiftRight,
    "shift_left_assign"  -> Operators.assignmentShiftLeft,
    "shift_right_assign" -> Operators.assignmentArithmeticShiftRight,
    "and_and"            -> Operators.logicalAnd,
    "or_or"              -> Operators.logicalOr,
    "comma"              -> "<operator>.expressionList",
    "subscript"          -> Operators.indirectIndexAccess
  )

  private val FunctionCallOperator = "<operator>()"

  private def explicitParams(r: Value): Int = r.list("params").count(p => !p.flag("this"))

  /** `x++` calls the operator that takes an extra `int`. */
  private def isPostfix(r: Value): Boolean =
      r.string("operator").exists(o => o == "plus_plus" || o == "minus_minus") &&
          explicitParams(r) == (if isMember(r) then 1 else 2)

  /** The built-in operator an expression calling the operator function `r` is written with. */
  protected def builtinOperatorOf(r: Value): Option[String] =
    val arity = explicitParams(r) + (if isMember(r) then 1 else 0)
    r.string("operator").flatMap {
        case "plus_plus" =>
            Some(if isPostfix(r) then Operators.postIncrement else Operators.preIncrement)
        case "minus_minus" =>
            Some(if isPostfix(r) then Operators.postDecrement else Operators.preDecrement)
        case "function_call"  => Some(FunctionCallOperator)
        case op if arity == 1 => UnaryOperators.get(op)
        case op               => BinaryOperators.get(op)
    }

  /** An expression that calls the operator function `r`; `operands` has the object of a member
    * operator first. Linked to `r`'s METHOD when the graph holds one, and tagged with the built-in
    * operator it is written with; the built-in operator itself otherwise.
    */
  protected def overloadedOperatorAst(e: Value, r: Value, operands: Seq[Value]): Option[Ast] =
      builtinOperatorOf(r).map { builtin =>
        // the `int` a postfix increment passes is not written
        val written = if isPostfix(r) then operands.dropRight(1) else operands
        val tpe     = types(e.long("t"))
        if builtin == FunctionCallOperator then functorCallAst(e, r, written)
        else if inProject(r) then
          val asts = written.map(expressionAst)
          val (receiver, args) =
              if isMember(r) then (asts.headOption, asts.drop(1)) else (None, asts)
          val (call, ast) = linkedCallAst(e, r, tpe, receiver, args)
          tagNode(call, X2CpgDefines.OperatorCallTag, builtin)
          ast
        else
          val call = callNode(
            e,
            code(e),
            builtin,
            builtin,
            if builtin == Operators.indirectFieldAccess then DispatchTypes.DYNAMIC_DISPATCH
            else DispatchTypes.STATIC_DISPATCH,
            None,
            Some(registerType(tpe))
          )
          callAst(call, written.map(expressionAst))
        end if
      }

  /** `f(x)` on an object: a lambda's call operator links to the lambda's METHOD, a project's
    * operator function to its METHOD; any other is the `<operator>()` call on the object.
    */
  private def functorCallAst(e: Value, r: Value, operands: Seq[Value]): Ast =
    val receiver = operands.headOption.map(expressionAst).getOrElse(Ast())
    val args     = operands.drop(1).map(expressionAst)
    val tpe      = registerType(types(e.long("t")))
    if r.flag("lambda") then
      val (name, fullName) = lambdaMethod(r)
      val call = callNode(
        e,
        code(e),
        name,
        fullName,
        DispatchTypes.STATIC_DISPATCH,
        Some(signatureOf(r)),
        Some(tpe)
      )
      tagNode(call, X2CpgDefines.OperatorCallTag, FunctionCallOperator)
      cppCallAst(call, args, receiver = Some(receiver))
    else if inProject(r) then
      val (call, ast) = linkedCallAst(e, r, tpe, Some(receiver), args)
      tagNode(call, X2CpgDefines.OperatorCallTag, FunctionCallOperator)
      ast
    else
      val signature = signatureOf(r)
      val call = callNode(
        e,
        code(e),
        FunctionCallOperator,
        s"$FunctionCallOperator:$signature",
        DispatchTypes.DYNAMIC_DISPATCH,
        Some(signature),
        Some(tpe)
      )
      cppCallAst(call, args, receiver = Some(receiver))
    end if
  end functorCallAst

  /** The object `p->m` reads through: when `p` is an object whose `operator->` the access applies
    * (a smart pointer), what that operator returns if the graph holds its METHOD, else `p` itself.
    */
  protected def fieldOwnerAst(owner: Value): Ast =
      arrowCallOf(owner) match
        case Some((r, obj)) if inProject(r) =>
            val tpe = types(owner.long("t"))
            linkedCallAst(
              owner,
              r,
              tpe,
              Some(expressionAst(obj)),
              Nil,
              Some(s"${code(obj)}.operator->()")
            )._2
        case Some((_, obj)) => expressionAst(obj)
        case None           => expressionAst(owner)

  private def arrowCallOf(e: Value): Option[(Value, Value)] =
      Option.when(
        e.kind == "operation" && e.string("op").exists(_.endsWith("member_call")) && e.flag(
          "operatorSyntax"
        )
      )(e).flatMap { call =>
          routineOf(call.long("callee")).filter(_.string("operator").contains("arrow")).flatMap(r =>
              call.list("ops").lift(1).map(r -> _)
          )
      }

  // ---- lambdas ------------------------------------------------------------------------------

  /** The METHODs built for lambdas, by their closure type: their name and full name. */
  private val lambdaMethods = mutable.HashMap.empty[Long, (String, String)]

  /** Lambda METHODs, for the file's global block. */
  protected val lambdaAsts = mutable.ArrayBuffer.empty[Ast]

  private var anonymousCount = 0

  /** The `this` of each closure's call operator, by variable id: the closure type, and the outer
    * variables its captures copy or refer to, by member name.
    */
  protected val closureThis = mutable.HashMap.empty[Long, Map[String, Long]]

  /** The METHOD of the lambda whose call operator is `r`, built the first time it is needed. */
  protected def lambdaMethod(r: Value, captures: Map[String, Long] = Map.empty): (String, String) =
    val closure = r.long("class").getOrElse(-1L)
    lambdaMethods.get(closure) match
      case Some(names) => names
      case None =>
          val name = s"anonymous_lambda_$anonymousCount"
          anonymousCount += 1
          val fullName = s"${enclosingMethodFullName}.$name"
          lambdaMethods(closure) = (name, fullName)
          lambdaRoutineAst(r, name, fullName, captures).foreach(lambdaAsts += _)
          (name, fullName)

  /** A lambda expression: the METHOD_REF to its METHOD. `init` is its initialiser, whose elements
    * initialise the closure's members from the captured variables, in member order.
    */
  protected def lambdaRefAst(at: Value, closureType: Option[Long], init: Option[Value]): Ast =
    val routine = closureType.flatMap { c =>
        unit.routines.find(r => r.flag("lambda") && r.long("class").contains(c))
    }
    routine match
      case Some(r) =>
          val members = closureType.flatMap(unit.types.get).toSeq.flatMap(_.list("fields"))
              .flatMap(_.string("name"))
          val captured = init.flatMap(_.field("const")).toSeq.flatMap(_.list("elements")).map {
              element =>
                  element.field("init").flatMap(_.field("expr")).flatMap(capturedVariable)
          }
          val captures      = members.zip(captured).collect { case (m, Some(v)) => m -> v }.toMap
          val (_, fullName) = lambdaMethod(r, captures)
          Ast(methodRefNode(at, code(at), fullName, globalTypeDeclFullName))
      case None => Ast(unknownNode(at, code(at)))

  private def capturedVariable(e: Value): Option[Long] =
      e.kind match
        case "variable"  => e.long("var")
        case "operation" => e.list("ops").headOption.flatMap(capturedVariable)
        case _           => None

  // ---- new and delete -----------------------------------------------------------------------

  /** `new T(args)`: an `<operator>.new` call of the allocated type (argument 1), tagged with its
    * form, then the call to the constructor when the graph holds its METHOD (which takes the
    * constructor arguments), or the arguments themselves. An array allocation has its extent after
    * the type. Placement arguments come last, inside the call to a user-defined `operator new` when
    * the graph holds it.
    *
    * `delete p`: an `<operator>.delete` call of the pointer, tagged with its form, then the calls
    * to the destructor and to a user-defined `operator delete` when the graph holds them.
    */
  protected def newDeleteAst(e: Value): Ast =
      if e.flag("new") then newAst(e) else deleteAst(e)

  private def newAst(e: Value): Ast =
    val allocated = e.long("of")
    val arrayType = allocated.flatMap(types.resolved(_)).filter(_.string("kind").contains("array"))
    val isArray   = arrayType.isDefined || e.field("count").isDefined || e.flag("array")
    val element   = if arrayType.isDefined then arrayType.flatMap(_.long("of")) else allocated
    val form =
        if isArray then X2CpgDefines.AllocFormArray
        else if e.flag("placement") then X2CpgDefines.AllocFormPlacement
        else X2CpgDefines.AllocFormScalar
    val call = callNode(
      e,
      code(e),
      "<operator>.new",
      "<operator>.new",
      DispatchTypes.STATIC_DISPATCH,
      None,
      Some(registerType(types(e.long("t"))))
    )
    tagNode(call, X2CpgDefines.AllocFormTag, form)
    val elementType = registerType(types(element))
    val typeName    = simpleTypeName(elementType)
    val typeId      = Ast(identifierNode(e, typeName, typeName, elementType))
    val init        = e.field("init")
    val constructor =
        init.filter(_.kind == "constructor").flatMap(i => routineOf(i.long("routine")))
            .filter(inProject)
    def constructorCall(args: Seq[Ast]): Option[Ast] = constructor.map { r =>
      val written =
          if isArray then s"$typeName()" else s"$typeName(${args.map(codeOfAst).mkString(", ")})"
      linkedCallAst(e, r, elementType, None, args, Some(written))._2
    }
    val placements = e.list("args").map(expressionAst)
    val allocation = routineOf(e.long("routine")).filter(inProject) match
      case Some(operatorNew) =>
          val tpe = types(operatorNew.long("returnType"))
          Seq(linkedCallAst(
            e,
            operatorNew,
            tpe,
            None,
            placements,
            Some(s"operator new(${placements.map(codeOfAst).mkString(", ")})")
          )._2)
      case None => placements
    val args =
        if isArray then
          val extent = e.field("count").map(expressionAst).orElse(
            arrayType.flatMap(_.long("count")).map(n =>
                Ast(literalNode(e, n.toString, registerType("int")))
            )
          )
          extent.toSeq ++ constructorCall(Nil).toSeq ++ allocation
        else
          val constructorArgs = init.toSeq.flatMap { i =>
              i.kind match
                case "constructor" => i.list("args").map(expressionAst)
                case "expression"  => i.field("expr").map(expressionAst).toSeq
                case _             => Seq.empty
          }
          constructorCall(constructorArgs).map(Seq(_)).getOrElse(constructorArgs) ++ allocation
    callAst(call, typeId +: args)
  end newAst

  private def deleteAst(e: Value): Ast =
    val call = callNode(
      e,
      code(e),
      Operators.delete,
      Operators.delete,
      DispatchTypes.STATIC_DISPATCH,
      None,
      Some(registerType("void"))
    )
    tagNode(
      call,
      X2CpgDefines.AllocFormTag,
      if e.flag("array") then X2CpgDefines.AllocFormArray else X2CpgDefines.AllocFormScalar
    )
    val operand     = e.list("args").headOption
    val operandCode = operand.map(code).getOrElse("")
    val destructor =
        routineOf(e.field("init").flatMap(_.long("destructor"))).filter(inProject).map {
            d =>
                linkedCallAst(
                  e,
                  d,
                  "void",
                  None,
                  Nil,
                  Some(s"$operandCode->${cppName(d.string("name").getOrElse(""))}()")
                )._2
        }
    val operatorDelete = routineOf(e.long("routine")).filter(inProject).map { d =>
        linkedCallAst(e, d, "void", None, Nil, Some(s"operator delete($operandCode)"))._2
    }
    callAst(call, operand.map(expressionAst).toSeq ++ destructor.toSeq ++ operatorDelete.toSeq)
  end deleteAst

  // ---- destructors where scopes end ---------------------------------------------------------

  /** An object a scope destroys: the variable, its destructor, and where it was declared. */
  /** An object a scope destroys: the variable, and its destructor, or the function its `cleanup`
    * attribute names (called with the variable's address).
    */
  protected final case class Destruction(
    variable: Long,
    name: String,
    destructor: Value,
    cleanup: Boolean = false
  )

  /** A scope objects can be destroyed at the end of: a block, the boundary of a function, a loop or
    * a `switch` (the targets of `break` and `continue`).
    */
  protected final class ExitScope(val kind: String, val start: Option[Pos], val end: Option[Pos]):
    val destructions: mutable.ArrayBuffer[Destruction] = mutable.ArrayBuffer.empty

  private var exitScopes: List[ExitScope] = Nil

  /** The labels of the routine being built, by name: where they are. */
  private var labelPositions: List[Map[String, Pos]] = Nil

  protected def withExitScope[T](kind: String, at: Value)(build: => T): T =
    val scope = new ExitScope(kind, at.position, at.field("end").flatMap(EdgaUnit.pos))
    exitScopes = scope :: exitScopes
    try build
    finally exitScopes = exitScopes.drop(1)

  /** Builds a routine's body with its own scopes and labels. */
  protected def withFunctionScope[T](body: Option[Value])(build: => T): T =
    val labels = mutable.HashMap.empty[String, Pos]
    def collect(v: Value): Unit = v match
      case o: ujson.Obj =>
          if o.value.get("k").exists(_.strOpt.contains("label")) then
            for
              name <- v.string("label")
              pos  <- v.position
            do labels(name) = pos
          o.value.foreach {
              case (k, child) if k != "p" && k != "end" && k != "range" => collect(child)
              case _                                                    =>
          }
      case ujson.Arr(items) => items.foreach(collect)
      case _                =>
    body.foreach(collect)
    val savedScopes = exitScopes
    labelPositions = labels.toMap :: labelPositions
    exitScopes = new ExitScope("function", None, None) :: Nil
    try build
    finally
      exitScopes = savedScopes
      labelPositions = labelPositions.drop(1)
  end withFunctionScope

  /** Records that the innermost scope destroys `variable` with `destructor`. */
  protected def destroysAtScopeEnd(variable: Long, name: String, destructor: Option[Long]): Unit =
      routineOf(destructor).filter(inProject).foreach { d =>
          exitScopes.headOption.foreach(_.destructions += Destruction(variable, name, d))
      }

  /** Records that the innermost scope calls `function(&variable)` where it ends: the variable's
    * `cleanup` attribute (C and C++ alike).
    */
  protected def cleansUpAtScopeEnd(variable: Long, name: String, function: Value): Unit =
      exitScopes.headOption.foreach(
        _.destructions += Destruction(variable, name, function, cleanup = true)
      )

  private def destructorCallAsts(
    destructions: Seq[Destruction],
    at: Value,
    atEnd: Boolean
  ): Seq[Ast] =
      destructions.map { d =>
        val (call, ast) =
            if d.cleanup then cleanupCallAst(at, d)
            else
              val callCode = s"${d.name}.${cppName(d.destructor.string("name").getOrElse(""))}()"
              linkedCallAst(at, d.destructor, "void", None, Nil, Some(callCode))
        if atEnd then
          at.field("end").flatMap(EdgaUnit.pos).foreach { p =>
              call.lineNumber(Integer.valueOf(p.line)).columnNumber(Integer.valueOf(p.column))
          }
        ast
      }

  /** `unlock(&guard)`: the call a `cleanup(unlock)` attribute makes as `guard` goes out of scope.
    */
  private def cleanupCallAst(at: Value, d: Destruction): (NewCall, Ast) =
    val function = d.destructor.string("name").getOrElse("")
    val tpe      = registerType(types.returnType(d.destructor.long("returnType")))
    val call = callNode(
      at,
      s"$function(&${d.name})",
      function,
      methodFullNameOf(d.destructor),
      DispatchTypes.STATIC_DISPATCH,
      Some(signatureOf(d.destructor)),
      Some(tpe)
    )
    val target   = variables.get(d.variable)
    val varType  = target.collect { case l: NewLocal => l.typeFullName }.getOrElse(X2CpgDefines.Any)
    val variable = identifierNode(at, d.name, d.name, varType)
    val address = callNode(
      at,
      s"&${d.name}",
      Operators.addressOf,
      Operators.addressOf,
      DispatchTypes.STATIC_DISPATCH,
      None,
      Some(registerType(s"$varType*"))
    )
    val variableAst =
        target.map(t => Ast(variable).withRefEdge(variable, t)).getOrElse(Ast(variable))
    (call, callAst(call, Seq(callAst(address, Seq(variableAst)))))
  end cleanupCallAst

  /** The destructor calls where control falls out of the innermost scope, after `statements`; none
    * when its last statement jumps away.
    */
  protected def scopeEndDestructorCalls(at: Value, statements: Seq[Value]): Seq[Ast] =
      exitScopes.headOption match
        case Some(scope) if !statements.lastOption.exists(isJump) =>
            destructorCallAsts(scope.destructions.reverse.toSeq, at, atEnd = true)
        case _ => Seq.empty

  private def isJump(s: Value): Boolean =
      s.kind == "return" && !s.flag("implicit") || s.kind == "goto"

  /** The objects a jump destroys, in destruction order. */
  private def destructionsLeftBy(jump: Value): Seq[Destruction] =
    val inFunction                        = exitScopes.takeWhile(_.kind != "function")
    def destroyed(scopes: Seq[ExitScope]) = scopes.flatMap(_.destructions.reverse)
    jump.kind match
      case "return" => destroyed(inFunction)
      case "goto" =>
          jump.string("jump") match
            case Some("break") =>
                destroyed(inFunction.takeWhile(s => s.kind != "loop" && s.kind != "switch"))
            case Some("continue") => destroyed(inFunction.takeWhile(_.kind != "loop"))
            case _ =>
                val label =
                    jump.string("label").flatMap(l => labelPositions.headOption.flatMap(_.get(l)))
                label match
                  case Some(target) =>
                      def encloses(s: ExitScope) =
                          s.start.exists(st => before(st, target)) && s.end.exists(en =>
                              before(target, en)
                          )
                      val (left, rest) = inFunction.span(s => !encloses(s))
                      // a jump back past a declaration in the scope holding both destroys it
                      val common = rest.headOption.toSeq.flatMap(_.destructions.reverse).filter {
                          d =>
                              variables.get(d.variable).collect { case l: NewLocal => l }.flatMap(
                                l =>
                                    Option(l.lineNumber).flatten
                              ).exists(line => line > target.line)
                      }
                      destroyed(left) ++ common
                  case None => Seq.empty
      case _ => Seq.empty
    end match
  end destructionsLeftBy

  private def before(a: Pos, b: Pos): Boolean =
      a.file == b.file && (a.line < b.line || a.line == b.line && a.column <= b.column)

  /** A `break`, `continue` or `goto`, after the destructor calls for the scopes it leaves. */
  protected def jumpLeavingScopes(s: Value, jump: Ast): Ast =
    val calls = destructorCallAsts(destructionsLeftBy(s), s, atEnd = false)
    if calls.isEmpty then jump
    else blockAst(blockNode(s, "<empty>", registerType("void")), (calls :+ jump).toList)

  /** A `return` after the destructor calls for the scopes it leaves. */
  protected def returnLeavingScopes(s: Value, value: Option[Value], plain: => Ast): Ast =
    val destructions = destructionsLeftBy(s)
    if destructions.isEmpty then plain
    else
      val calls = destructorCallAsts(destructions, s, atEnd = false)
      val block = blockNode(s, "<empty>", registerType("void"))
      value match
        case Some(v) if observesDestruction(v, destructions.map(_.variable).toSet) =>
            val name   = "<return-value>"
            val tpe    = registerType(types(v.long("t")))
            val local  = localNode(s, name, s"$tpe $name", tpe)
            val target = identifierNode(s, name, name, tpe)
            val store = callNode(
              s,
              s"$name = ${code(v)}",
              Operators.assignment,
              Operators.assignment,
              DispatchTypes.STATIC_DISPATCH,
              None,
              Some(tpe)
            )
            val storeAst =
                callAst(store, Seq(Ast(target).withRefEdge(target, local), expressionAst(v)))
            val read = identifierNode(s, name, name, tpe)
            val ret  = returnNode(s, code(s))
            val retAst =
                Ast(ret).withChild(Ast(read).withRefEdge(read, local)).withArgEdge(ret, read)
            blockAst(block, (Seq(Ast(local), storeAst) ++ calls :+ retAst).toList)
        case _ => blockAst(block, (calls :+ plain).toList)
      end match
    end if
  end returnLeavingScopes

  /** Whether evaluating `e` after the destructors ran could give a different value: it calls a
    * function, reads through a pointer or a reference, or names one of the `destroyed` objects.
    */
  private def observesDestruction(e: Value, destroyed: Set[Long]): Boolean =
    val here = e.kind match
      case "new_delete" | "lambda" | "throw" => true
      case "operation" =>
          e.string("op").exists(op =>
              op == "call" || op.endsWith("member_call") || op == "subscript" || op == "indirect" ||
                  op == "points_to_field" || op == "ref_indirect"
          )
      case "variable" =>
          e.long("var").exists(destroyed.contains) || e.long("t").exists(t =>
              unit.types.get(t).exists(x => x.flag("reference") || x.flag("rvalueReference"))
          )
      case _ => false
    here || children(e).exists(observesDestruction(_, destroyed))

  private def children(e: Value): Seq[Value] = e match
    case o: ujson.Obj =>
        o.value.toSeq.flatMap {
            case (k, v: ujson.Obj) if k != "p" && k != "po" && k != "end" => Seq(v)
            case (k, ujson.Arr(items)) if k == "ops" || k == "args" || k == "elements" =>
                items.toSeq.collect { case o: ujson.Obj => o }
            case _ => Seq.empty
        }
    case _ => Seq.empty

  // ---- attributes -------------------------------------------------------------------------

  /** An attribute as the CDT frontend renders it: `name` or `name(arg,arg)`, its name's leading and
    * trailing `__` dropped (`__noreturn__` is `noreturn`).
    */
  protected def attributeText(a: Value): Option[String] =
    val name = a.string("name").getOrElse("").stripPrefix("__").stripSuffix("__").trim
    val args = a.list("args").flatMap {
        case ujson.Str(s) => Some(s)
        case ujson.Num(n) => Some(if n == n.toLong then n.toLong.toString else n.toString)
        case o: ujson.Obj => o.value.get("name").collect { case ujson.Str(s) => s }
                .orElse(o.value.get("value").collect { case ujson.Str(s) => s })
        case _ => None
    }.map(_.filterNot(_.isWhitespace))
    Option.when(name.nonEmpty)(if args.isEmpty then name else s"$name(${args.mkString(",")})")

  /** The functions that return twice, as GCC treats them whether or not a header says so. */
  private val ReturnsTwice =
      Set("setjmp", "_setjmp", "sigsetjmp", "__sigsetjmp", "savectx", "vfork", "getcontext")

  /** The attributes a call's callee is declared with, on the CALL (where its semantics survive when
    * no METHOD is built for a library function), and the header it is declared in when the unit's
    * own file does not declare it.
    */
  protected def tagCallee(call: NewCall, r: Value): Unit =
    val attributes = r.list("attributes").flatMap(attributeText) ++
        Option.when(ReturnsTwice.contains(r.string("name").getOrElse("")))("returns_twice")
    attributes.distinct.foreach(tagNode(call, X2CpgDefines.FunctionAttributeTag, _))
    r.position.filter(_.file != 0L).flatMap(p => unit.files.get(p.file)).foreach { f =>
        tagNode(call, CalleeDeclaredInTag, f.path)
    }

  private val CalleeDeclaredInTag = "callee-declared-in"

  // ---- objects a declaration constructs -----------------------------------------------------

  /** The declaration `T v...;` of a class-type variable a constructor initialises: the assignment
    * of the constructor call to the variable when the graph holds the constructor's METHOD;
    * otherwise the shape of what is written - `T v(args)` a call named after the type, `T v = x`
    * the assignment of `x`, `T v{a}` the assignment of the braced list, `T v` nothing.
    */
  protected def constructedVariableAst(
    decl: Value,
    local: NewNode,
    tpe: String,
    init: Value
  ): Option[Ast] =
    val name     = decl.string("name").getOrElse("")
    val declText = declaratorText(decl)
    def target(): Ast =
      val id = identifierNode(decl, name, name, tpe)
      Ast(id).withRefEdge(id, local)
    def assignment(value: Ast): Ast =
      val call = callNode(
        decl,
        declText,
        Operators.assignment,
        Operators.assignment,
        DispatchTypes.STATIC_DISPATCH,
        None,
        Some(tpe)
      )
      callAst(call, Seq(target(), value))
    val args = init.list("args").map(expressionAst)
    routineOf(init.long("routine")).filter(inProject) match
      case Some(r) => Some(assignment(linkedCallAst(decl, r, tpe, None, args, Some(declText))._2))
      case None =>
          initializerSyntax(decl) match
            case '(' =>
                val typeName = simpleTypeName(tpe)
                val call = callNode(
                  decl,
                  declText,
                  typeName,
                  typeName,
                  DispatchTypes.STATIC_DISPATCH,
                  None,
                  Some(tpe)
                )
                Some(callAst(call, args))
            case '=' if args.size == 1 => Some(assignment(args.head))
            case '{' | '=' =>
                val list = callNode(
                  decl,
                  "{...}",
                  Operators.arrayInitializer,
                  Operators.arrayInitializer,
                  DispatchTypes.STATIC_DISPATCH,
                  None,
                  Some(registerType("<empty>"))
                )
                Some(assignment(callAst(list, args)))
            case _ => None
    end match
  end constructedVariableAst

  /** What follows a declarator's name: `(`, `=`, `{`, or nothing. */
  private def initializerSyntax(decl: Value): Char =
      declaratorText(decl).drop(decl.string("name").getOrElse("").length).trim.headOption.getOrElse(
        ' '
      )

  /** A declarator as written: `a(1, 2)`, `b`, `box{seed}`. */
  protected def declaratorText(decl: Value): String =
    val name = decl.string("name").getOrElse("")
    val text = decl.position.flatMap { start =>
        linesOf(start.file).flatMap(lines => lines.lift(start.line - 1)).map(_.drop(
          start.column - 1
        ))
    }.getOrElse(name)
    // up to the end of the declarator: a top-level `,` or `;`
    var depth = 0
    var i     = 0
    var done  = false
    while i < text.length && !done do
      text(i) match
        case '(' | '{' | '[' | '<'   => depth += 1
        case ')' | '}' | ']' | '>'   => depth -= 1
        case ',' | ';' if depth <= 0 => done = true
        case _                       =>
      if !done then i += 1
    val declarator = text.take(i).trim
    if declarator.startsWith(name) then declarator else name
  end declaratorText
end AstForCpp
