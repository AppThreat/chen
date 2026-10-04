package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.parser.EdgaUnit
import io.appthreat.edg2atom.parser.EdgaUnit.*
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import ujson.Value

/** Expressions in the CDT frontend's shapes. Conversions and other steps the front end made
  * implicitly are not nodes of their own (the CDT frontend has none): their operand stands in their
  * place. A pointer addition or subtraction carries the `ptr-arith` tag, a folded constant
  * expression its value as `const-value`.
  */
trait AstForExpressions(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  /** Operators with one meaning in the graph whatever the operand types. */
  private val Simple: Map[String, String] = Map(
    "add"              -> Operators.addition,
    "subtract"         -> Operators.subtraction,
    "multiply"         -> Operators.multiplication,
    "divide"           -> Operators.division,
    "remainder"        -> Operators.modulo,
    "shiftl"           -> Operators.shiftLeft,
    "and"              -> Operators.and,
    "or"               -> Operators.or,
    "xor"              -> Operators.xor,
    "eq"               -> Operators.equals,
    "ne"               -> Operators.notEquals,
    "lt"               -> Operators.lessThan,
    "gt"               -> Operators.greaterThan,
    "le"               -> Operators.lessEqualsThan,
    "ge"               -> Operators.greaterEqualsThan,
    "land"             -> Operators.logicalAnd,
    "lor"              -> Operators.logicalOr,
    "not"              -> Operators.logicalNot,
    "complement"       -> Operators.not,
    "negate"           -> Operators.minus,
    "unary_plus"       -> Operators.plus,
    "pre_incr"         -> Operators.preIncrement,
    "pre_decr"         -> Operators.preDecrement,
    "post_incr"        -> Operators.postIncrement,
    "post_decr"        -> Operators.postDecrement,
    "assign"           -> Operators.assignment,
    "add_assign"       -> Operators.assignmentPlus,
    "subtract_assign"  -> Operators.assignmentMinus,
    "multiply_assign"  -> Operators.assignmentMultiplication,
    "divide_assign"    -> Operators.assignmentDivision,
    "remainder_assign" -> Operators.assignmentModulo,
    "shiftl_assign"    -> Operators.assignmentShiftLeft,
    "shiftr_assign"    -> Operators.assignmentArithmeticShiftRight,
    "and_assign"       -> Operators.assignmentAnd,
    "or_assign"        -> Operators.assignmentOr,
    "xor_assign"       -> Operators.assignmentXor,
    "padd_assign"      -> Operators.assignmentPlus,
    "psubtract_assign" -> Operators.assignmentMinus,
    "question"         -> Operators.conditional,
    "indirect"         -> Operators.indirection,
    "address_of"       -> Operators.addressOf,
    "dot_field"        -> Operators.fieldAccess,
    "points_to_field"  -> Operators.indirectFieldAccess,
    "comma"            -> "<operator>.expressionList"
  )

  /** Steps the front end made implicitly that pass their operand on unchanged in the graph. */
  private val Transparent: Set[String] =
      Set(
        "array_to_pointer",
        "reference_to",
        "ref_indirect",
        "lvalue_adjust",
        "class_rvalue_adjust",
        "bool_cast"
      )

  /** `if (p)` is the front end's `p != 0`: the condition as written. */
  protected def withoutImplicitTest(e: Value): Value =
      if e.kind == "operation" && e.flag("implicit") && e.string("op").contains("ne") then
        e.list("ops").headOption.getOrElse(e)
      else e

  /** The node an implicit step stands for: its operand. */
  private def visible(e: Value): Value =
      if e.kind == "operation" && e.flag("implicit") then
        e.string("op") match
          case Some(op)
              if Transparent.contains(
                op
              ) || op == "cast" || op == "address_of" || op == "indirect" =>
              e.list("ops").headOption.map(visible).getOrElse(e)
          case _ => e
      else if e.kind == "operation" && e.string("op").exists(Transparent.contains) then
        e.list("ops").headOption.map(visible).getOrElse(e)
      else e

  protected def expressionAst(raw: Value): Ast = withMacroCall(raw)(expressionAstOf(raw))

  private def expressionAstOf(raw: Value): Ast =
    val e = visible(raw)
    e.kind match
      case "operation" => operationAst(e)
      case "constant"  => constantAst(e)
      case "variable"  => identifierAst(e)
      case "routine" =>
          val name     = e.string("name").getOrElse("")
          val target   = e.long("routine").flatMap(unit.routinesById.get)
          val fullName = target.map(methodFullNameOf).getOrElse(name)
          Ast(methodRefNode(e, name, fullName, registerType(types(e.long("t")))))
      case "field" =>
          val name = e.string("name").getOrElse("")
          Ast(fieldIdentifierNode(e, name, name))
      // a compound literal `(struct point){ .x = 0 }`: a cast of its braced initialiser, whose
      // designators name the members as FIELD_IDENTIFIERs
      case "temp_init" if e.field("init").flatMap(aggregateOf).isDefined =>
          val tpe     = typeOf(e)
          val typeRef = Ast(typeRefNode(e, tpe, tpe))
          val init    = aggregateAst(e, e.field("init").flatMap(aggregateOf).get, () => Ast())
          callAst(operatorCall(e, code(e), Operators.cast, tpe), Seq(typeRef, init))
      case "lambda" => lambdaRefAst(e, e.long("t"), e.field("init"))
      case "temp_init" =>
          e.field("init").map(initializerExpressionAst).getOrElse(Ast(unknownNode(e, code(e))))
      case "new_delete" => newDeleteAst(e)
      // `throw x`: the thrown value as the argument of `<operator>.throw`; a rethrow has none
      case "throw" =>
          val call = callNode(
            e,
            code(e),
            "<operator>.throw",
            "<operator>.throw",
            DispatchTypes.STATIC_DISPATCH,
            None,
            Some(registerType("void"))
          )
          callAst(call, e.field("init").map(initializerExpressionAst).toSeq)
      case "statement" =>
          e.field("stmt").map(statementAst).getOrElse(Ast())
      case "sizeof" | "alignof" =>
          val op = if e.kind == "sizeof" then Operators.sizeOf else "<operator>.alignOf"
          val call = callNode(
            e,
            code(e),
            op,
            op,
            DispatchTypes.STATIC_DISPATCH,
            None,
            Some(registerType(types(e.long("t"))))
          )
          val operand = e.field("expr").map(expressionAst).getOrElse(
            Ast(typeRefNode(e, types(e.long("of")), registerType(types(e.long("of")))))
          )
          callAst(call, Seq(operand))
      case "condition" => e.field("expr").map(expressionAst).getOrElse(Ast())
      case _           => Ast(unknownNode(e, code(e)))
    end match
  end expressionAstOf

  private def typeOf(e: Value): String = registerType(types(e.long("t")))

  private def identifierAst(e: Value): Ast =
      if e.long("var").exists(thisVariables.contains) then Ast(literalNode(e, "this", typeOf(e)))
      else
        val name = e.string("name").getOrElse("")
        val id   = identifierNode(e, name, name, typeOf(e))
        val ast  = Ast(id)
        e.long("var").flatMap(variables.get).orElse(scope.lookupVariable(name).map(_._1)) match
          case Some(target) => ast.withRefEdge(id, target)
          case None         => ast

  private def operationAst(e: Value): Ast =
    val op       = e.string("op").getOrElse("")
    val operands = e.list("ops")
    op match
      case "call" | "dot_member_call" | "points_to_member_call" =>
          callExpressionAst(e, op, operands)
      // a member named without `this->`: the member itself, as the CDT frontend writes it; in a
      // lambda, the captured variable
      case "points_to_field" if e.flag("implicit") && operands.headOption.exists(isImplicitThis) =>
          implicitMemberAst(e, operands)
      // `p->m` on an object with `operator->`: the access reads through what that returns
      case "points_to_field" if operands.headOption.exists(_.flag("operatorSyntax")) =>
          val call = callNode(
            e,
            code(e),
            Operators.indirectFieldAccess,
            Operators.indirectFieldAccess,
            DispatchTypes.DYNAMIC_DISPATCH,
            None,
            Some(typeOf(e))
          )
          callAst(call, fieldOwnerAst(operands.head) +: operands.drop(1).map(expressionAst))
      case "padd" =>
          // the pointer is the first operand unless the front end says it is the second
          val pointerIndex = if e.flag("pointerSecond") then 2 else 1
          val ast          = operatorAst(e, Operators.addition, operands)
          ast.root.foreach(r => tagNode(r, X2CpgDefines.PointerArithmeticTag, s"add:$pointerIndex"))
          ast
      case "psubtract" =>
          val ast = operatorAst(e, Operators.subtraction, operands)
          ast.root.foreach(r => tagNode(r, X2CpgDefines.PointerArithmeticTag, "sub:1"))
          ast
      case "pdiff" =>
          val ast = operatorAst(e, Operators.subtraction, operands)
          ast.root.foreach(r => tagNode(r, X2CpgDefines.PointerArithmeticTag, "diff"))
          ast
      case "padd_assign" | "psubtract_assign" =>
          val ast  = operatorAst(e, Simple(op), operands)
          val kind = if op == "padd_assign" then "add:1" else "sub:1"
          ast.root.foreach(r => tagNode(r, X2CpgDefines.PointerArithmeticTag, kind))
          ast
      case "pre_incr" | "pre_decr" | "post_incr" | "post_decr" =>
          val ast = operatorAst(e, Simple(op), operands)
          if operands.headOption.flatMap(_.long("t")).exists(types.isPointer) then
            val kind = if op.endsWith("incr") then "add:1" else "sub:1"
            ast.root.foreach(r => tagNode(r, X2CpgDefines.PointerArithmeticTag, kind))
          ast
      case "shiftr" =>
          val name =
              if operands.headOption.flatMap(_.long("t")).exists(types.isUnsignedInteger) then
                Operators.logicalShiftRight
              else Operators.arithmeticShiftRight
          operatorAst(e, name, operands)
      case "subscript" =>
          // the pointer or array is the base, written first
          val ordered = if e.flag("pointerSecond") then operands.reverse else operands
          val base    = ordered.headOption.map(visible)
          val name =
              if base.exists(b => b.long("t").exists(types.isArray)) then
                Operators.indirectIndexAccess
              else Operators.indirectIndexAccess
          operatorAst(e, name, ordered)
      case "cast" | "lvalue_cast" | "ref_cast" =>
          val call = callNode(
            e,
            code(e),
            Operators.cast,
            Operators.cast,
            DispatchTypes.STATIC_DISPATCH,
            None,
            Some(typeOf(e))
          )
          val typeRef = Ast(typeRefNode(e, types(e.long("t")), typeOf(e)))
          callAst(call, Seq(typeRef) ++ operands.headOption.map(expressionAst).toSeq)
      case other =>
          Simple.get(other) match
            case Some(name) => operatorAst(e, name, operands)
            case None       => Ast(unknownNode(e, code(e)))
    end match
  end operationAst

  /** `this`, as the front end passes it to a member access or call written without it. */
  private def isImplicitThis(e: Value): Boolean =
    val v = visible(e)
    v.kind == "variable" && v.long("var").exists(thisVariables.contains) && v.position.isEmpty

  private def implicitMemberAst(e: Value, operands: Seq[Value]): Ast =
    val name = operands.lift(1).flatMap(_.string("name")).getOrElse("")
    val id   = identifierNode(e, name, name, typeOf(e))
    val captured = visible(operands.head).long("var").flatMap(closureThis.get).flatMap(_.get(name))
        .flatMap(variables.get)
    captured match
      case Some(target) => Ast(id).withRefEdge(id, target)
      case None         => Ast(id)

  protected def operatorAst(e: Value, name: String, operands: Seq[Value]): Ast =
    // the CDT frontend writes `p->f` as a dynamic dispatch
    val dispatch =
        if name == Operators.indirectFieldAccess then DispatchTypes.DYNAMIC_DISPATCH
        else DispatchTypes.STATIC_DISPATCH
    val call = callNode(e, code(e), name, name, dispatch, None, Some(typeOf(e)))
    val args = operands.map(expressionAst)
    callAst(call, args)

  /** A call: to the routine the front end resolved, through a pointer otherwise. An operator
    * expression that calls an operator function is the CDT frontend's shape for it.
    */
  private def callExpressionAst(e: Value, op: String, operands: Seq[Value]): Ast =
    // the routine called: as the front end resolved it, else the routine its callee names
    val callee = e.long("callee").flatMap(unit.routinesById.get).orElse(
      operands.headOption.map(visible).filter(_.kind == "routine").flatMap(_.long("routine"))
          .flatMap(unit.routinesById.get)
    )
    val written = operands.drop(1)
    callee match
      case Some(r) if e.flag("operatorSyntax") && unit.isCpp =>
          overloadedOperatorAst(e, r, written).getOrElse(plainCallAst(e, op, r, written))
      case Some(r) => plainCallAst(e, op, r, written)
      case None =>
          val pointerCall = "<operator>.pointerCall"
          val call = callNode(
            e,
            code(e),
            pointerCall,
            pointerCall,
            DispatchTypes.DYNAMIC_DISPATCH,
            Some(""),
            Some(typeOf(e))
          )
          val receiver = operands.headOption.map(expressionAst).getOrElse(Ast())
          callAst(call, operands.drop(1).map(expressionAst), receiver = Some(receiver))
  end callExpressionAst

  /** A call to `r`. A member call has its object as argument 0 (and receiver, when the call
    * dispatches dynamically); a member function called without `this->` has no object.
    */
  private def plainCallAst(e: Value, op: String, r: Value, written: Seq[Value]): Ast =
    val name = if unit.isCpp then cppName(r.string("name").getOrElse(""))
    else r.string("name").getOrElse("")
    val fullName = methodFullNameOf(r)
    val dispatch =
        if e.flag("virtual") || unit.isCpp && (r.flag("virtual") || r.flag("pureVirtual")) then
          DispatchTypes.DYNAMIC_DISPATCH
        else DispatchTypes.STATIC_DISPATCH
    val call = callNode(e, code(e), name, fullName, dispatch, Some(signatureOf(r)), Some(typeOf(e)))
    tagCallee(call, r)
    if op == "call" then callAst(call, written.map(expressionAst))
    else
      val obj  = written.headOption
      val args = written.drop(1).map(expressionAst)
      obj.filterNot(isImplicitThis).map(expressionAst) match
        case Some(self) =>
            cppCallAst(
              call,
              args,
              base = Some(self),
              receiver = Option.when(dispatch == DispatchTypes.DYNAMIC_DISPATCH)(self)
            )
        case None => cppCallAst(call, args)
  end plainCallAst

  private def constantAst(e: Value): Ast =
      e.field("expr") match
        // a folded constant expression: the expression as written, and its value
        case Some(folded) if folded.kind != "constant" =>
            val ast = expressionAst(folded)
            e.string("value").foreach(v =>
                ast.root.foreach(r => tagNode(r, X2CpgDefines.ConstValueTag, v))
            )
            ast
        case _ =>
            e.string("ck") match
              case Some("address") =>
                  e.long("routine").flatMap(unit.routinesById.get) match
                    case Some(r) =>
                        Ast(methodRefNode(
                          e,
                          r.string("name").getOrElse(""),
                          methodFullNameOf(r),
                          typeOf(e)
                        ))
                    case None =>
                        e.field("of") match
                          case Some(target) => constantAst(target)
                          case None         => Ast(literalNode(e, code(e), typeOf(e)))
              case Some("string") =>
                  val text = sourceText(e).getOrElse(literalText(e))
                  // a C string literal is a `char*` in the CDT frontend's graph
                  val tpe =
                      if unit.isCpp then typeOf(e)
                      else
                        val element = e.long("t").flatMap(types.target).map(types(_))
                        registerType(s"${element.getOrElse("char")}*")
                  Ast(literalNode(e, text, tpe))
              case _ =>
                  val text = sourceText(e).getOrElse(literalText(e))
                  Ast(literalNode(e, text, typeOf(e)))

  private def literalText(e: Value): String =
      e.string("ck") match
        case Some("string") => "\"" + e.string("value").getOrElse("") + "\""
        case _              => e.string("value").getOrElse("")

  /** An initialiser in expression position (a temporary, a compound literal). */
  protected def initializerExpressionAst(init: Value): Ast =
      init.kind match
        case "expression" | "class_result_via_ctor" | "bitwise_copy" =>
            init.field("expr").map(expressionAst).getOrElse(Ast())
        case "constant" | "nonconstant_aggregate" =>
            init.field("const").map(constantAst).getOrElse(Ast())
        case "constructor" =>
            val target   = init.long("routine").flatMap(unit.routinesById.get)
            val name     = target.flatMap(_.string("name")).getOrElse("")
            val fullName = target.map(methodFullNameOf).getOrElse(name)
            // the constructed object's type
            val tpe = target.flatMap(_.long("class")).map(c => registerType(types(c)))
                .getOrElse("void")
            val args = init.list("args").map(expressionAst)
            val call = callNode(
              init,
              sourceText(init).getOrElse(
                s"${cppName(name)}(${args.map(codeOfAst).mkString(", ")})"
              ),
              cppName(name),
              fullName,
              DispatchTypes.STATIC_DISPATCH,
              target.map(signatureOf),
              Some(tpe)
            )
            callAst(call, args)
        case "lambda" =>
            lambdaRefAst(init, init.field("const").flatMap(_.long("t")), Some(init))
        case _ => Ast()

  /** `T v = init;` as the assignment of `init` to `v`, at the declaration. A braced initialiser is
    * an `<operator>.arrayInitializer` of its elements, a designated element the assignment of its
    * value to that member or element of `v` (`v.y = 2`, `grid[2] = 7`), as the CDT frontend writes
    * it.
    */
  protected def initializerAssignment(decl: Value, local: NewNode, tpe: String, init: Value): Ast =
    val name = decl.string("name").getOrElse("")
    def target(): Ast =
      val id = identifierNode(decl, name, name, tpe)
      Ast(id).withRefEdge(id, local)
    val value = aggregateOf(init) match
      case Some(aggregate) if init.kind != "lambda" => aggregateAst(decl, aggregate, () => target())
      case _                                        => initializerExpressionAst(init)
    val written = codeOfAst(value)
    // the CDT frontend writes an initialisation from an address or through a pointer as a dynamic
    // dispatch
    val dispatch =
        if written.startsWith("&") || written.contains("->") then DispatchTypes.DYNAMIC_DISPATCH
        else DispatchTypes.STATIC_DISPATCH
    val call = callNode(
      decl,
      s"$name = $written",
      Operators.assignment,
      Operators.assignment,
      dispatch,
      None,
      Some(registerType(tpe))
    )
    callAst(call, Seq(target(), value))
  end initializerAssignment

  private def operatorCall(at: Value, code: String, name: String, tpe: String): NewCall =
      callNode(at, code, name, name, DispatchTypes.STATIC_DISPATCH, None, Some(registerType(tpe)))

  private def aggregateOf(init: Value): Option[Value] =
      init.field("const").orElse(Option.when(init.kind == "constant")(init))
          .filter(_.string("ck").contains("aggregate"))

  /** The elements of a braced initialiser; a designator names the member or element the value after
    * it initialises.
    */
  private def aggregateAst(at: Value, aggregate: Value, base: () => Ast): Ast =
    val elements = aggregate.list("elements")
    val asts = elements.indices.flatMap { i =>
      val e = elements(i)
      if e.string("ck").contains("designator") then None
      else
        val designator =
            elements.lift(i - 1).filter(_ => i > 0).filter(_.string("ck").contains("designator"))
        designator match
          case Some(d) =>
              val elementType = types(e.long("t"))
              def designated(): Ast =
                  d.string("field") match
                    case Some(field) =>
                        val access = operatorCall(
                          at,
                          s"${codeOfAst(base())}.$field",
                          Operators.fieldAccess,
                          elementType
                        )
                        val baseAst = base()
                        // a compound literal's designator names the member alone
                        if baseAst.root.isEmpty then Ast(fieldIdentifierNode(at, field, field))
                        else
                          callAst(access, Seq(baseAst, Ast(fieldIdentifierNode(at, field, field))))
                    case None =>
                        val index = d.long("index").getOrElse(0L).toString
                        val access = operatorCall(
                          at,
                          s"${codeOfAst(base())}[$index]",
                          Operators.indirectIndexAccess,
                          elementType
                        )
                        callAst(
                          access,
                          Seq(base(), Ast(literalNode(at, index, registerType("int"))))
                        )
              val value = aggregateOf(e) match
                case Some(nested) => aggregateAst(at, nested, () => designated())
                case None         => elementAst(e)
              val assign = operatorCall(
                at,
                s"${codeOfAst(designated())} = ${codeOfAst(value)}",
                Operators.assignment,
                elementType
              )
              Some(callAst(assign, Seq(designated(), value)))
          case None if e.string("ck").contains("init_repeat") => None
          case None                                           => Some(elementAst(e))
        end match
      end if
    }
    callAst(operatorCall(at, "{...}", Operators.arrayInitializer, "<empty>"), asts)
  end aggregateAst

  /** An element of a braced initialiser: a constant, or what initialises it at run time. */
  private def elementAst(e: Value): Ast =
      if e.string("ck").contains("dynamic_init") then
        e.field("init").map(initializerExpressionAst).getOrElse(Ast())
      else constantAst(e)
end AstForExpressions
