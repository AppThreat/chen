package io.appthreat.edg2atom.astcreation

import io.appthreat.x2cpg.Ast
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*

/** The code of an expression a macro expanded. The text at the position of such a node is the
  * invocation, not the expression, so its code is composed from the code of its operands in the
  * operator's own syntax (`a + b`, `*p`, `sizeof(T)`, `(T)x`, `a->b`, `a[i]`, `f(a, b)`, `c ? a :
  * b`), the way the CDT frontend prints an expanded expression. The front end does not keep the
  * parentheses a macro's definition wrote, so an operand is parenthesised where its operator binds
  * weaker than the one it belongs to.
  */
object ExpansionCode:

  private val Binary: Map[String, (String, Int)] = Map(
    Operators.multiplication       -> ("*", 13),
    Operators.division             -> ("/", 13),
    Operators.modulo               -> ("%", 13),
    Operators.addition             -> ("+", 12),
    Operators.subtraction          -> ("-", 12),
    Operators.shiftLeft            -> ("<<", 11),
    Operators.arithmeticShiftRight -> (">>", 11),
    Operators.logicalShiftRight    -> (">>", 11),
    Operators.lessThan             -> ("<", 10),
    Operators.greaterThan          -> (">", 10),
    Operators.lessEqualsThan       -> ("<=", 10),
    Operators.greaterEqualsThan    -> (">=", 10),
    Operators.equals               -> ("==", 9),
    Operators.notEquals            -> ("!=", 9),
    Operators.and                  -> ("&", 8),
    Operators.xor                  -> ("^", 7),
    Operators.or                   -> ("|", 6),
    Operators.logicalAnd           -> ("&&", 5),
    Operators.logicalOr            -> ("||", 4),
    "<operator>.expressionList"    -> (",", 1)
  )

  private val Assignment: Map[String, String] = Map(
    Operators.assignment                     -> "=",
    Operators.assignmentPlus                 -> "+=",
    Operators.assignmentMinus                -> "-=",
    Operators.assignmentMultiplication       -> "*=",
    Operators.assignmentDivision             -> "/=",
    Operators.assignmentModulo               -> "%=",
    Operators.assignmentShiftLeft            -> "<<=",
    Operators.assignmentArithmeticShiftRight -> ">>=",
    Operators.assignmentLogicalShiftRight    -> ">>=",
    Operators.assignmentAnd                  -> "&=",
    Operators.assignmentOr                   -> "|=",
    Operators.assignmentXor                  -> "^="
  )

  private val Prefix: Map[String, String] = Map(
    Operators.indirection  -> "*",
    Operators.addressOf    -> "&",
    Operators.minus        -> "-",
    Operators.plus         -> "+",
    Operators.not          -> "~",
    Operators.logicalNot   -> "!",
    Operators.preIncrement -> "++",
    Operators.preDecrement -> "--"
  )

  private val Postfix: Map[String, String] =
      Map(Operators.postIncrement -> "++", Operators.postDecrement -> "--")

  private val UnaryPrecedence   = 14
  private val PostfixPrecedence = 15
  private val Atom              = 16
  private val ConditionalPrec   = 3
  private val AssignmentPrec    = 2

  private def precedenceOf(n: NewNode): Int =
      n match
        case c: NewCall =>
            val name = c.name
            Binary.get(name).map(_._2)
                .orElse(Assignment.get(name).map(_ => AssignmentPrec))
                .orElse(Prefix.get(name).map(_ => UnaryPrecedence))
                .orElse(Option.when(name == Operators.cast || name == Operators.sizeOf)(
                  UnaryPrecedence
                ))
                .orElse(Option.when(name == Operators.conditional)(ConditionalPrec))
                .orElse(Postfix.get(name).map(_ => PostfixPrecedence))
                .getOrElse(Atom)
        case _ => Atom

  /** An operand's code, in parentheses when its own operator binds weaker than `min`. */
  private def operand(child: NewNode, min: Int): String =
    val text = codeOf(child)
    if precedenceOf(child) < min && !enclosed(text) then s"($text)" else text

  private def enclosed(text: String): Boolean =
      if !text.startsWith("(") || !text.endsWith(")") then false
      else
        var depth = 0
        var i     = 0
        while i < text.length do
          text(i) match
            case '(' => depth += 1
            case ')' =>
                depth -= 1
                if depth == 0 && i < text.length - 1 then return false
            case _ =>
          i += 1
        true

  def codeOf(n: NewNode): String =
      n match
        case e: ExpressionNew => e.code
        case _                => ""

  private def withCode(n: NewNode, code: String): Unit =
      n match
        case c: NewCall            => c.code = code
        case l: NewLiteral         => l.code = code
        case i: NewIdentifier      => i.code = code
        case u: NewUnknown         => u.code = code
        case f: NewFieldIdentifier => f.code = code
        case t: NewTypeRef         => t.code = code
        case _                     =>

  /** Sets the code of the root of `ast`, a node of an expansion, from its operands. */
  def fill(ast: Ast): Unit =
      ast.root.foreach { root =>
          compose(ast, root).filter(_.nonEmpty).foreach(withCode(root, _))
      }

  private def children(ast: Ast, root: NewNode): Seq[NewNode] =
    val kids = ast.edges.filter(_.src eq root).map(_.dst).toSeq
    kids.sortBy {
        case e: ExpressionNew => e.argumentIndex
        case _                => 0
    }

  private def compose(ast: Ast, root: NewNode): Option[String] =
      root match
        case call: NewCall =>
            val all  = children(ast, root)
            val args = all.filter { case e: ExpressionNew => e.argumentIndex >= 1; case _ => true }
            def at(i: Int, min: Int): String = args.lift(i).map(operand(_, min)).getOrElse("")
            val name                         = call.name
            if Binary.contains(name) && args.size == 2 then
              val (symbol, prec) = Binary(name)
              val separator      = if symbol == "," then ", " else s" $symbol "
              Some(s"${at(0, prec)}$separator${at(1, prec + 1)}")
            else if Assignment.contains(name) && args.size == 2 then
              Some(s"${at(0, AssignmentPrec + 1)} ${Assignment(name)} ${at(1, AssignmentPrec)}")
            else if Prefix.contains(name) && args.size == 1 then
              Some(s"${Prefix(name)}${at(0, UnaryPrecedence)}")
            else if Postfix.contains(name) && args.size == 1 then
              Some(s"${at(0, PostfixPrecedence)}${Postfix(name)}")
            else if name == Operators.sizeOf && args.size == 1 then
              Some(s"sizeof(${at(0, 0)})")
            else if name == Operators.cast && args.size == 2 then
              Some(s"(${at(0, 0)})${at(1, UnaryPrecedence)}")
            else if name == Operators.conditional && args.size == 3 then
              Some(s"${at(0, ConditionalPrec + 1)} ? ${at(1, 0)} : ${at(2, ConditionalPrec)}")
            else if name == Operators.fieldAccess && args.size == 2 then
              Some(s"${at(0, PostfixPrecedence)}.${at(1, 0)}")
            else if name == Operators.indirectFieldAccess && args.size == 2 then
              Some(s"${at(0, PostfixPrecedence)}->${at(1, 0)}")
            else if (name == Operators.indirectIndexAccess || name == Operators.indexAccess) &&
              args.size == 2
            then Some(s"${at(0, PostfixPrecedence)}[${at(1, 0)}]")
            else if name.startsWith("<operator>") && name != "<operator>.pointerCall" then
              Some(s"$name(${args.map(operand(_, 0)).mkString(", ")})")
            else
              // a call: through its name, or through the pointer it is made through
              val callee = if name.startsWith("<operator>") then
                all.collectFirst { case e: ExpressionNew if e.argumentIndex < 1 => e }
                    .map(operand(_, PostfixPrecedence)).getOrElse("")
              else name
              Some(s"$callee(${args.map(operand(_, 2)).mkString(", ")})")
            end if
        case _ => None
end ExpansionCode
