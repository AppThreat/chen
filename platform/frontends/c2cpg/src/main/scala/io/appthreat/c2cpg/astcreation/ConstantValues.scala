package io.appthreat.c2cpg.astcreation

import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.nodes.NewLiteral
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.internal.core.dom.parser.{SizeofCalculator, ValueFactory}
import org.eclipse.cdt.internal.core.dom.parser.cpp.semantics.CPPSemantics

/** The value of each integer constant expression a file writes as more than a literal: `sizeof` and
  * `alignof`, enumerators, `const` integers with a known initializer, and arithmetic, casts and
  * conditionals over those, including the expansion of a macro constant (`#define N (4 * 8)`). The
  * expression's node is tagged [[X2CpgDefines.ConstValueTag]] with the value in decimal, as the
  * C/C++ compiler for the target computes it: type sizes come from the target's predefined macros
  * (`long` is 4 bytes for MSVC, 8 for an LP64 compiler), and an unsigned result wraps at its type's
  * width.
  *
  * A literal is its own value and is not tagged. An expression is evaluated only when each of its
  * operands is a constant, so a large non-constant expression costs nothing.
  */
trait ConstantValues(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  /** Each expression of this file seen so far: None when it is not an integer constant expression,
    * else its value when CDT reports one (a literal is constant whether or not it does).
    */
  private val constantExpressions =
      new java.util.IdentityHashMap[IASTExpression, Option[Option[BigInt]]]()

  private def constantOf(expression: IASTExpression): Option[Option[BigInt]] =
      if constantExpressions.containsKey(expression) then constantExpressions.get(expression)
      else
        val constant =
            if isIntegerLiteral(expression) then Some(integerValueOf(expression))
            else if mayBeConstant(expression) then integerValueOf(expression).map(Some(_))
            else None
        constantExpressions.put(expression, constant)
        constant

  /** Tags the root of `ast`, built for `expression`, with its constant value when it has one: the
    * expression's own node, or the INLINED call that stands for a macro's expansion (`#define N 32`
    * too). A literal node is its own value and is not tagged.
    */
  protected def tagConstantValue(expression: IASTExpression, ast: Ast): Unit =
    val value = constantOf(expression).flatten
    for v <- value; root <- ast.root if !root.isInstanceOf[NewLiteral] do
      tagNode(root, X2CpgDefines.ConstValueTag, v.toString)

  private def isConstant(e: IASTExpression): Boolean =
      e != null && Option(constantExpressions.get(e)).exists(_.isDefined)

  private def isIntegerLiteral(e: IASTExpression): Boolean = e match
    case l: IASTLiteralExpression =>
        l.getKind match
          case IASTLiteralExpression.lk_integer_constant | IASTLiteralExpression.lk_char_constant |
              IASTLiteralExpression.lk_true | IASTLiteralExpression.lk_false => true
          case _ => false
    case _ => false

  /** The shapes an integer constant expression can take, with every operand already known to be
    * one.
    */
  private def mayBeConstant(e: IASTExpression): Boolean =
      isIntegral(e) && (e match
        case u: IASTUnaryExpression =>
            u.getOperator match
              case IASTUnaryExpression.op_sizeof | IASTUnaryExpression.op_alignOf => true
              case IASTUnaryExpression.op_minus | IASTUnaryExpression.op_plus |
                  IASTUnaryExpression.op_tilde | IASTUnaryExpression.op_not |
                  IASTUnaryExpression.op_bracketedPrimary => isConstant(u.getOperand)
              case _ => false
        case t: IASTTypeIdExpression =>
            t.getOperator == IASTTypeIdExpression.op_sizeof ||
            t.getOperator == IASTTypeIdExpression.op_alignof
        case b: IASTBinaryExpression =>
            !isAssignment(b.getOperator) && isConstant(b.getOperand1) && isConstant(b.getOperand2)
        case c: IASTConditionalExpression =>
            isConstant(c.getLogicalConditionExpression) &&
            (c.getPositiveResultExpression == null || isConstant(c.getPositiveResultExpression)) &&
            isConstant(c.getNegativeResultExpression)
        case c: IASTCastExpression => isConstant(c.getOperand)
        case id: IASTIdExpression =>
            CdtQuery(id.getName.resolveBinding()).toOption.exists {
                case _: IEnumerator => true
                case _: IParameter  => false
                case v: IVariable   => isConstQualified(v.getType)
                case _              => false
            }
        case _ => false
      )

  private def isAssignment(op: Int): Boolean =
      op == IASTBinaryExpression.op_assign || op == IASTBinaryExpression.op_multiplyAssign ||
          op == IASTBinaryExpression.op_divideAssign || op == IASTBinaryExpression.op_moduloAssign ||
          op == IASTBinaryExpression.op_plusAssign || op == IASTBinaryExpression.op_minusAssign ||
          op == IASTBinaryExpression.op_shiftLeftAssign ||
          op == IASTBinaryExpression.op_shiftRightAssign ||
          op == IASTBinaryExpression.op_binaryAndAssign ||
          op == IASTBinaryExpression.op_binaryXorAssign ||
          op == IASTBinaryExpression.op_binaryOrAssign

  /** `const` and not `volatile`: a `const volatile` object (a device register) changes under the
    * program.
    */
  private def isConstQualified(t: IType): Boolean =
    @scala.annotation.tailrec
    def qualifiers(t: IType, const: Boolean, volatile: Boolean): (Boolean, Boolean) = t match
      case q: IQualifierType => qualifiers(q.getType, const || q.isConst, volatile || q.isVolatile)
      case td: ITypedef      => qualifiers(td.getType, const, volatile)
      case _                 => (const, volatile)
    val (const, volatile) = qualifiers(t, false, false)
    const && !volatile

  @scala.annotation.tailrec
  private def unqualified(t: IType): IType = t match
    case q: IQualifierType => unqualified(q.getType)
    case td: ITypedef      => unqualified(td.getType)
    case other             => other

  private def isIntegral(e: IASTExpression): Boolean =
      CdtQuery(unqualified(e.getExpressionType)).toOption.exists {
          case b: IBasicType =>
              b.getKind match
                case IBasicType.Kind.eInt | IBasicType.Kind.eChar | IBasicType.Kind.eBoolean |
                    IBasicType.Kind.eWChar | IBasicType.Kind.eChar16 | IBasicType.Kind.eChar32 |
                    IBasicType.Kind.eChar8 | IBasicType.Kind.eInt128 => true
                case _ => false
          case _: IEnumeration => true
          case _               => false
      }

  /** Evaluates `body` with `e` as CDT's lookup point: sizes then come from `e`'s translation unit,
    * whose predefined macros describe the target, instead of CDT's defaults.
    */
  private def atLookupPoint[T](e: IASTExpression)(body: => T): T =
    CPPSemantics.pushLookupPoint(e)
    try body
    finally CPPSemantics.popLookupPoint()

  /** CDT's value of the expression, an unsigned result reduced to its type's width. */
  private def integerValueOf(e: IASTExpression): Option[BigInt] =
    val number = CdtQuery(atLookupPoint(e)(Option(ValueFactory.getConstantNumericalValue(e))))
    number.toOption.flatten.collect {
        case n: java.lang.Long       => BigInt(n)
        case n: java.lang.Integer    => BigInt(n.longValue)
        case n: java.lang.Short      => BigInt(n.longValue)
        case n: java.lang.Byte       => BigInt(n.longValue)
        case n: java.math.BigInteger => BigInt(n)
    }.map { v =>
        if v >= 0 then v
        else
          unsignedWidthOf(e) match
            case Some(bits) => v.mod(BigInt(1) << bits)
            case None       => v
    }

  /** The width in bits of an unsigned integral expression's type, for the target. */
  private def unsignedWidthOf(e: IASTExpression): Option[Int] =
      CdtQuery(unqualified(e.getExpressionType)).toOption.collect {
          case b: IBasicType if b.isUnsigned => b
      }.flatMap(b =>
          CdtQuery(Option(atLookupPoint(e)(SizeofCalculator.getSizeAndAlignment(b)))).toOption.flatten
              .map(s => (s.size * 8).toInt)
      )
end ConstantValues
