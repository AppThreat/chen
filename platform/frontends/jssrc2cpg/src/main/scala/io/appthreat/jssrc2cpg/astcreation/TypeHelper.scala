package io.appthreat.jssrc2cpg.astcreation

import io.appthreat.jssrc2cpg.parser.{BabelJsonParser, BabelNodeInfo}
import io.appthreat.jssrc2cpg.passes.Defines
import io.appthreat.jssrc2cpg.parser.BabelAst.*
import io.appthreat.jssrc2cpg.utils.TypeStringNormalizer

import java.util.regex.Pattern

trait TypeHelper:
  this: AstCreator =>

  private val TypeAnnotationKey = "typeAnnotation"
  private val ReturnTypeKey     = "returnType"
  private val ImportMatcher     = Pattern.compile("(typeof )?import\\([\"'](.*)[\"']\\)")

  private val ArrayReplacements = Map(
    "any[]"     -> s"${Defines.Any}[]",
    "unknown[]" -> s"${Defines.Unknown}[]",
    "number[]"  -> s"${Defines.Number}[]",
    "string[]"  -> s"${Defines.String}[]",
    "boolean[]" -> s"${Defines.Boolean}[]"
  )

  private val TypeReplacements = Map(
    " any"     -> s" ${Defines.Any}",
    " unknown" -> s" ${Defines.Unknown}",
    " number"  -> s" ${Defines.Number}",
    " null"    -> s" ${Defines.Null}",
    " string"  -> s" ${Defines.String}",
    " boolean" -> s" ${Defines.Boolean}",
    " bigint"  -> s" ${Defines.BigInt}",
    "{}"       -> Defines.Object,
    "typeof "  -> ""
  )

  protected def isPlainTypeAlias(alias: BabelNodeInfo): Boolean =
      if hasKey(alias.json, "right") then
        val rhsNode = createBabelNodeInfo(alias.json("right")).node
        rhsNode == GenericTypeAnnotation || rhsNode == TypeofTypeAnnotation || rhsNode == NullableTypeAnnotation
      else if hasKey(alias.json, "typeAnnotation") then
        createBabelNodeInfo(
          alias.json("typeAnnotation")
        ).node == TSTypeReference
      else
        false

  private def typeForFlowType(flowType: BabelNodeInfo): String = flowType.node match
    case BooleanTypeAnnotation        => Defines.Boolean
    case NumberTypeAnnotation         => Defines.Number
    case ObjectTypeAnnotation         => Defines.Object
    case StringTypeAnnotation         => Defines.String
    case SymbolTypeAnnotation         => Defines.Symbol
    case VoidTypeAnnotation           => Defines.Void
    case AnyTypeAnnotation            => Defines.Any
    case MixedTypeAnnotation          => Defines.Unknown
    case EmptyTypeAnnotation          => Defines.Never
    case NumberLiteralTypeAnnotation  => code(flowType.json)
    case ArrayTypeAnnotation          => code(flowType.json)
    case BooleanLiteralTypeAnnotation => code(flowType.json)
    case NullLiteralTypeAnnotation    => code(flowType.json)
    case StringLiteralTypeAnnotation  => code(flowType.json)
    case GenericTypeAnnotation        => code(flowType.json("id"))
    case UnionTypeAnnotation          => code(flowType.json)
    case IntersectionTypeAnnotation   => code(flowType.json)
    case TypeofTypeAnnotation =>
        if hasKey(flowType.json, "argument") then
          code(flowType.json("argument"))
        else Defines.Any
    case ThisTypeAnnotation =>
        typeHintForThisExpression(Option(flowType)).headOption.getOrElse(Defines.Any);
    case NullableTypeAnnotation =>
        typeForTypeAnnotation(createBabelNodeInfo(flowType.json(TypeAnnotationKey)))
    case _ => Defines.Any

  private def typeForTsType(tsType: BabelNodeInfo): String = tsType.node match
    case TSBooleanKeyword   => Defines.Boolean
    case TSBigIntKeyword    => Defines.Number
    case TSNullKeyword      => Defines.Null
    case TSNumberKeyword    => Defines.Number
    case TSObjectKeyword    => Defines.Object
    case TSStringKeyword    => Defines.String
    case TSSymbolKeyword    => Defines.Symbol
    case TSUnknownKeyword   => Defines.Unknown
    case TSVoidKeyword      => Defines.Void
    case TSUndefinedKeyword => Defines.Undefined
    case TSNeverKeyword     => Defines.Never
    case TSIntrinsicKeyword => code(tsType.json)
    case TSTypeReference    => code(tsType.json)
    case TSArrayType        => code(tsType.json)
    case TSThisType =>
        typeHintForThisExpression(Option(tsType)).headOption.getOrElse(Defines.Any)
    case TSOptionalType =>
        typeForTypeAnnotation(createBabelNodeInfo(tsType.json(TypeAnnotationKey)))
    case TSRestType =>
        typeForTypeAnnotation(createBabelNodeInfo(tsType.json(TypeAnnotationKey)))
    case TSParenthesizedType =>
        typeForTypeAnnotation(createBabelNodeInfo(tsType.json(TypeAnnotationKey)))
    case _ => Defines.Any

  private def typeForTypeAnnotation(typeAnnotation: BabelNodeInfo): String =
      typeAnnotation.node match
        case TypeAnnotation =>
            typeForFlowType(createBabelNodeInfo(typeAnnotation.json(TypeAnnotationKey)))
        case TSTypeAnnotation =>
            typeForTsType(createBabelNodeInfo(typeAnnotation.json(TypeAnnotationKey)))
        case _: FlowType => typeForFlowType(typeAnnotation)
        case _: TSType   => typeForTsType(typeAnnotation)
        case _           => Defines.Any

  /** A string literal type, or a union of them. TypeScript 7 keeps the quote style of the source,
    * so a single quoted literal is one too (only the native type map has them).
    */
  private def isStringType(tpe: String): Boolean =
      (tpe.startsWith("\"") && tpe.endsWith("\"")) ||
          (nativeTypeMap && tpe.startsWith("'") && tpe.endsWith("'"))

  /** Whether astgen was asked for the native binary's type map (TypeScript 7's checker), by the
    * configuration or by an inherited ASTGEN_TYPES. When astgen fell back to TypeScript 6, its
    * strings are brought to the same canonical spelling, which only reorders them.
    */
  private lazy val nativeTypeMap: Boolean = config.effectiveAstGenTypes() == "native"

  private def isNumberType(tpe: String): Boolean =
      tpe.toDoubleOption.isDefined

  /** The type string of the type map or the span map, as chen names it. */
  private def nameOfMapped(value: String): String = value match
    case v if v.isEmpty                          => Defines.String
    case "string"                                => Defines.String
    case v if isStringType(v)                    => Defines.String
    case "number"                                => Defines.Number
    case v if isNumberType(v)                    => Defines.Number
    case "null"                                  => Defines.Null
    case "boolean"                               => Defines.Boolean
    case "any"                                   => Defines.Any
    case v if ImportMatcher.matcher(v).matches() => importToModule(v)
    case other =>
        (TypeReplacements ++ ArrayReplacements).foldLeft(other) { case (typeStr, (m, r)) =>
            typeStr.replace(m, r)
        }

  private def typeFromTypeMap(node: BabelNodeInfo): String =
      pos(node.json).flatMap(parserResult.typeMap.get).map(normalizeNative) match
        case Some(value) => nameOfMapped(value)
        case None        => Defines.Any

  /** Whether the file came with a span map: the native binary writes one next to its type map. */
  protected lazy val hasTypeSpans: Boolean = parserResult.typeSpans.nonEmpty

  /** Babel nodes of the kinds the type map has no usable key for: it keeps one type for every node
    * that starts at an offset, so the type at the start of `a` is the one of `a.b()` when that is
    * what the checker gave the longest or most specific text. With a span map such a node is looked
    * up by its own extent, and without a type there it has none.
    */
  protected def isExpressionNode(node: BabelNodeInfo): Boolean =
      node.node match
        case Identifier | PrivateName | Super => true
        case _: Expression                    => true
        case other =>
            val name = other.toString
            name.endsWith("Expression") || name.endsWith("Literal")

  /** The type the span map has for exactly this node, when it is a concrete one (not `any`). The
    * type of every other node is a lookup of the type map, see [[typeFor]].
    */
  protected def spanType(node: BabelNodeInfo): Option[String] =
      if !hasTypeSpans then None
      else
        for
          s   <- pos(node.json)
          e   <- endPos(node.json)
          raw <- parserResult.typeSpans.get(BabelJsonParser.spanKey(s, e))
          tpe = nameOfMapped(normalizeNative(raw))
          if tpe != Defines.Any
        yield
          registerType(tpe, tpe)
          tpe

  protected def spanTypeOrAny(node: BabelNodeInfo): String =
      spanType(node).getOrElse(Defines.Any)

  /** The local of a temporary variable that holds the value of `node`. The references to it that
    * are made later (see `identifierNode`) have its type.
    */
  protected def newTmpLocal(name: String, node: BabelNodeInfo) =
    val tpe = spanTypeOrAny(node)
    tmpVariableTypes.update(name, tpe)
    io.appthreat.x2cpg.utils.NodeBuilders.newLocalNode(name, tpe)

  /** A reference to a temporary variable that holds the value of `node`. */
  protected def tmpIdentifierNode(node: BabelNodeInfo, name: String) =
    tmpVariableTypes.update(name, spanTypeOrAny(node))
    identifierNode(node, name)

  /** The type of a call node built for `node`, when the call is the operation `node` stands for
    * (the call, the `await`, the sum), and not one of the helper operations a lowering adds with
    * the node of the expression it belongs to (`void 0` in a default value).
    */
  protected def callTypeFor(node: BabelNodeInfo, name: String): String =
      if isExpressionNode(node) && node.node != Identifier && name != "<operator>.void" then
        spanTypeOrAny(node)
      else Defines.Any

  /** Native type maps are brought to one canonical spelling first (see [[TypeStringNormalizer]]),
    * so the member order and quote style of TypeScript 7 do not change the type name chen derives.
    * TypeScript 6 strings are used as they are.
    */
  private def normalizeNative(value: String): String =
      if nativeTypeMap then TypeStringNormalizer.normalize(value) else value

  private def importToModule(value: String): String =
    val matcher = ImportMatcher.matcher(value)
    this.rootTypeDecl.headOption match
      case Some(typeDecl) => typeDecl.fullName
      case None if matcher.matches() =>
          matcher.group(2).stripSuffix(".js").concat(".js::program")
      case None => value

  /** The type of a class or interface member. A method's member keeps the signature the type map
    * has at its name (`(u: User) => User`), where [[typeFor]] of the same node, as the method's
    * return, gives what the span map has for it (`User`).
    */
  protected def typeForMember(node: BabelNodeInfo): String = node.node match
    case ClassMethod | ClassPrivateMethod | ObjectMethod | TSDeclareMethod | TSDeclareFunction |
        TSMethodSignature | TSCallSignatureDeclaration
        if hasTypeSpans && !hasKey(node.json, ReturnTypeKey) =>
        val tpe = typeFromTypeMap(node)
        registerType(tpe, tpe)
        tpe
    case _ => typeFor(node)

  protected def typeFor(node: BabelNodeInfo): String =
    val json = node.json
    val typeNodeOpt = if hasKey(json, TypeAnnotationKey) then
      Some(createBabelNodeInfo(json(TypeAnnotationKey)))
    else if hasKey(json, ReturnTypeKey) then
      Some(createBabelNodeInfo(json(ReturnTypeKey)))
    else if node.node == ObjectTypeProperty && hasKey(json, "value") then
      Some(createBabelNodeInfo(json("value")))
    else if node.node == TypeofTypeAnnotation then
      Some(node)
    else
      None
    val tpe = typeNodeOpt match
      case Some(typeNode) => typeForTypeAnnotation(typeNode)
      case None =>
          spanType(node).getOrElse {
              if hasTypeSpans && isExpressionNode(node) then Defines.Any else typeFromTypeMap(node)
          }
    registerType(tpe, tpe)
    tpe
  end typeFor

  protected def typeHintForThisExpression(node: Option[BabelNodeInfo] = None): Seq[String] =
      dynamicInstanceTypeStack.headOption match
        case Some(tpe) => Seq(tpe)
        case None if node.isDefined =>
            typeFor(node.get) match
              case t if t != Defines.Any && t != "this" => Seq(t)
              case _                                    => rootTypeDecl.map(_.fullName).toSeq
        case None => rootTypeDecl.map(_.fullName).toSeq
end TypeHelper
