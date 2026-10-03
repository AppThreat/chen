package io.appthreat.c2cpg.astcreation

import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.x2cpg.utils.NodeBuilders.newDependencyNode
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.utils.StringUtils
import io.appthreat.x2cpg.{Ast, SourceFiles, ValidationMode}
import io.shiftleft.codepropertygraph.generated.nodes.{
    ExpressionNew,
    NewCall,
    NewIdentifier,
    NewNode
}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes, Operators}
import io.shiftleft.utils.IOUtils
import org.eclipse.cdt.core.dom.ast.*
import org.eclipse.cdt.core.dom.ast.c.{
    ICASTArrayDesignator,
    ICASTDesignatedInitializer,
    ICASTFieldDesignator
}
import org.eclipse.cdt.core.dom.ast.cpp.*
import org.eclipse.cdt.core.dom.ast.gnu.c.ICASTKnRFunctionDeclarator
import org.eclipse.cdt.internal.core.dom.parser.c.{CASTArrayRangeDesignator, CASTFunctionDeclarator}
import org.eclipse.cdt.internal.core.dom.parser.cpp.*
import org.eclipse.cdt.internal.core.dom.parser.cpp.semantics.{
    EvalBinding,
    EvalFunctionCall,
    EvalMemberAccess,
    TypeOfDependentExpression
}
import org.eclipse.cdt.internal.core.model.ASTStringUtil

import java.nio.file.{Path, Paths}
import scala.annotation.nowarn
import scala.collection.mutable
import scala.util.Try

object AstCreatorHelper:

  implicit class OptionSafeAst(val ast: Ast) extends AnyVal:
    def withArgEdge(src: NewNode, dst: Option[NewNode]): Ast = dst match
      case Some(value) => ast.withArgEdge(src, value)
      case None        => ast

trait AstCreatorHelper(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  /** Type names registered while parsing this file. Tracked per-creator (in addition to the global
    * table) so the contribution can be cached and replayed on a cache hit.
    */
  private val localUsedTypes: java.util.Set[String] =
      java.util.concurrent.ConcurrentHashMap.newKeySet[String]()

  private val localMemberOwners: java.util.Set[String] =
      java.util.concurrent.ConcurrentHashMap.newKeySet[String]()

  /** Record the ordered member layout of the struct or class a member access reads: a type defined
    * in a header is otherwise known to the graph only as an `<includes>` stub without members, and
    * the member's declared type (`char space_[200]`) is what extent reasoning reads. CDT's binding
    * resolves across includes. Recorded through the used-types channel, so the AST cache replays
    * it; registered under the spelling the graph uses for the type and under the composite's own
    * name (a typedef and its struct).
    */
  protected def registerMembersOf(owner: IType): Unit =
      unwrapCompositeType(owner).foreach { ct =>
        val spelled =
            Try(safeGetType(owner)).toOption.toList ++ Try(safeGetType(ct)).toOption.toList
        val names = spelled
            .map(t =>
                fixQualifiedName(StringUtils.normalizeSpace(cleanType(t))).stripSuffix("*").trim
            )
            .filter(n => n.nonEmpty && n != Defines.anyTypeName)
            .distinct
        val fields = Try(ct.getFields.toList).getOrElse(Nil)
        // the header that defines the composite: same-named structs differ by it
        val definedIn = (ct match
          case b: org.eclipse.cdt.internal.core.dom.parser.c.ICInternalBinding =>
              Option(b.getDefinition)
          case b: org.eclipse.cdt.internal.core.dom.parser.cpp.ICPPInternalBinding =>
              Option(b.getDefinition)
          case _ => None
        ).flatMap(d => Option(d.getFileLocation)).flatMap(l => Option(l.getFileName)).getOrElse("")
        names.filter(localMemberOwners.add).foreach { ownerName =>
            fields.zipWithIndex.foreach { (f, i) =>
              val tpe = fieldDeclarationType(f)
                  .getOrElse(declarationSpelling(cleanType(safeGetType(f.getType))))
              val record = CGlobal.memberRecord(ownerName, definedIn, i + 1, f.getName, tpe)
              CGlobal.usedTypes.putIfAbsent(record, true)
              localUsedTypes.add(record)
            }
        }
      }

  /** A member type as the declaration pass spells it: CDT's string with the extent attached (`char
    * [16]` -> `char[16]`), the signedness where CDT puts it (`short unsigned`, as a parsed struct's
    * own members read).
    */
  private def declarationSpelling(t: String): String = t.replaceAll("\\s+\\[", "[")

  /** The member type exactly as the declaration pass computes it for a parsed struct: the field's
    * own declarator (CDT's binding keeps its definition, in whichever header) - `typeFor` for an
    * array declarator, the declaration's specifier otherwise.
    */
  private def fieldDeclarationType(f: IField): Option[String] =
    val definition = f match
      case b: org.eclipse.cdt.internal.core.dom.parser.c.ICInternalBinding =>
          Option(b.getDefinition)
      case b: ICPPInternalBinding => Option(b.getDefinition)
      case _                      => None
    definition.flatMap(n => Option(n.getParent)).collect { case d: IASTDeclarator => d }.flatMap {
        d =>
            d.getParent match
              case decl: IASTSimpleDeclaration =>
                  Try {
                      d match
                        case _: IASTArrayDeclarator => typeFor(d)
                        case _ =>
                            typeForDeclSpecifier(
                              decl.getDeclSpecifier,
                              index = decl.getDeclarators.indexOf(d).max(0)
                            )
                  }.toOption.filter(t => t.nonEmpty && t != Defines.anyTypeName)
              case _ => None
    }
  end fieldDeclarationType

  private def unwrapCompositeType(t: IType): Option[ICompositeType] = t match
    case ct: ICompositeType => Some(ct)
    case td: ITypedef       => Option(td.getType).flatMap(unwrapCompositeType)
    case q: IQualifierType  => Option(q.getType).flatMap(unwrapCompositeType)
    case p: IPointerType    => Option(p.getType).flatMap(unwrapCompositeType)
    case _                  => None

  /** A name the file reads but does not define, bound to a `const`/`constexpr` integral variable
    * with a compile-time value (`config::kNumLevels` from a header): record the value, the way the
    * preprocessor already shows a `#define` as its literal.
    */
  protected def registerConstantRead(ident: IASTNode): Unit =
    val binding = ident match
      case id: IASTIdExpression => Try(id.getName.resolveBinding()).toOption
      case n: IASTName          => Try(n.resolveBinding()).toOption
      case _                    => None
    binding.collect { case v: IVariable if !v.isInstanceOf[IParameter] => v }.foreach { v =>
      val constant = Try(v.getType).toOption.exists {
          case q: IQualifierType => q.isConst
          case _                 => false
      } || (v match
        case c: ICPPVariable => Try(c.isConstexpr).getOrElse(false)
        case _               => false
      )
      val value =
          Try(Option(v.getInitialValue).flatMap(iv => Option(iv.numericalValue()))).toOption.flatten
      if constant then
        value.foreach { n =>
          val record = CGlobal.constRecord(v.getName, n.longValue)
          CGlobal.usedTypes.putIfAbsent(record, true)
          localUsedTypes.add(record)
        }
    }
  end registerConstantRead

  /** An implicit-this member read (`space_` inside a method): record its class's layout. */
  protected def registerImplicitMemberOwner(ident: IASTNode): Unit = ident match
    case s: CPPASTIdExpression =>
        safeGetEvaluation(s) match
          case Some(e: EvalMemberAccess) => registerMembersOf(e.getOwnerType)
          case _                         => ()
    case _ => ()

  /** Registers a side-channel record (member layouts, constants, array typedefs) the way a used
    * type is registered, so an AST cache hit replays it.
    */
  protected def registerRecord(record: String): Unit =
    CGlobal.usedTypes.putIfAbsent(record, true)
    localUsedTypes.add(record)

  /** The distinct type names this creator registered, for caching. */
  def usedTypes: Seq[String] =
    import scala.jdk.CollectionConverters.*
    localUsedTypes.asScala.toSeq

  import AstCreatorHelper.*

  private val IncludeKeyword = "include"
  // Sadly, there is no predefined List / Enum of this within Eclipse CDT:
  private val reservedTypeKeywords: List[String] =
      List(
        "const",
        "static",
        "volatile",
        "restrict",
        "extern",
        "typedef",
        "inline",
        "constexpr",
        "auto",
        "virtual",
        "enum",
        "struct",
        "interface",
        "class",
        "naked",
        "export",
        "module",
        "import"
      )
  private var usedVariablePostfix: Int = 0

  def createCallAst(
    callNode: NewCall,
    arguments: Seq[Ast] = List(),
    base: Option[Ast] = None,
    receiver: Option[Ast] = None
  ): Ast =

    setArgumentIndices(arguments)

    val baseRoot = base.flatMap(_.root).toList
    val bse      = base.getOrElse(Ast())
    baseRoot match
      case List(x: ExpressionNew) =>
          x.argumentIndex = 0
      case _ =>

    var ast =
        Ast(callNode)
            .withChild(bse)

    if receiver.isDefined && receiver != base then
      receiver.get.root.get.asInstanceOf[ExpressionNew].argumentIndex = -1
      ast = ast.withChild(receiver.get)

    ast = ast
        .withChildren(arguments)
        .withArgEdges(callNode, baseRoot)
        .withArgEdges(callNode, arguments.flatMap(_.root))

    if receiver.isDefined then
      ast = ast.withReceiverEdge(callNode, receiver.get.root.get)

    ast
  end createCallAst

  protected def uniqueName(target: String, name: String, fullName: String): (String, String) =
      if name.isEmpty && (fullName.isEmpty || fullName.endsWith(".")) then
        val name              = s"anonymous_${target}_$usedVariablePostfix"
        val resultingFullName = s"$fullName$name"
        usedVariablePostfix = usedVariablePostfix + 1
        (name, resultingFullName)
      else
        (name, fullName)

  protected def code(node: IASTNode): String = shortenCode(nodeSignature(node))

  protected def line(node: IASTNode): Option[Integer] =
      nullSafeFileLocation(node).map(_.getStartingLineNumber)

  protected def lineEnd(node: IASTNode): Option[Integer] =
      nullSafeFileLocationLast(node).map(_.getEndingLineNumber)

  private def nullSafeFileLocationLast(node: IASTNode): Option[IASTFileLocation] =
    val locations = node.getNodeLocations
    if locations == null || locations.isEmpty then
      None
    else
      Option(cdtAst.flattenLocationsToFile(locations.lastOption.toArray)).map(
        _.asFileLocation()
      )

  protected def column(node: IASTNode): Option[Integer] =
    val loc = nullSafeFileLocation(node)
    loc.map { x =>
        offsetToColumn(node, x.getNodeOffset)
    }

  protected def columnEnd(node: IASTNode): Option[Integer] =
    val loc = nullSafeFileLocation(node)
    loc.map { x =>
        offsetToColumn(node, x.getNodeOffset + x.getNodeLength - 1)
    }

  private def offsetToColumn(node: IASTNode, offset: Int): Int =
    val table      = fileOffsetTable(node)
    val index      = java.util.Arrays.binarySearch(table, offset)
    val tableIndex = if index < 0 then -(index + 1) else index + 1
    val lineStartOffset = if tableIndex == 0 then
      0
    else
      table(tableIndex - 1)
    val column = offset - lineStartOffset + 1
    column

  /** The 1-based line and column of `offset` in the file at `path` (absolute, as CDT names it). */
  protected def positionIn(path: String, offset: Int): Option[(Int, Int)] =
      scala.util.Try {
          val table =
              file2OffsetTable.computeIfAbsent(path, _ => genFileOffsetTable(Paths.get(path)))
          val index = java.util.Arrays.binarySearch(table, offset)
          val line  = if index < 0 then -(index + 1) else index + 1
          val start = if line == 0 then 0 else table(line - 1)
          (line + 1, offset - start + 1)
      }.toOption

  private def fileOffsetTable(node: IASTNode): Array[Int] =
    val path = SourceFiles.toAbsolutePath(fileName(node), config.inputPath)
    file2OffsetTable.computeIfAbsent(path, _ => genFileOffsetTable(Paths.get(path)))

  private def genFileOffsetTable(absolutePath: Path): Array[Int] =
    val asCharArray = sourceText(absolutePath)
    val offsets     = mutable.ArrayBuffer.empty[Int]

    for i <- Range(0, asCharArray.length) do
      if asCharArray(i) == '\n' then
        offsets.append(i + 1)
    offsets.toArray

  protected def fileName(node: IASTNode): String =
    val path = nullSafeFileLocation(node).map(_.getFileName).getOrElse(filename)
    SourceFiles.toRelativePath(path, config.inputPath)

  private def nullSafeFileLocation(node: IASTNode): Option[IASTFileLocation] =
    val locations = node.getNodeLocations
    if locations == null then
      None
    else
      Option(cdtAst.flattenLocationsToFile(locations)).map(_.asFileLocation())

  protected def registerType(typeName: String): String =
    val fixedTypeName = fixQualifiedName(StringUtils.normalizeSpace(typeName))
    CGlobal.usedTypes.putIfAbsent(fixedTypeName, true)
    // also track locally so this file's contribution can be cached and re-registered on a cache hit
    localUsedTypes.add(fixedTypeName)
    fixedTypeName

  protected def fixQualifiedName(name: String): String =
      name.stripPrefix(Defines.qualifiedNameSeparator).replace(
        Defines.qualifiedNameSeparator,
        "."
      )

  /** Collapse whitespace adjacent to pointer (`*`), array (`[` `]`) and reference (`&`) punctuation
    * while preserving the single spaces between the words of multi-token builtin types (e.g.
    * `unsigned long int`, `long long`). So `unsigned int *` -> `unsigned int*` and `long long int
    * [2]` -> `long long int[2]`, but `unsigned long int` is left intact.
    */
  private def tightenTypePunctuation(t: String): String =
      t.replaceAll("""\s*([\[\]*&])\s*""", "$1")

  protected def cleanType(rawType: String, stripKeywords: Boolean = true): String =
    if rawType.contains("TypeOfDependentExpression") || rawType.contains("CPPTypedef") then
      return Defines.anyTypeName
    val tpe =
        if stripKeywords then
          reservedTypeKeywords.foldLeft(rawType) { (cur, repl) =>
              // Strip the qualifier keyword only. Note: we must NOT also dereference here - doing so
              // dropped legitimate pointer stars from qualified expression/field types
              // (e.g. "const char *" -> "char" instead of "char*"). Pointer/array punctuation is
              // either already part of the type or re-applied by `pointersAsString`.
              if cur.contains(s"$repl ") then cur.replace(s"$repl ", "")
              else cur
          }
        else
          rawType
    StringUtils.normalizeSpace(tpe) match
      case "" => Defines.anyTypeName
      // A bare placeholder keyword that survived deduction is not a real type - never leak it.
      case "auto" | "decltype(auto)" | "decltype" => Defines.anyTypeName
      case t if t.contains("org.eclipse.cdt.internal.core.dom.parser.ProblemType") =>
          Defines.anyTypeName
      case t if t.contains(" ->") && t.contains("}::") =>
          fixQualifiedName(t.substring(t.indexOf("}::") + 3, t.indexOf(" ->")))
      case t if t.contains(" ->") =>
          fixQualifiedName(t.substring(0, t.indexOf(" ->")))
      case t if t.contains("( ") =>
          fixQualifiedName(t.substring(0, t.indexOf("( ")))
      case t if t.contains("?") => Defines.anyTypeName
      case t if t.contains("#") => Defines.anyTypeName
      case t if t.contains("{") && t.contains("}") =>
          val anonType =
              s"${uniqueName("type", "", "")._1}${t
                      .substring(0, t.indexOf("{"))}${t.substring(t.indexOf("}") + 1)}"
          anonType.replace(" ", "")
      case t if t.startsWith("[") && t.endsWith("]")       => Defines.anyTypeName
      case t if t.contains(Defines.qualifiedNameSeparator) => fixQualifiedName(t)
      // Tighten spacing around pointer/array/reference punctuation only. A blanket
      // `replace(" ", "")` here used to merge the words of multi-token builtin types, producing
      // invalid names such as "unsigned long int" -> "unsigned longint" and "long long int*" ->
      // "longlongint*" (observed en masse in real slices).
      case t if t.startsWith("unsigned ")          => tightenTypePunctuation(t)
      case t if t.contains("[") && t.contains("]") => tightenTypePunctuation(t)
      case t if t.contains("*")                    => tightenTypePunctuation(t)
      case someType                                => someType
    end match
  end cleanType

  @nowarn
  protected def typeFor(node: IASTNode, stripKeywords: Boolean = true): String =
    import org.eclipse.cdt.core.dom.ast.ASTSignatureUtil.getNodeSignature
    node match
      case f: CPPASTFieldReference =>
          safeGetEvaluation(f.getFieldOwner) match
            case Some(evaluation: EvalBinding) =>
                cleanType(safeGetType(evaluation.getType), stripKeywords)
            case _ =>
                val rawType = safeGetType(f.getFieldOwner.getExpressionType)
                cleanType(rawType, stripKeywords)
      case f: IASTFieldReference =>
          val rawType = safeGetType(f.getFieldOwner.getExpressionType)
          cleanType(rawType, stripKeywords)
      case a: IASTArrayDeclarator if safeGetNodeType(a).startsWith("? ") =>
          val tpe = getNodeSignature(a).replace("[]", "").strip()
          val arr = safeGetNodeType(a).replace("? ", "")
          s"$tpe$arr"
      case a: IASTArrayDeclarator if safeGetNodeType(a).contains("} ") =>
          val tpe      = getNodeSignature(a).replace("[]", "").strip()
          val nodeType = safeGetNodeType(node)
          val arr      = nodeType.substring(nodeType.indexOf("["), nodeType.indexOf("]") + 1)
          s"$tpe$arr"
      case a: IASTArrayDeclarator if safeGetNodeType(a).contains(" [") =>
          cleanType(safeGetNodeType(node))
      case s: CPPASTIdExpression =>
          safeGetEvaluation(s) match
            case Some(evaluation: EvalMemberAccess) =>
                cleanType(safeGetType(evaluation.getOwnerType), stripKeywords)
            case Some(evalBinding: EvalBinding) =>
                evalBinding.getBinding match
                  case m: CPPMethod =>
                      val bindingFullName = fullName(m.getDefinition)
                      cleanType(bindingFullName, stripKeywords)
                  case _ =>
                      val nodeType = safeGetNodeType(s)
                      cleanType(nodeType, stripKeywords)
            case _ =>
                val nodeType = safeGetNodeType(s)
                cleanType(nodeType, stripKeywords)
      case _: IASTIdExpression | _: IASTName | _: IASTDeclarator =>
          val nodeType = safeGetNodeType(node)
          cleanType(nodeType, stripKeywords)
      case s: IASTNamedTypeSpecifier =>
          val spelled = ASTStringUtil.getReturnTypeString(s, null)
          val name    = s.getName.toString
          val qualified = bindingQualifiedName(s.getName)
              .filter(_ => spelled.endsWith(name))
              .map(q => spelled.dropRight(name.length) + q)
          cleanType(qualified.getOrElse(spelled), stripKeywords)
      case s: IASTCompositeTypeSpecifier =>
          cleanType(ASTStringUtil.getReturnTypeString(s, null), stripKeywords)
      case s: IASTEnumerationSpecifier =>
          cleanType(ASTStringUtil.getReturnTypeString(s, null), stripKeywords)
      case s: IASTElaboratedTypeSpecifier =>
          cleanType(ASTStringUtil.getReturnTypeString(s, null), stripKeywords)
      case l: IASTLiteralExpression =>
          val rawType = safeGetType(l.getExpressionType)
          cleanType(rawType)
      case e: IASTExpression =>
          val nodeType = safeGetNodeType(e)
          cleanType(nodeType, stripKeywords)
      case c: ICPPASTConstructorInitializer
          if c.getParent.isInstanceOf[ICPPASTConstructorChainInitializer] =>
          val memberInitIdFullName = fullName(c.getParent.asInstanceOf[
            ICPPASTConstructorChainInitializer
          ].getMemberInitializerId)
          cleanType(memberInitIdFullName, stripKeywords)
      case _ =>
          val nodeSig = getNodeSignature(node)
          cleanType(nodeSig, stripKeywords)
    end match
  end typeFor

  protected def notHandledYet(node: IASTNode): Ast =
    if !node.isInstanceOf[IASTProblem] && !node.isInstanceOf[IASTProblemHolder] then
      val text = notHandledText(node)
      logger.debug(text)
    Ast(unknownNode(node, nodeSignature(node)))

  protected def nullSafeCode(node: IASTNode): String =
      Option(node).map(nodeSignature).getOrElse("")

  protected def nullSafeAst(node: IASTExpression, argIndex: Int): Ast =
    val r = nullSafeAst(node)
    r.root match
      case Some(x: ExpressionNew) =>
          x.argumentIndex = argIndex
      case _ =>
    r

  protected def nullSafeAst(node: IASTExpression): Ast =
      Option(node).map(astForNode).getOrElse(Ast())

  protected def nullSafeAst(node: IASTStatement, argIndex: Int = -1): Seq[Ast] =
      Option(node).map(astsForStatement(_, argIndex)).getOrElse(Seq.empty)

  protected def dereferenceTypeFullName(fullName: String): String =
      fullName.replace("*", "")

  protected def isQualifiedName(name: String): Boolean =
      name.startsWith(Defines.qualifiedNameSeparator)

  protected def lastNameOfQualifiedName(name: String): String =
    val cleanedName = if name.contains("<") && name.contains(">") then
      name.substring(0, name.indexOf("<"))
    else
      name
    cleanedName.split(Defines.qualifiedNameSeparator).lastOption.getOrElse(cleanedName)

  /** Converts an [[IFunctionType]] to a human-readable signature string using the CPG dot-separator
    * convention for namespaces. Both the return type and every parameter type are normalised
    * through [[cleanType]] so that raw CDT spellings (e.g. `::` separators, `const` qualifiers,
    * unresolved `?` placeholders, CDT-internal template indices) are canonicalised consistently
    * with all other type names in the graph.
    */
  protected def functionTypeToSignature(
    typ: IFunctionType,
    returnTypeOverride: Option[String] = None
  ): String =
    val returnType     = returnTypeOverride.getOrElse(cleanType(safeGetType(typ.getReturnType)))
    val parameterTypes = typ.getParameterTypes.map(t => cleanType(safeGetType(t)))
    s"$returnType(${parameterTypes.mkString(",")})"

  protected def fullName(node: IASTNode): String =
    val visitedNodes = mutable.Set.empty[IASTNode]
    def fullNameInternal(node: IASTNode): String =
      if node == null then return ""
      if visitedNodes.contains(node) then
        return uniqueName("recursive_type", "", "")._1
      try
        visitedNodes += node

        node match
          case declarator: CPPASTFunctionDeclarator =>
              declarator.getName.resolveBinding() match
                case function: ICPPFunction =>
                    return methodFullNameOf(function)
                case field: ICPPField =>
                case _: IProblemBinding =>
                    val fullNameNoSig = ASTStringUtil.getQualifiedName(declarator.getName)
                    val fixedFullName = fixQualifiedName(fullNameNoSig).stripPrefix(".")
                    if fixedFullName.isEmpty then
                      return ""
                    else
                      return s"$fixedFullName"
                case _ =>
          case declarator: CASTFunctionDeclarator =>
              val fn = declarator.getName.toString
              return fn
          case definition: ICPPASTFunctionDefinition =>
              return fullNameInternal(definition.getDeclarator)
          case x =>
        end match

        val qualifiedName: String = node match
          case d: CPPASTIdExpression =>
              safeGetEvaluation(d) match
                case Some(evalBinding: EvalBinding) =>
                    evalBinding.getBinding match
                      case f: CPPFunction if f.getDeclarations != null =>
                          f.getDeclarations.headOption.map(n => s"${fullNameInternal(n)}").getOrElse(
                            f.getName
                          )
                      case f: CPPFunction if f.getDefinition != null =>
                          s"${fullNameInternal(f.getDefinition)}"
                      case other =>
                          other.getName
                case _ => ASTStringUtil.getSimpleName(d.getName)

          case alias: ICPPASTNamespaceAlias => alias.getMappingName.toString
          case namespace: ICPPASTNamespaceDefinition
              if ASTStringUtil.getSimpleName(namespace.getName).nonEmpty =>
              s"${fullNameInternal(namespace.getParent)}.${ASTStringUtil.getSimpleName(namespace.getName)}"
          case namespace: ICPPASTNamespaceDefinition
              if ASTStringUtil.getSimpleName(namespace.getName).isEmpty =>
              s"${fullNameInternal(namespace.getParent)}.${uniqueName("namespace", "", "")._1}"
          case compType: IASTCompositeTypeSpecifier
              if ASTStringUtil.getSimpleName(compType.getName).nonEmpty =>
              s"${fullNameInternal(compType.getParent)}.${ASTStringUtil.getSimpleName(compType.getName)}"
          case compType: IASTCompositeTypeSpecifier
              if ASTStringUtil.getSimpleName(compType.getName).isEmpty =>
              val name = compType.getParent match
                case decl: IASTSimpleDeclaration =>
                    decl.getDeclarators.headOption
                        .map(n => ASTStringUtil.getSimpleName(n.getName))
                        .getOrElse(uniqueName("composite_type", "", "")._1)
                case _ => uniqueName("composite_type", "", "")._1
              s"${fullNameInternal(compType.getParent)}.$name"
          case enumSpecifier: IASTEnumerationSpecifier =>
              s"${fullNameInternal(enumSpecifier.getParent)}.${ASTStringUtil.getSimpleName(enumSpecifier.getName)}"
          case f: ICPPASTLambdaExpression =>
              s"${fullNameInternal(f.getParent)}."
          case f: IASTFunctionDeclarator
              if ASTStringUtil.getSimpleName(f.getName).isEmpty && f.getNestedDeclarator != null =>
              s"${fullNameInternal(f.getParent)}.${fullNameInternal(f.getNestedDeclarator)}"
          case f: IASTFunctionDeclarator if f.getParent.isInstanceOf[IASTFunctionDefinition] =>
              s"${fullNameInternal(f.getParent)}"
          case f: IASTFunctionDeclarator =>
              s"${fullNameInternal(f.getParent)}.${ASTStringUtil.getSimpleName(f.getName)}"
          case f: IASTFunctionDefinition if f.getDeclarator != null =>
              s"${fullNameInternal(f.getParent)}.${ASTStringUtil.getQualifiedName(f.getDeclarator.getName)}"
          case f: IASTFunctionDefinition =>
              s"${fullNameInternal(f.getParent)}.${shortName(f)}"
          case e: IASTElaboratedTypeSpecifier =>
              s"${fullNameInternal(e.getParent)}.${ASTStringUtil.getSimpleName(e.getName)}"
          case d: IASTIdExpression     => ASTStringUtil.getSimpleName(d.getName)
          case _: IASTTranslationUnit  => ""
          case u: IASTUnaryExpression  => code(u.getOperand)
          case x: ICPPASTQualifiedName => ASTStringUtil.getQualifiedName(x)
          case other if other != null && other.getParent != null =>
              val parent          = other.getParent
              val parentClassName = parent.getClass.getSimpleName
              if parentClassName == "CPPTypedef" || parentClassName.contains(
                  "TypeOfDependentExpression"
                )
              then
                uniqueName("type", "", "")._1
              else
                fullNameInternal(parent)
          case other if other != null => notHandledYet(other); ""
          case null                   => ""
        fixQualifiedName(qualifiedName).stripPrefix(".")
      finally
        visitedNodes -= node
      end try
    end fullNameInternal

    fullNameInternal(node)
  end fullName

  protected def shortName(node: IASTNode): String =
    val name = node match
      case d: IASTDeclarator
          if ASTStringUtil.getSimpleName(
            d.getName
          ).isEmpty && d.getNestedDeclarator != null =>
          shortName(d.getNestedDeclarator)
      case d: IASTDeclarator => ASTStringUtil.getSimpleName(d.getName)
      case f: ICPPASTFunctionDefinition
          if ASTStringUtil
              .getSimpleName(f.getDeclarator.getName)
              .isEmpty && f.getDeclarator.getNestedDeclarator != null =>
          shortName(f.getDeclarator.getNestedDeclarator)
      case f: ICPPASTFunctionDefinition =>
          lastNameOfQualifiedName(ASTStringUtil.getSimpleName(f.getDeclarator.getName))
      case f: IASTFunctionDefinition
          if ASTStringUtil
              .getSimpleName(f.getDeclarator.getName)
              .isEmpty && f.getDeclarator.getNestedDeclarator != null =>
          shortName(f.getDeclarator.getNestedDeclarator)
      case f: IASTFunctionDefinition => ASTStringUtil.getSimpleName(f.getDeclarator.getName)
      case d: CPPASTIdExpression if d.getEvaluation.isInstanceOf[EvalBinding] =>
          val evaluation = d.getEvaluation.asInstanceOf[EvalBinding]
          evaluation.getBinding match
            case f: CPPFunction if f.getDeclarations != null =>
                f.getDeclarations.headOption.map(n =>
                    ASTStringUtil.getSimpleName(n.getName)
                ).getOrElse(f.getName)
            case f: CPPFunction if f.getDefinition != null =>
                ASTStringUtil.getSimpleName(f.getDefinition.getName)
            case other =>
                other.getName
      case d: IASTIdExpression =>
          lastNameOfQualifiedName(ASTStringUtil.getSimpleName(d.getName))
      case u: IASTUnaryExpression         => shortName(u.getOperand)
      case c: IASTFunctionCallExpression  => shortName(c.getFunctionNameExpression)
      case s: IASTSimpleDeclSpecifier     => s.getRawSignature
      case e: IASTEnumerationSpecifier    => ASTStringUtil.getSimpleName(e.getName)
      case c: IASTCompositeTypeSpecifier  => ASTStringUtil.getSimpleName(c.getName)
      case e: IASTElaboratedTypeSpecifier => ASTStringUtil.getSimpleName(e.getName)
      case s: IASTNamedTypeSpecifier      => ASTStringUtil.getSimpleName(s.getName)
      case other                          => notHandledYet(other); ""
    name
  end shortName

  protected def astsForDependenciesAndImports(iASTTranslationUnit: IASTTranslationUnit): Seq[Ast] =
    val allIncludes = iASTTranslationUnit.getIncludeDirectives.toList.filterNot(isIncludedNode)
    allIncludes.map { include =>
      val name            = include.getName.toString
      val _dependencyNode = newDependencyNode(name, name, IncludeKeyword)
      val importNode      = newImportNode(nodeSignature(include), name, name, include)
      diffGraph.addNode(_dependencyNode)
      diffGraph.addEdge(importNode, _dependencyNode, EdgeTypes.IMPORTS)
      // the file the include resolved to, which names the package that provides it far better
      // than the header name, and whether it was written as a system include
      Option(include.getPath).filter(p => include.isResolved && p.nonEmpty).foreach { path =>
          tagNode(importNode, Defines.IncludeResolvedPathTag, path)
      }
      if include.isSystemInclude then tagNode(importNode, Defines.IncludeSystemTag, "true")
      Ast(importNode)
    }

  protected def isIncludedNode(node: IASTNode): Boolean = fileName(node) != filename

  protected def astsForComments(iASTTranslationUnit: IASTTranslationUnit): Seq[Ast] =
      if config.includeComments then
        iASTTranslationUnit.getComments.toList.filterNot(isIncludedNode).map(comment =>
            astForComment(comment)
        )
      else
        Seq.empty

  protected def astForNode(node: IASTNode): Ast =
      if config.includeFunctionBodies then astForNodeFull(node) else astForNodePartial(node)

  protected def astForNodeFull(node: IASTNode): Ast =
      node match
        case expr: IASTExpression             => astForExpression(expr)
        case name: IASTName                   => astForIdentifier(name)
        case decl: IASTDeclSpecifier          => astForIdentifier(decl)
        case l: IASTInitializerList           => astForInitializerList(l)
        case c: ICPPASTConstructorInitializer => astForCPPASTConstructorInitializer(c)
        case d: ICASTDesignatedInitializer    => astForCASTDesignatedInitializer(d)
        case d: ICPPASTDesignatedInitializer  => astForCPPASTDesignatedInitializer(d)
        case d: CASTArrayRangeDesignator      => astForCASTArrayRangeDesignator(d)
        case d: CPPASTArrayRangeDesignator    => astForCPPASTArrayRangeDesignator(d)
        case d: ICASTArrayDesignator          => nullSafeAst(d.getSubscriptExpression)
        case d: ICPPASTArrayDesignator        => nullSafeAst(d.getSubscriptExpression)
        case d: ICPPASTFieldDesignator        => astForNode(d.getName)
        case d: ICASTFieldDesignator          => astForNode(d.getName)
        case decl: ICPPASTDecltypeSpecifier   => astForDecltypeSpecifier(decl)
        case arrMod: IASTArrayModifier        => astForArrayModifier(arrMod)
        case _                                => notHandledYet(node)

  protected def astForNodePartial(node: IASTNode): Ast =
      node match
        case expr: IASTExpression           => astForExpression(expr)
        case name: IASTName                 => astForIdentifier(name)
        case decl: IASTDeclSpecifier        => astForIdentifier(decl)
        case decl: ICPPASTDecltypeSpecifier => astForDecltypeSpecifier(decl)
        case _                              => notHandledYet(node)

  protected def typeForDeclSpecifier(
    spec: IASTNode,
    stripKeywords: Boolean = true,
    index: Int = 0
  ): String =
    val tpe = spec match
      case s: IASTSimpleDeclSpecifier if s.getParent.isInstanceOf[IASTParameterDeclaration] =>
          val parentDecl = s.getParent.asInstanceOf[IASTParameterDeclaration].getDeclarator
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTSimpleDeclSpecifier if s.getParent.isInstanceOf[IASTFunctionDefinition] =>
          val parentDecl = s.getParent.asInstanceOf[IASTFunctionDefinition].getDeclarator
          ASTStringUtil.getReturnTypeString(s, parentDecl)
      case s: IASTSimpleDeclaration if s.getParent.isInstanceOf[ICASTKnRFunctionDeclarator] =>
          val declaratorsList = s.getDeclarators.toList
          if declaratorsList.nonEmpty && index >= 0 && index < declaratorsList.length then
            val decl = declaratorsList(index)
            pointersAsString(s.getDeclSpecifier, decl, stripKeywords)
          else
            Defines.anyTypeName
      case s: IASTSimpleDeclSpecifier if s.getParent.isInstanceOf[IASTSimpleDeclaration] =>
          val parentDecl =
              s.getParent.asInstanceOf[IASTSimpleDeclaration].getDeclarators.toList(index)
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTSimpleDeclSpecifier =>
          ASTStringUtil.getReturnTypeString(s, null)
      case s: IASTNamedTypeSpecifier if s.getParent.isInstanceOf[IASTParameterDeclaration] =>
          val parentDecl = s.getParent.asInstanceOf[IASTParameterDeclaration].getDeclarator
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTNamedTypeSpecifier if s.getParent.isInstanceOf[IASTSimpleDeclaration] =>
          val parentDecl =
              s.getParent.asInstanceOf[IASTSimpleDeclaration].getDeclarators.toList(index)
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTNamedTypeSpecifier if s.getParent.isInstanceOf[IASTFunctionDefinition] =>
          // Return type of a function definition (e.g. `std::string foo() {...}`). Without this
          // case the named type falls through to getSimpleName below, which drops the namespace
          // qualifier (`std::string` -> `string`). Mirror the parameter/declaration paths that
          // qualify correctly via pointersAsString.
          val parentDecl = s.getParent.asInstanceOf[IASTFunctionDefinition].getDeclarator
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTNamedTypeSpecifier =>
          bindingQualifiedName(s.getName).map(fixQualifiedName)
              .getOrElse(ASTStringUtil.getSimpleName(s.getName))
      case s: IASTCompositeTypeSpecifier if s.getParent.isInstanceOf[IASTSimpleDeclaration] =>
          val parentDecl =
              s.getParent.asInstanceOf[IASTSimpleDeclaration].getDeclarators.toList(index)
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTCompositeTypeSpecifier => ASTStringUtil.getSimpleName(s.getName)
      case s: IASTEnumerationSpecifier if s.getParent.isInstanceOf[IASTSimpleDeclaration] =>
          val parentDecl =
              s.getParent.asInstanceOf[IASTSimpleDeclaration].getDeclarators.toList(index)
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTEnumerationSpecifier => ASTStringUtil.getSimpleName(s.getName)
      case s: IASTElaboratedTypeSpecifier
          if s.getParent.isInstanceOf[IASTParameterDeclaration] =>
          val parentDecl = s.getParent.asInstanceOf[IASTParameterDeclaration].getDeclarator
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTElaboratedTypeSpecifier
          if s.getParent.isInstanceOf[IASTSimpleDeclaration] =>
          val parentDecl =
              s.getParent.asInstanceOf[IASTSimpleDeclaration].getDeclarators.toList(index)
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTElaboratedTypeSpecifier
          if s.getParent.isInstanceOf[IASTFunctionDefinition] =>
          // `struct entry *find(...) {...}`: the return type's pointer lives on the function
          // declarator. Without this case the definition's return type would be `struct entry` -
          // no pointer - while the same function's declaration says `struct entry*`
          val parentDecl = s.getParent.asInstanceOf[IASTFunctionDefinition].getDeclarator
          pointersAsString(s, parentDecl, stripKeywords)
      case s: IASTElaboratedTypeSpecifier => ASTStringUtil.getSignatureString(s, null)
      case _                              => Defines.anyTypeName
    if tpe.isEmpty then Defines.anyTypeName else tpe
  end typeForDeclSpecifier

  private def safeGetEvaluation(expr: ICPPASTExpression): Option[ICPPEvaluation] =
      Try(expr.getEvaluation).toOption

  protected def safeGetType(tpe: IType): String =
      Try(ASTTypeUtil.getType(tpe)).getOrElse(Defines.anyTypeName)

  /** The name of a type CDT resolved, normalised like every other type in the graph. A closure or
    * an anonymous struct (spelled with braces) has no name worth recording: normalising it would
    * mint a fresh anonymous name from the counter the lambdas of the file are numbered with.
    */
  protected def typeNameOf(tpe: IType): String =
    val raw = safeGetType(tpe)
    if raw == null || raw.contains("{") || raw.contains("}") then Defines.anyTypeName
    else tightenTypePunctuation(cleanType(raw))

  /** The type CDT gives an expression, normalised and registered like every other type. */
  protected def expressionType(expression: IASTExpression): String =
      registerType(Try(expression.getExpressionType).map(typeNameOf).getOrElse(
        Defines.anyTypeName
      ))

  /** An operand of unsigned integer type, through typedefs and qualifiers: `>>` on it shifts in
    * zeros.
    */
  protected def isUnsignedOperand(operand: IASTExpression): Boolean =
    @scala.annotation.tailrec
    def unwrap(t: IType): IType = t match
      case td: ITypedef      => unwrap(td.getType)
      case q: IQualifierType => unwrap(q.getType)
      case other             => other
    Try(unwrap(operand.getExpressionType)).toOption.exists {
        case b: IBasicType => b.isUnsigned
        case _             => false
    }

  /** The qualified name (`kv::LookupKey`) of a C++ class or enum written as a plain name inside its
    * namespace or class. The member layouts, implicit-this owners and resolved calls all spell the
    * type through its binding, so the source spelling alone (`LookupKey`) would give the same class
    * a second, member-less `<includes>` stub. Only a plain name bound to a non-template class or
    * enum outside the global scope is qualified: typedefs, template ids, names already written with
    * a qualifier and unresolved names keep their spelling.
    */
  private def bindingQualifiedName(name: IASTName): Option[String] = name match
    case _: ICPPASTQualifiedName | _: ICPPASTTemplateId => None
    case _ =>
        Try(name.resolveBinding()).toOption
            .collect {
                case _: IProblemBinding        => None
                case _: ICPPTemplateDefinition => None
                case _: ICPPSpecialization     => None
                case _: ICPPUnknownBinding     => None
                case t: ICPPClassType          => Some(t)
                case t: ICPPEnumeration        => Some(t)
            }
            .flatten
            .map(t => safeGetType(t))
            .filter(q => q.endsWith(s"${Defines.qualifiedNameSeparator}${name.toString}"))

  protected def safeGetNodeType(node: IASTNode): String =
      Try(ASTTypeUtil.getNodeType(node)).getOrElse(Defines.anyTypeName)

  private def notHandledText(node: IASTNode): String =
      s"""Node '${node.getClass.getSimpleName}' not handled yet!
           |  Code: '${node.getRawSignature}'
           |  File: '$filename'
           |  Line: ${line(node).getOrElse(-1)}
           |  """.stripMargin

  /** `auto`, `decltype(auto)` and `decltype(expr)` carry no useful spelling on the declaration
    * specifier itself - the real (deduced) type lives on the resolved variable binding. CDT
    * performs the deduction for us, so we read the binding's `IType` and stringify it. The binding
    * type already encodes pointers/references/const, so callers must not re-append pointer
    * punctuation.
    */
  private def deducedTypeFromBinding(spec: IASTNode, parentDecl: IASTDeclarator): Option[String] =
      spec match
        case s: IASTSimpleDeclSpecifier
            if s.getType == IASTSimpleDeclSpecifier.t_auto ||
                s.getType == IASTSimpleDeclSpecifier.t_decltype_auto ||
                s.getType == IASTSimpleDeclSpecifier.t_decltype =>
            Try {
                Option(parentDecl).flatMap { d =>
                    d.getName.resolveBinding() match
                      case v: IVariable if v.getType != null =>
                          val raw = safeGetType(v.getType)
                          // Match the codebase convention: references are modelled as the
                          // underlying value type (drop trailing `&`/`&&`), and pointer spacing is
                          // tightened. Pointers (`*`) are retained.
                          val t =
                              if raw == null then ""
                              else tightenTypePunctuation(raw.replaceAll("""\s*&+\s*$""", ""))
                          if t.isEmpty || t == "auto" ||
                            t.contains("ProblemType") || t.contains("TypeOfDependentExpression") ||
                            // Closure / anonymous brace types (e.g. a lambda's deduced type) carry
                            // no useful spelling and, when fed through `cleanType`, mint an
                            // anonymous "type" name that steals from the shared anonymous-name
                            // counter (shifting lambda indices). Fall back instead.
                            t.contains("{") || t.contains("}")
                          then None
                          else Option(t)
                      case _ => None
                }
            }.toOption.flatten
        case _ => None

  private def pointersAsString(
    spec: IASTDeclSpecifier,
    parentDecl: IASTDeclarator,
    stripKeywords: Boolean
  ): String =
      deducedTypeFromBinding(spec, parentDecl) match
        case Some(deduced) =>
            // The deduced binding type is the complete type (incl. pointers/refs); return as-is.
            deduced
        case None =>
            val tpe      = typeFor(spec, stripKeywords)
            val pointers = parentDecl.getPointerOperators
            val arr = parentDecl match
              case p: IASTArrayDeclarator =>
                  p.getArrayModifiers.toList.map(_.getRawSignature).mkString
              case _ => ""
            if pointers.isEmpty then s"$tpe$arr"
            else
              val refs =
                  "*" * (pointers.length - pointers.count(_.isInstanceOf[ICPPASTReferenceOperator]))
              s"$tpe$arr$refs".strip()

  private def astForDecltypeSpecifier(decl: ICPPASTDecltypeSpecifier): Ast =
    val op       = "<operator>.typeOf"
    val cpgUnary = callNode(decl, nodeSignature(decl), op, op, DispatchTypes.STATIC_DISPATCH)
    val operand  = nullSafeAst(decl.getDecltypeExpression)
    callAst(cpgUnary, List(operand))

  /** The object an initializer list initialises, innermost last: `s` while `{ .a = 1 }` of `struct
    * S s = { .a = 1 }` is created, `s.a` inside `{ .a = { .b = 1 } }`. Each entry builds a fresh
    * AST of that object.
    */
  private val initializedObjects = mutable.Stack.empty[(IASTNode, () => Ast)]

  /** Creates `body` with `target` as the object the designated initializers of `list` assign into.
    * Only that list's own designated initializers use it: a compound literal nested in the
    * initializer initialises another object. When the whole initializer is a compound literal, as
    * in `T v = (T){ .a = 1 }`, the literal is copied into the object, so its list assigns into it
    * as well.
    */
  protected def withInitializedObject[T](list: IASTNode, target: () => Ast)(body: => T): T =
      list match
        case l: IASTInitializerList =>
            initializedObjects.push((l, target))
            try body
            finally initializedObjects.pop()
        case c: IASTTypeIdInitializerExpression =>
            withInitializedObject(c.getInitializer, target)(body)
        case _ => body

  /** The object's code for a member access built on it: a variable by its name, since inside a
    * macro expansion an identifier's code is the invocation's text.
    */
  private def rootCode(ast: Ast): String =
      ast.root.collect {
          case i: NewIdentifier => i.name
          case n: ExpressionNew => n.code
      }.getOrElse("")

  /** `base.field`, `base[index]` or `base[low ... high]` for one designator. */
  private def designatorAccessAst(base: Ast, designator: IASTNode): Ast =
      designator match
        case f: ICASTFieldDesignator   => fieldDesignatorAst(base, f, f.getName)
        case f: ICPPASTFieldDesignator => fieldDesignatorAst(base, f, f.getName)
        case a: ICASTArrayDesignator =>
            indexDesignatorAst(base, a, nullSafeAst(a.getSubscriptExpression))
        case a: ICPPASTArrayDesignator =>
            indexDesignatorAst(base, a, nullSafeAst(a.getSubscriptExpression))
        case r: CASTArrayRangeDesignator   => indexDesignatorAst(base, r, astForNode(r))
        case r: CPPASTArrayRangeDesignator => indexDesignatorAst(base, r, astForNode(r))
        case other                         => indexDesignatorAst(base, other, astForNode(other))

  private def fieldDesignatorAst(base: Ast, designator: IASTNode, name: IASTName): Ast =
    val field = name.toString
    val tpe = Try(name.resolveBinding()).toOption.collect { case v: IVariable => v.getType }
        .map(t => registerType(cleanType(safeGetType(t)))).getOrElse(Defines.anyTypeName)
    val op = Operators.fieldAccess
    val access = callNode(
      designator,
      s"${rootCode(base)}.$field",
      op,
      op,
      DispatchTypes.STATIC_DISPATCH,
      None,
      Some(tpe)
    )
    callAst(access, List(base, Ast(fieldIdentifierNode(designator, field, field))))

  private def indexDesignatorAst(base: Ast, designator: IASTNode, index: Ast): Ast =
    val op = Operators.indirectIndexAccess
    // `[1]` or `[3 ... 9]`, as written
    val access = callNode(
      designator,
      s"${rootCode(base)}${nodeSignature(designator)}",
      op,
      op,
      DispatchTypes.STATIC_DISPATCH
    )
    callAst(access, List(base, index))

  /** A designated initializer (`.a.b[2] = v` in an initializer list) assigns `v` to the designated
    * member of the object the list initialises: `s.a.b[2] = v`. A nested list (`.a = { .b = 1 }`)
    * initialises that member in turn. Outside a declaration's initializer (a compound literal, a
    * C++ temporary) the object has no name: the assignment's target is the designator itself, a
    * FIELD_IDENTIFIER for a member.
    */
  private def astForDesignatedInitializer(
    d: IASTNode,
    designators: Seq[IASTNode],
    operand: IASTInitializerClause
  ): Ast =
      initializedObjects.headOption.filter((list, _) => list eq d.getParent)
          .map(_._2).orElse(declaredObjectOf(d.getParent)) match
        case Some(target) =>
            val member = () => designators.foldLeft(target())(designatorAccessAst)
            val right  = withInitializedObject(operand, member)(astForNode(operand))
            val op     = Operators.assignment
            val assignment =
                callNode(d, nodeSignature(d), op, op, DispatchTypes.STATIC_DISPATCH)
            callAst(assignment, List(member(), right))
        case None =>
            val node = blockNode(d, Defines.empty, Defines.voidTypeName)
            scope.pushNewScope(node)
            val op = Operators.assignment
            val calls = withIndex(designators.toArray) { (des, o) =>
              val callNode_ =
                  callNode(d, nodeSignature(d), op, op, DispatchTypes.STATIC_DISPATCH)
                      .argumentIndex(o)
              // a member of the unnamed object, never a variable of the same name
              val left = des match
                case f: ICASTFieldDesignator =>
                    Ast(fieldIdentifierNode(f, f.getName.toString, f.getName.toString))
                case f: ICPPASTFieldDesignator =>
                    Ast(fieldIdentifierNode(f, f.getName.toString, f.getName.toString))
                case _ => astForNode(des)
              val right = astForNode(operand)
              callAst(callNode_, List(left, right))
            }
            scope.popScope()
            blockAst(node, calls.toList)

  /** The object a declaration's initializer list initialises, whatever form the initializer takes
    * (`T v = {...}`, `T v{...}`, `T v({...})`).
    */
  private def declaredObjectOf(list: IASTNode): Option[() => Ast] =
      list match
        case l: IASTInitializerList =>
            val declarator = l.getParent match
              case d: IASTDeclarator => Some(d)
              case i: IASTInitializer =>
                  Option(i.getParent).collect { case d: IASTDeclarator => d }
              case _ => None
            declarator.map(d => () => astForNode(effectiveDeclaratorName(d)))
        case _ => None

  private def astForCASTDesignatedInitializer(d: ICASTDesignatedInitializer): Ast =
      astForDesignatedInitializer(d, d.getDesignators.toSeq, d.getOperand)

  private def astForCPPASTDesignatedInitializer(d: ICPPASTDesignatedInitializer): Ast =
      astForDesignatedInitializer(d, d.getDesignators.toSeq, d.getOperand)

  private def astForCPPASTConstructorInitializer(c: ICPPASTConstructorInitializer): Ast =
    val name = "<operator>.constructorInitializer"
    val callNode_ =
        callNode(c, nodeSignature(c), name, name, DispatchTypes.STATIC_DISPATCH)
    val args = c.getArguments.toList.map(a => astForNode(a))
    callAst(callNode_, args)

  private def astForCASTArrayRangeDesignator(des: CASTArrayRangeDesignator): Ast =
    val op         = Operators.arrayInitializer
    val callNode_  = callNode(des, nodeSignature(des), op, op, DispatchTypes.STATIC_DISPATCH)
    val floorAst   = nullSafeAst(des.getRangeFloor)
    val ceilingAst = nullSafeAst(des.getRangeCeiling)
    callAst(callNode_, List(floorAst, ceilingAst))

  private def astForCPPASTArrayRangeDesignator(des: CPPASTArrayRangeDesignator): Ast =
    val op         = Operators.arrayInitializer
    val callNode_  = callNode(des, nodeSignature(des), op, op, DispatchTypes.STATIC_DISPATCH)
    val floorAst   = nullSafeAst(des.getRangeFloor)
    val ceilingAst = nullSafeAst(des.getRangeCeiling)
    callAst(callNode_, List(floorAst, ceilingAst))
end AstCreatorHelper
