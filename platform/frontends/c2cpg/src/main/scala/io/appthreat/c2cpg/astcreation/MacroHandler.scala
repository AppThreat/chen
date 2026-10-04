package io.appthreat.c2cpg.astcreation

import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.codepropertygraph.generated.nodes.{
    AstNodeNew,
    ExpressionNew,
    NewBlock,
    NewCall,
    NewFieldIdentifier,
    NewNode
}
import io.appthreat.x2cpg.{Ast, AstEdge, SourceFiles, ValidationMode}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.utils.StringUtils
import io.shiftleft.codepropertygraph.generated.nodes.NewLocal
import org.eclipse.cdt.core.dom.ast.{
    IASTImageLocation,
    IASTMacroExpansionLocation,
    IASTName,
    IASTNode,
    IASTPreprocessorMacroDefinition
}
import org.eclipse.cdt.core.dom.ast.IASTBinaryExpression
import org.eclipse.cdt.internal.core.model.ASTStringUtil

import java.util.regex.Pattern
import scala.annotation.nowarn
import scala.collection.mutable

trait MacroHandler(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>
  private val TokenizerPattern = Pattern.compile("(?<=[^a-zA-Z0-9_])|(?=[^a-zA-Z0-9_])")

  /** Outside any string or character literal while splitting macro arguments. */
  private val NoQuote = '\u0000'

  private val nodeOffsetMacroPairs: mutable.Stack[(Int, IASTPreprocessorMacroDefinition)] =
      mutable.Stack.from(
        cdtAst.getNodeLocations.toList
            .collect { case exp: IASTMacroExpansionLocation =>
                (exp.asFileLocation().getNodeOffset, exp.getExpansion.getMacroDefinition)
            }
            .sortBy(_._1)
      )

  /** The root node built for each expression of the file, by CDT node: the argument of a macro
    * invocation is found by where CDT says its tokens came from.
    */
  protected val expressionRoots = new java.util.IdentityHashMap[IASTNode, NewNode]()

  /** The index of the next macro invocation of this file. */
  private var nextInvocationIndex = 0

  /** For the given node, determine if it is expanded from a macro, and if so, create a Call node to
    * represent the macro invocation and attach `ast` as its child.
    */
  def asChildOfMacroCall(node: IASTNode, ast: Ast): Ast =
    // If a macro in a header file contained a method definition already seen in some
    // source file we skipped that during the previous AST creation and returned an empty AST.
    if ast.root.isEmpty && isExpandedFromMacro(node) then return ast
    // We do nothing for locals only.
    if ast.nodes.size == 1 && ast.root.exists(_.isInstanceOf[NewLocal]) then return ast
    // Otherwise, we create the synthetic call AST.
    extractMatchingMacro(node) match
      case Some((mac, args)) =>
          val index = nextInvocationIndex
          nextInvocationIndex += 1
          val nestedNames = nestedMacroNames(node)
          val roots       = argumentRoots(node, ast, args, nestedNames)
          // an argument that is itself a macro invocation is an invocation nested in this one:
          // its source range, and its own index
          val nested = argumentRanges(node).zip(args).collect {
              case (range, text) if nestedNames.contains(leadingName(text)) =>
                  val nestedIndex = nextInvocationIndex
                  nextInvocationIndex += 1
                  range -> nestedIndex
          }
          tagExpansion(node, ast, index, nested)
          val callAst = createMacroCallAst(ast, node, mac, args, roots.map(_.map(_._2)))
          // a local of the expansion's AST that is not under its root would be lost by the copy;
          // a local declared outside the macro keeps its own place
          val underRoot = java.util.Collections.newSetFromMap(
            new java.util.IdentityHashMap[NewNode, java.lang.Boolean]()
          )
          var frontier = ast.root.toList
          while frontier.nonEmpty do
            val n = frontier.head
            frontier = frontier.tail
            if underRoot.add(n) then
              frontier = ast.edges.filter(_.src eq n).map(_.dst).toList ++ frontier
          val inExpansion = java.util.Collections.newSetFromMap(
            new java.util.IdentityHashMap[NewNode, java.lang.Boolean]()
          )
          ast.nodes.foreach(inExpansion.add)
          val lostLocals = ast.refEdges.collect {
              case AstEdge(_, dst: NewLocal)
                  if inExpansion.contains(dst) && !underRoot.contains(dst) =>
                  Ast(dst)
          }.toList.distinctBy(_.root.map(System.identityHashCode))
          // The expansion follows the argument copies (1..n) and is not an argument itself, so
          // it takes the next index rather than colliding with the first argument's.
          val expansionIndex = args.size + 1
          val newAst = copyTagged(ast, ast.root.get.asInstanceOf[AstNodeNew], expansionIndex)
          // We need to wrap the copied AST as it may contain CPG nodes not being allowed
          // to be connected via AST edges under a CALL. E.g., LOCALs but only if its not already a BLOCK.
          val childAst = newAst.root match
            case Some(_: NewBlock) =>
                newAst
            case _ =>
                val b = NewBlock().argumentIndex(expansionIndex).typeFullName(
                  registerType(Defines.voidTypeName)
                )
                blockAst(b, List(newAst))
          val result = callAst.withChildren(lostLocals).withChild(childAst)
          result.root.foreach(tagNode(_, X2CpgDefines.MacroInvocationTag, index.toString))
          result
      case None => ast
    end match
  end asChildOfMacroCall

  /** The macros the invocation's expansion names besides its own: those written in its arguments or
    * its definition.
    */
  private def nestedMacroNames(node: IASTNode): Set[String] =
      expandedFromMacro(node).headOption.toList
          .flatMap(loc => Option(loc.getExpansion.getNestedMacroReferences).toList.flatten)
          .map(_.toString)
          .toSet

  /** The identifier an argument's text starts with: `MAX` for `MAX(b, c)`, `LIMIT` for `LIMIT`. */
  private def leadingName(text: String): String =
      text.trim.takeWhile(c => c.isLetterOrDigit || c == '_')

  /** The source ranges [start, end) of an invocation's arguments, in its file. */
  private def argumentRanges(node: IASTNode): List[(Int, Int)] =
      Option(node.getFileLocation).toList.flatMap(invocation =>
          macroArgumentRanges(safeGetRawSignature(node)).map((s, e) =>
              (invocation.getNodeOffset + s, invocation.getNodeOffset + e)
          )
      )

  /** Whether every name of `n` is a token CDT took from the source range `range` of the
    * invocation's file.
    */
  private def fromRange(n: IASTNode, file: String, range: (Int, Int)): Boolean =
    val images = namesIn(n).map(name => Option(name.getImageLocation))
    images.nonEmpty && images.forall(_.exists(img =>
        img.getLocationKind == IASTImageLocation.ARGUMENT_TO_MACRO_EXPANSION &&
            img.getFileName == file && img.getNodeOffset >= range._1 &&
            img.getNodeOffset + img.getNodeLength <= range._2
    ))

  /** Tags the nodes `node`'s expansion produced with the invocation's index - those of an
    * invocation nested in it (`nested`: the source range of an argument that is a macro invocation,
    * with that one's index) with its index and this one as its parent - and those written in a
    * macro's definition with their position there. Done before the expansion is copied under its
    * INLINED call: the copies carry the tags.
    */
  private def tagExpansion(
    node: IASTNode,
    ast: Ast,
    index: Int,
    nested: List[((Int, Int), Int)]
  ): Unit =
    val inExpansion = java.util.Collections.newSetFromMap(
      new java.util.IdentityHashMap[NewNode, java.lang.Boolean]()
    )
    ast.nodes.foreach(inExpansion.add)
    val file = Option(node.getFileLocation).map(_.getFileName).getOrElse("")
    def visit(n: IASTNode, current: Int, parent: Option[Int], inNested: Boolean): Unit =
      // the widest node whose names all come from a nested invocation's argument is (one copy
      // of) that invocation's expansion
      val enters =
          if inNested then None else nested.find((range, _) => fromRange(n, file, range))
      val (here, hereParent) = enters match
        case Some((_, nestedIndex)) => (nestedIndex, Some(current))
        case None                   => (current, parent)
      Option(expressionRoots.get(n)).filter(inExpansion.contains).foreach { root =>
        tagNode(root, X2CpgDefines.MacroInvocationTag, here.toString)
        hereParent.foreach(p => tagNode(root, X2CpgDefines.MacroParentTag, p.toString))
        // where the node's first name was written: CDT keeps image locations on names
        namesIn(n).headOption.flatMap(name => Option(name.getImageLocation)).filter(
          _.getLocationKind == IASTImageLocation.MACRO_DEFINITION
        ).foreach { image =>
            positionIn(image.getFileName, image.getNodeOffset).foreach { (line, col) =>
                tagNode(
                  root,
                  X2CpgDefines.MacroOriginTag,
                  s"${projectRelative(image.getFileName)}:$line:$col"
                )
            }
        }
      }
      n.getChildren.foreach(visit(_, here, hereParent, inNested || enters.isDefined))
    end visit
    visit(node, index, None, inNested = false)
  end tagExpansion

  /** A path relative to the project root, comparing real paths (macOS's `/var` is `/private/var`).
    */
  private def projectRelative(path: String): String =
    val relative = SourceFiles.toRelativePath(path, config.inputPath)
    if relative != path then relative
    else
      CdtQuery {
          val root = java.nio.file.Paths.get(config.inputPath).toRealPath()
          val file = java.nio.file.Paths.get(path).toRealPath()
          if file.startsWith(root) then root.relativize(file).toString else path
      }.getOrElse(path)

  /** The names in `n`'s subtree, in source order. */
  private def namesIn(n: IASTNode): List[IASTName] = n match
    case name: IASTName => List(name)
    case other          => other.getChildren.toList.flatMap(namesIn)

  /** Each argument's subtree in the expansion, with the CDT node it was built from when known.
    *
    * By where CDT says the expansion's tokens came from: an expression every name of which is a
    * token of the i-th argument is (part of) it, and the widest such expression is the argument -
    * one that shows each argument token once (`TWICE(count + 1)` expands to `(count + 1) + (count +
    * 1)`, and the argument is one of the halves), unless the argument is itself a macro invocation
    * whose own expansion repeats them (`MIN(a, MAX(b, c))`). An argument with no names that is an
    * object-like macro (`LIMIT`) is the literal it expands to; any other is matched by its text.
    */
  private def argumentRoots(
    node: IASTNode,
    ast: Ast,
    args: List[String],
    nestedNames: Set[String]
  ): List[Option[(Option[IASTNode], NewNode)]] =
    val byLocation = argumentRootsByLocation(node, ast, args, nestedNames)
    args.zipWithIndex.map { case (arg, i) =>
        byLocation.get(i).map((cdt, root) => (Some(cdt), root))
            .orElse(objectMacroLiteral(node, ast, arg, nestedNames).map((cdt, root) =>
                (Some(cdt), root)
            ))
            .orElse(argForCode(arg, ast).map(root => (None, root)))
    }

  private def argumentRootsByLocation(
    node: IASTNode,
    ast: Ast,
    args: List[String],
    nestedNames: Set[String]
  ): Map[Int, (IASTNode, NewNode)] =
      Option(node.getFileLocation).toList.flatMap { invocation =>
        val text = safeGetRawSignature(node)
        val ranges = macroArgumentRanges(text).map((s, e) =>
            (invocation.getNodeOffset + s, invocation.getNodeOffset + e)
        )
        if ranges.size != args.size then Nil
        else
          val inAst = java.util.Collections.newSetFromMap(
            new java.util.IdentityHashMap[NewNode, java.lang.Boolean]()
          )
          ast.nodes.foreach(inAst.add)
          // arg, span, each token once, node, root
          val candidates = mutable.ArrayBuffer.empty[(Int, Int, Boolean, IASTNode, NewNode)]
          def argumentOf(n: IASTNode): Option[(Int, Int, Boolean)] =
            val images = namesIn(n).map(name => Option(name.getImageLocation))
            if images.isEmpty || images.exists(_.isEmpty) then None
            else
              val located = images.flatten.filter(img =>
                  img.getLocationKind == IASTImageLocation.ARGUMENT_TO_MACRO_EXPANSION &&
                      img.getFileName == invocation.getFileName
              )
              if located.size != images.size then None
              else
                val start = located.map(_.getNodeOffset).min
                val end   = located.map(i => i.getNodeOffset + i.getNodeLength).max
                val once  = located.map(_.getNodeOffset).distinct.size == located.size
                ranges.indexWhere((s, e) => start >= s && end <= e) match
                  case -1 => None
                  case i  => Some((i, end - start, once))
          def visit(n: IASTNode): Unit =
            Option(expressionRoots.get(n)).filter(inAst.contains).foreach { root =>
                argumentOf(n).foreach((i, span, once) => candidates += ((i, span, once, n, root)))
            }
            n.getChildren.foreach(visit)
          node.getChildren.foreach(visit)
          candidates.groupBy(_._1).toList.flatMap { (i, cs) =>
            val invocationArgument = nestedNames.contains(leadingName(args(i)))
            val eligible           = if invocationArgument then cs else cs.filter(_._3)
            // the expression written as the argument (names alone cannot tell `x` from `(16) <
            // (x)`), else the widest, the first of them in source order
            val written = eligible.find(c =>
                c._5 match
                  case e: ExpressionNew => tokenize(e.code) == tokenize(args(i))
                  case _                => false
            )
            written.orElse(
              eligible.maxByOption(_._2).map(_._2).flatMap(widest => eligible.find(_._2 == widest))
            ).map(c => i -> (c._4, c._5))
          }
        end if
      }.toMap

  /** An argument that is an object-like macro expanding to a literal (`LIMIT` for `16`): the first
    * such literal of the expansion.
    */
  private def objectMacroLiteral(
    node: IASTNode,
    ast: Ast,
    arg: String,
    nestedNames: Set[String]
  ): Option[(IASTNode, NewNode)] =
    val name = arg.trim
    if !nestedNames.contains(name) || leadingName(name) != name then None
    else
      val expansion = expandedFromMacro(node).headOption.toList
          .flatMap(loc => Option(loc.getExpansion.getNestedMacroReferences).toList.flatten)
          .find(_.toString == name)
          .flatMap(ref => Option(ref.resolveBinding()))
          .collect { case m: org.eclipse.cdt.core.dom.ast.IMacroBinding => m }
          .flatMap(m => Option(m.getExpansion)).map(new String(_).trim)
      val inAst = java.util.Collections.newSetFromMap(
        new java.util.IdentityHashMap[NewNode, java.lang.Boolean]()
      )
      ast.nodes.foreach(inAst.add)
      def literals(n: IASTNode): List[IASTNode] = n match
        case l: org.eclipse.cdt.core.dom.ast.IASTLiteralExpression => List(l)
        case other => other.getChildren.toList.flatMap(literals)
      expansion.toList.flatMap(text =>
          literals(node).filter(l =>
              new String(
                l.asInstanceOf[org.eclipse.cdt.core.dom.ast.IASTLiteralExpression].getValue
              )
                  .trim == text.stripPrefix("(").stripSuffix(")").trim
          )
      ).flatMap(l => Option(expressionRoots.get(l)).filter(inAst.contains).map(l -> _)).headOption
    end if
  end objectMacroLiteral

  /** The [start, end) offsets of each argument inside an invocation's text `NAME(a, b)`. */
  private def macroArgumentRanges(text: String): List[(Int, Int)] =
    val open  = text.indexOf('(')
    val close = text.lastIndexOf(')')
    if open < 0 || close <= open then Nil
    else
      val ranges  = mutable.ListBuffer.empty[(Int, Int)]
      var depth   = 0
      var quote   = NoQuote
      var escaped = false
      var start   = open + 1
      for i <- open + 1 until close do
        val c = text.charAt(i)
        if escaped then escaped = false
        else if c == '\\' && quote != NoQuote then escaped = true
        else if quote != NoQuote then
          if c == quote then quote = NoQuote
        else
          c match
            case '"' | '\''      => quote = c
            case '(' | '[' | '{' => depth += 1
            case ')' | ']' | '}' => depth -= 1
            case ',' if depth == 0 =>
                ranges += ((start, i))
                start = i + 1
            case _ =>
      if text.substring(start, close).trim.nonEmpty || ranges.nonEmpty then
        ranges += ((start, close))
      ranges.toList.map((s, e) => trimmed(text, s, e)).filter((s, e) => e > s)
    end if
  end macroArgumentRanges

  private def trimmed(text: String, start: Int, end: Int): (Int, Int) =
    var s = start
    var e = end
    while s < e && text.charAt(s).isWhitespace do s += 1
    while e > s && text.charAt(e - 1).isWhitespace do e -= 1
    (s, e)

  /** For the given node, determine if it is expanded from a macro, and if so, find the first
    * matching (offset, macro) pair in nodeOffsetMacroPairs, removing non-matching elements from the
    * start of nodeOffsetMacroPairs. Returns (Some(macroDefinition, arguments)) if a macro
    * definition matches and None otherwise.
    */
  private def extractMatchingMacro(node: IASTNode)
    : Option[(IASTPreprocessorMacroDefinition, List[String])] =
    var matchingMacro = Option.empty[(IASTPreprocessorMacroDefinition, List[String])]
    val fileLocation  = node.getFileLocation
    if fileLocation != null then
      val nodeOffset = fileLocation.getNodeOffset
      val expansionLocations =
          expandedFromMacro(node).filterNot(isExpandedFrom(node.getParent, _))

      expansionLocations.foreach { macroLocation =>
          while matchingMacro.isEmpty && nodeOffsetMacroPairs.headOption.exists(
              _._1 <= nodeOffset
            )
          do
            val (_, macroDefinition) = nodeOffsetMacroPairs.pop()
            val macroExpansionName = ASTStringUtil.getSimpleName(
              macroLocation.getExpansion.getMacroDefinition.getName
            )
            val macroDefinitionName = ASTStringUtil.getSimpleName(macroDefinition.getName)
            if macroExpansionName == macroDefinitionName then
              matchingMacro = Option((macroDefinition, macroInvocationArguments(node)))
      }
    matchingMacro
  end extractMatchingMacro

  /** The argument expressions of a function-like macro invocation, as source text.
    *
    * Without them the synthetic CALL this trait builds for a macro invocation carries NO arguments,
    * so nothing can taint the call's value: the data-flow chain `x = FFMIN(a, b)` stops at the
    * macro call for every consumer - a guard written as a macro is invisible to taint tracking. The
    * invocation's own source text is the argument source; the corresponding expression subtrees are
    * matched inside the expansion by [[argumentTrees]].
    *
    * Object-like macros (`#define NULL 0`) have no parentheses and yield no arguments.
    */
  private def macroInvocationArguments(node: IASTNode): List[String] =
    val text = safeGetRawSignature(node).trim
    val open = text.indexOf('(')
    if open < 0 then
      List.empty
    else
      val args = text.substring(open + 1)
      val body = args.substring(0, args.lastIndexOf(')')).trim
      if body.isEmpty then List.empty else splitTopLevelCommas(body)

  /** Split on commas that are not nested inside parentheses/brackets/braces, and not inside a
    * string or character literal. A backslash escapes the next character outright, so `"a\", b"`
    * stays one argument.
    */
  private def splitTopLevelCommas(s: String): List[String] =
    val parts   = mutable.ListBuffer[String]()
    val curr    = new StringBuilder
    var depth   = 0
    var quote   = NoQuote // the delimiter of the literal we are inside
    var escaped = false
    s.foreach { c =>
      curr.append(c)
      if escaped then escaped = false
      else if c == '\\' && quote != NoQuote then escaped = true
      else if quote != NoQuote then
        if c == quote then quote = NoQuote
      else
        c match
          case '"' | '\''      => quote = c
          case '(' | '[' | '{' => depth += 1
          case ')' | ']' | '}' => depth -= 1
          case ',' if depth == 0 =>
              curr.setLength(curr.length - 1) // the separator itself
              parts.addOne(curr.toString.trim)
              curr.clear()
          case _ =>
    }
    if curr.nonEmpty then parts.addOne(curr.toString.trim)
    parts.toList.filter(_.nonEmpty)
  end splitTopLevelCommas

  /** Determine whether `node` is expanded from the macro expansion at `loc`.
    */
  private def isExpandedFrom(node: IASTNode, loc: IASTMacroExpansionLocation): Boolean =
      expandedFromMacro(node).map(_.getExpansion.getMacroDefinition).contains(
        loc.getExpansion.getMacroDefinition
      )

  private def argumentTrees(ast: Ast, roots: List[Option[NewNode]]): List[Option[Ast]] =
      roots.zipWithIndex.map { case (root, i) =>
          root.map { x =>
            val copy = copyTagged(ast, x.asInstanceOf[AstNodeNew], i + 1)
            copy.nodes.foreach(tagNode(_, X2CpgDefines.MacroArgumentCopyTag, "true"))
            copy
          }
      }

  /** A copy of the subtree at `node`, whose nodes carry the tags of the nodes they copy. */
  private def copyTagged(ast: Ast, node: AstNodeNew, argIndex: Int): Ast =
    val copies = mutable.LinkedHashMap.empty[AstNodeNew, AstNodeNew]
    val copy   = ast.subTreeCopy(node, argIndex, copyMap = copies)
    copyTags(copies)
    copy

  private def tokenize(s: String): Seq[String] =
      TokenizerPattern.split(s).map(_.trim).filter(_.nonEmpty).toSeq

  private def argForCode(code: String, ast: Ast): Option[NewNode] =
    val argTokens = tokenize(code)
    if argTokens.isEmpty then
      None
    else
      val strictMatch = ast.nodes.collectFirst {
          case x: ExpressionNew if !x.isInstanceOf[NewFieldIdentifier] && x.code == code => x
      }
      if strictMatch.isDefined then strictMatch
      else
        ast.nodes.collectFirst {
            case x: ExpressionNew
                if !x.isInstanceOf[NewFieldIdentifier] && tokenize(x.code) == argTokens => x
        }

  /** Create an AST that represents a macro expansion as a call. The AST is rooted in a CALL node
    * and contains sub trees for arguments. These are also connected to the AST via ARGUMENT edges.
    * We include line number information in the CALL node that is picked up by the
    * MethodStubCreator.
    */
  private def createMacroCallAst(
    ast: Ast,
    node: IASTNode,
    macroDef: IASTPreprocessorMacroDefinition,
    arguments: List[String],
    roots: List[Option[NewNode]]
  ): Ast =
    val name    = ASTStringUtil.getSimpleName(macroDef.getName)
    val code    = safeGetRawSignature(node).stripSuffix(";")
    val argAsts = argumentTrees(ast, roots).map(_.getOrElse(Ast()))

    val callName     = StringUtils.normalizeSpace(name)
    val callFullName = StringUtils.normalizeSpace(fullName(macroDef, argAsts))
    val callNode =
        NewCall()
            .name(callName)
            .dispatchType(DispatchTypes.INLINED)
            .methodFullName(callFullName)
            .code(code)
            .typeFullName(typeFor(node))
            .lineNumber(line(node))
            .columnNumber(column(node))
    callAst(callNode, argAsts)
  end createMacroCallAst

  /** Create a full name field that encodes line information that can be picked up by the
    * MethodStubCreator in order to create a METHOD node with the correct location information.
    */
  private def fullName(macroDef: IASTPreprocessorMacroDefinition, argAsts: List[Ast]) =
    val name               = ASTStringUtil.getSimpleName(macroDef.getName)
    val filename           = fileName(macroDef)
    val lineNo: Integer    = line(macroDef).getOrElse(-1)
    val lineNoEnd: Integer = lineEnd(macroDef).getOrElse(-1)
    if name != "NULL" then s"$filename:$lineNo:$lineNoEnd:$name:${argAsts.size}" else name

  /** The CDT utility method is unfortunately in a class that is marked as deprecated, however, this
    * is because the CDT team would like to discourage its use but at the same time does not plan to
    * remove this code.
    */
  @nowarn
  def nodeSignature(node: IASTNode): String =
    val sig = if isExpandedFromMacro(node) then
      val sig = safeGetNodeSignature(node)
      if sig.isEmpty then
        safeGetRawSignature(node)
      else
        sig
    else
      safeGetRawSignature(node)
    shortenCode(sig)

  private def safeGetRawSignature(node: IASTNode): String =
      try
        node.getRawSignature
      catch
        case _: Throwable => ""

  @nowarn
  private def safeGetNodeSignature(node: IASTNode): String =
    import org.eclipse.cdt.core.dom.ast.ASTSignatureUtil.getNodeSignature
    try
      getNodeSignature(node)
    catch
      case _: Throwable => ""

  private def isExpandedFromMacro(node: IASTNode): Boolean = expandedFromMacro(node).nonEmpty

  private def expandedFromMacro(node: IASTNode): Option[IASTMacroExpansionLocation] =
    val locations = node.getNodeLocations.toList
    val locationsSorted = node match
      // For binary expressions the expansion locations may occur in any order.
      // We manually sort them here to ignore this.
      // TODO: This may also happen with other expressions that allow for multiple sub elements.
      case _: IASTBinaryExpression =>
          locations.sortBy(_.isInstanceOf[IASTMacroExpansionLocation])
      case _ => locations
    locationsSorted match
      case (head: IASTMacroExpansionLocation) :: _ => Option(head)
      case _                                       => None
end MacroHandler
