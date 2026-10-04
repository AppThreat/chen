package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.parser.{EdgaUnit, Pos}
import io.appthreat.edg2atom.parser.EdgaUnit.*
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import ujson.Value

import java.nio.file.Paths

/** Macro invocations as the CDT frontend writes them: a top-level invocation is an INLINED call
  * named after the macro, its full name `<definition file>:<line>:<last line>:<NAME>:<number of
  * parameters>`, its arguments as copies of the subtrees they became (tagged
  * `macro-argument-copy`), and its expansion in a block after them. Every node of the expansion
  * carries the invocation's index (`macro-invocation`). An invocation inside another one's
  * arguments or definition is part of that expansion.
  *
  * The front end tells which nodes an invocation expanded (each node's innermost invocation) and
  * where their text was written: an argument's text lies in the invocation itself, the rest in the
  * definitions.
  */
trait MacroCalls(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  /** The top-level invocation whose expansion is being built, 0 outside any. */
  private var macroContext: Long = 0L

  private def topLevelOf(v: Value): Long =
      v.long("mi").filter(_ > 0).map(unit.topLevelInvocation).getOrElse(0L)

  /** `build`'s AST, as the expansion of an INLINED call when `node` starts a top-level invocation's
    * expansion.
    */
  protected def withMacroCall(node: Value)(build: => Ast): Ast =
    val top = topLevelOf(node)
    if top == 0L || top == macroContext then build
    else
      val saved = macroContext
      macroContext = top
      try
        val expansion = build
        unit.invocations.get(top) match
          case Some(invocation) => macroCallAst(node, top, invocation, expansion)
          case None             => expansion
      finally macroContext = saved

  private def macroCallAst(node: Value, index: Long, invocation: Value, expansion: Ast): Ast =
    val name       = invocation.string("name").getOrElse("")
    val definition = invocation.long("macro").flatMap(unit.macros.get)
    val params     = definition.flatMap(_.string("text")).map(parameterCount).getOrElse(0)
    val definedAt  = definition.flatMap(_.position)
    val definitionFile = definedAt.flatMap(p => unit.files.get(p.file)).map(f => relativeTo(f.path))
        .getOrElse(filename)
    val firstLine = definedAt.map(_.line).getOrElse(0)
    val lastLine =
        firstLine + definition.flatMap(_.string("text")).map(_.count(_ == '\n')).getOrElse(0)
    val fullName       = s"$definitionFile:$firstLine:$lastLine:$name:$params"
    val invocationText = invocationSpan(invocation).flatMap((s, e) => textOf(s, e)).getOrElse(name)
    val args           = argumentAsts(node, invocation)
    // the CDT frontend types an invocation by its expansion only when that is a literal
    val tpe =
        expansion.root.collect { case l: NewLiteral => l.typeFullName }.getOrElse(X2CpgDefines.Any)
    val call = callNode(
      node,
      invocationText,
      name,
      fullName,
      DispatchTypes.INLINED,
      None,
      Some(registerType(tpe))
    )
    // the invocation is where it is written, not where its expansion starts
    invocation.field("start").flatMap(EdgaUnit.pos).foreach { p =>
        call.lineNumber(Integer.valueOf(p.line)).columnNumber(Integer.valueOf(p.column))
    }
    val block = NewBlock().code("<empty>").typeFullName(registerType("void"))
        .argumentIndex(params + 1).order(params + 1)
    // the expansion follows the argument copies
    expansion.root.foreach {
        case _: NewBlock =>
        case e: ExpressionNew =>
            e.argumentIndex = params + 1
            e.order = params + 1
        case _ =>
    }
    val expansionBlock = expansion.root match
      case Some(_: NewBlock) => expansion
      case _                 => Ast(block).withChild(expansion)
    expansion.nodes.foreach(n => tagNode(n, X2CpgDefines.MacroInvocationTag, index.toString))
    args.foreach { a =>
        a.nodes.foreach { n =>
          tagNode(n, X2CpgDefines.MacroInvocationTag, index.toString)
          tagNode(n, X2CpgDefines.MacroArgumentCopyTag, "true")
        }
    }
    val result = callAst(call, args).withChild(expansionBlock)
    tagNode(call, X2CpgDefines.MacroInvocationTag, index.toString)
    result
  end macroCallAst

  private def rootType(e: ExpressionNew): Option[String] = e match
    case c: NewCall       => Option(c.typeFullName)
    case i: NewIdentifier => Option(i.typeFullName)
    case l: NewLiteral    => Option(l.typeFullName)
    case _                => None

  /** One AST per argument written in the invocation: the outermost node of the expansion whose text
    * was written in the argument, else the argument's text as a literal (a number, or an
    * object-like macro's value).
    */
  private def argumentAsts(root: Value, invocation: Value): Seq[Ast] =
      argumentSpans(invocation).flatMap { (start, end, text) =>
          outermostWithin(root, start, end) match
            // a stringised argument (`#x`) is text of the expansion, not a value passed in
            case Some(n) if n.string("ck").contains("string") && !text.trim.startsWith("\"") =>
                None
            case Some(n) => Some(expressionAst(n))
            case None =>
                val value = objectMacroValue(root, text).getOrElse(text.trim)
                Some(Ast(literalNode(root, value, registerType(literalType(value)))))
      }

  private def literalType(text: String): String =
      if text.startsWith("\"") then "char*"
      else if text.startsWith("'") then "char"
      else if text.exists(c => c == '.' || c == 'e' || c == 'E') && !text.startsWith("0x") then
        "double"
      else "int"

  /** An argument naming an object-like macro: the constant it expanded to, as the CDT frontend
    * writes it.
    */
  private def objectMacroValue(root: Value, text: String): Option[String] =
    val name = text.trim
    if name.isEmpty || !(name.head.isLetter || name.head == '_') then None
    else
      val invocations =
          unit.invocations.values.filter(i => i.string("name").contains(name)).flatMap(
            _.long("id")
          ).toSet
      nodes(root).find(n => n.kind == "constant" && n.long("mi").exists(invocations.contains))
          .flatMap(_.string("value"))

  private def outermostWithin(root: Value, start: Pos, end: Pos): Option[Value] =
    def within(p: Pos): Boolean =
        p.file == start
            .file && (p.line > start.line || p.line == start.line && p.column >= start.column) &&
            (p.line < end.line || p.line == end.line && p.column <= end.column)
    // breadth-first: the first match is the outermost
    val queue                = scala.collection.mutable.Queue(root)
    var found: Option[Value] = None
    while found.isEmpty && queue.nonEmpty do
      val n = queue.dequeue()
      if (n.kind == "variable" || n.kind == "operation" || n.kind == "constant") &&
        n.origin.orElse(n.position.filter(_ => n.field("mi").isEmpty)).exists(within) && !n.flag(
          "implicit"
        )
      then found = Some(n)
      else children(n).foreach(queue.enqueue)
    found

  private def nodes(root: Value): Iterator[Value] =
      Iterator.single(root) ++ children(root).iterator.flatMap(nodes)

  private def children(n: Value): Seq[Value] =
      n match
        case o: ujson.Obj =>
            o.value.toSeq.flatMap {
                case (k, v: ujson.Obj) if k != "p" && k != "po" && k != "end" => Seq(v)
                case (k, ujson.Arr(items))
                    if k == "ops" || k == "args" || k == "stmts" || k == "elements" =>
                    items.toSeq.collect { case o: ujson.Obj => o }
                case _ => Seq.empty
            }
        case _ => Seq.empty

  /** The invocation's arguments, with where each is written: `MIN(a, f(b, c))` has `a` and `f(b,
    * c)`.
    */
  private def argumentSpans(invocation: Value): Seq[(Pos, Pos, String)] =
      invocationSpan(invocation).toSeq.flatMap { (start, end) =>
          textOf(start, end).toSeq.flatMap { text =>
            val open = text.indexOf('(')
            if open < 0 then Seq.empty
            else
              val spans   = scala.collection.mutable.ArrayBuffer.empty[(Int, Int)]
              var depth   = 0
              var from    = open + 1
              var i       = open + 1
              var inQuote = 0.toChar
              while i < text.length && depth >= 0 do
                val c = text(i)
                if inQuote != 0 then
                  if c == '\\' then i += 1
                  else if c == inQuote then inQuote = 0.toChar
                else if c == '"' || c == '\'' then inQuote = c
                else if c == '(' || c == '[' || c == '{' then depth += 1
                else if c == ')' || c == ']' || c == '}' then
                  if depth == 0 then
                    spans += ((from, i))
                    depth = -1
                  else depth -= 1
                else if c == ',' && depth == 0 then
                  spans += ((from, i))
                  from = i + 1
                i += 1
              spans.toSeq.filter((a, b) => text.substring(a, b).trim.nonEmpty).map { (a, b) =>
                  (
                    offsetToPos(start, text, a),
                    offsetToPos(start, text, b - 1),
                    text.substring(a, b)
                  )
              }
            end if
          }
      }

  private def offsetToPos(start: Pos, text: String, offset: Int): Pos =
    val before   = text.substring(0, offset)
    val newlines = before.count(_ == '\n')
    if newlines == 0 then Pos(start.file, start.line, start.column + offset)
    else Pos(start.file, start.line + newlines, offset - before.lastIndexOf('\n'))

  private def invocationSpan(invocation: Value): Option[(Pos, Pos)] =
      for
        s <- invocation.field("start").flatMap(EdgaUnit.pos)
        e <- invocation.field("end").flatMap(EdgaUnit.pos)
      yield (s, e)

  /** The number of parameters in `#define NAME(a, b) ...`; 0 for an object-like macro. */
  private def parameterCount(text: String): Int =
    val afterDefine = text.stripPrefix("#define").trim
    val nameEnd     = afterDefine.indexWhere(c => !(c.isLetterOrDigit || c == '_'))
    if nameEnd < 0 || afterDefine(nameEnd) != '(' then 0
    else
      val close = afterDefine.indexOf(')', nameEnd)
      if close < 0 then 0
      else
        val inner = afterDefine.substring(nameEnd + 1, close).trim
        if inner.isEmpty then 0 else inner.split(',').length

  private def relativeTo(path: String): String =
    val root = AstCreator.realPath(Paths.get(config.inputPath))
    val p    = AstCreator.realPath(Paths.get(path))
    if p.startsWith(root) then root.relativize(p).toString else path
end MacroCalls
