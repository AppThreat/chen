package io.appthreat.jssrc2cpg.astcreation

import io.appthreat.jssrc2cpg.parser.BabelNodeInfo
import io.appthreat.jssrc2cpg.parser.BabelAst.*
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.codepropertygraph.generated.nodes.{
    NewBlock,
    NewCall,
    NewIdentifier,
    NewMethodRef,
    NewTypeRef
}
import ujson.Obj

object AstForTemplateDomCreator:
  /** The operation of interpolating a value into a template. Not a JavaScript operator: it names
    * the framework-level step a template performs, so that the interpolated value participates in
    * the data dependence graph. See `wrapInterpolation`.
    */
  val InterpolationOperator: String = "<operator>.interpolation"

  /** The props object a component element passes: `<Card a={x} {...rest} />` calls `Card` with
    * `<operator>.jsxProps(x, rest)`. Like an object literal it holds every value it is built from.
    */
  val JsxPropsOperator: String = "<operator>.jsxProps"

trait AstForTemplateDomCreator(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  import AstForTemplateDomCreator.{InterpolationOperator, JsxPropsOperator}

  /** The name to give a template DOM node.
    *
    * Normally the Babel node type, which keeps Vue, React and Svelte uniform for elements and
    * attributes. The exception is `JSXExpressionContainer`: every Svelte block and tag maps onto
    * that one carrier, so `{#if}`, `{#each}`, `{@html}`, `{#await}`, `{#snippet}` and `{@render}`
    * would all be indistinguishable in the graph. When astgen supplies the additive `svelteKind`
    * key those are named after the construct instead - `SvelteIfBlock`, `SvelteHtmlTag`, and so on
    * \- so a query can select them directly.
    *
    * Output from a Vue/React parse, or from an astgen too old to emit `svelteKind`, has no such key
    * and keeps the Babel type.
    */
  private def templateDomNodeName(nodeInfo: BabelNodeInfo): String =
    val babelName = nodeInfo.node.toString
    if babelName != JSXExpressionContainer.toString then babelName
    else safeStr(nodeInfo.json, "svelteKind").map(kind => s"Svelte$kind").getOrElse(babelName)

  protected def astForJsxElement(jsxElem: BabelNodeInfo): Ast =
    val domNode = createTemplateDomNode(
      jsxElem.node.toString,
      jsxElem.code,
      jsxElem.lineNumber,
      jsxElem.columnNumber
    )
    val openingAst   = astForNodeWithFunctionReference(jsxElem.json("openingElement"))
    val childrenAsts = astForNodes(jsxElem.json("children").arr.toList)
    val closingAst =
        safeObj(jsxElem.json, "closingElement")
            .map(e => astForNodeWithFunctionReference(Obj(e)))
            .getOrElse(Ast())
    val allChildrenAsts = openingAst +: childrenAsts :+ closingAst
    setArgumentIndices(allChildrenAsts)
    val elementAst = Ast(domNode).withChildren(allChildrenAsts)
    // An element named by a capitalised identifier is a COMPONENT - a function, in React-like
    // frameworks and in every template astgen lowers to JSX - and its attributes are the props it
    // is called with. The element also lowers to a CALL of that component, so that a resolved call
    // edge carries a parent's values into the component's props: no call site exists for
    // `<RichText html={bio} />` otherwise. Host elements (`div`) keep the template DOM alone.
    componentName(jsxElem.json("openingElement"))
        .map(name => componentCallAst(jsxElem, name, elementAst))
        .getOrElse(elementAst)
  end astForJsxElement

  /** `<RichText html={bio} title="About" {...rest} />` lowered to `RichText(<props>)`, where
    * `<props>` is a [[JsxPropsOperator]] call over every value the code computes - `bio`, `rest` -
    * since the component receives them all in its one props object. Each value is named by its prop
    * (`bio` is the argument named `html`); a spread is unnamed. Constant attributes carry nothing
    * and are left out. The value expressions are lowered a second time for the call; the originals
    * stay under the attribute template nodes, where the template sinks are tagged.
    */
  private def componentCallAst(jsxElem: BabelNodeInfo, name: String, elementAst: Ast): Ast =
    val attributes = safeObj(jsxElem.json, "openingElement")
        .flatMap(_.get("attributes"))
        .collect { case attrs: ujson.Arr => attrs.value.toList }
        .getOrElse(Nil)
    // each value with the prop it is passed as; a spread passes props the code does not name
    val values = attributes.flatMap { attr =>
        safeStr(attr, "type") match
          // `{...rest}` passes every prop of `rest`
          case Some("JSXSpreadAttribute") => attr.obj.get("argument").toList.map(None -> _)
          // `html={bio}`; a boolean attribute (`replace`) has no value, `title="About"` a constant
          case Some("JSXAttribute") =>
              val name = safeObj(attr, "name").flatMap(safeStr(_, "name"))
              attr.obj.get("value").toList.flatMap {
                  case container: ujson.Obj
                      if safeStr(container, "type").contains("JSXExpressionContainer") =>
                      container.obj.get("expression").toList.map(name -> _)
                  case _ => Nil
              }
          case _ => Nil
    }.filterNot((_, v) =>
        safeStr(v, "type").exists(t =>
            Set(
              "StringLiteral",
              "NumericLiteral",
              "BooleanLiteral",
              "NullLiteral",
              "JSXEmptyExpression"
            )
                .contains(t)
        )
    )
    // the prop's name is the argument's name, for the bridges that follow one prop
    val valueAsts = values.map { (name, v) =>
      val ast = astForNodeWithFunctionReference(v)
      name.foreach(n =>
          ast.root.foreach {
              case e: NewIdentifier => e.argumentName = Some(n)
              case e: NewCall       => e.argumentName = Some(n)
              case e: NewBlock      => e.argumentName = Some(n)
              case e: NewMethodRef  => e.argumentName = Some(n)
              case _                =>
          }
      )
      ast
    }
    val propsCall = NewCall()
        .name(JsxPropsOperator)
        .methodFullName(JsxPropsOperator)
        .code(values.map((_, v) => createBabelNodeInfo(v).code).mkString("{", ", ", "}"))
        .dispatchType(DispatchTypes.STATIC_DISPATCH)
        .argumentIndex(1)
        .order(1)
        .lineNumber(jsxElem.lineNumber)
        .columnNumber(jsxElem.columnNumber)
        .typeFullName(io.appthreat.jssrc2cpg.passes.Defines.Any)
    val propsAst = callAst(propsCall, valueAsts)
    val componentCall = NewCall()
        .code(jsxElem.code)
        .name(name)
        .methodFullName(io.appthreat.x2cpg.Defines.DynamicCallUnknownFullName)
        .dispatchType(DispatchTypes.DYNAMIC_DISPATCH)
        .lineNumber(jsxElem.lineNumber)
        .columnNumber(jsxElem.columnNumber)
        .typeFullName(io.appthreat.jssrc2cpg.passes.Defines.Any)
    callAst(componentCall, List(propsAst)).withChild(elementAst)
  end componentCallAst

  /** The component a JSX element names, when the name is a capitalised identifier - the naming rule
    * React-like frameworks use for component references.
    */
  private def componentName(openingElement: ujson.Value): Option[String] =
      safeObj(openingElement, "name").flatMap { nameNode =>
          safeStr(nameNode, "name").filter(n =>
              n.nonEmpty && n.charAt(0).isUpper &&
                  n.forall(c => c.isLetterOrDigit || c == '_' || c == '$')
          )
      }

  protected def astForJsxFragment(jsxFragment: BabelNodeInfo): Ast =
    val domNode = createTemplateDomNode(
      jsxFragment.node.toString,
      jsxFragment.code,
      jsxFragment.lineNumber,
      jsxFragment.columnNumber
    )
    val childrenAsts = astForNodes(jsxFragment.json("children").arr.toList)
    setArgumentIndices(childrenAsts)
    Ast(domNode).withChildren(childrenAsts)

  protected def astForJsxAttribute(jsxAttr: BabelNodeInfo): Ast =
    // A colon in front of a JSXAttribute cant be parsed by Babel.
    // Hence, we strip it away with astgen and restore it here.
    // parserResult.fileContent contains the unmodified Vue.js source code for the current file.
    // We look at the previous character there and re-add the colon if needed.
    val colon = pos(jsxAttr.json)
        .collect {
            case position
                if position > 0 && parserResult.fileContent.substring(
                  position - 1,
                  position
                ) == ":" => ":"
        }
        .getOrElse("")
    val domNode =
        createTemplateDomNode(
          jsxAttr.node.toString,
          s"$colon${jsxAttr.code}",
          jsxAttr.lineNumber,
          jsxAttr.columnNumber.map(_ - colon.length)
        )
    val valueAst = safeObj(jsxAttr.json, "value")
        .map(e => astForNodeWithFunctionReference(Obj(e)))
        .getOrElse(Ast())
    setArgumentIndices(List(valueAst))
    Ast(domNode).withChild(valueAst)
  end astForJsxAttribute

  protected def astForJsxOpeningElement(jsxOpeningElem: BabelNodeInfo): Ast =
    val domNode = createTemplateDomNode(
      jsxOpeningElem.node.toString,
      jsxOpeningElem.code,
      jsxOpeningElem.lineNumber,
      jsxOpeningElem.columnNumber
    )
    val childrenAsts = astForNodes(jsxOpeningElem.json("attributes").arr.toList)
    setArgumentIndices(childrenAsts)
    Ast(domNode).withChildren(childrenAsts)

  protected def astForJsxClosingElement(jsxClosingElem: BabelNodeInfo): Ast =
    val domNode = createTemplateDomNode(
      jsxClosingElem.node.toString,
      jsxClosingElem.code,
      jsxClosingElem.lineNumber,
      jsxClosingElem.columnNumber
    )
    Ast(domNode)

  protected def astForJsxText(jsxText: BabelNodeInfo): Ast =
      Ast(createTemplateDomNode(
        jsxText.node.toString,
        jsxText.code,
        jsxText.lineNumber,
        jsxText.columnNumber
      ))

  protected def astForJsxExprContainer(jsxExprContainer: BabelNodeInfo): Ast =
    val domNode = createTemplateDomNode(
      templateDomNodeName(jsxExprContainer),
      jsxExprContainer.code,
      jsxExprContainer.lineNumber,
      jsxExprContainer.columnNumber
    )
    val nodeInfo = createBabelNodeInfo(jsxExprContainer.json("expression"))
    val exprAst = nodeInfo.node match
      case JSXEmptyExpression => Ast()
      case _                  => astForNodeWithFunctionReference(nodeInfo.json)
    val childAst = wrapInterpolation(jsxExprContainer, exprAst)
    setArgumentIndices(List(childAst))
    Ast(domNode).withChild(childAst)

  /** Wrap a template interpolation's expression in an `<operator>.interpolation` call.
    *
    * Without this, an expression sitting directly inside a `JSXExpressionContainer` is not a use as
    * far as the data dependence graph is concerned: `DdgGenerator.uses` harvests uses from `Return`
    * and `Call` nodes only, and `ReachingDefProblem.initGen` generates definitions for parameters
    * and call arguments only. A `TEMPLATE_DOM` parent supplies neither, so `<div>{bio}</div>` and
    * Svelte's `{@html bio}` got no reaching definition and could never be found by
    * `reachableByFlows` - the single most security-relevant shape in any template dialect.
    *
    * Interpolating a value into the DOM is a real operation, so modelling it as a call is not a
    * workaround: the argument becomes a use, the call is a CFG node that `CfgCreator` already
    * handles via `case _: Call`, and taint reaches the markup itself rather than stopping at the
    * script-side definition of the value.
    *
    * A call is wrapped too. It carries its own uses, but when the value IS what a framework reads
    * from outside - a signal input `{partner()}`, `{props.html}` - the read is the source and the
    * interpolation the sink, and two roles on one node make no flow. A function reference (an event
    * handler) interpolates nothing and stays bare.
    */
  private def wrapInterpolation(container: BabelNodeInfo, exprAst: Ast): Ast =
      exprAst.root match
        case None                  => exprAst
        case Some(_: NewMethodRef) => exprAst
        case Some(_: NewTypeRef)   => exprAst
        case Some(_) =>
            val interpolationCall = callNode(
              container,
              container.code,
              InterpolationOperator,
              DispatchTypes.STATIC_DISPATCH
            )
            callAst(interpolationCall, List(exprAst))

  protected def astForJsxSpreadAttribute(jsxSpreadAttr: BabelNodeInfo): Ast =
    val domNode = createTemplateDomNode(
      jsxSpreadAttr.node.toString,
      jsxSpreadAttr.code,
      jsxSpreadAttr.lineNumber,
      jsxSpreadAttr.columnNumber
    )
    val argAst = astForNodeWithFunctionReference(jsxSpreadAttr.json("argument"))
    setArgumentIndices(List(argAst))
    Ast(domNode).withChild(argAst)
end AstForTemplateDomCreator
