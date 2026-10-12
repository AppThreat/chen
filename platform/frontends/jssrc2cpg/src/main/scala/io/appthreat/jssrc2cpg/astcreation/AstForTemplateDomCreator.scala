package io.appthreat.jssrc2cpg.astcreation

import io.appthreat.jssrc2cpg.parser.BabelNodeInfo
import io.appthreat.jssrc2cpg.parser.BabelAst.*
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewMethodRef, NewTypeRef}
import ujson.Obj

object AstForTemplateDomCreator:
  /** The operation of interpolating a value into a template. Not a JavaScript operator: it names
    * the framework-level step a template performs, so that the interpolated value participates in
    * the data dependence graph. See `wrapInterpolation`.
    */
  val InterpolationOperator: String = "<operator>.interpolation"

trait AstForTemplateDomCreator(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  import AstForTemplateDomCreator.InterpolationOperator

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
    // An element whose name is a capitalized identifier names a COMPONENT - a function, in
    // React-like frameworks and in every template astgen lowers to JSX. The element also lowers
    // to a CALL of that component with its attribute values as arguments, so a resolved call
    // edge can carry a parent's value into the component's props - no call site exists for
    // `<RichText html={bio} />` otherwise. The attribute expressions are lowered a second time
    // for the call: the originals stay under the attribute template nodes, where the template
    // sinks are tagged. Host elements (`div`) keep the template DOM alone.
    componentName(jsxElem.json("openingElement"))
        .map { name =>
            componentCallAst(jsxElem, name, elementAst)
        }
        .getOrElse(elementAst)
  end astForJsxElement

  /** The call of the component an element names, with the element's first computed attribute value
    * as its argument: `<RichText html={bio} />` lowers to a call whose argument is `bio`'s
    * expression. React itself passes one props object; the dataflow engine maps a call's argument
    * to the component's single props parameter by index, so one argument - the first value the code
    * computes, constants excluded - is what carries a parent's value into the component's props.
    * The attribute expressions are lowered a second time for the call; the originals stay under the
    * attribute template nodes, where the template sinks are tagged.
    */
  private def componentCallAst(jsxElem: BabelNodeInfo, name: String, elementAst: Ast): Ast =
    val attributes = jsxElem.json("openingElement").obj.getOrElse("attributes", ujson.Arr()) match
      case attrs: ujson.Arr => attrs.value.toList
      case _                => Nil
    val values = attributes.flatMap { attr =>
      val attrObj = attr.obj
      val valueOpt =
          for
            typ <- attrObj.get("type").collect { case ujson.Str("JSXAttribute") => () }
            // a boolean attribute (`replace`) has a null value
            v <- attrObj.get("value") if v != ujson.Null
          yield v
      valueOpt.map { v =>
          // `{expr}` lowers to a template node; the argument is the expression inside it
          v match
            case container: ujson.Obj => container.obj.get("expression").getOrElse(v)
            case other                => other
      }.filter {
          // a constant attribute (`author="guest"`) carries nothing
          case ujson.Str(_) => false
          case expr: ujson.Obj =>
              expr.obj.get("type").collect { case ujson.Str(t) => t }.forall(t =>
                  !Set("StringLiteral", "NumericLiteral", "BooleanLiteral", "NullLiteral")
                      .contains(t)
              )
          case _ => true
      }
    }
    val argAsts = values.headOption.map(v => astForNodeWithFunctionReference(v)).toList
    val componentCall = NewCall()
        .code(jsxElem.code)
        .name(name)
        .methodFullName(io.appthreat.x2cpg.Defines.DynamicCallUnknownFullName)
        .dispatchType(DispatchTypes.DYNAMIC_DISPATCH)
        .lineNumber(jsxElem.lineNumber)
        .columnNumber(jsxElem.columnNumber)
        .typeFullName(io.appthreat.jssrc2cpg.passes.Defines.Any)
    Ast(componentCall)
        .withChildren(argAsts)
        .withArgEdges(componentCall, argAsts.flatMap(_.root), 1)
        .withChild(elementAst)
  end componentCallAst

  /** The component a JSX element names, when the name is a capitalized identifier - the naming rule
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
    * Expressions that are already a call carry their own uses, so they are left alone - wrapping
    * them would add a redundant node to every `{foo()}` in every template.
    */
  private def wrapInterpolation(container: BabelNodeInfo, exprAst: Ast): Ast =
      exprAst.root match
        case None                  => exprAst
        case Some(_: NewCall)      => exprAst
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
