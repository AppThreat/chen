package io.appthreat.jssrc2cpg.passes

import io.shiftleft.codepropertygraph.generated.nodes.Expression
import io.shiftleft.codepropertygraph.generated.nodes.TemplateDom
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*
import io.appthreat.x2cpg.utils.StringUtils

abstract class AbstractDomPassTest extends AbstractPassTest:

  protected def templateDomName(cpg: Cpg): Set[String] =
      cpg.templateDom.name.toSetImmutable

  protected def templateDomCode(cpg: Cpg): List[String] =
      cpg.templateDom.code.map(StringUtils.normalizeSpace).l

  /** The template DOM node an expression belongs to.
    *
    * Walks up rather than taking the direct parent: an interpolated expression is wrapped in an
    * `<operator>.interpolation` call (see `AstForTemplateDomCreator.wrapInterpolation`), so the DOM
    * node is its grandparent. Walking makes this independent of how many lowering nodes sit in
    * between.
    */
  protected def parentTemplateDom(c: Expression): TemplateDom =
      c.inAst.filter(_.id != c.id).collectFirst { case dom: TemplateDom => dom }.get
