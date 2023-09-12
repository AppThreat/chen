package io.appthreat.dataflowengineoss.language.dotextension

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.dotgenerator.{DotCpg14Generator, DotDdgGenerator, DotPdgGenerator}
import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.dotextension.{ImageViewer, Shared}

class DdgNodeDot(val traversal: Iterator[Method]) extends AnyVal {

  def dotDdg(implicit semantics: Semantics = DefaultSemantics()): Iterator[String] =
    DotDdgGenerator.toDotDdg(traversal)

  def dotPdg(implicit semantics: Semantics = DefaultSemantics()): Iterator[String] =
    DotPdgGenerator.toDotPdg(traversal)

  def dotCpg14(implicit semantics: Semantics = DefaultSemantics()): Iterator[String] =
    DotCpg14Generator.toDotCpg14(traversal)

  def plotDotDdg(implicit viewer: ImageViewer, semantics: Semantics = DefaultSemantics()): Unit = {
    Shared.plotAndDisplay(traversal.dotDdg.l, viewer)
  }

  def plotDotPdg(implicit viewer: ImageViewer, semantics: Semantics = DefaultSemantics()): Unit = {
    Shared.plotAndDisplay(traversal.dotPdg.l, viewer)
  }

  def plotDotCpg14(implicit viewer: ImageViewer, semantics: Semantics = DefaultSemantics()): Unit = {
    Shared.plotAndDisplay(traversal.dotCpg14.l, viewer)
  }

}
