package io.shiftleft.semanticcpg.language.android

import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*
import overflowdb.traversal.TraversalLogicExt

class MethodTraversal(val traversal: Iterator[Method]) extends AnyVal:
  def exposedToJS: TraversalLogicExt[Method]#Traversal[Method] =
      traversal.where(_.annotation.fullNameExact("android.webkit.JavascriptInterface"))
