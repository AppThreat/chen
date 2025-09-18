package io.shiftleft.semanticcpg.language.android

import io.shiftleft.codepropertygraph.generated.nodes.{Call, Local}
import io.shiftleft.semanticcpg.language.*
import overflowdb.traversal.TraversalLogicExt

class LocalTraversal(val traversal: Iterator[Local]) extends AnyVal:
  def callsEnableJS: TraversalLogicExt[Local]#Traversal[Local] =
      traversal
          .where(
            _.referencingIdentifiers.inCall
                .nameExact("getSettings")
                .where(
                  _.inCall
                      .nameExact("setJavaScriptEnabled")
                      .argument
                      .isLiteral
                      .codeExact("true")
                )
          )

  def loadUrlCalls: Iterator[Call] =
      traversal.referencingIdentifiers.inCall.nameExact("loadUrl")

  def addJavascriptInterfaceCalls(): Iterator[Call] =
      traversal.referencingIdentifiers.inCall.nameExact("addJavascriptInterface")
end LocalTraversal
