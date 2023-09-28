package io.appthreat.x2cpg.passes.controlflow.cfgdominator

import io.shiftleft.codepropertygraph.generated.nodes.StoredNode

class CpgCfgAdapter extends CfgAdapter[StoredNode] {

  override def successors(node: StoredNode): IterableOnce[StoredNode] =
    node._cfgOut

  override def predecessors(node: StoredNode): IterableOnce[StoredNode] =
    node._cfgIn

}
