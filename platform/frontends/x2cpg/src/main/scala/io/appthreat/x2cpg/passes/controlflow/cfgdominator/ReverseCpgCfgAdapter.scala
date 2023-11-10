package io.appthreat.x2cpg.passes.controlflow.cfgdominator

import io.shiftleft.codepropertygraph.generated.nodes.StoredNode

class ReverseCpgCfgAdapter extends CfgAdapter[StoredNode]:

    override def successors(node: StoredNode): IterableOnce[StoredNode] =
        node._cfgIn

    override def predecessors(node: StoredNode): IterableOnce[StoredNode] =
        node._cfgOut
