package io.appthreat.x2cpg;

import io.shiftleft.codepropertygraph.generated.nodes.NewMember;
import scala.collection.immutable.Map;

/**
 * Not public and declares {@code properties} itself, so reflection from another package cannot
 * call it: the position every generated node is in inside a native image.
 */
class UnreflectableMember extends NewMember {
    @Override
    public Map<String, Object> properties() {
        return super.properties();
    }
}
