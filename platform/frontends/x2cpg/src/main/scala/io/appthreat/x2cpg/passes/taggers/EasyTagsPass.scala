package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern

/** Creates tags on any node
  */
class EasyTagsPass(atom: Cpg) extends CpgPass(atom):

    val language: String = atom.metaData.language.head

    override def run(dstGraph: DiffGraphBuilder): Unit =
        atom.method.internal.name(".*(valid|check).*").newTagNode("validation").store()(dstGraph)
        atom.method.internal.name("is[A-Z].*").newTagNode("validation").store()(dstGraph)
        if language == Languages.PYTHON || language == Languages.PYTHONSRC then
            atom.method.internal.name("is_[a-z].*").newTagNode("validation").store()(dstGraph)
        atom.method.internal.name(".*(encode|escape|sanit).*").newTagNode("sanitization").store()(
          dstGraph
        )
        atom.method.internal.name(".*(login|authenti).*").newTagNode("authentication").store()(
          dstGraph
        )
        atom.method.internal.name(".*(authori).*").newTagNode("authorization").store()(dstGraph)
