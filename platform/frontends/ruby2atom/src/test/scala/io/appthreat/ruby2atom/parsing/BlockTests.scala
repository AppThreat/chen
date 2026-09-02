package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** `itblock` and `numblock` lowering (plan 04 §3). Both used to drop the call and the body: the
  * numblock collapsed to a bare identifier and the itblock was unknown outright.
  */
class BlockTests extends RubyCode2CpgFixture:

  "a Ruby 3.4 `it` block lowers to a call with a block and a synthetic `it` parameter" in {
    val cpg = fixtureWithoutUnknowns("it_block")

    // `evens = items.select { it.even? }`
    cpg.assignment.code.l should contain("evens = items.select { it.even? }")
    cpg.call.nameExact("select").l should not be empty
    // `it.even?` is a zero-arg member access on the `it` reference
    cpg.fieldAccess.code.l should contain("it.even?")
    // body references to `it` resolve to identifiers
    cpg.identifier.name.l should contain("it")

    // `items.each do puts it * 10 end`
    cpg.call.nameExact("each").l should not be empty
    cpg.call.nameExact("puts").l should not be empty
    cpg.call.nameExact(Operators.multiplication).l should not be empty
  }

  "a numbered-parameter block keeps its call and synthesizes _1.._n parameters" in {
    val cpg = fixtureWithoutUnknowns("numblock")

    // `sums = pairs.map { _1 + _2 }` - the block lowers to a lambda method with parameters.
    cpg.assignment.code.l should contain("sums = pairs.map { _1 + _2 }")
    cpg.call.nameExact("map").l should not be empty
    cpg.call.nameExact(Operators.addition).l should not be empty
    cpg.parameter.name.l should contain("_1")
    cpg.parameter.name.l should contain("_2")

    // `doubled = [1, 2].map { _1 * 2 }` - single numbered parameter
    cpg.assignment.code.l should contain("doubled = [1, 2].map { _1 * 2 }")
    cpg.call.nameExact(Operators.multiplication).l should not be empty
    cpg.parameter.name.l should contain("_1")
  }
