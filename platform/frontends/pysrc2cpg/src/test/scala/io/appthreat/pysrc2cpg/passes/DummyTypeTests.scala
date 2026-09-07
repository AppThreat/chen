package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.{PySrc2CpgFixture, Py2CpgOnFileSystemConfig}
import io.appthreat.x2cpg.passes.frontend.{XTypeRecovery, XTypeRecoveryConfig}
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Dummy types (`<returnValue>`, `<member>(x)`, `<indexAccess>`) are placeholders the type recovery
  * invents while chaining through calls and members it cannot resolve. They are an internal device
  * of the recovery, not a product of it: nothing in chen or atom matches on them downstream, no
  * `TYPE` node backs them, and no `METHOD` exists at the full names they generate.
  *
  * `XTypeRecoveryConfig.enabledDummyTypes` decides whether they may reach the graph, and it is what
  * `--no-dummy-types` sets. These tests pin the two halves of that contract:
  *
  *   - **enabled** - placeholders are visible, and chaining off them still resolves calls. This is
  *     the fixture default and the configuration the rest of the suite exercises.
  *   - **disabled** - no placeholder reaches a *type-bearing* property of any node, while
  *     name-bearing properties are left alone. This is the configuration atom ships for Python, and
  *     it had no coverage at all until these tests, during which time the flag was inert:
  *     placeholders were reaching ~14% of typed nodes on real packages regardless of it.
  *
  * The suppression is enforced after the fact by [[PythonPseudoTypeSanityPass]] rather than by
  * filtering inside the recovery, because the recovery's own view of the flag is per-iteration
  * (`isFinalIteration && enabled`) and its earlier iterations chain through the placeholders they
  * already wrote. That is not a stylistic preference: filtering at the recovery's write paths was
  * tried first and measurably broke resolution, which is what
  * [[DummyTypesDisabledResolvableChainTests]] now guards against.
  */
object DummyTypeTests:

  /** Shapes that force the recovery into placeholders on every axis it has one, and - crucially -
    * on every write path that persists them.
    *
    * The last two functions are not decoration. A placeholder on an assignment target is filtered
    * by `persistType`, so the obvious `client = external.connect()` shape alone cannot tell a
    * working flag from a broken one. What escaped was a placeholder *returned* from a method:
    * `visitReturns` sets `METHOD_RETURN.dynamicTypeHintFullName` directly, and every later caller
    * of `methodReturnValues` reads it back, which is how a suppressed placeholder still spread to
    * identifiers and calls across a real package. `returned_chain` and `K` reproduce that.
    */
  val code: String =
      """import external
        |import typing
        |
        |def handler(payload: str) -> str:
        |    client = external.connect()
        |    session = client.session
        |    first = session.rows[0]
        |    return first.name
        |
        |def returned_chain(v):
        |    return typing.cast(str, v).strip()
        |
        |class K:
        |    def __init__(self, opts):
        |        self.h = opts.handle
        |        self.n = self.h.name
        |""".stripMargin

  /** A chain that is entirely internal, so the recovery can resolve every link from the CPG without
    * inventing anything. Suppressing placeholders must leave this untouched.
    */
  val resolvableCode: String =
      """class Row:
        |    def label(self):
        |        return "x"
        |
        |class Store:
        |    def __init__(self):
        |        self.row = Row()
        |
        |def use():
        |    store = Store()
        |    return store.row.label()
        |""".stripMargin

  /** Every string any node carries in a *type-bearing* property - the two the sanitizer owns. */
  def allTypeStrings(cpg: io.shiftleft.codepropertygraph.Cpg): List[(String, String, String)] =
      cpg.all.collectAll[StoredNode].flatMap { n =>
        val primary = Option(n.property[String](PropertyNames.TYPE_FULL_NAME, null))
            .map(v => (n.label, PropertyNames.TYPE_FULL_NAME, v))
        val hints = n
            .property[Seq[String]](PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME, Seq.empty)
            .map(v => (n.label, PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME, v))
        primary ++ hints
      }.l

end DummyTypeTests

class DummyTypesEnabledTests extends PySrc2CpgFixture(withOssDataflow = false):

  private lazy val cpg = code(DummyTypeTests.code, "chain.py")

  "the type recovery with dummy types enabled" should:

    "place a placeholder return type on an unresolvable external call" in:
      // The mechanism under test: `external.connect()` is not in the CPG, so its return is
      // named after the call rather than left as ANY.
      val types = cpg.identifier.nameExact("client").flatMap(i =>
          i.typeFullName +: i.dynamicTypeHintFullName
      ).toSet
      withClue(s"types on `client`: [${types.mkString(", ")}]") {
          types.exists(_.contains(XTypeRecovery.DummyReturnType)) shouldBe true
      }

    "chain a member load off a placeholder" in:
      val types = cpg.identifier.nameExact("session").flatMap(i =>
          i.typeFullName +: i.dynamicTypeHintFullName
      ).toSet
      withClue(s"types on `session`: [${types.mkString(", ")}]") {
          types.exists(XTypeRecovery.isDummyType) shouldBe true
      }
end DummyTypesEnabledTests

class DummyTypesDisabledTests
    extends PySrc2CpgFixture(
      withOssDataflow = false,
      typeRecoveryConfig = PySrc2CpgFixture.shippedTypeRecoveryConfig
    ):

  private lazy val cpg = code(DummyTypeTests.code, "chain.py")

  "the type recovery with dummy types disabled" should:

    "leave no placeholder in any type-bearing property of any node" in:
      // The contract, in one assertion. It covers every property the leak reached on real
      // packages: IDENTIFIER/LOCAL/MEMBER/METHOD_RETURN `typeFullName` and the
      // `dynamicTypeHintFullName` they are merged from.
      val leaks = DummyTypeTests.allTypeStrings(cpg)
          .filter { case (_, _, v) => XTypeRecovery.isDummyType(v) }
      withClue(
        s"placeholders reached a type field despite enabledDummyTypes = false: " +
            s"${leaks.map { case (l, p, v) => s"$l.$p=$v" }.distinct.take(12).mkString("; ")}"
      ) {
          leaks shouldBe empty
      }

    "leave the unresolvable variable untyped rather than named after its call" in:
      // The near-miss: suppressing a placeholder must yield ANY, not some other invented
      // string.
      cpg.identifier.nameExact("client").typeFullName.toSet shouldBe Set("ANY")

    "still type what is genuinely knowable" in:
      // Suppression must cost no real facts. The import alias and the parameter/return
      // annotations come from sources the flag has no business touching.
      cpg.identifier.nameExact("external").typeFullName.toSet shouldBe Set(
        "external"
      )
      cpg.method.nameExact("handler").parameter.nameExact("payload").typeFullName.l shouldBe
          List("__builtin.str")
      cpg.method.nameExact("handler").methodReturn.typeFullName.l shouldBe List("__builtin.str")

    "not touch the METHOD_FULL_NAME of an operator call, which is a name and not a type" in:
      // Guards the sanitizer's scope from the obvious over-reach. `<operator>.fieldAccess` is
      // the correct `methodFullName` of a field-access call; a pass that cleaned name-bearing
      // properties the way it cleans type-bearing ones would corrupt every operator call in
      // the graph. Placeholder names are out of scope for the same reason - see the pass
      // documentation - and are exercised on real packages, where the call linker does mint
      // stubs from them.
      cpg.call.name("<operator>.fieldAccess").methodFullName.toSet shouldBe Set(
        "<operator>.fieldAccess"
      )
end DummyTypesDisabledTests

class DummyTypesDisabledResolvableChainTests
    extends PySrc2CpgFixture(
      withOssDataflow = false,
      typeRecoveryConfig = PySrc2CpgFixture.shippedTypeRecoveryConfig
    ):

  private lazy val cpg = code(DummyTypeTests.resolvableCode, "store.py")

  "suppressing placeholders" should:

    "cost nothing on a chain the recovery can resolve for real" in:
      // The load-bearing near-miss: placeholders exist to carry chains, so their removal has to
      // be shown NOT to break a chain that never needed them. `store.row.label()` resolves
      // link by link out of the CPG itself.
      cpg.identifier.nameExact("store").typeFullName.toSet should contain(
        "store.Store"
      )
      val labelCall = cpg.call.nameExact("label").methodFullName.l
      withClue(s"methodFullName of the chained `label()` call: [${labelCall.mkString(", ")}]") {
          labelCall should contain("store.Row.label")
      }

    "resolve that chained call to the real method, not a stub" in:
      cpg.call.nameExact("label").callee(using NoResolve).fullName.l should contain(
        "store.Row.label"
      )
end DummyTypesDisabledResolvableChainTests

class DummyTypeConfigTests extends PySrc2CpgFixture(withOssDataflow = false):

  "XTypeRecovery.configFor" should:

    "carry both knobs of the frontend config, not just the dummy-type one" in:
      // `--no-dummy-types` and `--type-prop-iterations` are only live if the recovery pass is
      // built from the frontend config. Three pipelines each restated it as a literal and
      // dropped one or both knobs; this pins the translation they now share.
      val config = new Py2CpgOnFileSystemConfig()
          .withDisableDummyTypes(true)
          .withTypePropagationIterations(3)
      XTypeRecovery.configFor(config) shouldBe
          XTypeRecoveryConfig(iterations = 3, enabledDummyTypes = false)

    "treat dummy types as enabled when the frontend does not disable them" in:
      val config = new Py2CpgOnFileSystemConfig().withTypePropagationIterations(2)
      XTypeRecovery.configFor(config) shouldBe
          XTypeRecoveryConfig(iterations = 2, enabledDummyTypes = true)

  "XTypeRecovery.isDummyType" should:

    "recognise each placeholder form the recovery generates" in:
      XTypeRecovery.isDummyType("mod.connect.<returnValue>") shouldBe true
      XTypeRecovery.isDummyType("mod.Cls.<member>(session)") shouldBe true
      XTypeRecovery.isDummyType("mod.rows.<indexAccess>") shouldBe true

    "not mistake a real type for a placeholder" in:
      // `<module>` and `<meta>` are ordinary parts of a Python full name, and an operator name
      // is a different defect with a different owner (PythonPseudoTypeSanityPass).
      XTypeRecovery.isDummyType("flask.Flask") shouldBe false
      XTypeRecovery.isDummyType("__builtin.property<meta>") shouldBe false
      XTypeRecovery.isDummyType("__builtin.dict[__builtin.str, __builtin.int]") shouldBe false
      XTypeRecovery.isDummyType("<operator>.indexAccess") shouldBe false
end DummyTypeConfigTests
