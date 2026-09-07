package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Task 5: annotation-driven typing, container element types, and the guarantee that operator names
  * never surface as types. Alongside each presence assertion live the near-misses: the unannotated
  * variable that must stay untyped, and the heuristic an annotation must override.
  */
class PythonTypeInferenceTests extends PySrc2CpgFixture(withOssDataflow = false):

  private val OPERATOR_PSEUDO_TYPE = "<operator>"

  "annotated parameters" should:
    lazy val cpg = code(
      """
        |def greet(name: str, times: int) -> str:
        |    return name
        |""".stripMargin,
      "ann.py"
    )

    "carry their declared type on the parameter node" in:
      cpg.parameter.nameExact("name").typeFullName.l shouldBe List("__builtin.str")
      cpg.parameter.nameExact("times").typeFullName.l shouldBe List("__builtin.int")

    "reach read-only occurrences of the parameter" in:
      // `name` is only read in the return statement - no assignment shapes it
      cpg.identifier.nameExact("name").typeFullName.toSet should contain("__builtin.str")

    "type the method return from the annotation" in:
      cpg.method.nameExact("greet").methodReturn.typeFullName.l shouldBe List("__builtin.str")

  "annotated assignments" should:
    lazy val cpg = code(
      """
        |CONFIG: dict[str, int] = {}
        |limit: int
        |def run(overrides: dict[str, int]) -> int:
        |    total: int = 0
        |    return total
        |""".stripMargin,
      "annassign.py"
    )

    "type the module-level target and its local" in:
      cpg.identifier.nameExact("CONFIG").typeFullName.toSet should contain(
        "__builtin.dict[__builtin.str, __builtin.int]"
      )
      cpg.local.nameExact("CONFIG").typeFullName.toSet should contain(
        "__builtin.dict[__builtin.str, __builtin.int]"
      )

    "type declaration-only targets" in:
      cpg.identifier.nameExact("limit").typeFullName.toSet should contain("__builtin.int")

    "type function-local targets and their locals" in:
      cpg.identifier.nameExact("total").typeFullName.toSet should contain("__builtin.int")
      cpg.local.nameExact("total").typeFullName.toSet should contain("__builtin.int")

    "keep the annotation when a container literal is assigned (annotation wins over the " +
        "literal heuristic)" in:
          // `CONFIG = {}` must not dilute `dict[str, int]` down to the bare `__builtin.dict`
          cpg.identifier.nameExact("CONFIG").typeFullName.toSet should not contain "__builtin.dict"

  "an annotation disagreeing with the constructor heuristic" should:
    lazy val cpg = code(
      """
        |class Client:
        |    def connect(self): ...
        |def build() -> Client:
        |    label: str = Client()
        |    return label
        |""".stripMargin,
      "annwin.py"
    )

    "keep the declared type on the target" in:
      cpg.identifier.nameExact("label").typeFullName.toSet should contain("__builtin.str")

    "never let the naming convention win" in:
      cpg.identifier.nameExact("label").typeFullName.toSet should not contain (
        "annwin.Client"
      )

  "unannotated, uninferable variables" should:
    lazy val cpg = code(
      """
        |def f(x):
        |    return x
        |""".stripMargin,
      "nearmiss.py"
    )

    "stay untyped rather than being guessed" in:
      cpg.parameter.nameExact("x").typeFullName.l shouldBe List("ANY")

  "annotated varargs, keyword-only and **kwargs parameters" should:
    lazy val cpg = code(
      """
        |def f(*names: str, sep: str, **options: int) -> None: ...
        |""".stripMargin,
      "vararg.py"
    )

    "keep their annotations" in:
      cpg.parameter.nameExact("names").typeFullName.l shouldBe List("__builtin.str")
      cpg.parameter.nameExact("sep").typeFullName.l shouldBe List("__builtin.str")
      cpg.parameter.nameExact("options").typeFullName.l shouldBe List("__builtin.int")

  "annotated self attributes" should:
    lazy val cpg = code(
      """
        |class Service:
        |    def __init__(self):
        |        self.endpoint: str = ""
        |""".stripMargin,
      "field.py"
    )

    "declare the member type" in:
      cpg.typeDecl.nameExact("Service").member.nameExact("endpoint").typeFullName.l shouldBe
          List("__builtin.str")

  "self" should:
    lazy val cpg = code(
      """
        |class Service:
        |    endpoint = "x"
        |    def start(self):
        |        return self.endpoint
        |""".stripMargin,
      "selftype.py"
    )

    "be typed with the enclosing class at read-only occurrences" in:
      cpg.identifier.nameExact("self").typeFullName.toSet should contain(
        "selftype.Service"
      )

  "subscripting annotated containers" should:
    lazy val cpg = code(
      """
        |from typing import Dict, List, Tuple
        |def by_typing(items: list[str], mapping: dict[str, int], pair: tuple[int, str]) -> None:
        |    a = items[0]
        |    b = mapping["key"]
        |    c = pair[0]
        |def by_typing_module(items: List[str], mapping: Dict[str, int]) -> None:
        |    d = items[0]
        |    e = mapping["key"]
        |""".stripMargin,
      "index.py"
    )

    "yield the element type of a list" in:
      cpg.identifier.nameExact("a").typeFullName.toSet should contain("__builtin.str")

    "yield the value type of a dict" in:
      cpg.identifier.nameExact("b").typeFullName.toSet should contain("__builtin.int")
      cpg.identifier.nameExact("b").typeFullName.toSet should not contain "__builtin.str"

    "yield any member of a tuple" in:
      // a tuple index may yield any of its members; the head type plus hints carry the set
      val ts = cpg.identifier.nameExact("c").flatMap(i =>
          i.typeFullName +: i.dynamicTypeHintFullName
      ).toSet
      ts should contain("__builtin.int")
      ts should contain("__builtin.str")

    "accept the typing.List / typing.Dict spellings" in:
      cpg.identifier.nameExact("d").typeFullName.toSet should contain("__builtin.str")
      cpg.identifier.nameExact("e").typeFullName.toSet should contain("__builtin.int")

  "chained subscripting" should:
    // Regression for the `<operator>.indexAccess` TYPE_FULL_NAME leak: `spec["table"][-1]`
    // used to type `ref_name` as `<operator>.indexAccess` (or
    // `<container>.<operator>.indexAccess`).
    lazy val cpg = code(
      """
        |def ref_name(spec: dict[str, list[str]]) -> str:
        |    name = spec["table"][-1]
        |    return name
        |def literal_index() -> str:
        |    y = "a,b,c".split(",")[1]
        |    return y
        |""".stripMargin,
      "chain.py"
    )

    "carry no operator pseudo type on the chained result" in:
      // Exact element typing through chained subscripts on `typing.*` generics remains a
      // dummy-chain (`...<indexAccess>`) - a pre-existing recovery limitation, handed off.
      // What must hold - and what used to be `<operator>.indexAccess` - is that no operator
      // name survives on the node.
      val ts = cpg.identifier.nameExact("name").flatMap(i =>
          i.typeFullName +: i.dynamicTypeHintFullName
      ).toSet
      ts.foreach(t => (t should not).include("<operator>"))

    "never persist an operator name as a type anywhere in the graph" in:
      val allTypes =
          (cpg.identifier.typeFullName ++ cpg.local.typeFullName ++ cpg.member.typeFullName ++
              cpg.parameter.typeFullName ++ cpg.methodReturn.typeFullName ++
              cpg.call.typeFullName).l
      allTypes.filter(_.contains(OPERATOR_PSEUDO_TYPE)) shouldBe empty

    "never leave an operator name in a dynamic type hint either" in:
      // The sanitizer originally selected nodes by their primary TYPE_FULL_NAME only, which
      // misses the shape the recovery actually produces most often: the primary stays ANY
      // and every candidate is parked in the hints, so `<operator>.indexAccess` survived on
      // `dict[...].<operator>.indexAccess` there. `dynamicTypeHintFullName` is not a private
      // scratch field - the type-hint call linker and `atom reachables` both read it.
      val poisoned = cpg.all.collectAll[StoredNode].flatMap { n =>
          n.property[Seq[String]](PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME, Seq.empty)
              .filter(_.contains(OPERATOR_PSEUDO_TYPE))
              .map(t => s"${n.label}: $t")
      }.l
      withClue(s"operator names left in dynamic type hints: ${poisoned.distinct.mkString(", ")}") {
          poisoned shouldBe empty
      }

  "references to builtin names" should:
    lazy val cpg = code(
      """
        |def f(xs):
        |    n = len(xs)
        |    if isinstance(xs, str):
        |        return str(n)
        |    return n
        |""".stripMargin,
      "builtins.py"
    )

    "type a builtin class, which denotes a type" in:
      cpg.identifier.nameExact("str").typeFullName.toSet should contain("__builtin.str")

    "leave a builtin function untyped, because it denotes no type" in:
      // `len` is a callable, not a class: `__builtin.len` is not a type and typing the name
      // with it only deflates the ANY metric with a string no consumer can resolve. The
      // near-miss for the builtin-reference rule.
      val fnTypes =
          (cpg.identifier.nameExact("len", "isinstance").typeFullName ++
              cpg.local.nameExact("len", "isinstance").typeFullName).toSet
      withClue(s"types put on builtin function names: [${fnTypes.mkString(", ")}]") {
          fnTypes.filter(_ != "ANY") shouldBe empty
      }

  "a callee whose body contradicts its return annotation" should:
    lazy val cpg = code(
      """
        |def pick(flag) -> str:
        |    if flag:
        |        return "a"
        |    return 1
        |def use(flag):
        |    v = pick(flag)
        |    return v
        |""".stripMargin,
      "multiret.py"
    )

    "take the declared return type as the call's primary type" in:
      // Propagation must carry the annotation, not the literal the body actually returns.
      // (The pass also stopped choosing that primary type with `Set.head`, which diverges
      // from declaration order once there are five or more candidates - a latent hazard
      // rather than a reachable one, since the recovery records no return candidates
      // alongside an annotation.)
      cpg.call.nameExact("pick").typeFullName.toSet shouldBe Set("__builtin.str")
      cpg.identifier.nameExact("v").typeFullName.toSet should contain("__builtin.str")

  "internal call sites" should:
    lazy val cpg = code(
      """
        |def helper() -> str:
        |    return "x"
        |class Service:
        |    def make(self) -> int:
        |        return 1
        |def use() -> None:
        |    a = helper()
        |    s = Service()
        |    b = s.make()
        |""".stripMargin,
      "ret.py"
    )

    "receive the callee's return type" in:
      cpg.identifier.nameExact("a").typeFullName.toSet should contain("__builtin.str")
      cpg.identifier.nameExact("b").typeFullName.toSet should contain("__builtin.int")

  "recursively defined functions" should:
    lazy val cpg = code(
      """
        |def even(n: int) -> bool:
        |    return odd(n - 1)
        |def odd(n: int) -> bool:
        |    return even(n - 1)
        |""".stripMargin,
      "rec.py"
    )

    "not prevent return-type propagation" in:
      cpg.method.nameExact("even").methodReturn.typeFullName.l shouldBe List("__builtin.bool")
      cpg.method.nameExact("odd").methodReturn.typeFullName.l shouldBe List("__builtin.bool")

  "imported module aliases" should:
    lazy val cpg = code(
      """
        |import json
        |def load(data: str):
        |    return json.loads(data)
        |""".stripMargin,
      "alias.py"
    )

    "type the alias identifier where it is read" in:
      cpg.identifier.nameExact("json").typeFullName.toSet should contain("json")
end PythonTypeInferenceTests
