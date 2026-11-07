package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.{DataFlowCodeToCpgSuite, DataFlowTestCpg}
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    MemorySemanticsPass,
    ReentrantApiRules,
    ValueOriginPass
}
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

/** MS-INVAL-002: a borrowed item or a size read from a mutable Python container, used after a call
  * that can run Python code. The declarations spell the C API names; the bodies are this rule's own
  * shapes.
  */
class ReentrantApiRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg: DataFlowTestCpg = new DataFlowTestCpg()
      .moreCode(
        """
          |typedef struct pyobj { long refs; } pyobj;
          |typedef struct holder { pyobj *callback; pyobj *items; } holder;
          |extern pyobj *PyObject_CallOneArg(pyobj *callable, pyobj *arg);
          |extern int PyObject_RichCompareBool(pyobj *a, pyobj *b, int op);
          |extern long PyList_GET_SIZE(pyobj *l);
          |extern pyobj *PyList_GET_ITEM(pyobj *l, long i);
          |extern long PyTuple_GET_SIZE(pyobj *t);
          |extern pyobj *PyTuple_GET_ITEM(pyobj *t, long i);
          |extern pyobj *PyList_New(long n);
          |pyobj *PyDict_GetItem(pyobj *d, pyobj *k) {
          |    /* a lookup compares keys, and a key's __eq__ is Python code */
          |    return PyObject_RichCompareBool(d, k, 2) ? d : 0;
          |}
          |extern pyobj *PyUnicode_FromString(const char *s);
          |extern void Py_INCREF(pyobj *o);
          |extern void Py_DECREF(pyobj *o);
          |
          |static pyobj *notify(holder *self, pyobj *arg) {
          |    return PyObject_CallOneArg(self->callback, arg);
          |}
          |
          |pyobj *borrowed_then_compare(pyobj *list, pyobj *x) {
          |    pyobj *item = PyList_GET_ITEM(list, 0);
          |    PyObject_RichCompareBool(x, x, 2);
          |    return item;
          |}
          |
          |pyobj *borrowed_then_helper(holder *self, pyobj *x) {
          |    pyobj *items = self->items;
          |    pyobj *item = PyList_GET_ITEM(items, 0);
          |    notify(self, x);
          |    return item;
          |}
          |
          |pyobj *borrowed_then_decref(pyobj *dict, pyobj *key, pyobj *other) {
          |    pyobj *v = PyDict_GetItem(dict, key);
          |    Py_DECREF(other);
          |    return v;
          |}
          |
          |pyobj *size_then_index(pyobj *list, pyobj *x) {
          |    long n = PyList_GET_SIZE(list);
          |    PyObject_RichCompareBool(x, x, 2);
          |    return PyList_GET_ITEM(list, n - 1);
          |}
          |
          |pyobj *strong_reference_taken(pyobj *list, pyobj *x) {
          |    pyobj *item = PyList_GET_ITEM(list, 0);
          |    Py_INCREF(item);
          |    PyObject_RichCompareBool(item, x, 2);
          |    return item;
          |}
          |
          |pyobj *tuple_is_immutable(pyobj *tup, pyobj *x) {
          |    long n = PyTuple_GET_SIZE(tup);
          |    pyobj *item = PyTuple_GET_ITEM(tup, 0);
          |    PyObject_RichCompareBool(x, x, 2);
          |    return PyTuple_GET_ITEM(tup, n - 1) == item ? item : 0;
          |}
          |
          |pyobj *own_list(pyobj *x) {
          |    pyobj *list = PyList_New(1);
          |    pyobj *item = PyList_GET_ITEM(list, 0);
          |    PyObject_RichCompareBool(x, x, 2);
          |    return item;
          |}
          |
          |pyobj *inert_decref(pyobj *dict, pyobj *key) {
          |    pyobj *name = PyUnicode_FromString("k");
          |    pyobj *v = PyDict_GetItem(dict, key);
          |    Py_DECREF(name);
          |    return v;
          |}
          |
          |long size_not_reused(pyobj *list, pyobj *x) {
          |    long n = PyList_GET_SIZE(list);
          |    PyObject_RichCompareBool(x, x, 2);
          |    return n;
          |}
          |
          |int stale_length_in_loop(pyobj *list) {
          |    long len = PyList_GET_SIZE(list);
          |    for (long i = 0; i < len; i++) {
          |        pyobj *item = PyList_GET_ITEM(list, i);
          |        if (PyObject_RichCompareBool(item, item, 2) < 0) return -1;
          |    }
          |    return 0;
          |}
          |
          |pyobj *reader_is_not_in_between(pyobj *dict, pyobj *key) {
          |    pyobj *v;
          |    if ((v = PyDict_GetItem(dict, key)) == 0) return 0;
          |    return v;
          |}
          |
          |pyobj *reassigned_before_use(pyobj *list, pyobj *x) {
          |    pyobj *item = PyList_GET_ITEM(list, 0);
          |    PyObject_RichCompareBool(x, x, 2);
          |    item = PyList_GET_ITEM(list, 0);
          |    return item;
          |}
          |""".stripMargin,
        "reentrant.c"
      )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  /** The identifiers of `method` that carry an MS-INVAL-002 finding, with its confidence. */
  private def findingsIn(method: String): List[(String, String)] =
      cpg.method
          .nameExact(method)
          .ast
          .isIdentifier
          .l
          .filter(_.tag.name("ms-finding").value.l.contains("MS-INVAL-002"))
          .map { i =>
            val rule = MemorySafetyFindingPass.rules("MS-INVAL-002")
            (i.name, MemorySafetyFindingPass.confidenceOf(i, rule))
          }

  "MS-INVAL-002" should:

    "fire on a borrowed list item used after a rich comparison" in:
      findingsIn("borrowed_then_compare") shouldBe List(("item", "medium"))

    "fire through a defined helper that calls into Python, the list read from a field" in:
      findingsIn("borrowed_then_helper") shouldBe List(("item", "medium"))

    "fire at low when only a reference decrement sits in between" in:
      findingsIn("borrowed_then_decref") shouldBe List(("v", "low"))

    "fire on a size that bounds a later read of the same list" in:
      findingsIn("size_then_index") shouldBe List(("n", "medium"))

    "not fire when a strong reference is taken before the call" in:
      findingsIn("strong_reference_taken") shouldBe empty

    "not fire on tuple reads" in:
      findingsIn("tuple_is_immutable") shouldBe empty

    "not fire on a list the method built and never handed out" in:
      findingsIn("own_list") shouldBe empty

    "not count the decrement of a str the method created" in:
      findingsIn("inert_decref") shouldBe empty

    "not fire on a size that indexes nothing after the call" in:
      findingsIn("size_not_reused") shouldBe empty

    "fire on a length that bounds a loop whose body calls into Python, not on the item it re-reads" in:
      findingsIn("stale_length_in_loop") shouldBe List(("len", "medium"))

    "not treat the reading call itself as the call in between" in:
      findingsIn("reader_is_not_in_between") shouldBe empty

    "not fire when the item is read again after the call" in:
      findingsIn("reassigned_before_use") shouldBe empty

    "tag the re-entrant calls py-reentrant, directly and through the closure" in:
      val tagged = cpg.tag
          .nameExact(ReentrantApiRules.TagReentrant)
          .l
          .flatMap(_._taggedByIn.collectAll[Call])
          .map(_.name)
          .toSet
      tagged should contain("PyObject_RichCompareBool")
      tagged should contain("notify")
      tagged should contain("Py_DECREF")
end ReentrantApiRuleTests
