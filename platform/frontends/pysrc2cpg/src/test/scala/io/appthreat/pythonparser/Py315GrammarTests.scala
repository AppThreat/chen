package io.appthreat.pythonparser

import io.appthreat.pythonparser.ast.*
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

/** Python 3.15 syntax, plus the pre-3.15 grammar gaps found by diffing chen against CPython 3.15's
  * own `ast.parse` over Lib/ and Tools/ of the v3.15.0 tag and over the real-world corpus.
  *
  * Oracle for every expectation here: CPython 3.15.0 (`python3.15 --version`), ground truth taken
  * from `ast.dump(ast.parse(src))`; the expected shape is quoted next to each probe. Every probe
  * asserts AST SHAPE (printer output or the node structure), not just the absence of an error.
  */
class Py315GrammarTests extends AnyFreeSpec with Matchers:

  private def parseModule(code: String): Module =
    val parser = new PyParser()
    val module = parser.parse(code).asInstanceOf[Module]
    parser.errors shouldBe empty
    module

  private def print(code: String): String =
      new AstPrinter("  ").print(parseModule(code))

  private def firstStmt(code: String): istmt = parseModule(code).stmts.head

  private def valueOf(code: String): iexpr =
      firstStmt(code) match
        case Assign(_, value, _, _) => value
        case Expr(value, _)         => value
        case other                  => fail(s"not an assignment or expression: $other")

  private def errorsOf(code: String): Iterable[ErrorStatement] =
    val parser = new PyParser()
    parser.parse(code)
    parser.errors

  /** A format spec as its parts: literal text, or a nested field's value printed in braces. */
  private def specParts(spec: Option[JoinedString]): Seq[String] =
      spec.toSeq.flatMap(_.values).map {
          case Constant(JoinedStringConstant(text), _) => text
          case FormattedValue(value, _, _, _, _) => "{" + new AstPrinter("  ").print(value) + "}"
          case other                             => fail(s"unexpected spec part: $other")
      }

  private def onlyField(code: String): FormattedValue =
      valueOf(code) match
        case JoinedString(values, _, _, _) =>
            values.collect { case f: FormattedValue => f }.toSeq match
              case Seq(field) => field
              case other      => fail(s"expected one replacement field: $other")
        case other => fail(s"not an f-string: $other")

  "PEP 810 lazy imports keep their flag" - {

      "lazy import" in {
          // Import(names=[alias(name='a.b', asname='c'), alias(name='d')], is_lazy=1)
          firstStmt("lazy import a.b as c, d\n") match
            case Import(names, isLazy, _) =>
                isLazy shouldBe true
                names.map(a => (a.name, a.asName)) shouldBe Seq(("a.b", Some("c")), ("d", None))
            case other => fail(s"not an Import: $other")
          print("lazy import json\n") shouldBe "lazy import json"
      }

      "lazy from, absolute and relative" in {
          // ImportFrom(module='os', names=[alias(name='path')], level=0, is_lazy=1)
          firstStmt("lazy from os import path\n") match
            case ImportFrom(module, _, level, isLazy, _) =>
                (module, level, isLazy) shouldBe (Some("os"), 0, true)
            case other => fail(s"not an ImportFrom: $other")
          // ImportFrom(names=[alias(name='x'), alias(name='y')], level=2, is_lazy=1)
          firstStmt("lazy from .. import (x, y)\n") match
            case ImportFrom(module, names, level, isLazy, _) =>
                (module, level, isLazy) shouldBe (None, 2, true)
                names.map(_.name) shouldBe Seq("x", "y")
            case other => fail(s"not an ImportFrom: $other")
          print("lazy from . import x\n") shouldBe "lazy from . import x"
      }

      "plain imports are not lazy" in {
          // Import(names=[alias(name='os')], is_lazy=0)
          firstStmt("import os\n").asInstanceOf[Import].is_lazy shouldBe false
          firstStmt("from os import path\n").asInstanceOf[ImportFrom].is_lazy shouldBe false
      }

      "the statement starts at the lazy keyword" in {
          // CPython: Import(lineno=1, col_offset=0) - the span begins at `lazy`, not at `import`
          val lazyStmt  = firstStmt("lazy import json\n").asInstanceOf[Import]
          val plainStmt = firstStmt("import json\n").asInstanceOf[Import]
          (lazyStmt.lineno, lazyStmt.col_offset) shouldBe (plainStmt.lineno, plainStmt.col_offset)
          lazyStmt.end_col_offset shouldBe plainStmt.end_col_offset + "lazy ".length
      }

      "lazy imports in every position ast.parse accepts them" in {
          // compile() rejects these ("lazy import not allowed inside functions", "... inside
          // try/except blocks", "lazy from ... import * is not allowed"); ast.parse does not.
          print("def f():\n    lazy import json\n") should include("lazy import json")
          print("try:\n    lazy import json\nexcept E:\n    pass\n") should include(
            "lazy import json"
          )
          print("lazy from os import *\n") shouldBe "lazy from os import *"
          print("lazy import a; lazy from b import c\n") shouldBe
              "lazy import a\nlazy from b import c"
      }

      "lazy is an identifier everywhere else" in {
          print("lazy = 1\nlazy.x = lazy(lazy)\n") shouldBe "lazy = 1\nlazy.x = lazy(lazy)"
          parseModule("def lazy(lazy=None): return lazy\n")
          parseModule("import lazy\nfrom lazy import lazy\nlazy import lazy\n")
          parseModule("class Lazy:\n    lazy = 1\n")
          parseModule("match lazy:\n    case lazy:\n        pass\n")
      }
  }

  "PEP 798 unpacking in comprehensions" - {

      "list, set and generator elements are Starred" in {
          // ListComp(elt=Starred(value=Name(id='L')), ...)
          valueOf("r = [*L for L in ls]") match
            case ListComp(Starred(Name("L", _), _), _, _) =>
            case other                                    => fail(s"unexpected: $other")
          valueOf("r = {*s for s in ss}") match
            case SetComp(Starred(Name("s", _), _), _, _) =>
            case other                                   => fail(s"unexpected: $other")
          valueOf("r = (*L for L in ls)") match
            case GeneratorExp(Starred(Name("L", _), _), _, _) =>
            case other                                        => fail(s"unexpected: $other")
      }

      "a dict-unpacking comprehension has no value" in {
          // DictComp(key=Name(id='d'), generators=[...])  - value is None
          valueOf("r = {**d for d in ds if d}") match
            case DictComp(Name("d", _), None, generators, _) =>
                generators.head.ifs should have size 1
            case other => fail(s"unexpected: $other")
          print("r = {**d for d in ds}") shouldBe "r = {**d for d in ds}"
          // a key: value comprehension keeps its value
          valueOf("r = {k: v for k, v in kvs}").asInstanceOf[DictComp].value shouldBe defined
      }

      "a starred generator expression as the sole call argument" in {
          // Call(func=Name(id='f'), args=[GeneratorExp(elt=Starred(value=Name(id='L')), ...)])
          valueOf("r = f(*L for L in ls)") match
            case Call(Name("f", _), args, keywords, _) =>
                keywords shouldBe empty
                args.toSeq match
                  case Seq(GeneratorExp(Starred(Name("L", _), _), _, _)) =>
                  case other => fail(s"unexpected args: $other")
            case other => fail(s"unexpected: $other")
          // an ordinary starred argument is unchanged
          valueOf("r = f(*a, *b)") match
            case Call(_, args, _, _) => args.forall(_.isInstanceOf[Starred]) shouldBe true
            case other               => fail(s"unexpected: $other")
      }

      "async comprehensions" in {
          print("async def f():\n    return [*a async for a in g()]\n") should include(
            "[*a async for a in g()]"
          )
          parseModule("async def f():\n    return {**a async for a in g()}\n")
      }
  }

  "unary plus in match literal patterns (3.15)" - {

      "signed numbers, complex literals and mapping keys" in {
          // MatchValue(value=UnaryOp(op=UAdd(), operand=Constant(value=1)))
          val out = print(
            "match x:\n    case +1:\n        pass\n    case +1.5 - 2j:\n        pass\n" +
                "    case {+1: y}:\n        pass\n    case +1 | -1:\n        pass\n"
          )
          out should include("case +1:")
          out should include("case +1.5 - 2j:")
          out should include("case {+1: y}:")
          out should include("case +1 | -1:")
      }

      "the pattern is a MatchValue over UnaryOp(UAdd)" in {
          firstStmt("match x:\n    case +1:\n        pass\n") match
            case Match(_, cases, _) =>
                cases.head.pattern match
                  case MatchValue(UnaryOp(UAdd, Constant(IntConstant("1"), _), _), _) =>
                  case other => fail(s"unexpected pattern: $other")
            case other => fail(s"not a match: $other")
      }
  }

  "PEP 646 starred forms" - {

      "starred subscripts are tuples" in {
          // Subscript(slice=Tuple(elts=[Starred(value=Name(id='b'))]))
          print("x = a[*b]") shouldBe "x = a[(*b,)]"
          print("x = a[1, *b]") shouldBe "x = a[(1,*b)]"
          print("x = tuple[int, *Ts, str]") shouldBe "x = tuple[(int,*Ts,str)]"
          print("x = a[*b, 1:2]") shouldBe "x = a[(*b,1:2)]"
      }

      "a starred annotation on *args only" in {
          // arg(arg='args', annotation=Starred(value=Name(id='Ts')))
          print("def f(*args: *Ts): pass") should include("def f(*args: *Ts):")
          print("def f(*args: *tuple[int, ...]): pass") should include("*args: *tuple[(int,...)]")
          // any other parameter still rejects a starred annotation, as CPython does
          errorsOf("def f(a: *Ts): pass") should not be empty
      }

      "a starred TypeVarTuple default (PEP 696)" in {
          // TypeVarTuple(name='Ts', default_value=Starred(...))
          print("class C[*Ts = *tuple[int, str]]: pass") should include("[*Ts = *tuple[(int,str)]]")
          print("type A[*Ts = *tuple[int]] = tuple[*Ts]") should include("*Ts = *tuple[int]")
      }
  }

  "named expressions in subscripts and set displays" - {

      "subscripts" in {
          // Subscript(slice=NamedExpr(target=Name(id='b'), value=Constant(value=0)))
          print("x = a[b := 0]") shouldBe "x = a[b := 0]"
          print("x = a[b:=0]") shouldBe "x = a[b := 0]"
          print("x = a[b:=0, c:=1]") shouldBe "x = a[(b := 0,c := 1)]"
          // a real slice keeps working
          print("x = a[b:0]") shouldBe "x = a[b:0]"
      }

      "set displays" in {
          // Set(elts=[NamedExpr(target=Name(id='y'), value=Constant(value=1)), Constant(value=2)])
          print("s = {y := 1, 2}") shouldBe "s = {y := 1, 2}"
          print("s = {y := 1}") shouldBe "s = {y := 1}"
          print("s = {1, y := 2}") shouldBe "s = {1, y := 2}"
          // dict displays and comprehensions are unaffected by the set-element walrus arm
          print("d = {a: 1, **b, c: 2}") shouldBe "d = {a:1, **b, c:2}"
          valueOf("d = {k: (v := 1) for k in ks}") shouldBe a[DictComp]
          // a dict key cannot be a named expression (CPython: "invalid syntax")
          errorsOf("d = {y := 1: 2}") should not be empty
          errorsOf("d = {1: 2, y := 1: 2}") should not be empty
          print("d = {(y := 1): 2}") shouldBe "d = {y := 1:2}"
      }
  }

  "with statements whose first item is a parenthesised expression" - {

      "the parentheses belong to the context expression" in {
          // With(items=[withitem(context_expr=Call(func=Attribute(value=BinOp(...), attr='open')),
          //      optional_vars=Name(id='f'))])
          firstStmt("with (p / 'a').open() as f:\n    pass\n") match
            case With(items, _, _, _) =>
                items should have size 1
                items.head.context_expr match
                  case Call(Attribute(BinOp(_, Div, _, _), "open", _), _, _, _) =>
                  case other => fail(s"unexpected context expression: $other")
                items.head.optional_vars shouldBe defined
            case other => fail(s"not a with: $other")
          parseModule("with (a if c else b) as x:\n    pass\n")
          parseModule("with (open('a')).f() as f, (open('b')).g() as g:\n    pass\n")
          parseModule("async def f(s):\n    async with (s.get('u')).cm() as r:\n        pass\n")
      }

      "parenthesised item lists keep working" in {
          firstStmt("with (open('a') as f, open('b') as g,):\n    pass\n") match
            case With(items, _, _, _) => items should have size 2
            case other                => fail(s"not a with: $other")
          firstStmt("with (open('a'), open('b')):\n    pass\n") match
            case With(items, _, _, _) => items should have size 2
            case other                => fail(s"not a with: $other")
          // `with (a, b) as t:` is ONE item whose context expression is a tuple
          firstStmt("with (a, b) as t:\n    pass\n") match
            case With(items, _, _, _) =>
                items should have size 1
                items.head.context_expr shouldBe a[Tuple]
            case other => fail(s"not a with: $other")
      }
  }

  "except* with whitespace" in {
      // TryStar(handlers=[ExceptHandler(type=Name(id='E'), name='e', ...)])
      print("try:\n    pass\nexcept *E as e:\n    pass\n") should include("except* E as e:")
      print("try:\n    pass\nexcept * E:\n    pass\n") should include("except* E:")
      print("try:\n    pass\nexcept*(A, B):\n    pass\n") should include("except* (A,B):")
      // a plain except clause is not affected
      print("try:\n    pass\nexcept E:\n    pass\n") should include("except E:")
  }

  "sequence patterns with patterns after the star" in {
      val out = print(
        "match x:\n    case [*h, 2]:\n        pass\n    case (*a, b, c):\n        pass\n" +
            "    case [1, *m, 9]:\n        pass\n"
      )
      out should include("case [*h, 2]:")
      out should include("case [1, *m, 9]:")
      // two stars in one sequence are still an error ("multiple starred names in sequence pattern")
      errorsOf("match x:\n    case [*a, *b]:\n        pass\n") should not be empty
  }

  "match statement detection" - {

      "an annotated variable named match is not a match statement" in {
          // AnnAssign(target=Name(id='match'), annotation=BinOp(...), value=Constant(value=None))
          firstStmt("match: str | None = None\n") shouldBe an[AnnAssign]
          firstStmt("match: int\n") shouldBe an[AnnAssign]
          firstStmt("match[x]: int = 1\n") shouldBe an[AnnAssign]
          firstStmt("match = lambda m: m\n") shouldBe an[Assign]
      }

      "match statements are still detected" in {
          firstStmt("match x:\n    case 1:\n        pass\n") shouldBe a[Match]
          firstStmt("match lambda: 1:\n    case _:\n        pass\n") shouldBe a[Match]
          firstStmt("match {1: 2}:\n    case _:\n        pass\n") shouldBe a[Match]
          firstStmt("match x[1:2]:\n    case _:\n        pass\n") shouldBe a[Match]
      }
  }

  "type aliases whose parameters have bounds" in {
      // TypeAlias(type_params=[TypeVar(name='T', bound=Name(id='int'))])
      firstStmt("type X[T: int] = list[T]\n") shouldBe a[TypeAlias]
      firstStmt("type X[T: (int, str) = int] = T\n") shouldBe a[TypeAlias]
      firstStmt("type X[T: [lambda: T for T in (T,)]] = T\n") shouldBe a[TypeAlias]
      // `type` as an annotated name is still an annotation
      firstStmt("type: int = 3\n") shouldBe an[AnnAssign]
  }

  "f-strings" - {

      "a named unicode escape is not a replacement field" in {
          // JoinedStr(values=[Constant(value='Δ')])  - no FormattedValue
          valueOf("x = f'\\N{GREEK CAPITAL LETTER DELTA}'") match
            case JoinedString(values, _, _, _) =>
                values.exists(_.isInstanceOf[FormattedValue]) shouldBe false
            case other => fail(s"unexpected: $other")
          valueOf("x = f'{a}\\N{BULLET}{b}'") match
            case JoinedString(values, _, _, _) =>
                values.count(_.isInstanceOf[FormattedValue]) shouldBe 2
            case other => fail(s"unexpected: $other")
          valueOf("x = t'\\N{BULLET} {a}'") match
            case TemplateStr(values, _, _, _) =>
                values.count(_.isInstanceOf[Interpolation]) shouldBe 1
            case other => fail(s"unexpected: $other")
      }

      "in a raw f-string \\N is text and {...} is a replacement field" in {
          // rf'\N{x}' -> JoinedStr(values=[Constant(value='\\N'), FormattedValue(value=Name(id='x'))])
          valueOf("x = rf'\\N{v}'") match
            case JoinedString(values, _, _, _) =>
                values.collect { case FormattedValue(Name(id, _), _, _, _, _) => id } shouldBe
                    Seq("v")
            case other => fail(s"unexpected: $other")
      }

      "':=' at the top of a field is a format spec, not a walrus" in {
          // FormattedValue(value=Name(id='x'), format_spec=JoinedStr([Constant(value='=10')]))
          onlyField("y = f'{x:=10}'") match
            case field @ FormattedValue(Name("x", _), -1, _, false, _) =>
                specParts(field.format_spec) shouldBe Seq("=10")
            case other => fail(s"unexpected: $other")
          onlyField("y = f'{x!r:=^10}'") match
            case field @ FormattedValue(_, 114, _, _, _) =>
                specParts(field.format_spec) shouldBe Seq("=^10")
            case other => fail(s"unexpected: $other")
          // a parenthesised walrus is still a walrus
          valueOf("y = f'{(x := 10)}'") match
            case JoinedString(values, _, _, _) =>
                values.head.asInstanceOf[FormattedValue].value shouldBe a[NamedExpr]
            case other => fail(s"unexpected: $other")
      }

      "braces inside string literals of a nested format-spec field" in {
          // f'{2:{"{"}>10}' used to make the lexer run to the end of the file (a fatal error)
          print("x = f'{2:{\"{\"}>10}'\ny = 1\n") should include("y = 1")
          print("x = f'{v:{\"}\"}}'\ny = 1\n") should include("y = 1")
          // format_spec=JoinedStr([FormattedValue(Constant('{')), Constant('>10')])
          specParts(onlyField("x = f'{2:{\"{\"}>10}'").format_spec) shouldBe Seq("{\"{\"}", ">10")
      }

      "format specs are JoinedStrings with their nested replacement fields parsed" in {
          // f'{x:>{w}.{p}f}' -> format_spec=JoinedStr([Constant('>'), FormattedValue(Name('w')),
          //                                           Constant('.'), FormattedValue(Name('p')), Constant('f')])
          specParts(onlyField("s = f'{x:>{w}.{p}f}'").format_spec) shouldBe
              Seq(">", "{w}", ".", "{p}", "f")
          specParts(onlyField("s = f'{x:{w}{p}}'").format_spec) shouldBe Seq("{w}", "{p}")
          specParts(onlyField("s = f'{x:{w}:{p}}'").format_spec) shouldBe Seq("{w}", ":", "{p}")
          specParts(onlyField("s = f'{x:{a + b}x}'").format_spec) shouldBe Seq("{a + b}", "x")
          // an empty spec is an empty JoinedStr; a literal spec keeps its text, colons included
          onlyField("s = f'{x:}'").format_spec.map(_.values.size) shouldBe Some(0)
          specParts(onlyField("s = f'{x:%H:%M}'").format_spec) shouldBe Seq("%H:%M")
          // subscripts and slices inside a nested field
          specParts(onlyField("s = f\"{d['k']:{width}}\"").format_spec) shouldBe Seq("{width}")
          specParts(onlyField("s = f'{x:{d[1:2]}}'").format_spec) shouldBe Seq("{d[1:2]}")
          // the text and fields after a nested spec are lexed normally again
          print("s = f'{x:{w}} and {y!r}'\nt = 2\n") shouldBe "s = f'{x:{w}} and {y!r}'\nt = 2"
      }

      "nested fields keep their own conversion, debug '=' and spec" in {
          // f'{x:{y:>3}}' -> FormattedValue(Name('y'), format_spec=JoinedStr([Constant('>3')]))
          onlyField("s = f'{x:{y:>3}}'").format_spec.get.values.toSeq match
            case Seq(inner: FormattedValue) => specParts(inner.format_spec) shouldBe Seq(">3")
            case other                      => fail(s"unexpected: $other")
          // f'{x:{y:{z}}}' nests twice
          onlyField("s = f'{x:{y:{z}}}'").format_spec.get.values.toSeq match
            case Seq(inner: FormattedValue) => specParts(inner.format_spec) shouldBe Seq("{z}")
            case other                      => fail(s"unexpected: $other")
          onlyField("s = f'{x:{w!r}}'").format_spec.get.values.toSeq match
            case Seq(FormattedValue(Name("w", _), 114, None, false, _)) =>
            case other => fail(s"unexpected: $other")
          onlyField("s = f'{x:{w=}}'").format_spec.get.values.toSeq match
            case Seq(FormattedValue(Name("w", _), _, None, true, _)) =>
            case other                                               => fail(s"unexpected: $other")
          // an f-string inside a nested field
          print("s = f'{x:{f\"{y}\"}}'\n") shouldBe "s = f'{x:{f\"{y}\"}}'"
      }

      "t-string interpolations carry their spec the same way" in {
          // Interpolation(Name('x'), format_spec=JoinedStr([Constant('>'), FormattedValue(Name('w'))]))
          valueOf("s = t'{x:>{w}}'") match
            case TemplateStr(values, _, _, _) =>
                values.toSeq match
                  case Seq(interpolation: Interpolation) =>
                      specParts(interpolation.format_spec) shouldBe Seq(">", "{w}")
                  case other => fail(s"unexpected values: $other")
            case other => fail(s"unexpected: $other")
      }

      "triple-quoted and raw f-strings with nested spec fields" in {
          print("s = f'''{x:{\n w}}'''\n") shouldBe "s = f'''{x:{w}}'''"
          specParts(onlyField("s = rf'{x:{w}\\d}'").format_spec) shouldBe Seq("{w}", "\\d")
      }
  }

  "Unicode 17 identifiers" - {

      "XID_Continue characters inside identifiers" in {
          // combining marks, Indic vowel signs and viramas, the middle dot, non-ASCII digits, ZWNJ
          for name <- Seq(
              "cafe\u0301",
              "\u0928\u092e\u0938\u094d\u0924\u0947",
              "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35",
              "l\u00b7l",
              "x\u0967",
              "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
              "x\u203fy"
            )
          do
            print(s"$name = 1") shouldBe s"${java.text.Normalizer.normalize(name, java.text.Normalizer.Form.NFKC)} = 1"
      }

      "letters added in Unicode 16 and 17" in {
          parseModule("\u1c89\u1c8a = 1\nx\ua7cb = 2\n\u088f_noon = 3\n\u0c5c = 4\n")
      }

      "identifiers are NFKC-normalised like CPython's" in {
          // ast.parse('ﬁle = 1').body[0].targets[0].id == 'file'
          print("\ufb01le = 1") shouldBe "file = 1"
          print("\uff58 = \uff58 + 1") shouldBe "x = x + 1"
      }

      "supplementary-plane identifiers" in {
          // ast.parse(<U+1D431 MATHEMATICAL BOLD SMALL X> + ' = 1').body[0].targets[0].id == 'x'
          print("\ud835\udc31 = 1\nprint(x)\n") shouldBe "x = 1\nprint(x)"
          // Fraktur f, o, o (U+1D523, U+1D52C) fold to foo; U+1D7D9 DOUBLE-STRUCK DIGIT ONE continues
          print("\ud835\udd23\ud835\udd2c\ud835\udd2c = x\ud835\udfd9\n") shouldBe "foo = x1"
          // CJK Unified Ideographs Extension B (U+20000, U+20001) have no NFKC decomposition
          print("class \ud840\udc00:\n    \ud840\udc01 = 2\n") should include("\ud840\udc01 = 2")
          // an emoji is not an identifier character: only its statement is lost
          errorsOf("a = 1\n\ud83d\ude00 = 2\nc = 3\n") should have size 1
      }
  }

  "lexer robustness" - {

      "form feed is whitespace" in {
          print("x = 1\n\f\ndef f():\n    return 1\n") should include("def f():")
          print("\fy = 2\n") shouldBe "y = 2"
          print("z =\f3\n") shouldBe "z = 3"
      }

      "tabs advance to the next multiple of eight" in {
          // three tab-indented levels: `indent / 8 + 8` put the second and third at column 9
          val out =
              print("def f(v):\n\tif v:\n\t\tif v > 1:\n\t\t\treturn 3\n\t\treturn 2\n\treturn 0\n")
          out should include("return 3")
          out should include("return 2")
      }

      "a character no token starts with loses its statement, not the file" in {
          // used to be a TokenMgrError that escaped error recovery and dropped the whole file
          val parser = new PyParser()
          val module = parser.parse("a = 1\nb = $\nc = 3\n").asInstanceOf[Module]
          parser.errors should have size 1
          new AstPrinter("  ").print(module) should include("c = 3")
      }
  }

  "a bound except clause takes one expression" in {
      // CPython 3.14 and 3.15: "multiple exception types must be parenthesized when using 'as'"
      errorsOf("try:\n    pass\nexcept A, B as e:\n    pass\n") should not be empty
      errorsOf("try:\n    pass\nexcept* A, B as e:\n    pass\n") should not be empty
      errorsOf("try:\n    pass\nexcept A, as e:\n    pass\n") should not be empty
      // the parenthesised tuple, a conditional and the unbound PEP 758 tuple are all fine
      print("try:\n    pass\nexcept (A, B) as e:\n    pass\n") should include("as e")
      print("try:\n    pass\nexcept A if c else B as e:\n    pass\n") should include("as e")
      print("try:\n    pass\nexcept* A as e:\n    pass\n") should include("as e")
      print("try:\n    pass\nexcept A, B:\n    pass\n") should include("except (A,B):")
  }
end Py315GrammarTests
