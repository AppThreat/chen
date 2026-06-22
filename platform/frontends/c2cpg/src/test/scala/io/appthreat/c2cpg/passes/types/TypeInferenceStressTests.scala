package io.appthreat.c2cpg.passes.types

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** Stress / evaluation suite for C++ type inference (`cleanType`, `typeFor`,
  * `typeForDeclSpecifier` in `AstCreatorHelper`, and the downstream type passes).
  *
  * The goal is to exercise the corners that show up as low-quality `ANY` / malformed type names in
  * real-world slices (evaluated against abseil-cpp). Each block documents the *expected* behaviour.
  * Tests tagged with `BUG:` in their name encode behaviour that is currently believed to be wrong -
  * they are written to assert the correct result so they fail until the underlying defect is fixed.
  */
class TypeInferenceStressTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  /** CDT's `ASTTypeUtil` canonicalises some multi-word builtin types into a different word order
    * than the source spelling (e.g. `unsigned long` is rendered `long unsigned`, while `unsigned
    * int` is kept). The property we care about is that the individual keywords are preserved and
    * never merged together (the `unsigned longint` defect), regardless of order. This compares the
    * space-separated tokens as a multiset.
    */
  private def sameWords(actual: String, expected: String): Unit =
      actual.split(" ").sorted.toList shouldBe expected.split(" ").sorted.toList

  "Builtin scalar types" should {

      "preserve plain fundamental types on locals" in {
          val cpg = code("""
          |void f() {
          |  int a;
          |  double b;
          |  char c;
          |  bool d;
          |}
          |""".stripMargin)
          cpg.local.name("a").typeFullName.head shouldBe "int"
          cpg.local.name("b").typeFullName.head shouldBe "double"
          cpg.local.name("c").typeFullName.head shouldBe "char"
          cpg.local.name("d").typeFullName.head shouldBe "bool"
      }

      // BUG: cleanType's `case t.startsWith("unsigned ") => "unsigned " + rest.replace(" ", "")`
      // collapses *all* inner whitespace, turning multi-word integer types into invalid names
      // (e.g. "unsigned long int" -> "unsigned longint", "unsigned long long" -> "unsigned
      // longlong"). The space-stripping was meant only to tighten pointers ("unsigned int *").
      "BUG: keep spaces in multi-word unsigned integer types" in {
          val cpg = code("""
          |void f() {
          |  unsigned long a;
          |  unsigned long int b;
          |  unsigned long long c;
          |  unsigned long long int d;
          |  unsigned short e;
          |}
          |""".stripMargin)
          sameWords(cpg.local.name("a").typeFullName.head, "unsigned long")
          sameWords(cpg.local.name("b").typeFullName.head, "unsigned long int")
          sameWords(cpg.local.name("c").typeFullName.head, "unsigned long long")
          sameWords(cpg.local.name("d").typeFullName.head, "unsigned long long int")
          sameWords(cpg.local.name("e").typeFullName.head, "unsigned short")
      }

      "keep spaces in signed multi-word integer types" in {
          val cpg = code("""
          |void f() {
          |  long long a;
          |  long double b;
          |  long int c;
          |}
          |""".stripMargin)
          cpg.local.name("a").typeFullName.head shouldBe "long long"
          cpg.local.name("b").typeFullName.head shouldBe "long double"
          cpg.local.name("c").typeFullName.head shouldBe "long int"
      }

      "tighten pointer spacing without merging type words" in {
          val cpg = code("""
          |void f() {
          |  unsigned int *a;
          |  unsigned long *b;
          |  const char *c;
          |}
          |""".stripMargin)
          // pointer star is tightened to the type without merging the builtin keywords; word
          // order follows CDT's canonical spelling (see `sameWords`).
          val at = cpg.local.name("a").typeFullName.head
          at should endWith("*")
          sameWords(at.dropRight(1), "unsigned int")
          val bt = cpg.local.name("b").typeFullName.head
          bt should endWith("*")
          sameWords(bt.dropRight(1), "unsigned long")
          cpg.local.name("c").typeFullName.head shouldBe "char*"
      }
  }

  "Const / pointer / reference qualifiers" should {

      "strip const but retain the underlying type" in {
          val cpg = code("""
          |void f() {
          |  const int a = 1;
          |  const double b = 2.0;
          |}
          |""".stripMargin)
          cpg.local.name("a").typeFullName.head shouldBe "int"
          cpg.local.name("b").typeFullName.head shouldBe "double"
      }

      "represent references to fundamental types" in {
          val cpg = code("""
          |void f(int& r, const int& cr) {
          |}
          |""".stripMargin)
          // references are modelled as the underlying value type (the '&' is dropped)
          cpg.parameter.name("r").typeFullName.head shouldBe "int"
          cpg.parameter.name("cr").typeFullName.head shouldBe "int"
      }

      // BUG (fixed): stripping `const` also dropped the pointer star for qualified
      // expression/return/field types, e.g. "const char *" became "char" instead of "char*".
      "retain the pointer star on const-qualified pointer return types" in {
          val cpg = code("""
          |const char* name();
          |const int* values();
          |""".stripMargin)
          cpg.method.name("name").methodReturn.typeFullName.head shouldBe "char*"
          cpg.method.name("values").methodReturn.typeFullName.head shouldBe "int*"
      }

      "retain the pointer star on const-qualified pointer parameters" in {
          val cpg = code("""
          |void f(const char* s, const int* p) {}
          |""".stripMargin)
          cpg.parameter.name("s").typeFullName.head shouldBe "char*"
          cpg.parameter.name("p").typeFullName.head shouldBe "int*"
      }

      "represent pointers and double pointers" in {
          val cpg = code("""
          |void f() {
          |  int *p;
          |  int **pp;
          |  char *s;
          |}
          |""".stripMargin)
          cpg.local.name("p").typeFullName.head shouldBe "int*"
          cpg.local.name("pp").typeFullName.head shouldBe "int**"
          cpg.local.name("s").typeFullName.head shouldBe "char*"
      }
  }

  "auto deduction" should {

      // BUG/GAP: `auto` is only stripped by cleanType when followed by a space, and even then the
      // resulting type comes back empty -> ANY unless the initializer's deduced type is used. A
      // good frontend resolves `auto x = <expr>` to the static type of <expr>.
      "BUG: deduce auto from a literal initializer" in {
          val cpg = code("""
          |void f() {
          |  auto a = 1;
          |  auto b = 2.0;
          |  auto c = true;
          |  auto d = 'x';
          |}
          |""".stripMargin)
          cpg.local.name("a").typeFullName.head shouldBe "int"
          cpg.local.name("b").typeFullName.head shouldBe "double"
          cpg.local.name("c").typeFullName.head shouldBe "bool"
          cpg.local.name("d").typeFullName.head shouldBe "char"
          // regression guard: the literal 'auto' keyword must never survive as a type name
          cpg.local.typeFullName.toSet should not contain "auto"
      }

      "BUG: deduce auto from a constructor / call initializer" in {
          val cpg = code("""
          |struct Widget { int x; };
          |Widget makeWidget();
          |void f() {
          |  auto w = makeWidget();
          |  auto v = Widget();
          |}
          |""".stripMargin)
          cpg.local.name("w").typeFullName.head shouldBe "Widget"
          cpg.local.name("v").typeFullName.head shouldBe "Widget"
      }
  }

  "decltype" should {
      "resolve decltype of a declared variable" in {
          val cpg = code("""
          |void f() {
          |  int x = 0;
          |  decltype(x) y = x;
          |}
          |""".stripMargin)
          cpg.local.name("y").typeFullName.head shouldBe "int"
      }
  }

  "Templates and STL containers" should {

      "carry template arguments on local declarations" in {
          val cpg = code("""
          |#include <vector>
          |#include <string>
          |void f() {
          |  std::vector<int> v;
          |  std::string s;
          |}
          |""".stripMargin)
          // exact spelling of the qualified template name may vary; assert the essentials
          val vt = cpg.local.name("v").typeFullName.head
          vt should include("vector")
          vt should include("int")
          vt should not be "ANY"
          cpg.local.name("s").typeFullName.head should include("string")
      }

      "handle nested template arguments" in {
          val cpg = code("""
          |#include <vector>
          |#include <map>
          |#include <string>
          |void f() {
          |  std::map<std::string, std::vector<int>> m;
          |}
          |""".stripMargin)
          val mt = cpg.local.name("m").typeFullName.head
          mt should include("map")
          mt should not be "ANY"
      }
  }

  "typedef and using aliases" should {

      "resolve a C-style typedef to its alias name" in {
          val cpg = code("""
          |typedef unsigned int u32;
          |void f() {
          |  u32 a;
          |}
          |""".stripMargin)
          cpg.local.name("a").typeFullName.head shouldBe "u32"
      }

      "resolve a using alias" in {
          val cpg = code("""
          |using Byte = unsigned char;
          |void f() {
          |  Byte a;
          |}
          |""".stripMargin)
          cpg.local.name("a").typeFullName.head shouldBe "Byte"
      }
  }

  "Namespaces and qualified names" should {

      "use '.' as the qualified-name separator (never '::')" in {
          val cpg = code("""
          |namespace outer { namespace inner { struct S { int x; }; } }
          |void f() {
          |  outer::inner::S s;
          |}
          |""".stripMargin)
          val t = cpg.local.name("s").typeFullName.head
          t should not include "::"
          t should include("outer")
          t should include("inner")
          t should include("S")
      }

      // BUG: anonymous namespaces produce an empty path segment, surfacing as doubled separators
      // such as "absl::::Convertible1" / "absl..Convertible1" in real slices.
      "BUG: not emit doubled separators for anonymous-namespace types" in {
          val cpg = code("""
          |namespace { struct Local { int x; }; }
          |void f() {
          |  Local l;
          |}
          |""".stripMargin)
          val t = cpg.local.name("l").typeFullName.head
          t should not include "::"
          t should not include ".."
          t should not include "::::"
      }
  }

  "Member and field access types" should {

      "infer the type of a struct member" in {
          val cpg = code("""
          |struct Point { int x; double y; };
          |void f() {
          |  Point p;
          |  int a = p.x;
          |  double b = p.y;
          |}
          |""".stripMargin)
          cpg.local.name("a").typeFullName.head shouldBe "int"
          cpg.local.name("b").typeFullName.head shouldBe "double"
      }
  }

  "Function return type inference" should {

      "record fundamental and user-defined return types" in {
          val cpg = code("""
          |struct Widget { int x; };
          |int geti();
          |Widget getw();
          |unsigned long getul();
          |""".stripMargin)
          cpg.method.name("geti").methodReturn.typeFullName.head shouldBe "int"
          cpg.method.name("getw").methodReturn.typeFullName.head shouldBe "Widget"
          sameWords(cpg.method.name("getul").methodReturn.typeFullName.head, "unsigned long")
      }
  }

  "No malformed type names anywhere" should {

      // Cross-cutting invariant probes: regardless of exact spelling, type full names should never
      // contain CDT internal artefacts or merged builtin keywords.
      "not contain CDT ProblemType / placeholder artefacts" in {
          val cpg = code("""
          |#include <vector>
          |#include <string>
          |struct A { int x; };
          |void f() {
          |  std::vector<int> v;
          |  std::string s;
          |  unsigned long ul;
          |  long long ll;
          |  A a;
          |  auto z = 1;
          |}
          |""".stripMargin)
          val allTypes = cpg.local.typeFullName.toSet ++ cpg.parameter.typeFullName.toSet
          allTypes.foreach { t =>
              t should not include "ProblemType"
              t should not include "TypeOfDependentExpression"
              t should not include "longint"
              t should not include "longlong "
          }
      }
  }
end TypeInferenceStressTests
