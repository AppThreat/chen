package io.appthreat.php2atom.querying

import io.appthreat.php2atom.parser.Domain
import io.appthreat.php2atom.parser.Domain.{PhpFile, PhpMethodDecl}

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import ujson.Value

/** Unit tests for the PHP 8.1-8.3 complex-type decode landed by task 11.1.
  *
  * These exercise `Domain.fromJson` directly with representative nikic php-parser JSON for
  * `UnionType`, `IntersectionType`, `NullableType` and their Disjunctive Normal Form (DNF)
  * combination, without depending on a PHP runtime or the vendored parser being able to emit every
  * 8.x grammar. The decode is where task 11.1's precedence-preserving `renderTypeName` runs, and
  * where Requirement 3.4 ("retain every constituent type ... rather than flattening the
  * constituents to a single type or dropping the construct") is enforced.
  *
  * The rendered type surfaces on the decoded [[Domain.PhpNameExpr]] `.name`, which AstCreator later
  * copies onto the parameter's / method's `typeFullName`.
  *
  * _Requirements: 3.4_
  */
class ComplexTypeTests extends AnyWordSpec with Matchers:

  /** A nikic `Name` node carrying a single class/type identifier. */
  private def name(n: String): String =
      s"""{"nodeType":"Name","name":"$n","attributes":{}}"""

  /** A nikic `IntersectionType` node over the given member type-JSON fragments. */
  private def intersection(members: String*): String =
      s"""{"nodeType":"IntersectionType","types":[${members.mkString(",")}],"attributes":{}}"""

  /** A nikic `UnionType` node over the given member type-JSON fragments. */
  private def union(members: String*): String =
      s"""{"nodeType":"UnionType","types":[${members.mkString(",")}],"attributes":{}}"""

  /** A nikic `NullableType` node wrapping the given member type-JSON fragment. */
  private def nullable(member: String): String =
      s"""{"nodeType":"NullableType","type":$member,"attributes":{}}"""

  /** Wrap a single-parameter/return function around a type fragment so it can be decoded through
    * the public `Domain.fromJson` entry point, then return the decoded method declaration.
    */
  private def decodeFn(paramType: String, returnType: String): PhpMethodDecl =
    val json =
        s"""[
               |  {
               |    "nodeType": "Stmt_Function",
               |    "byRef": false,
               |    "name": {"nodeType": "Identifier", "name": "f", "attributes": {}},
               |    "params": [
               |      {
               |        "nodeType": "Param",
               |        "var": {"nodeType": "Expr_Variable", "name": "p", "attributes": {}},
               |        "type": $paramType,
               |        "byRef": false,
               |        "variadic": false,
               |        "default": null,
               |        "flags": 0,
               |        "attributes": {}
               |      }
               |    ],
               |    "returnType": $returnType,
               |    "stmts": [],
               |    "namespacedName": null,
               |    "attributes": {}
               |  }
               |]""".stripMargin
    val parsed: Value = ujson.read(json)
    val file: PhpFile = Domain.fromJson(parsed)
    file.children.collectFirst { case m: PhpMethodDecl => m }.getOrElse(
      fail("expected a decoded PhpMethodDecl")
    )
  end decodeFn

  /** Convenience: the rendered name of the decoded function's first parameter type. */
  private def paramTypeName(paramType: String): String =
      decodeFn(paramType, "null").params.head.paramType
          .getOrElse(fail("expected a decoded parameter type"))
          .name

  "Complex-type decode (Requirement 3.4)" should {

      "render an intersection type A&B distinctly, retaining both constituents" in {
          paramTypeName(intersection(name("A"), name("B"))) shouldEqual "A&B"
      }

      "render a union type A|B, retaining both constituents" in {
          paramTypeName(union(name("A"), name("B"))) shouldEqual "A|B"
      }

      "render a nullable type ?T" in {
          paramTypeName(nullable(name("T"))) shouldEqual "?T"
      }

      "render a DNF type as (A&B)|C, parenthesising the intersection group" in {
          // The key regression: the intersection group must NOT flatten into the ambiguous
          // "A&B|C" that would lose the DNF precedence between & and |.
          val dnf      = union(intersection(name("A"), name("B")), name("C"))
          val rendered = paramTypeName(dnf)
          rendered shouldEqual "(A&B)|C"
          (rendered should not).equal("A&B|C")
      }

      "retain every constituent of a three-way DNF (A&B)|(C&D)" in {
          val dnf = union(
            intersection(name("A"), name("B")),
            intersection(name("C"), name("D"))
          )
          paramTypeName(dnf) shouldEqual "(A&B)|(C&D)"
      }

      "preserve a nullable intersection distinctly as ?(A&B)" in {
          // A nullable wrapping an intersection keeps both the `?` and the intersection group.
          paramTypeName(nullable(intersection(name("A"), name("B")))) shouldEqual "?A&B"
      }

      "render a union of a nullable and a plain type distinctly" in {
          paramTypeName(union(nullable(name("A")), name("B"))) shouldEqual "?A|B"
      }

      "render complex types on a return type as well as a parameter" in {
          val dnf = union(intersection(name("A"), name("B")), name("C"))
          val fn  = decodeFn("null", dnf)
          fn.returnType.getOrElse(fail("expected a decoded return type")).name shouldEqual "(A&B)|C"
      }

      "decode a plain class type unchanged" in {
          paramTypeName(name("Foo")) shouldEqual "Foo"
      }
  }
end ComplexTypeTests
