package io.appthreat.php2atom.passes

import io.appthreat.php2atom.parser.Domain
import io.appthreat.php2atom.parser.Domain.*
import org.scalatest.Inside
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Parser-level unit tests for PHP 8.0+ attribute-group decoding (task 9.1, Requirement 3.2).
  *
  * These exercise `Domain.fromJson` directly against synthesised nikic-shaped JSON so the tests are
  * hermetic (no PHP generator required). They assert that `#[Route(...)]`, `#[\Override]`, and
  * `#[\Deprecated]` decode to explicit `PhpAttributeGroup`/`PhpAttribute` model nodes rather than
  * degrading to the `Nop` catch-all, that names and arguments survive decoding, and that absent
  * `attrGroups` yields an empty list.
  */
class AttributeGroupTests extends AnyWordSpec with Matchers with Inside:

  /** A nikic `Name` node with the given parts. */
  private def nameJson(part: String, fullyQualified: Boolean = false): String =
    val nodeType = if fullyQualified then "Name_FullyQualified" else "Name"
    s"""{"nodeType":"$nodeType","parts":["$part"]}"""

  /** A single `#[Name(args...)]` attribute JSON fragment. */
  private def attributeJson(nameFragment: String, argsJson: String = "[]"): String =
      s"""{"nodeType":"Attribute","name":$nameFragment,"args":$argsJson}"""

  /** An `AttributeGroup` wrapping the given attribute fragments. */
  private def groupJson(attrs: String*): String =
      s"""{"nodeType":"AttributeGroup","attrs":[${attrs.mkString(",")}]}"""

  /** A string-literal `Arg` fragment for attribute arguments. */
  private def stringArgJson(value: String): String =
      s"""{"nodeType":"Arg","value":{"nodeType":"Scalar_String","value":"$value"},"byRef":false,"unpack":false}"""

  /** A `Stmt_Class` node carrying the supplied `attrGroups` JSON array. */
  private def classWithAttrGroups(attrGroupsJson: String): String =
      s"""[{"nodeType":"Stmt_Class","name":{"nodeType":"Identifier","name":"C"},"stmts":[],"flags":0,"attrGroups":$attrGroupsJson}]"""

  private def parse(json: String): PhpFile =
      Domain.fromJson(ujson.read(json))

  private def classStmt(file: PhpFile): PhpClassLikeStmt =
      file.children match
        case (c: PhpClassLikeStmt) :: Nil => c
        case other => fail(s"expected a single PhpClassLikeStmt, got: $other")

  "attribute-group decoding" should {

      "decode a single attribute with a string argument (#[Route(\"/users\")]) to explicit nodes, not Nop" in {
          val json = classWithAttrGroups(
            s"[${groupJson(attributeJson(nameJson("Route"), s"[${stringArgJson("/users")}]"))}]"
          )
          val cls = classStmt(parse(json))

          cls.attributeGroups should have size 1
          val group = cls.attributeGroups.head
          group.attrs should have size 1

          val attr = group.attrs.head
          attr.name.name shouldBe "Route"
          attr.args should have size 1
          inside(attr.args.head) { case PhpArg(PhpString(value, _), _, _, _, _) =>
              value should include("/users")
          }
      }

      "decode a fully-qualified attribute (#[\\Override]) with no arguments to an explicit node" in {
          val json = classWithAttrGroups(
            s"[${groupJson(attributeJson(nameJson("Override", fullyQualified = true)))}]"
          )
          val cls = classStmt(parse(json))

          cls.attributeGroups should have size 1
          val attr = cls.attributeGroups.head.attrs.head
          attr.name.name shouldBe "Override"
          attr.args shouldBe empty
      }

      "decode multiple attributes within a single group (#[\\Override, \\Deprecated])" in {
          val json = classWithAttrGroups(
            s"[${groupJson(
                  attributeJson(nameJson("Override", fullyQualified = true)),
                  attributeJson(nameJson("Deprecated", fullyQualified = true))
                )}]"
          )
          val cls = classStmt(parse(json))

          cls.attributeGroups should have size 1
          cls.attributeGroups.head.attrs.map(_.name.name) shouldBe List("Override", "Deprecated")
      }

      "decode multiple attribute groups on the same declaration" in {
          val json = classWithAttrGroups(
            s"[${groupJson(attributeJson(nameJson("Route"), s"[${stringArgJson("/a")}]"))}," +
                s"${groupJson(attributeJson(nameJson("Deprecated", fullyQualified = true)))}]"
          )
          val cls = classStmt(parse(json))

          cls.attributeGroups should have size 2
          cls.attributeGroups.map(_.attrs.map(_.name.name)) shouldBe List(
            List("Route"),
            List("Deprecated")
          )
      }

      "yield an empty attribute-group list when attrGroups is absent" in {
          val json =
              """[{"nodeType":"Stmt_Class","name":{"nodeType":"Identifier","name":"C"},"stmts":[],"flags":0}]"""
          val cls = classStmt(parse(json))

          cls.attributeGroups shouldBe empty
      }

      "yield an empty attribute-group list when attrGroups is an empty array" in {
          val cls = classStmt(parse(classWithAttrGroups("[]")))
          cls.attributeGroups shouldBe empty
      }

      "decode attributes on a class method to explicit nodes" in {
          val method =
              s"""{"nodeType":"Stmt_ClassMethod","name":{"nodeType":"Identifier","name":"index"},"params":[],"stmts":[],"byRef":false,"returnType":null,"flags":0,"attrGroups":[${groupJson(
                    attributeJson(nameJson("Route"), s"[${stringArgJson("/index")}]")
                  )}]}"""
          val json =
              s"""[{"nodeType":"Stmt_Class","name":{"nodeType":"Identifier","name":"C"},"stmts":[$method],"flags":0}]"""
          val cls = classStmt(parse(json))

          val methodDecl = cls.stmts.collect { case m: PhpMethodDecl => m } match
            case m :: Nil => m
            case other    => fail(s"expected a single PhpMethodDecl, got: $other")

          methodDecl.attributeGroups should have size 1
          methodDecl.attributeGroups.head.attrs.head.name.name shouldBe "Route"
      }

      "decode attributes on a method parameter to explicit nodes" in {
          val param =
              s"""{"nodeType":"Param","var":{"nodeType":"Expr_Variable","name":"id"},"type":null,"byRef":false,"variadic":false,"default":null,"flags":0,"attrGroups":[${groupJson(
                    attributeJson(nameJson("Sensitive", fullyQualified = true))
                  )}]}"""
          val method =
              s"""{"nodeType":"Stmt_ClassMethod","name":{"nodeType":"Identifier","name":"m"},"params":[$param],"stmts":[],"byRef":false,"returnType":null,"flags":0}"""
          val json =
              s"""[{"nodeType":"Stmt_Class","name":{"nodeType":"Identifier","name":"C"},"stmts":[$method],"flags":0}]"""
          val cls = classStmt(parse(json))

          val methodDecl = cls.stmts.collect { case m: PhpMethodDecl => m }.head
          val param0     = methodDecl.params.head
          param0.attributeGroups should have size 1
          param0.attributeGroups.head.attrs.head.name.name shouldBe "Sensitive"
      }

      "decode attributes on a property to explicit nodes" in {
          val prop =
              s"""{"nodeType":"Stmt_Property","flags":0,"type":null,"props":[{"nodeType":"PropertyProperty","name":{"nodeType":"VarLikeIdentifier","name":"x"},"default":null}],"attrGroups":[${groupJson(
                    attributeJson(nameJson("Deprecated", fullyQualified = true))
                  )}]}"""
          val json =
              s"""[{"nodeType":"Stmt_Class","name":{"nodeType":"Identifier","name":"C"},"stmts":[$prop],"flags":0}]"""
          val cls = classStmt(parse(json))

          val property = cls.stmts.collect { case p: PhpPropertyStmt => p }.head
          property.attributeGroups should have size 1
          property.attributeGroups.head.attrs.head.name.name shouldBe "Deprecated"
      }

      "decode attributes on an enum case to explicit nodes" in {
          val enumCase =
              s"""{"nodeType":"Stmt_EnumCase","name":{"nodeType":"Identifier","name":"Active"},"expr":null,"attrGroups":[${groupJson(
                    attributeJson(nameJson("Deprecated", fullyQualified = true))
                  )}]}"""
          val json =
              s"""[{"nodeType":"Stmt_Enum","name":{"nodeType":"Identifier","name":"Status"},"stmts":[$enumCase],"flags":0}]"""
          val cls = classStmt(parse(json))

          val ec = cls.stmts.collect { case e: PhpEnumCaseStmt => e }.head
          ec.attributeGroups should have size 1
          ec.attributeGroups.head.attrs.head.name.name shouldBe "Deprecated"
      }
  }
end AttributeGroupTests
