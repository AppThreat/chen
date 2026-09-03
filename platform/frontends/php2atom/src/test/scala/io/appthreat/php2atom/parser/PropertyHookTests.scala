package io.appthreat.php2atom.parser

import io.appthreat.php2atom.parser.Domain.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import ujson.Value

/** Domain-level decode tests for PHP 8.4 property hooks and asymmetric visibility (task 10.2,
  * Requirement 3.3).
  *
  * These feed representative nikic/php-parser 5.x JSON (the `--json-dump` shape for PHP 8.4
  * `Stmt_Property` with a `hooks` array and set-visibility `flags` bits) straight into
  * [[Domain.fromJson]]. A Domain-level decode test is used deliberately rather than a `source ->
  * cpg` fixture: property hooks require the PHP 8.4 grammar, which the runtime bundled in CI may
  * not be able to parse, so exercising the JSON contract directly keeps the test hermetic while
  * still asserting the exact decoded [[PhpPropertyHook]] / `asymmetricVisibility` shapes landed by
  * task 10.1.
  */
class PropertyHookTests extends AnyWordSpec with Matchers:

  private def attributes(line: Int = 1): ujson.Obj =
      ujson.Obj("startLine" -> line, "startFilePos" -> 0)

  private def identifier(name: String): ujson.Obj =
      ujson.Obj("nodeType" -> "Identifier", "name" -> name, "attributes" -> attributes())

  private def varLikeIdentifier(name: String): ujson.Obj =
      ujson.Obj("nodeType" -> "VarLikeIdentifier", "name" -> name, "attributes" -> attributes())

  private def variable(name: String): ujson.Obj =
      ujson.Obj(
        "nodeType"   -> "Expr_Variable",
        "name"       -> name,
        "attributes" -> attributes()
      )

  private def intLiteral(value: Int): ujson.Obj =
      ujson.Obj("nodeType" -> "Scalar_Int", "value" -> value, "attributes" -> attributes())

  private def name(str: String): ujson.Obj =
      ujson.Obj("nodeType" -> "Name", "parts" -> ujson.Arr(str), "attributes" -> attributes())

  /** A single `PropertyItem` (the `props` element of `Stmt_Property`). */
  private def propItem(name: String): ujson.Obj =
      ujson.Obj(
        "nodeType"   -> "PropertyItem",
        "name"       -> varLikeIdentifier(name),
        "default"    -> ujson.Null,
        "attributes" -> attributes()
      )

  /** A PHP 8.4 `PropertyHook` node. `body` is null (abstract), a single expression node (arrow form
    * `get => expr`), or an array of statements (block form `get { ... }`).
    */
  private def hook(
    name: String,
    body: Value,
    params: ujson.Arr = ujson.Arr(),
    byRef: Boolean = false
  ): ujson.Obj =
      ujson.Obj(
        "nodeType"   -> "PropertyHook",
        "name"       -> identifier(name),
        "params"     -> params,
        "body"       -> body,
        "byRef"      -> byRef,
        "flags"      -> 0,
        "attrGroups" -> ujson.Arr(),
        "attributes" -> attributes()
      )

  private def param(name: String): ujson.Obj =
      ujson.Obj(
        "nodeType"   -> "Param",
        "var"        -> variable(name),
        "type"       -> ujson.Null,
        "byRef"      -> false,
        "variadic"   -> false,
        "default"    -> ujson.Null,
        "flags"      -> 0,
        "attrGroups" -> ujson.Arr(),
        "attributes" -> attributes()
      )

  /** A `Stmt_Property` node with the given flags, optional type, hooks, and a single `$x` prop. */
  private def property(
    flags: Int = 1, // Modifiers::PUBLIC
    typeNode: Value = name("string"),
    hooks: ujson.Arr = ujson.Arr(),
    propName: String = "x"
  ): ujson.Obj =
      ujson.Obj(
        "nodeType"   -> "Stmt_Property",
        "flags"      -> flags,
        "type"       -> typeNode,
        "props"      -> ujson.Arr(propItem(propName)),
        "hooks"      -> hooks,
        "attrGroups" -> ujson.Arr(),
        "attributes" -> attributes()
      )

  /** Decode a single top-level statement and cast it to a [[PhpPropertyStmt]]. */
  private def decodeProperty(stmt: Value): PhpPropertyStmt =
      Domain.fromJson(ujson.Arr(stmt)).children match
        case (prop: PhpPropertyStmt) :: Nil => prop
        case other => fail(s"Expected a single PhpPropertyStmt but got: $other")

  "Property hook decoding" should {

      "decode a block-form get hook (`get { return $this->x; }`) to an explicit PhpPropertyHook" in {
          val getBody = ujson.Arr(
            ujson.Obj(
              "nodeType"   -> "Stmt_Return",
              "expr"       -> intLiteral(1),
              "attributes" -> attributes()
            )
          )
          val prop = decodeProperty(property(hooks = ujson.Arr(hook("get", getBody))))

          prop.hooks match
            case PhpPropertyHook("get", params, Some(body), false, _, _) :: Nil =>
                params shouldBe empty
                body should not be empty
            case other => fail(s"Expected a single block-form get hook but got: $other")
      }

      "decode an arrow-form get hook (`get => $this->x`) with a single-expression body" in {
          val prop =
              decodeProperty(property(hooks = ujson.Arr(hook("get", intLiteral(42)))))

          prop.hooks match
            case PhpPropertyHook("get", _, Some(body), _, _, _) :: Nil =>
                // Arrow form normalises to a single-element statement list holding the expression.
                (body should have).length(1)
                body.head shouldBe a[PhpExpr]
            case other => fail(s"Expected a single arrow-form get hook but got: $other")
      }

      "decode a set hook with an explicit `$value` param" in {
          val setBody = ujson.Arr(
            ujson.Obj(
              "nodeType"   -> "Stmt_Expression",
              "expr"       -> intLiteral(0),
              "attributes" -> attributes()
            )
          )
          val setHook = hook("set", setBody, params = ujson.Arr(param("value")))
          val prop    = decodeProperty(property(hooks = ujson.Arr(setHook)))

          prop.hooks match
            case PhpPropertyHook("set", param :: Nil, Some(body), _, _, _) :: Nil =>
                param.name shouldBe "value"
                body should not be empty
            case other => fail(s"Expected a single set hook with one param but got: $other")
      }

      "decode both get and set hooks on the same property" in {
          val hooks = ujson.Arr(
            hook("get", intLiteral(1)),
            hook("set", ujson.Arr(), params = ujson.Arr(param("value")))
          )
          val prop = decodeProperty(property(hooks = hooks))

          prop.hooks.map(_.name) shouldBe List("get", "set")
      }

      "decode an abstract/interface hook (null body) with no body" in {
          val prop = decodeProperty(property(hooks = ujson.Arr(hook("get", ujson.Null))))

          prop.hooks match
            case PhpPropertyHook("get", _, None, _, _, _) :: Nil => succeed
            case other => fail(s"Expected a single body-less get hook but got: $other")
      }

      "leave `hooks` empty for a plain property with no hooks" in {
          val prop = decodeProperty(property())
          prop.hooks shouldBe empty
      }

      "tolerate a missing `hooks` key (additive contract) and yield an empty list" in {
          val stmt = ujson.Obj(
            "nodeType"   -> "Stmt_Property",
            "flags"      -> 1,
            "type"       -> name("string"),
            "props"      -> ujson.Arr(propItem("x")),
            "attrGroups" -> ujson.Arr(),
            "attributes" -> attributes()
          )
          val prop = decodeProperty(stmt)
          prop.hooks shouldBe empty
      }
  }

  "Asymmetric visibility decoding" should {

      "capture `private(set)` from the PRIVATE_SET flag bit (512)" in {
          // public private(set) string $x  ->  PUBLIC (1) | PRIVATE_SET (512)
          val prop = decodeProperty(property(flags = 1 | 512))
          prop.asymmetricVisibility shouldBe Some("private(set)")
      }

      "capture `protected(set)` from the PROTECTED_SET flag bit (256)" in {
          val prop = decodeProperty(property(flags = 1 | 256))
          prop.asymmetricVisibility shouldBe Some("protected(set)")
      }

      "capture `public(set)` from the PUBLIC_SET flag bit (128)" in {
          val prop = decodeProperty(property(flags = 1 | 128))
          prop.asymmetricVisibility shouldBe Some("public(set)")
      }

      "report no asymmetric visibility when no set-visibility bit is present" in {
          val prop = decodeProperty(property(flags = 1))
          prop.asymmetricVisibility shouldBe None
      }
  }
end PropertyHookTests
