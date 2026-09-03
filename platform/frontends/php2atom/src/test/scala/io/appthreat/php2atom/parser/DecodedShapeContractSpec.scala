package io.appthreat.php2atom.parser

import io.appthreat.php2atom.parser.Domain.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** ==Cross-repo decoded-shape contract guard (Design Decision 4)==
  *
  * This is the CHEN side of the contract-evolution discipline. A companion JSON shape snapshot
  * lives in `atom-parsetools` (the generator side). Together they pin the JSON contract the PHP AST
  * generator (`phpastgen`) emits and the [[Domain]] decoder consumes, so that a BREAKING
  * (non-additive) change — a removed or renamed contract key, or a removed/renamed Domain field —
  * fails CI in BOTH repositories. (Requirements 4.3, 4.4.)
  *
  * ==How this guards the contract (and why it is not a restatement)==
  *
  * The [[Domain]] decoder reads the generator's JSON by STRING LITERAL key names
  * (`"parser_backend"`, `"encoding_scrubbed"`, `"attrGroups"`, `"startFilePos"`, `"ast"`,
  * `"nodeType"`, ...). Those literals are the actual contract surface. This spec pins them two
  * ways:
  *
  *   1. Round-tripping representative JSON that uses the EXACT contract key names, then asserting
  *      the decoded value is populated. If someone renames the key the decoder looks for (or drops
  *      the field it fills), the decoded value goes empty/None and the assertion breaks — even
  *      though the test JSON is unchanged.
  *
  * 2. Reflecting over the [[PhpProvenance]] case class to assert its field names are EXACTLY the
  * expected set. Renaming or removing a provenance field flips this assertion (and, because the
  * field names are referenced structurally, a removal also tends to fail compilation).
  *
  * ==Evolution rule: changes MUST be ADDITIVE==
  *
  * Growing the contract (new optional keys, new node types, new Domain fields with defaults) must
  * NOT break this spec — the additive-tolerance assertions below encode that. If a change to this
  * spec is required to make CI pass, that change is by definition NON-ADDITIVE: stop and treat it
  * as a coordinated breaking change across `chen` and `atom-parsetools` (Decision 4), not a local
  * test fix.
  *
  * Kept hermetic (JSON fed straight into [[Domain.fromJson]], no PHP runtime) to match the sibling
  * specs in this package (`ProvenanceAndFallbackTests`, `PropertyHookTests`, `AttributeGroupTests`,
  * `ContractAdditivityTests`).
  */
class DecodedShapeContractSpec extends AnyWordSpec with Matchers:

  // ---------------------------------------------------------------------------
  // Exact contract key strings the decoder reads. Duplicated here on purpose:
  // these literals are the pinned contract. They must match the string literals
  // in Domain.scala's readers (PhpProvenance.fromWrapper, PhpAttributes.apply,
  // readAttributeGroups, readPropertyHooks, readFile, nodeTypeOf). If the
  // decoder's literal changes, the round-trip below breaks.
  // ---------------------------------------------------------------------------
  private object ContractKeys:
    // Provenance wrapper keys (snake_case, read by PhpProvenance.fromWrapper).
    val ParserBackend    = "parser_backend"
    val GeneratorVersion = "generator_version"
    val PhpVersion       = "php_version"
    val TargetVersion    = "target_version"
    val RelFilePath      = "rel_file_path"
    val EncodingScrubbed = "encoding_scrubbed"
    val TruncatedNodes   = "truncated_nodes"
    // Top-level wrapper / node discriminators.
    val Ast      = "ast"
    val NodeType = "nodeType"
    // Per-node source attributes (nikic `attributes` object) read by PhpAttributes.apply.
    val Attributes   = "attributes"
    val StartLine    = "startLine"    // -> lineNumber
    val StartFilePos = "startFilePos" // -> columnNumber
    val Kind         = "kind"
    // Additive per-node/attribute contract keys.
    val AttrGroups = "attrGroups"
    val Hooks      = "hooks"
  end ContractKeys

  /** The provenance field names chen relies on, in declaration order. Pinned so a rename/removal on
    * [[PhpProvenance]] fails this spec (see the reflection check below).
    */
  private val ExpectedProvenanceFields: List[String] = List(
    "parserBackend",
    "generatorVersion",
    "phpVersion",
    "targetVersion",
    "relFilePath",
    "encodingScrubbed",
    "truncatedNodes"
  )

  // --- JSON builders using the EXACT contract keys -------------------------------------------

  private def attributesJson(line: Int = 1, filePos: Int = 0, kind: Int = 1): ujson.Obj =
      ujson.Obj(
        ContractKeys.StartLine    -> line,
        ContractKeys.StartFilePos -> filePos,
        ContractKeys.Kind         -> kind
      )

  private def nopStmt(line: Int = 1): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "Stmt_Nop",
        ContractKeys.Attributes -> attributesJson(line)
      )

  /** A full provenance wrapper carrying every pinned key with a distinctive value. */
  private def fullWrapper(ast: ujson.Arr): ujson.Obj =
      ujson.Obj(
        ContractKeys.Ast              -> ast,
        ContractKeys.ParserBackend    -> "nikic/php-parser@5.8.0",
        ContractKeys.GeneratorVersion -> "2.0.0",
        ContractKeys.PhpVersion       -> "8.4.1",
        ContractKeys.TargetVersion    -> "8.4",
        ContractKeys.RelFilePath      -> "src/App/Service.php",
        ContractKeys.EncodingScrubbed -> true,
        ContractKeys.TruncatedNodes   -> 7
      )

  private def name(str: String): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "Name",
        "parts"                 -> ujson.Arr(str),
        ContractKeys.Attributes -> attributesJson()
      )

  private def identifier(n: String): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "Identifier",
        "name"                  -> n,
        ContractKeys.Attributes -> attributesJson()
      )

  private def varLikeIdentifier(n: String): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "VarLikeIdentifier",
        "name"                  -> n,
        ContractKeys.Attributes -> attributesJson()
      )

  private def propItem(n: String): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "PropertyItem",
        "name"                  -> varLikeIdentifier(n),
        "default"               -> ujson.Null,
        ContractKeys.Attributes -> attributesJson()
      )

  /** A single `#[Attr]` attribute node inside an `AttributeGroup`. */
  private def attributeNode(attrName: String): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "Attribute",
        "name"                  -> name(attrName),
        "args"                  -> ujson.Arr(),
        ContractKeys.Attributes -> attributesJson()
      )

  private def attributeGroup(attrNames: String*): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "AttributeGroup",
        "attrs"                 -> ujson.Arr(attrNames.map(attributeNode)*),
        ContractKeys.Attributes -> attributesJson()
      )

  /** A PHP 8.4 `PropertyHook` node. */
  private def propertyHook(hookName: String): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "PropertyHook",
        "name"                  -> identifier(hookName),
        "params"                -> ujson.Arr(),
        "body"                  -> ujson.Null,
        "byRef"                 -> false,
        "flags"                 -> 0,
        ContractKeys.AttrGroups -> ujson.Arr(),
        ContractKeys.Attributes -> attributesJson()
      )

  /** A `Stmt_Property` carrying attribute groups, property hooks, and asymmetric set-visibility. */
  private def propertyStmt(
    flags: Int,
    attrGroups: ujson.Arr,
    hooks: ujson.Arr
  ): ujson.Obj =
      ujson.Obj(
        ContractKeys.NodeType   -> "Stmt_Property",
        "flags"                 -> flags,
        "type"                  -> name("string"),
        "props"                 -> ujson.Arr(propItem("x")),
        ContractKeys.AttrGroups -> attrGroups,
        ContractKeys.Hooks      -> hooks,
        ContractKeys.Attributes -> attributesJson()
      )

  private def decodeSingleProperty(stmt: ujson.Value): PhpPropertyStmt =
      Domain.fromJson(ujson.Arr(stmt)).children match
        case (p: PhpPropertyStmt) :: Nil => p
        case other => fail(s"Expected a single PhpPropertyStmt but got: $other")

  // =====================================================================================
  //  1. Provenance wrapper contract — snake_case keys -> PhpProvenance fields
  // =====================================================================================

  "The PhpProvenance decoded-shape contract" should {

      "populate every provenance field from its exact snake_case wrapper key" in {
          // If any decoder key literal is renamed/dropped, the matching field goes empty here.
          val file = Domain.fromJson(fullWrapper(ujson.Arr(nopStmt())))
          val p    = file.provenance

          p.parserBackend shouldBe Some("nikic/php-parser@5.8.0") // <- "parser_backend"
          p.generatorVersion shouldBe Some("2.0.0")               // <- "generator_version"
          p.phpVersion shouldBe Some("8.4.1")                     // <- "php_version"
          p.targetVersion shouldBe Some("8.4")                    // <- "target_version"
          p.relFilePath shouldBe Some("src/App/Service.php")      // <- "rel_file_path"
          p.encodingScrubbed shouldBe true                        // <- "encoding_scrubbed"
          p.truncatedNodes shouldBe Some(7)                       // <- "truncated_nodes"
      }

      "expose EXACTLY the expected field names on the PhpProvenance case class" in {
          // Reflection guard: a renamed or removed provenance field flips this set. This is the
          // non-additive tripwire — adding a new field to the list here is the ONLY change allowed,
          // and only alongside a coordinated contract bump (Decision 4).
          val actualFields = classOf[PhpProvenance].getDeclaredFields.map(_.getName).toList
          actualFields should contain theSameElementsAs ExpectedProvenanceFields
      }
  }

  // =====================================================================================
  //  2. Top-level wrapper contract — `ast` array unwrapped; bare array still decodes
  // =====================================================================================

  "The top-level wrapper contract" should {

      "unwrap a wrapper object carrying an `ast` array (forward-compatible direction)" in {
          val file = Domain.fromJson(fullWrapper(ujson.Arr(nopStmt(), nopStmt(2))))
          (file.children should have).length(2)
          all(file.children) shouldBe a[NopStmt]
          // Provenance rides along only in the wrapped form.
          file.provenance.parserBackend shouldBe Some("nikic/php-parser@5.8.0")
      }

      "decode a bare statement array with empty provenance (backward-compatible direction)" in {
          val file = Domain.fromJson(ujson.Arr(nopStmt(), nopStmt(2)))
          (file.children should have).length(2)
          file.provenance shouldBe PhpProvenance.Empty
      }
  }

  // =====================================================================================
  //  3. Per-node source attributes — startLine/startFilePos/kind mapping
  // =====================================================================================

  "The per-node source-attribute contract (PhpAttributes)" should {

      "map startLine -> lineNumber, startFilePos -> columnNumber, and read kind" in {
          val node = ujson.Obj(
            ContractKeys.NodeType   -> "Stmt_Nop",
            ContractKeys.Attributes -> attributesJson(line = 42, filePos = 100, kind = 8)
          )
          Domain.fromJson(ujson.Arr(node)).children match
            case (nop: NopStmt) :: Nil =>
                nop.attributes.lineNumber.map(_.intValue) shouldBe Some(42)    // <- "startLine"
                nop.attributes.columnNumber.map(_.intValue) shouldBe Some(100) // <- "startFilePos"
                nop.attributes.kind shouldBe Some(8)                           // <- "kind"
            case other => fail(s"Expected a single NopStmt but got: $other")
      }

      "expose EXACTLY the expected field names on the PhpAttributes case class" in {
          val actualFields = classOf[PhpAttributes].getDeclaredFields.map(_.getName).toList
          actualFields should contain theSameElementsAs List("lineNumber", "columnNumber", "kind")
      }
  }

  // =====================================================================================
  //  4. Additive per-node contract — attribute groups, property hooks, asymmetric visibility
  // =====================================================================================

  "The additive per-node contract (attrGroups / hooks / asymmetricVisibility)" should {

      "decode `attrGroups` into explicit PhpAttributeGroup / PhpAttribute nodes" in {
          val prop = decodeSingleProperty(
            propertyStmt(
              flags = 1,
              attrGroups = ujson.Arr(attributeGroup("Deprecated")),
              hooks = ujson.Arr()
            )
          )
          prop.attributeGroups match
            case (group: PhpAttributeGroup) :: Nil =>
                group.attrs match
                  case (attr: PhpAttribute) :: Nil => attr.name.name shouldBe "Deprecated"
                  case other => fail(s"Expected a single PhpAttribute but got: $other")
            case other => fail(s"Expected a single PhpAttributeGroup but got: $other")
      }

      "decode `hooks` into explicit PhpPropertyHook nodes on PhpPropertyStmt" in {
          val prop = decodeSingleProperty(
            propertyStmt(
              flags = 1,
              attrGroups = ujson.Arr(),
              hooks = ujson.Arr(propertyHook("get"), propertyHook("set"))
            )
          )
          prop.hooks.map(_.name) shouldBe List("get", "set")
          all(prop.hooks) shouldBe a[PhpPropertyHook]
      }

      "read PHP 8.4 asymmetric set-visibility from the property flags bitmask" in {
          // public private(set): PUBLIC (1) | PRIVATE_SET (512)
          val prop = decodeSingleProperty(
            propertyStmt(flags = 1 | 512, attrGroups = ujson.Arr(), hooks = ujson.Arr())
          )
          prop.asymmetricVisibility shouldBe Some("private(set)")
      }

      "expose the pinned additive fields on PhpPropertyStmt (hooks, asymmetricVisibility, attributeGroups)" in {
          val fields = classOf[PhpPropertyStmt].getDeclaredFields.map(_.getName).toSet
          fields should contain("hooks")
          fields should contain("asymmetricVisibility")
          fields should contain("attributeGroups")
      }

      "remain additive: absent `attrGroups` and `hooks` decode to empty (never fail)" in {
          // A property carrying neither optional key must still decode with both left empty. This is
          // the additivity tripwire in the other direction: making these keys REQUIRED would break it.
          val stmt = ujson.Obj(
            ContractKeys.NodeType   -> "Stmt_Property",
            "flags"                 -> 1,
            "type"                  -> name("string"),
            "props"                 -> ujson.Arr(propItem("x")),
            ContractKeys.Attributes -> attributesJson()
          )
          val prop = decodeSingleProperty(stmt)
          prop.attributeGroups shouldBe empty
          prop.hooks shouldBe empty
          prop.asymmetricVisibility shouldBe None
      }
  }

  // =====================================================================================
  //  5. Unknown nodeType degrades to a placeholder — never crashes
  // =====================================================================================

  "The unknown-node degradation contract" should {

      "degrade an unknown statement `nodeType` to NopStmt, retaining source attributes" in {
          val unknown = ujson.Obj(
            ContractKeys.NodeType   -> "Stmt_FutureThing_9_9",
            ContractKeys.Attributes -> attributesJson(line = 5, filePos = 11, kind = 1)
          )
          Domain.fromJson(ujson.Arr(unknown)).children match
            case (nop: NopStmt) :: Nil =>
                nop.attributes.lineNumber.map(_.intValue) shouldBe Some(5)
                nop.attributes.columnNumber.map(_.intValue) shouldBe Some(11)
            case other => fail(s"Expected a NopStmt fallback but got: $other")
      }

      "degrade an unknown expression `nodeType` to a placeholder instead of crashing" in {
          val unknownExpr = ujson.Obj(
            ContractKeys.NodeType   -> "Expr_FutureOp_9_9",
            ContractKeys.Attributes -> attributesJson(line = 7, filePos = 20)
          )
          val stmt = ujson.Obj(
            ContractKeys.NodeType   -> "Stmt_Expression",
            "expr"                  -> unknownExpr,
            ContractKeys.Attributes -> attributesJson()
          )
          Domain.fromJson(ujson.Arr(stmt)).children match
            case (expr: PhpExpr) :: Nil =>
                expr.attributes.lineNumber.map(_.intValue) shouldBe Some(7)
                expr.attributes.columnNumber.map(_.intValue) shouldBe Some(20)
            case other => fail(s"Expected an expression placeholder but got: $other")
      }
  }

end DecodedShapeContractSpec
