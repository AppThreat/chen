package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Schema validation as a neutraliser.
  *
  * A schema validator that produces a typed value - zod's `z.number()`, `z.coerce.number()`,
  * `z.enum([...])`, `z.boolean()`, `z.literal(x)` and the equivalents of valibot and yup - makes
  * the validated value a number, a boolean, or one of the named constants: nothing to inject. A
  * string schema (`z.string()`) passes any text and neutralises nothing.
  *
  * Where a framework routes a request's data through such a schema, the member of the validated
  * object that the schema types as non-text carries nothing: reads of it are tagged `predicate`, so
  * a flow that starts at one - like a flow through the result of `Number.isFinite(x)` - carries no
  * injectable value and is dropped by reachables.
  *
  * The link is structural: the schema is the value a route's `validateSearch` option names, and the
  * consumer is a read of a member of that route's `useSearch()` result in the same file.
  */
object ValidationBridge:

  /** Validator builders whose result holds no attacker-chosen text. */
  private val NonTextValidators =
      Set("number", "bigint", "boolean", "literal", "enum", "nativeEnum", "picklist", "date")

  /** Packages that provide the validators, matched on the import binding's package. */
  private val SchemaPackages = Seq("zod", "valibot", "yup")

  /** The local names a schema root (`z`, `v`) is bound by in `file`. */
  private def schemaRoots(ctx: JsContext, file: String): Set[String] =
      SchemaPackages.flatMap(pkg =>
          ctx.modules.moduleBindingsOf(file, pkg) ++ ctx.modules.localNamesOf(file, pkg, "z") ++
              ctx.modules.localNamesOf(file, pkg, "v")
      ).toSet

  /** The object literal a `z.object({...})`-shaped schema call builds, when the chain roots in a
    * schema package binding: `z` of `z.object({...})` in `file`. Its property writes `_tmp.<key> =
    * <validator>` are the schema's fields. A local the schema is assigned to (`const searchSchema =
    * z.object({...})`) is followed to its assignment.
    */
  private def schemaObject(ctx: JsContext, file: String, schema: Expression): Option[Expression] =
    val roots = schemaRoots(ctx, file)
    JsValues.origin(schema) match
      case c: Call if callName(c) == "object" =>
          receiverOf(c).flatMap(memberPath) match
            case Some(root :: Nil) if roots.contains(root) =>
                c.argument.filter(_.argumentIndex == 1).headOption
            case _ => None
      case _ => None

  /** True when the validator expression chained onto a schema root produces a non-text value:
    * `z.number().int().catch(1)`. The chain's method names and its only source identifier - the
    * schema root - decide; lowering temporaries are ignored.
    */
  private def isNonText(ctx: JsContext, file: String, validator: Expression): Boolean =
    val roots  = schemaRoots(ctx, file)
    val idents = validator.ast.isIdentifier.l.map(_.name).filterNot(_.startsWith("_tmp_")).toSet
    idents.nonEmpty && idents.forall(roots.contains) &&
    validator.ast.isCall.map(callName).l.exists(NonTextValidators.contains)

  /** Keys of the schema's object literal that a non-text validator types. */
  def nonTextKeys(ctx: JsContext, file: String, schema: Expression): Set[String] =
      schemaObject(ctx, file, schema).toList.flatMap { obj =>
          obj.ast.isCall.nameExact(Operators.assignment).l.flatMap { a =>
              (a.argumentOption(1), a.argumentOption(2)) match
                case (Some(fa: Call), Some(v)) =>
                    fieldName(fa).filter(_ => isNonText(ctx, file, v))
                case _ => None
          }
      }.toSet

  /** TanStack Router: `createFileRoute(...)({ validateSearch: schema, ... })` types what
    * `Route.useSearch()` returns. A member the schema types as non-text is tagged `predicate`
    * wherever it is read off a `useSearch()` result in the same file.
    */
  def tagTanStackValidatedSearch(ctx: JsContext): Unit =
    val schemas = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(_.argumentOption(1).exists {
            case fa: Call => fieldName(fa).contains("validateSearch")
            case _        => false
        })
        .l
    val keysByFile = schemas.flatMap { a =>
      val file = a.method.filename
      a.argumentOption(2).toList
          .flatMap(nonTextKeys(ctx, file, _).map(k => file -> k))
    }.toSet
    if keysByFile.isEmpty then return
    val reads = ctx.fieldAccesses.filterNot(isAssignmentTarget).filter { fa =>
        fieldName(fa).exists(k => keysByFile.contains((fa.method.filename, k))) &&
        fieldBase(fa).exists(b =>
            JsValues.origin(b) match
              case c: Call => c.name == "useSearch"
              case _       => false
        )
    }
    ctx.tagger.tag(reads, PREDICATE)
  end tagTanStackValidatedSearch
end ValidationBridge
