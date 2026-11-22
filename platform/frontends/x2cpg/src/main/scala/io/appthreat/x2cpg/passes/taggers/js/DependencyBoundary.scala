package io.appthreat.x2cpg.passes.taggers.js

import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

import JsTags.*

/** Sink tags on the calls project code makes into npm packages, for graphs built with
  * `node_modules` left out. The code of a package the project imports is not in the graph, so a
  * flow that ends in one of its functions ends at the call: that call is the sink.
  *
  * A call is tagged `library-call`, or `http-client` when the package is a known HTTP request
  * client, when all of these hold. It is not a sink already: a response, SQL, file, shell or code
  * execution sink keeps its own vocabulary. Every method it is linked to is external, because a
  * workspace package parsed with the project is the project's own code. A recognizer has not made
  * it a framework input: a call that reads the request in (`getCookie(event, 'session')`) is where
  * a flow starts, and as a sink it would only end a flow at its own start. And it resolves to an
  * npm package, which a Node built-in is not (Node resolves it before `node_modules`, and
  * [[PackageAttribution]] names it itself, `node:fs`) and neither is a framework alias
  * (`$app/state`, `#imports`).
  *
  * The package comes first from [[PackageAttribution.packageOf]]: the import a callee or its
  * receiver is bound to, a handle made from one (`pool = new pg.Pool()`, `pool.query(q)`), or the
  * package a resolved callee name carries. Failing that, a call can still be a use of a member a
  * project class inherits. `ChallengeModel.bulkCreate()` or `challenge.save()` with `class
  * ChallengeModel extends Model` and `Model` imported from `sequelize` is named
  * `<file>::program:<Class>:<member>` in the class's file and `<specifier>:<export>:<member>` in a
  * file that imports the class, or is left unresolved with a receiver the frontend typed as the
  * class. Such a call belongs to the package of the nearest ancestor that no project class
  * declares, when the class and every project ancestor leave the member undeclared: a member any of
  * them declares is the project's own, an override. The call's package is returned so that
  * [[PackageAttribution]], which runs next, layers the SBOM's purl on it as it does on every other
  * sink.
  */
object DependencyBoundary:

  private val LIBRARY_CALL = "library-call"

  /** The tags that make a JavaScript call a sink already. */
  private val ExistingSinkTags = Seq(
    LIBRARY_CALL,
    HTTP_CLIENT,
    OUTPUT,
    XSS,
    "sql",
    "file-io",
    "shell-exec",
    CODE_EXEC
  )

  /** What makes a call a request's own data. A request client's response is a service-ingress
    * source too, and its call stays a sink, so only `framework-input` counts.
    */
  private val SourceTags = Seq(INPUT)

  /** Tags the calls into packages and returns the package of each one found through inheritance, by
    * call id.
    */
  def run(ctx: JsContext, typeOf: Expression => Option[JsTypeRef]): Map[Long, String] =
    val skipped = ExistingSinkTags ++ SourceTags
    val sunk = ctx.tagger.taggedIds(skipped*).toSet ++
        ctx.cpg.tag.nameExact(skipped*)._taggedByIn.collect {
            case c: Call => c.id()
        }
    val inheritance = Inheritance(ctx)
    val inherited   = mutable.HashMap.empty[Long, String]
    ctx.cpg.call
        .filterNot(c => c.name.startsWith("<operator>") || sunk.contains(c.id()))
        .filter(c =>
            c._callOut.collectAll[Method].forall(_.isExternal) &&
                ctx.tagger.targetsOf(c).forall(_.isExternal)
        )
        .foreach { c =>
          val direct = PackageAttribution.packageOf(ctx, c, typeOf)
          val pkg = direct.orElse {
              inheritance.packageOf(c).map { p =>
                inherited.update(c.id(), p)
                p
              }
          }
          pkg.filterNot(p => JsModules.isNodeBuiltin(p) || isFrameworkAlias(p)).foreach { p =>
              ctx.tagger.tag(
                Iterator(c),
                if HttpClients.contains(p) then HTTP_CLIENT else LIBRARY_CALL
              )
          }
        }
    inherited.toMap
  end run

  /** `$app/state` (SvelteKit) and `#imports` (Nuxt) are framework modules, not npm packages. */
  private def isFrameworkAlias(pkg: String): Boolean = pkg.startsWith("$") || pkg.startsWith("#")

  private val HttpClients: Set[String] = EasyTagsPass.HttpClientPackages.toSet

  /** The package a project class inherits a member from, by the rule in the object's description.
    */
  private final class Inheritance(ctx: JsContext):
    private val cpg = ctx.cpg

    private val projectTypes: Map[String, List[TypeDecl]] =
        cpg.typeDecl.isExternal(false).l.groupBy(_.name)

    // project files by their path without the extension (`models/user` for `models/user.ts`)
    private lazy val filesByStem: Map[String, String] =
        cpg.method.nameExact(":program").filename.l.distinct
            .map(f => f.replaceFirst("\\.[cm]?[jt]sx?$", "") -> f)
            .toMap

    private val lineages = mutable.HashMap.empty[String, List[TypeDecl]]

    // the last segment of a heritage name: `Model` of `sequelize.js::program:Model`
    private def simpleName(name: String): String =
        name.split("[:.]").lastOption.getOrElse(name)

    /** The npm package a heritage name is bound to by an import of `file`: `ng.Component` through
      * the namespace `ng`, `sequelize.js::program:Model` through the `Model` it names.
      */
    private def packageBound(file: String, name: String): Option[String] =
        Iterator(name.takeWhile(_ != '.'), simpleName(name))
            .flatMap(local => ctx.modules.resolve(file, local).flatMap(_.packageName))
            .nextOption()

    /** The project class a heritage clause names: by full name, else by a name that is unique in
      * the project, unless the file imports that name from a package.
      */
    private def baseClass(td: TypeDecl, base: String): Option[TypeDecl] =
        cpg.typeDecl.fullNameExact(base).isExternal(false).headOption.orElse {
            if packageBound(td.filename, base).isDefined then None
            else
              projectTypes.get(simpleName(base)) match
                case Some(List(one)) => Some(one)
                case _               => None
        }

    /** A class and its ancestors in the project, nearest first. */
    private def lineageOf(td: TypeDecl): List[TypeDecl] =
        lineages.getOrElseUpdate(
          td.fullName, {
              val seen = mutable.LinkedHashMap[String, TypeDecl](td.fullName -> td)
              var next = List(td)
              while next.nonEmpty do
                next = next.flatMap(t => t.inheritsFromTypeFullName.flatMap(baseClass(t, _)))
                    .filterNot(t => seen.contains(t.fullName))
                next.foreach(t => seen(t.fullName) = t)
              seen.values.toList
          }
        )

    private def inheritedFrom(td: TypeDecl, member: String): Option[String] =
      val chain = lineageOf(td)
      if chain.exists(_.member.nameExact(member).nonEmpty) then None
      else
        chain.iterator.flatMap { t =>
            t.inheritsFromTypeFullName
                .filterNot(b => b.isEmpty || b == "ANY" || baseClass(t, b).isDefined)
                .flatMap(packageBound(t.filename, _))
        }.nextOption()

    /** The project class a call's resolved owner names: a type's full name, or `<relative
      * specifier>:<export>` as a file that imports the class sees it.
      */
    private def projectClass(owner: String, callerFile: String): Option[TypeDecl] =
        if owner.contains("::program:") then
          cpg.typeDecl.fullNameExact(owner).isExternal(false).headOption
        else if owner.count(_ == ':') == 1 then
          // the frontend keeps `../` but drops a leading `./` (`./order` is `order`)
          val (raw, exported) = owner.splitAt(owner.indexOf(':'))
          val specifier       = if raw.startsWith(".") then raw else s"./$raw"
          val target          = JsModules.resolveRelative(callerFile, specifier).stripPrefix("./")
          val file = filesByStem.getOrElse(target, filesByStem.getOrElse(s"$target/index", ""))
          if file.isEmpty then None else exportedClass(file, exported.drop(1))
        else None

    /** The class a file exports as `name`: `export class Name`, or `export { Local as Name }`,
      * which the frontend lowers to `exports.Name = Local`.
      */
    private def exportedClass(file: String, name: String): Option[TypeDecl] =
      val local = cpg.method.nameExact(":program").filenameExact(file).ast.isCall
          .nameExact(Operators.assignment).l.flatMap { a =>
              a.argument.l.sortBy(_.argumentIndex) match
                case (target: Call) :: (value: Identifier) :: _
                    if target.name == Operators.fieldAccess &&
                        target.argument.isIdentifier.nameExact("exports").nonEmpty &&
                        target.argument.isFieldIdentifier.canonicalNameExact(name).nonEmpty =>
                    Some(value.name)
                case _ => None
          }.headOption.getOrElse(name)
      cpg.typeDecl.fullNameExact(s"$file::program:$local").isExternal(false).headOption

    private val SourceTextChars = "\"'`(){}[]<>=,;".toSet

    /** A callee name the frontend resolved: not a placeholder and not source text. */
    private def isResolvedName(name: String): Boolean =
        name.nonEmpty && name != "ANY" && !name.startsWith("<") &&
            !name.exists(ch => ch.isWhitespace || SourceTextChars.contains(ch))

    def packageOf(call: Call): Option[String] =
      val name = call.methodFullName
      if isResolvedName(name) then
        val split = name.lastIndexOf(':')
        if split <= 0 then None
        else
          val member = name.substring(split + 1)
          val owner  = name.substring(0, split).stripSuffix(":<init>")
          if member.isEmpty || member.startsWith("<") then None
          else projectClass(owner, call.method.filename).flatMap(inheritedFrom(_, member))
      else if call.name.startsWith("<") then None
      else
        // unresolved, with a receiver the frontend typed as a project class
        call.argument.argumentIndex(0).headOption.orElse(call.receiver.headOption).collect {
            case i: Identifier => i
        }.flatMap { receiver =>
            (receiver.typeFullName +: receiver.dynamicTypeHintFullName)
                .filter(_.contains("::program:"))
                .map(_.stripSuffix(":<init>"))
                .flatMap(t => cpg.typeDecl.fullNameExact(t).isExternal(false).headOption)
                .headOption
                .flatMap(inheritedFrom(_, call.name))
        }
      end if
    end packageOf
  end Inheritance
end DependencyBoundary
