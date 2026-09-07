package io.appthreat.pysrc2cpg

import better.files.File as BFile
import io.appthreat.x2cpg.passes.frontend.ImportsPass.*
import io.appthreat.x2cpg.passes.frontend.XImportResolverPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import java.io.File as JFile
import java.util.regex.Pattern

import scala.collection.mutable

class ImportResolverPass(cpg: Cpg) extends XImportResolverPass(cpg):

  private lazy val root = cpg.metaData.root.headOption.getOrElse("").stripSuffix(JFile.separator)

  /** The separator of every path this pass reasons about. FILE names in the graph are
    * forward-slashed on every platform (see `Py2CpgOnFileSystem.ingested`), and so is anything
    * derived from one: a module's package, an `__init__.py` candidate, a relative-import anchor.
    *
    * `java.io.File.separator` is NOT interchangeable with it. On Windows a test for the platform
    * separator in `controller/urls.py` finds none, which reads as "this file sits at the input
    * root" - so a relative `from . import views` anchors at the empty package and silently resolves
    * to nothing. A real filesystem path entering this pass is normalised to this separator first,
    * by [[toCpgPath]].
    */
  private val CpgSep = '/'

  /** A real filesystem path, as a graph-space relative name. */
  private def toCpgPath(path: String): String = path.replace(JFile.separatorChar, CpgSep)

  /** All `import(...)` calls of the graph, grouped by file name - the same reduction
    * [[PythonDependencyStubs.importsOf]] performs, but ONCE per pass instead of once per re-export
    * hop. On a `python-deps=full` graph the per-hop scan made this pass the most expensive python
    * stage after the frontend itself (task 12 D.2: ~22s wall on the flask + typeshed fixture, an
    * O(imports x resolved-imports) full-graph scan); the index turns the per-hop cost into a map
    * lookup.
    */
  private lazy val importsByFile: Map[String, Seq[PythonDependencyStubs.DepImport]] =
      PythonDependencyStubs.importsByFile(cpg)

  override protected def optionalResolveImport(
    fileName: String,
    importCall: Call,
    importedEntity: String,
    importedAs: String,
    diffGraph: DiffGraphBuilder
  ): Unit =
    val (namespace, entityName) = if importedEntity.contains(".") then
      val splitName = importedEntity.split('.').toSeq
      val namespace = importedEntity.stripSuffix(s".${splitName.last}")
      (relativizeNamespace(namespace, fileName), splitName.last)
    else
      val currDir = BFile(root) / fileName match
        case x if x.isDirectory => x
        case x                  => x.parent

      // `currDir` is a real filesystem path; the namespace it becomes is a graph-space name.
      val relCurrDir =
          toCpgPath(currDir.pathAsString.stripPrefix(root).stripPrefix(JFile.separator))

      (relCurrDir, importedEntity)

    resolveEntities(namespace, entityName, importedAs).foreach(x =>
        resolvedImportToTag(x, importCall, diffGraph)
    )
  end optionalResolveImport

  private def relativizeNamespace(path: String, fileName: String): String =
      if path.startsWith(".") then
        // TODO: pysrc2cpg does not link files to the correct namespace nodes
        // The below gives us the full path of the relative "."
        val relativeNamespace =
            if fileName.contains(CpgSep) then
              fileName.substring(0, fileName.lastIndexOf(CpgSep)).replace(CpgSep, '.')
            else ""
        (if path.length > 1 then relativeNamespace + path.replace(CpgSep, '.')
         else relativeNamespace).stripPrefix(".")
      else path

  /** For an import - given by its module path and the name of the imported function or module -
    * determine the possible callee names.
    *
    * @param path
    *   the module path.
    * @param expEntity
    *   the name of the imported entity. This could be a function, module, or variable/field.
    * @param alias
    *   how the imported entity is named.
    * @return
    *   the possible callee names
    */
  /** `from pkg import x` where `pkg/__init__.py` itself binds `x` by importing it from a sibling
    * (`from .mod import x`): in real Python the user's `x` IS `pkg.mod.x`. When `pkg` is dependency
    * code ingested WITH bodies (`python-deps=full`), that target method is in the graph, and
    * resolving the user's import straight to it makes the call site join the real body - which is
    * the entire point of the mode.
    *
    * Re-exports chain (`sqlalchemy/__init__` imports from `.sql`, whose `__init__` imports from
    * `.sql.elements`), so each hop is followed until a real METHOD exists; a bound and depth guard
    * keeps pathological cycles from looping.
    *
    * Strictly gated so no other configuration changes behaviour:
    *   - the package module must be EXTERNAL (a project package is internal, so `python-deps=none`
    *     never enters this path);
    *   - NEITHER stub-alias spelling (`pkg/__init__.py:<module>.x`, `pkg.py:<module>.x`) may exist
    *     \- `stubs`/`summaries` create exactly those, and they resolve as today;
    *   - a target method must actually exist under one of the two module spellings, otherwise the
    *     plain fallback candidates answer as before.
    */
  private def reExportedTargets(
    path: String,
    expEntity: String,
    alias: String
  ): Seq[ResolvedImport] =
    // `path` is already the dotted package (`flask`, `flask.helpers`) and the package's
    // module-scope method is named by that dotted package itself - `flask/__init__.py:<module>`
    // IS the method `flask` - so there is exactly one spelling everywhere the file form needed
    // two, and no path rewriting is left to do here.
    val moduleMethod = cpg.method.fullNameExact(path)
    if moduleMethod.isEmpty || !moduleMethod.head.isExternal then return Seq.empty

    // No alias short-circuit: the alias spelling (`flask.passthrough`) and the plain
    // dotted candidate are the same string, so preferring the real re-export target here
    // is what keeps full-mode graphs joined to the module a symbol lives in.

    /** Import bindings of one external module, as (dotted target module, symbol) pairs. The imports
      * are read from the FILE of the module-scope method the dotted name resolves to - the dotted
      * name alone no longer encodes the path. A module that DEFINES the symbol itself contributes
      * nothing - a real method exists there and the plain candidates find it.
      */
    def fileRelOf(dottedModule: String): Option[String] =
        cpg.method.fullNameExact(dottedModule).headOption.flatMap(m => Option(m.filename))

    def bindingsOf(dottedModule: String): Seq[(String, String)] =
        fileRelOf(dottedModule).toSeq.flatMap { fileRel =>
          // Relative imports anchor at the FILE's directory (an `__init__.py` IS its
          // package), which the dotted name alone no longer encodes. Resolved from the one
          // `fileRelOf` lookup - this runs per re-export hop, so a second index probe for
          // the same answer is pure waste.
          val pkg = fileRel.split('/').dropRight(1).mkString("/")
          importsByFile.getOrElse(fileRel, Seq.empty).map { imp =>
              (PythonDependencyStubs.resolveModuleRel(pkg, imp).replace('/', '.'), imp.what)
          }
        }

    def methodUnder(dottedModule: String, name: String): Option[String] =
        cpg.method
            .fullNameExact(s"$dottedModule.$name")
            .headOption
            .map(_.fullName)

    // Breadth-first over re-export hops, with a visited set for cycles and a depth bound.
    val found = mutable.LinkedHashSet.empty[String]
    val queue = mutable.Queue.empty[(String, String)]
    queue.enqueueAll(bindingsOf(path).filter(_._2 == expEntity))
    val visited = mutable.HashSet.empty[String]
    var depth   = 0
    while queue.nonEmpty && found.isEmpty && depth < 6 do
      val level = queue.dequeueAll(_ => true)
      level.foreach { case (mod, name) =>
          if visited.add(s"$mod:$name") then
            methodUnder(mod, name) match
              case Some(full) => found += full
              case None       =>
                  // Not a method in this file: if THIS module is external dependency
                  // code, its own imports may re-export the symbol one hop further.
                  if cpg.method.fullNameExact(mod).headOption.exists(_.isExternal) then
                    queue.enqueueAll(bindingsOf(mod).filter(_._2 == name))
          end if
      }
      depth += 1
    found.toSeq.map(fullName => ResolvedMethod(fullName, alias))
  end reExportedTargets

  private def resolveEntities(
    path: String,
    expEntity: String,
    alias: String
  ): Set[ResolvedImport] =

    implicit class ResolvedNodeExt(val traversal: Seq[String]):
      def toResolvedImport(cpg: Cpg): Seq[ResolvedImport] =
        val resolvedEntities =
            traversal.flatMap(x =>
                cpg.typeDecl.fullNameExact(x) ++ cpg.method.fullNameExact(x)
            ).collect {
                case x: Method   => ResolvedMethod(x.fullName, alias)
                case x: TypeDecl => ResolvedTypeDecl(x.fullName)
            }
        if resolvedEntities.isEmpty then
          traversal.filterNot(_.contains("__init__.py")).map(x => UnknownImport(x))
        else
          resolvedEntities

    implicit class CalleeAsInitExt(val name: String):
      def asInit: String = if name.contains("__init__.py") then name
      else name.replace(".py", s"${CpgSep}__init__.py")

      def withInit: Seq[String] = Seq(name, name.asInit)

    val pathSep = "."
    val isMaybeConstructor =
        expEntity.split("\\.").lastOption.exists(s => s.nonEmpty && s.charAt(0).isUpper)

    lazy val membersMatchingImports: List[(TypeDecl, Member)] =
        // Only a MODULE's type decl may contribute members. The visitor names a module's decl (and
        // its METHOD twin) `<module>`; a class gets its own name. Without this scope a CLASS in the
        // graph under the same package (flask/app.py:<module>.Flask and its `url_for` method
        // member) shadows the module-level function of the same name, and `from flask import
        // url_for` resolves as a member access on the class instead of the module function - a
        // failure mode that only exists once dependency signatures are ingested. `from Class import
        // attr` is not Python, so no real import loses a resolution to this.
        cpg.typeDecl
            .fullName(s".*${Pattern.quote(path)}.*")
            .nameExact(PythonDependencyStubs.ModuleScope)
            .flatMap(t =>
                t.member.nameExact(expEntity).headOption match
                  case Some(member) => Option((t, member))
                  case None         => None
            )
            .toList

    (path match
      case "" if expEntity.contains(".") =>
          // Case 1: Qualified path: import foo.bar => (bar.py or bar/__init__.py).
          // Dotted mode: both spellings ARE `foo.bar` - one candidate, no init split.
          val splitFunc = expEntity.split("\\.")
          val name      = splitFunc.tail.mkString(".")
          Seq(expEntity).toResolvedImport(cpg)
      case "" =>
          // Case 2: import of a module: import foo => (foo.py or foo/__init__.py)
          Seq(expEntity).toResolvedImport(cpg)
      case _ if membersMatchingImports.nonEmpty =>
          // Case 3: import of a variable: from api import db => (api.py or foo.__init__.py) @ identifier(db)
          membersMatchingImports.map {
              case (t, m) if t.method.nameExact(m.name).nonEmpty =>
                  ResolvedMethod(t.method.nameExact(m.name).fullName.head, alias)
              case (t, m)
                  if t.astSiblings.isMethod.fullNameExact(
                    t.fullName
                  ).ast.isTypeDecl.nameExact(m.name).nonEmpty =>
                  ResolvedTypeDecl(
                    t.astSiblings.isMethod.fullNameExact(t.fullName).ast.isTypeDecl.nameExact(
                      m.name
                    ).fullName.head
                  )
              case (t, m) => ResolvedMember(t.fullName, m.name)
          }
      case _ =>
          // Import from module using alias, e.g. import bar from foo as faz. When `foo` is
          // ingested dependency code whose `__init__.py` re-exports the entity from a sibling
          // (`from .mod import faz`) and no stub alias spells it, resolve straight to the
          // re-export target - see [[reExportedTargets]] for the gating that keeps every other
          // mode byte-identical.
          // The real re-export chain wins over the plain candidate: in dotted form the
          // alias-under-package spelling (`flask.passthrough`) and a submodule method would
          // otherwise be indistinguishable strings, and the whole module the symbol actually
          // lives in (`flask.helpers.passthrough`) is the join the call graph needs.
          val reExported = reExportedTargets(path, expEntity, alias)
          if reExported.nonEmpty then reExported
          else Seq(s"$path$pathSep$expEntity").toResolvedImport(cpg)
    ).flatMap {
        // If we import the constructor, we also import the type
        case x: ResolvedMethod if isMaybeConstructor =>
            Seq(
              ResolvedMethod(Seq(x.fullName, "__init__").mkString(pathSep), alias),
              ResolvedTypeDecl(x.fullName)
            )
        // If we import the type, we also import the constructor
        case x: ResolvedTypeDecl if isMaybeConstructor =>
            Seq(x, ResolvedMethod(Seq(x.fullName, "__init__").mkString(pathSep), alias))
        // If we can determine the import is a constructor, then it is likely not a member
        case x: UnknownImport if isMaybeConstructor =>
            Seq(
              UnknownMethod(Seq(x.path, "__init__").mkString(pathSep), alias),
              UnknownTypeDecl(x.path)
            )
        case x => Seq(x)
    }.toSet
  end resolveEntities
end ImportResolverPass
