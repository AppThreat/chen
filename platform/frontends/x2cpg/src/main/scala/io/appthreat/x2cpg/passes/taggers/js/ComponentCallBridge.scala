package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** A template's component element, lowered to a call of the component, resolved to the method that
  * implements it.
  *
  * jssrc2cpg lowers `<RichText html={bio} />` to a call of `RichText` with the element's attribute
  * expressions as its argument; the CALL edge to the component is added here, from the import that
  * bound the name (`import RichText from './components/RichText'` - a default import names the
  * file's component) or, absent an import (Nuxt's auto-registered component directories), from the
  * one project method of that name. With the edge, the dataflow engine carries a parent's attribute
  * value into the component's props parameter - and a component's props are its only input
  * boundary.
  *
  * A component that is a FILE rather than a function (a `.vue` or `.svelte` single-file component)
  * has no parameter to receive the argument; those stay unresolved, and their props-side flows
  * start at the `defineProps()`/`$props()` read.
  */
object ComponentCallBridge:

  /** Extensionless suffixes a component import may resolve to. */
  private val ComponentExtensions =
      Seq(".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".vue", ".svelte", ".astro")

  def run(ctx: JsContext): Unit =
    val componentsByName = projectComponents(ctx)
    if componentsByName.isEmpty then return
    ctx.cpg.call
        .filter(c => isComponentElementCall(c))
        .foreach { call =>
          val file = call.method.filename
          // the import binding: `import RichText from './components/RichText'`
          val imported = ctx.modules.resolve(file, call.name)
          val byImport = imported.flatMap(i => resolveModule(ctx, file, i, call.name))
          val byName   = componentsByName.get(call.name)
          (byImport.orElse(byName)).foreach(m => ctx.tagger.resolveCall(call, m))
        }

  /** A component element's lowered call: `<RichText html={bio} />` lowered to a call named after
    * the element it came from.
    */
  private def isComponentElementCall(c: Call): Boolean =
      c.name.nonEmpty && c.name.charAt(0).isUpper &&
          c.code.startsWith(s"<${c.name}") && c.code.endsWith("/>") || c.code.startsWith(
            s"<${c.name}"
          )

  /** Methods a project defines that could be a component: every internal method is indexed by name
    * once; only unambiguous names are resolved.
    */
  private def projectComponents(ctx: JsContext): Map[String, Method] =
      ctx.cpg.method.internal.l
          .filter(m => !m.isExternal && m.name != ":program" && !m.name.startsWith("<"))
          .groupBy(_.name)
          .collect { case (name, m :: Nil) => name -> m }

  /** A component import resolved to the method: the module specifier made a file path, and the
    * file's component - its default export, or the method of the same name.
    */
  private def resolveModule(
    ctx: JsContext,
    fromFile: String,
    imp: JsImport,
    callName: String
  ): Option[Method] =
      if !imp.module.startsWith(".") && !imp.module.startsWith("/") then None
      else
        val base       = normalise(fromFile, imp.module)
        val candidates = ComponentExtensions.map(ext => s"$base$ext") :+ s"$base/index.ts"
        val methods    = candidates.flatMap(f => ctx.cpg.file.nameExact(f).method.internal.l)
        methods
            .filter(m =>
                m.name == callName || m.name.startsWith("anonymous") || m.name == "default"
            )
            .filter(isComponentShaped)
            .headOption

  private def isComponentShaped(m: Method): Boolean =
      m.name != ":program" && !m.name.contains("<")

  private def normalise(fromFile: String, module: String): String =
    val dir      = fromFile.substring(0, math.max(fromFile.lastIndexOf('/'), 0))
    val parts    = (dir.split("/").toSeq ++ module.split("/").toSeq).filter(_.nonEmpty)
    val resolved = scala.collection.mutable.ArrayBuffer.empty[String]
    parts.foreach {
        case "."  => ()
        case ".." => if resolved.nonEmpty then resolved.trimEnd(1)
        case p    => resolved += p
    }
    resolved.mkString("/", "/", "")
end ComponentCallBridge
