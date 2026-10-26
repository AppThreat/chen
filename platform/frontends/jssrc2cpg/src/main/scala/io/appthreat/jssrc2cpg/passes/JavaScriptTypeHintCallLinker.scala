package io.appthreat.jssrc2cpg.passes

import io.appthreat.x2cpg.passes.frontend.XTypeHintCallLinker
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

import java.util.regex.Pattern

class JavaScriptTypeHintCallLinker(cpg: Cpg) extends XTypeHintCallLinker(cpg):

  override protected val pathSep = ':'

  override protected def calls: Iterator[Call] = cpg.call
      .or(_.nameNot("<operator>.*", "<operators>.*"), _.name("<operator>.new"))
      .filter(c => calleeNames(c).nonEmpty && c.callee.isEmpty)

  /** Type recovery names a member call of a typed receiver `<Type>:<method>` - `this.articleService
    * .findAll(query)` in a NestJS controller recovers `ArticleService:findAll` from the injected
    * type - while the method the project declares is `<file>::program:ArticleService:findAll`.
    * Without this mapping the linker creates an external stub and the call never reaches the
    * internal method. A bare two-segment name (an import-resolved name like `express:Response:send`
    * has three, and a generic type like `Repository<X>:findOne` does not match) maps to the
    * internal method only when exactly one such method exists; two files declaring the same class
    * name stay unresolved rather than guessed.
    */
  private val typeMethodHint = Pattern.compile("[A-Za-z_$][\\w$]*:[\\w$]+")

  private val ProgramMarker = "::program:"

  /** The project's methods by their name within the file that declares them:
    * `ArticleService:findAll` for `article.service.ts::program:ArticleService:findAll`. Built once,
    * not searched per call.
    */
  private lazy val internalByLocalName: Map[String, List[String]] =
      cpg.method.internal.fullName.l
          .flatMap { fullName =>
            val idx = fullName.lastIndexOf(ProgramMarker)
            Option.when(idx >= 0)(fullName.substring(idx + ProgramMarker.length) -> fullName)
          }
          .groupMap(_._1)(_._2)

  override protected def resolveLocalTypeHint(methodName: String): Option[String] =
      if !typeMethodHint.matcher(methodName).matches() || cpg.method.fullNameExact(methodName).nonEmpty
      then None
      else
        internalByLocalName.get(methodName) match
          case Some(unique :: Nil) => Option(unique)
          case _                   => None
end JavaScriptTypeHintCallLinker
