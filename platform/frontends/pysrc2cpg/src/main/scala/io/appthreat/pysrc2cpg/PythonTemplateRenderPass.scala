package io.appthreat.pysrc2cpg

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Languages, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Task 12 D.1 - renderer-aware t-string semantics.
  *
  * PEP 750's boundary: a t-string is not a concatenation, and the no-flow semantic declared for
  * `<operator>.templateString` keeps an interpolation's taint out of the template object. That is
  * correct and stays - an UNRENDERED template reaching a sink is not a finding, because nothing has
  * been substituted.
  *
  * The other half, closed here: a RENDERER - a call that consumes a template and produces a string,
  * `str(tpl)` being the canonical example - re-exposes the interpolations in the real language, and
  * the engine should propagate their taint through it. Node-local taint cannot distinguish the
  * consumer, so the semantic alone cannot express "flow only when rendered"; instead this pass adds
  * the missing `REACHING_DEF` bridge edges from each interpolation's value expression to the
  * RENDERER CALL NODE, but only when a renderer's argument IS a `<operator>.templateString` call.
  * The permissive call-site walk then carries the value's taint to the renderer's result, while the
  * direct-consumption boundary keeps holding - the template object itself still receives nothing
  * from its interpolations.
  *
  * Precision notes: this never tags t-strings as sanitizers (the deferral is not a
  * declassification), and the bridge never fires for a renderer consuming anything but a literal
  * template expression - a `render(user_string)` call is untouched.
  */
class PythonTemplateRenderPass(cpg: Cpg) extends CpgPass(cpg):

  /** Renderer call names. Deliberately small and each justified: `str` is the documented
    * debug-render spelling; `substitute`/`safe_substitute` are string.Template's renderers;
    * `render`/`render_template`/`render_template_string` cover the common template-engine entry
    * points. The bridge only fires when such a call's argument is a templateString call, so a
    * same-named call over ordinary strings is unaffected.
    */
  private val RendererCallNames =
      Set(
        "str",
        "substitute",
        "safe_substitute",
        "render",
        "render_template",
        "render_template_string"
      )

  private val TemplateStringCall = "<operator>.templateString"
  private val InterpolationCall  = "<operator>.interpolation"

  override def run(dstGraph: DiffGraphBuilder): Unit =
      if cpg.metaData.language.headOption.exists(l =>
            l == Languages.PYTHON || l == Languages.PYTHONSRC
        )
      then
        cpg.call.nameExact(RendererCallNames.toSeq*).foreach { renderer =>
          // Deduplicated: a renderer can consume the same template through more than one
          // argument position, and a repeated REACHING_DEF between the same two nodes is
          // extra engine work for no extra reachability.
          val bridged = scala.collection.mutable.HashSet.empty[Long]
          renderer.argument.isCall.nameExact(TemplateStringCall).foreach { template =>
              template.argument.isCall.nameExact(InterpolationCall).foreach { interpolation =>
                  // An `<operator>.interpolation` carries exactly ONE argument, the value
                  // expression - the conversion and format spec are folded into the call's
                  // `code` by the visitor, not passed as arguments. So this is a single value
                  // per interpolation, and the match below is a dispatch on its kind purely to
                  // name the REACHING_DEF's variable the way the engine expects.
                  interpolation.argument.foreach { value =>
                    val variableName = value match
                      case i: Identifier => Some(i.name)
                      case c: Call       => Some(c.name)
                      // A literal interpolation (`t"{1}"`) needs no bridge: a constant
                      // carries no taint to re-expose, and an edge out of one only widens
                      // the engine's search.
                      case _ => None
                    variableName.foreach { name =>
                        if bridged.add(value.id()) then
                          dstGraph.addEdge(
                            value,
                            renderer,
                            EdgeTypes.REACHING_DEF,
                            PropertyNames.VARIABLE,
                            name
                          )
                    }
                  }
              }
          }
        }
  end run
end PythonTemplateRenderPass
