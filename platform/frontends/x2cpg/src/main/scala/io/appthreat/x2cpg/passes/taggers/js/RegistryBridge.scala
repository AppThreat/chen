package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*

/** A handler registry: functions put into a `Map` and called after a lookup.
  *
  * A hand-rolled router or event bus keeps its handlers in a map - `routes.set(name, handler)`,
  * often through a helper (`export function route(name, handler) { routes.set(name, handler) }`) -
  * and dispatches with `const handler = routes.get(current.name); handler(outlet, current)`. No
  * call site names a handler, so the value the dispatcher passes never reaches one. Each call of a
  * function that came out of such a map is resolved to every function put into it: directly, or
  * through a helper's parameter, to what the helper's callers pass.
  */
object RegistryBridge:

  def run(ctx: JsContext): Unit =
    val registries = ctx.cpg.call.nameExact("set").l.flatMap { set =>
        receiverOf(set).collect { case id: Identifier => id }
            .filter(DomRecognizer.constructedBy(_, Set("Map")))
            .map(id => (set.method.filename, id.name) -> set)
    }.groupMap(_._1)(_._2)
    if registries.isEmpty then return
    registries.foreach { case ((file, registry), sets) =>
        val handlers = sets.flatMap(_.argument.filter(_.argumentIndex == 2).l).flatMap(registered(
          ctx,
          _
        )).distinctBy(_.id())
        if handlers.nonEmpty then
          dispatches(ctx, file, registry).foreach(call =>
              handlers.foreach(ctx.tagger.resolveCall(call, _))
          )
    }

  /** The functions a registered value stands for: a function itself, or - for a parameter of the
    * helper that registers it - what the helper's callers pass there.
    */
  private def registered(ctx: JsContext, value: Expression, depth: Int = 2): List[Method] =
      if depth <= 0 then Nil
      else
        callbackMethod(value).toList ++ (value match
          // `views.homeView` off `import * as views from './views.js'`
          case fa: Call if fa.name == Operators.fieldAccess =>
              (fieldBase(fa), fieldName(fa)) match
                case (Some(base: Identifier), Some(member)) =>
                    ctx.modules.resolve(fa.method.filename, base.name)
                        .filter(_.module.startsWith(".")).toList
                        .flatMap { imp =>
                          val module = JsModules.resolveRelative(fa.method.filename, imp.module)
                          JsIndexes.internalMethodsByName(ctx.cpg.graph, member)
                              .filter(m =>
                                  m.filename == module || m.filename.startsWith(module + ".")
                              )
                        }
                case _ => Nil
          case id: Identifier =>
              id.method.parameter.nameExact(id.name).l.flatMap { p =>
                val helper = p.method
                callersOf(ctx, helper).flatMap(_.argument.filter(_.argumentIndex == p.index).l)
                    .flatMap(registered(ctx, _, depth - 1))
              }
          case _ => Nil
        )

  /** Calls of a function from its module or from modules importing it by name. */
  private def callersOf(ctx: JsContext, fn: Method): List[Call] =
      JsIndexes.callsNamed(ctx.cpg.graph, fn.name).filter { c =>
        val file = c.method.filename
        file == fn.filename || ctx.modules.resolve(file, fn.name).exists(i =>
            i.module.startsWith(".") &&
                fn.filename.startsWith(JsModules.resolveRelative(file, i.module))
        )
      }

  /** Calls in `file` of a local whose value is looked up in the registry: `handler(...)` after
    * `const handler = routes.get(name) || routes.get('home')`.
    */
  private def dispatches(ctx: JsContext, file: String, registry: String): List[Call] =
      ctx.cpg.file.nameExact(file).method.l.flatMap(_.call.l).filter { c =>
          !c.name.startsWith("<operator>") && c.receiver.headOption.exists {
              case id: Identifier =>
                  (JsIndexes.assignedValues(id.method, id.name) match
                    case Nil => JsValues.origin(id) :: Nil
                    case vs  => vs
                  ).exists(_.ast.isCall.nameExact("get").exists(g =>
                      receiverOf(g).exists {
                          case r: Identifier => r.name == registry
                          case _             => false
                      }
                  ))
              case _ => false
          }
      }
end RegistryBridge
