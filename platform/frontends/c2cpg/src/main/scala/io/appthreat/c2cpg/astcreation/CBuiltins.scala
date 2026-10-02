package io.appthreat.c2cpg.astcreation

import scala.io.Source
import scala.util.Using

/** The signatures of the GCC and Clang builtin functions (`builtin-functions.txt`, see
  * `tools/builtins/generate.py`), for the calls to builtins the parser does not declare:
  * `__builtin___memcpy_chk` and the other FORTIFY builtins, and the C library's `__memcpy_chk`
  * family when its header is not parsed. Such a call gets the builtin's signature and return type
  * instead of an unresolved one.
  */
object CBuiltins:

  /** A builtin's return type and parameter types (`...` for a variadic tail). */
  final case class Builtin(returnType: String, parameterTypes: Seq[String]):
    def signature: String = s"$returnType(${parameterTypes.mkString(",")})"

  private lazy val builtins: Map[String, Builtin] =
      Using(Source.fromResource("builtin-functions.txt"))(_.getLines().toList).toOption.toList
          .flatten
          .filterNot(l => l.isEmpty || l.startsWith("#"))
          .flatMap { line =>
              line.split(";", -1) match
                case Array(name, ret, params) =>
                    Some(name -> Builtin(
                      ret,
                      if params.isEmpty then Nil else params.split(",").toSeq
                    ))
                case _ => None
          }.toMap

  def get(name: String): Option[Builtin] = builtins.get(name)

  /** Whether `name` names a compiler builtin, which has C linkage: its calls are named without a
    * signature, as the C library's functions are, whatever the language.
    */
  def isBuiltinName(name: String): Boolean =
      name.startsWith("__builtin_") || name.startsWith("__sync_") || name.startsWith("__atomic_") ||
          builtins.contains(name)
end CBuiltins
