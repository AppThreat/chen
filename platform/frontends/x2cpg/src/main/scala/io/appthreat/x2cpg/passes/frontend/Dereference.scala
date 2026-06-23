package io.appthreat.x2cpg.passes.frontend

import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.semanticcpg.language.*

object Dereference:

  def apply(cpg: Cpg): Dereference = cpg.metaData.language.headOption match
    case Some(Languages.NEWC) => CDereference()
    case _                    => DefaultDereference()

sealed trait Dereference:

  def dereferenceTypeFullName(fullName: String): String

case class CDereference() extends Dereference:

  /** Owning and non-owning smart-pointer wrappers whose inner type should be used for member
    * resolution. Stored with the CPG dot-separator convention (e.g. `std.shared_ptr`).
    */
  private val SmartPointerPrefixes: List[String] = List(
    "std.shared_ptr",
    "std.unique_ptr",
    "std.weak_ptr",
    "boost.shared_ptr",
    "boost.scoped_ptr"
  )

  /** Strips raw pointer stars and, for well-known smart-pointer wrappers, unwraps the inner type
    * argument so that member-method lookup continues against the pointed-to type rather than the
    * wrapper itself.
    *
    * Examples (CPG dot-separator form):
    *   - `std.shared_ptr<Aws.Http.HttpRequest>*` → `Aws.Http.HttpRequest`
    *   - `std.unique_ptr<Foo>` → `Foo`
    *   - `Aws.Client.AWSClient*` → `Aws.Client.AWSClient`
    *   - `int*` → `int`
    */
  override def dereferenceTypeFullName(fullName: String): String =
    val withoutStars = fullName.replace("*", "").trim
    SmartPointerPrefixes
        .find(prefix => withoutStars.startsWith(s"$prefix<") && withoutStars.endsWith(">"))
        .map { prefix =>
          val inner = withoutStars.drop(prefix.length + 1).dropRight(1).trim
          // Recursively strip nested smart-pointer wrapping (e.g. shared_ptr<unique_ptr<T>>).
          dereferenceTypeFullName(inner)
        }
        .getOrElse(withoutStars)
end CDereference

case class DefaultDereference() extends Dereference:

  override def dereferenceTypeFullName(fullName: String): String = fullName
