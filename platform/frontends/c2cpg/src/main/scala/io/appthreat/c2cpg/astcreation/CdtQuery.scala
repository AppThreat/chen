package io.appthreat.c2cpg.astcreation

import scala.util.control.NonFatal
import scala.util.{Failure, Success, Try}

/** A question to CDT's semantics: a binding, a type, a value. CDT throws on code it does not model,
  * and its template instantiation and return-type deduction recurse without bound on
  * self-referential code (a variable template initialised with itself, a generic lambda whose
  * return type depends on calling itself). Either fails the one question, as `Try` fails on an
  * exception, instead of the whole file: `Try` lets a `StackOverflowError` through.
  */
object CdtQuery:
  def apply[T](query: => T): Try[T] =
      try Success(query)
      catch
        case e: StackOverflowError => Failure(e)
        case NonFatal(e)           => Failure(e)
