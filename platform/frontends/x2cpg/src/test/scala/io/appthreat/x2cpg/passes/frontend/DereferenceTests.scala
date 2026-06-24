package io.appthreat.x2cpg.passes.frontend

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Unit tests for [[CDereference.dereferenceTypeFullName]].
  *
  * Covers raw pointer stripping and smart-pointer unwrapping using the CPG
  * dot-separator convention for namespaces (e.g. `std.shared_ptr<T>`).
  */
class DereferenceTests extends AnyWordSpec with Matchers:

  private val deref = CDereference()

  "CDereference" when {

    "handling raw pointers" should {

      "strip a single pointer star" in {
          deref.dereferenceTypeFullName("Foo*") shouldBe "Foo"
      }

      "strip multiple pointer stars" in {
          deref.dereferenceTypeFullName("char**") shouldBe "char"
      }

      "leave non-pointer types unchanged" in {
          deref.dereferenceTypeFullName("Foo") shouldBe "Foo"
      }

      "strip pointer from a namespaced type" in {
          deref.dereferenceTypeFullName("Aws.Http.HttpRequest*") shouldBe "Aws.Http.HttpRequest"
      }
    }

    "handling std::shared_ptr" should {

      "unwrap shared_ptr with a simple inner type" in {
          deref.dereferenceTypeFullName("std.shared_ptr<Foo>") shouldBe "Foo"
      }

      "unwrap shared_ptr with a namespaced inner type" in {
          deref.dereferenceTypeFullName(
            "std.shared_ptr<Aws.Http.HttpRequest>"
          ) shouldBe "Aws.Http.HttpRequest"
      }

      "strip pointer star before unwrapping" in {
          deref.dereferenceTypeFullName(
            "std.shared_ptr<Aws.Http.HttpResponse>*"
          ) shouldBe "Aws.Http.HttpResponse"
      }
    }

    "handling std::unique_ptr" should {

      "unwrap unique_ptr with a simple inner type" in {
          deref.dereferenceTypeFullName("std.unique_ptr<Foo>") shouldBe "Foo"
      }

      "unwrap unique_ptr with a namespaced inner type" in {
          deref.dereferenceTypeFullName(
            "std.unique_ptr<Aws.Auth.AWSCredentials>"
          ) shouldBe "Aws.Auth.AWSCredentials"
      }
    }

    "handling std::weak_ptr" should {

      "unwrap weak_ptr" in {
          deref.dereferenceTypeFullName("std.weak_ptr<Bar>") shouldBe "Bar"
      }
    }

    "handling nested smart pointers" should {

      "recursively unwrap nested shared_ptr" in {
          deref.dereferenceTypeFullName(
            "std.shared_ptr<std.unique_ptr<Foo>>"
          ) shouldBe "Foo"
      }
    }

    "handling boost smart pointers" should {

      "unwrap boost::shared_ptr" in {
          deref.dereferenceTypeFullName("boost.shared_ptr<Foo>") shouldBe "Foo"
      }

      "unwrap boost::scoped_ptr" in {
          deref.dereferenceTypeFullName("boost.scoped_ptr<Bar>") shouldBe "Bar"
      }
    }

    "handling template types that are not smart pointers" should {

      "leave unrecognised template types intact" in {
          deref.dereferenceTypeFullName("std.vector<int>") shouldBe "std.vector<int>"
      }

      "leave map types intact" in {
          deref.dereferenceTypeFullName(
            "std.map<std.string,int>"
          ) shouldBe "std.map<std.string,int>"
      }
    }

    "handling ANY / empty types" should {

      "leave ANY unchanged" in {
          deref.dereferenceTypeFullName("ANY") shouldBe "ANY"
      }

      "leave empty string unchanged" in {
          deref.dereferenceTypeFullName("") shouldBe ""
      }
    }
  }
