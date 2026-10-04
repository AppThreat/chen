package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.parser.EdgaUnit
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class TypeNamesTests extends AnyWordSpec with Matchers:

  private val unit = EdgaUnit.parse(
    """{
      |  "tu": { "path": "t.cpp", "status": "ok", "language": "c++" },
      |  "types": [
      |    { "id": 0, "kind": "integer", "name": "int", "signed": true },
      |    { "id": 1, "kind": "pointer", "name": "int *", "to": 0 },
      |    { "id": 2, "kind": "integer", "name": "char", "signed": true },
      |    { "id": 3, "kind": "array", "name": "char [16]", "of": 2, "count": 16 },
      |    { "id": 4, "kind": "struct", "name": "geo::Point", "tag": "Point", "qualifiedName": "geo::Point" },
      |    { "id": 5, "kind": "pointer", "name": "const geo::Point &", "to": 6, "reference": true },
      |    { "id": 6, "kind": "typeref", "name": "const geo::Point", "of": 4 },
      |    { "id": 7, "kind": "typeref", "name": "size_t", "typedef": "size_t", "of": 8 },
      |    { "id": 8, "kind": "integer", "name": "unsigned long", "signed": false },
      |    { "id": 9, "kind": "routine", "name": "int (int *, char *)", "returns": 0, "params": [1, 10] },
      |    { "id": 10, "kind": "pointer", "name": "char *", "to": 2 },
      |    { "id": 11, "kind": "class", "name": "lambda []", "closure": true },
      |    { "id": 12, "kind": "pointer", "name": "int &", "to": 0, "reference": true },
      |    { "id": 13, "kind": "pointer", "name": "geo::Point *", "to": 4 },
      |    { "id": 14, "kind": "pointer", "name": "char **", "to": 10 },
      |    { "id": 15, "kind": "class", "name": "std::__1::vector<int, std::__1::allocator<int>>", "tag": "vector", "qualifiedName": "std::__1::vector<int, std::__1::allocator<int>>" },
      |    { "id": 16, "kind": "typeref", "name": "std::__1::literals::chrono_literals::hours", "typedef": "std::__1::literals::chrono_literals::hours", "of": 0 },
      |    { "id": 17, "kind": "typeref", "name": "std::__1::string", "typedef": "string", "of": 15 }
      |  ],
      |  "inlineNamespaces": ["std::__1", "std::__1::literals", "std::__1::literals::chrono_literals"]
      |}""".stripMargin
  )
  private val types = new TypeNames(unit)

  "a type name" should {
      "spell pointers, arrays and typedefs as the CDT frontend does" in {
          types(1L) shouldBe "int*"
          types(3L) shouldBe "char[16]"
          types(7L) shouldBe "size_t"
          types(9L) shouldBe "int(int*,char*)"
      }

      "join C++ scopes with dots and drop qualifiers and references" in {
          types(4L) shouldBe "geo.Point"
          types(5L) shouldBe "geo.Point"
      }

      "leave out the inline namespaces a program names their members without" in {
          types(15L) shouldBe "std.vector<int, std.allocator<int>>"
          types(16L) shouldBe "std.hours"
          // a typedef by the name its scope gives it
          types(17L) shouldBe "std.string"
      }

      "not name a lambda's closure" in {
          types(11L) shouldBe "ANY"
      }

      "be ANY for what the document does not have" in {
          types(-1L) shouldBe "ANY"
          types(99L) shouldBe "ANY"
      }
  }

  "a type in a C++ signature" should {
      "keep the spaces of a qualified name" in {
          types.signatureType(Some(5L)) shouldBe "geo.Point &"
          types.signatureType(Some(13L)) shouldBe "geo.Point *"
      }

      "spell an integer type as the CDT frontend does" in {
          types.signatureType(Some(8L)) shouldBe "unsigned long int"
      }

      "tighten an unqualified pointer, but not a reference" in {
          types.signatureType(Some(14L)) shouldBe "char**"
          types.signatureType(Some(12L)) shouldBe "int &"
      }
  }

  "the type helpers" should {
      "follow typedefs to the type" in {
          types.isUnsignedInteger(7L) shouldBe true
          types.isPointer(1L) shouldBe true
          types.isArray(3L) shouldBe true
          types.target(3L) shouldBe Some(2L)
      }
  }
end TypeNamesTests
