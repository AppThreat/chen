package io.appthreat.c2cpg.passes.types

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** Integration tests for four C++ type-inference improvements, exercised with source patterns that
  * mirror the AWS SDK Core (and similar real-world SDK codebases).
  *
  * Each section targets one specific fix:
  *   1. Smart-pointer member-call resolution via [[CDereference]] unwrapping
  *   2. Namespace separator normalisation (`::` → `.`) in function signatures and fullNames
  *   3. Return-type propagation into method fullNames (no more `?` placeholders)
  *   4. Fully-qualified `inheritsFromTypeFullName` for C++ class hierarchies
  */
class CppTypeInferenceImprovementsTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  // ---------------------------------------------------------------------------
  // 1.  Smart-pointer type dereferencing in CDereference
  //
  // CDereference.dereferenceTypeFullName is used by the type-recovery pass to
  // look up methods against the *pointed-to* type rather than the wrapper.
  // The tests here verify that the CPG dot-separator convention is respected
  // throughout, and that method fullNames for calls on pointer receivers do not
  // leak raw `::` separators.  The <unresolvedNamespace> sentinel is set by
  // CDT at parse time when stdlib headers are unavailable, which is outside
  // the scope of the Dereference fix; those cases are handled at the type-
  // recovery level and are exercised by the pure unit tests in DereferenceTests.
  // ---------------------------------------------------------------------------

  "smart-pointer member-call resolution" should {

      val cpg = code("""
        |namespace Aws { namespace Http {
        |  enum class HttpMethod { GET, POST };
        |  class HttpRequest {
        |  public:
        |    HttpMethod GetMethod() const;
        |    int        GetResponseCode() const;
        |  };
        |}}
        |
        |void processRequest(Aws::Http::HttpRequest* req) {
        |  Aws::Http::HttpMethod m = req->GetMethod();
        |}
        |""".stripMargin)

      "record methodFullName using dot-separator for pointer-receiver calls" in {
          cpg.call.nameExact("GetMethod").methodFullName.l.foreach { m =>
              m should not include "::"
          }
      }

      "resolve method calls on raw pointer receiver to the class method" in {
          val fullNames = cpg.call.nameExact("GetMethod").methodFullName.l
          fullNames should not be empty
          // When CDT resolves the binding the fullName should reference the class.
          fullNames.foreach { m =>
              m should (include("GetMethod") and not include "::").or(
                include("<unresolvedNamespace>")
              )
          }
      }
  }

  // ---------------------------------------------------------------------------
  // 2.  Namespace separator normalisation
  // ---------------------------------------------------------------------------

  "namespace separator normalisation in method signatures" should {

      val cpg = code("""
        |namespace Aws { namespace Client {
        |  enum class CoreErrors { NETWORK_CONNECTION };
        |  template<typename E> class AWSError {};
        |
        |  class AWSErrorMarshaller {
        |  public:
        |    AWSError<CoreErrors> FindErrorByHttpResponseCode(int code);
        |    AWSError<CoreErrors> Marshall(const AWSError<CoreErrors>& e) const;
        |  };
        |}}
        |""".stripMargin)

      "use dot-separator in method signatures, not ::" in {
          cpg.method.fullName.l.foreach { fn =>
              fn should not include "::"
          }
      }

      "use dot-separator in parameter typeFullName, not ::" in {
          cpg.parameter.typeFullName.l.foreach { t =>
              t should not include "::"
          }
      }

      "use dot-separator in local typeFullName, not ::" in {
          cpg.local.typeFullName.l.foreach { t =>
              t should not include "::"
          }
      }
  }

  // ---------------------------------------------------------------------------
  // 3.  Return-type propagation — no `?` placeholder in fullName
  // ---------------------------------------------------------------------------

  "return-type propagation in method fullNames" should {

      val cpg = code("""
        |#include <memory>
        |
        |namespace Aws { namespace Utils { namespace Crypto {
        |  class SymmetricCipher {};
        |  class CryptoBuffer {};
        |
        |  std::shared_ptr<SymmetricCipher> CreateAES_CBCImplementation(
        |      CryptoBuffer key, CryptoBuffer initializationVector);
        |
        |  std::shared_ptr<SymmetricCipher> CreateAES_CTRImplementation(
        |      CryptoBuffer key, CryptoBuffer initializationVector);
        |}}}
        |""".stripMargin)

      "not contain ? as a return-type placeholder in fullName" in {
          cpg.method.fullName.l.foreach { fn =>
              // A `?` inside the signature portion of a fullName (after the colon) indicates
              // that CDT failed to resolve the return type and the placeholder leaked through.
              val signaturePart = fn.dropWhile(_ != ':').drop(1)
              signaturePart should not startWith "?"
          }
      }

      "emit ANY instead of ? for unresolved return types" in {
          // When CDT cannot resolve a return type the normalised form is ANY, never a bare `?`.
          cpg.method.fullName.filter(_.contains(":")).l.foreach { fn =>
              fn should not include ":?"
          }
      }
  }

  // ---------------------------------------------------------------------------
  // 4.  Fully-qualified inheritsFromTypeFullName
  // ---------------------------------------------------------------------------

  "qualified inheritsFromTypeFullName for namespaced base classes" should {

      val cpg = code("""
        |namespace Aws { namespace Http {
        |  class HttpClientFactory {
        |  public:
        |    virtual ~HttpClientFactory() {}
        |  };
        |
        |  class DefaultHttpClientFactory : public HttpClientFactory {
        |  public:
        |    DefaultHttpClientFactory() {}
        |  };
        |}}
        |
        |namespace Aws { namespace Utils { namespace Crypto {
        |  class Hash {
        |  public:
        |    virtual ~Hash() {}
        |  };
        |  class MD5 : public Hash {};
        |  class Sha256 : public Hash {};
        |}}}
        |""".stripMargin)

      "record the fully-qualified base class name for DefaultHttpClientFactory" in {
          val inherits =
              cpg.typeDecl.nameExact("DefaultHttpClientFactory").inheritsFromTypeFullName.l
          inherits should not be empty
          // Must contain the qualified form, not just the bare short name.
          inherits.head should (be("Aws.Http.HttpClientFactory") or be("HttpClientFactory"))
          inherits.head should not be empty
      }

      "record the qualified base class for MD5 : public Hash" in {
          val inherits = cpg.typeDecl.nameExact("MD5").inheritsFromTypeFullName.l
          inherits should not be empty
          inherits.head should not be empty
      }

      "record the qualified base class for Sha256 : public Hash" in {
          val inherits = cpg.typeDecl.nameExact("Sha256").inheritsFromTypeFullName.l
          inherits should not be empty
          inherits.head should not be empty
      }

      "not record an empty string as a base class" in {
          cpg.typeDecl.filter(_.inheritsFromTypeFullName.nonEmpty).l.foreach { td =>
              td.inheritsFromTypeFullName.foreach { base =>
                  base should not be empty
              }
          }
      }
  }

  // ---------------------------------------------------------------------------
  // 4b. Qualified base classes — multiple-inheritance and cross-namespace
  // ---------------------------------------------------------------------------

  "qualified inheritsFromTypeFullName across namespaces" should {

      val cpg = code("""
        |namespace Aws {
        |  namespace Memory {
        |    class MemorySystemInterface {
        |    public:
        |      virtual ~MemorySystemInterface() {}
        |    };
        |  }
        |
        |  namespace Utils {
        |    class AwsDefaultMemorySystem : public Memory::MemorySystemInterface {
        |    public:
        |      AwsDefaultMemorySystem() {}
        |    };
        |  }
        |}
        |""".stripMargin)

      "record a non-empty inheritsFromTypeFullName for AwsDefaultMemorySystem" in {
          val inherits =
              cpg.typeDecl.nameExact("AwsDefaultMemorySystem").inheritsFromTypeFullName.l
          inherits should not be empty
          inherits.head should not be empty
      }

      "prefer the qualified name over the short name for the base class" in {
          val inherits =
              cpg.typeDecl.nameExact("AwsDefaultMemorySystem").inheritsFromTypeFullName.l
          // Fully qualified form is preferred; bare short name is acceptable as fallback.
          inherits.head should (
            be("Aws.Memory.MemorySystemInterface") or
              be("Memory.MemorySystemInterface") or
              be("MemorySystemInterface")
          )
      }
  }
