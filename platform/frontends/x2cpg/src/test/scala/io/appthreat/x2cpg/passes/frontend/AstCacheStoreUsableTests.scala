package io.appthreat.x2cpg.passes.frontend

import org.scalatest.BeforeAndAfterEach
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files

class AstCacheStoreUsableTests extends AnyWordSpec with Matchers with BeforeAndAfterEach:

  override def afterEach(): Unit = CacheControl.enable(CacheControl.Ast)

  private def cacheDir: String =
      Files.createTempDirectory("ast-store-usable").resolve(".chen").toString

  "AstCacheStore.isUsable" should {

      "be true when the frontend asks for the cache and it is not switched off" in {
          CacheControl.enable(CacheControl.Ast)
          new AstCacheStore(true, cacheDir, onlyAstCache = false).isUsable shouldBe true
      }

      "be false when the frontend does not ask for the cache" in {
          new AstCacheStore(false, cacheDir, onlyAstCache = false).isUsable shouldBe false
      }

      "be false when the AST cache is switched off" in {
          CacheControl.disable(CacheControl.Ast)
          new AstCacheStore(true, cacheDir, onlyAstCache = false).isUsable shouldBe false
      }
  }
end AstCacheStoreUsableTests
