package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Java 25 source shapes: module imports (`import module java.base;`, JEP 511), statements before
  * the `super()` call in a constructor (JEP 513), and the instance `main` method (JEP 512). All
  * three must keep parsing, and the module import must lower to an IMPORT node the recognizers can
  * gate on, so a JavaParser change cannot break them silently.
  */
class Java25SourceTests extends JavaSrcCode2CpgFixture:

  val cpg = code(
    """
    |import module java.base;
    |
    |class Modern {
    |    private final int size;
    |
    |    Modern(int size) {
    |        if (size < 0) throw new IllegalArgumentException();
    |        super();
    |        this.size = size;
    |    }
    |
    |    void main() {
    |        java.util.List<String> xs = java.util.List.of("a");
    |        System.out.println(xs.size() + size);
    |    }
    |}
    |""".stripMargin
  )

  "the Java 25 frontend" should {

      "parse statements before super() and an instance main() method" in {
          cpg.method.name("main").l.size shouldBe 1
          // The constructor body keeps every statement, whichever order they appear in: the guard
          // throw runs before the super() call.
          cpg.method
              .name("<init>")
              .ast
              .isCall
              .methodFullName(".*IllegalArgumentException.*")
              .l should not be empty
          cpg.call.name("println").l should not be empty
      }

      "lower the module import to an import node" in {
          // The import gate consults imported entities by root; `java.base` must be visible there
          // the way an ordinary `java.util.List` import is.
          cpg.imports.importedEntity.l should contain("java.base")
      }
  }
end Java25SourceTests
