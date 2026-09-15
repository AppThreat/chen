package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

class ConstClosurePassTests extends DataFlowCodeToCpgSuite:

  "should return method `foo` via `cpg.method`" in {
      val cpg = code("const foo = (x,y) => { return x + y; }")

      val List(m) = cpg.method.name("foo").l
      m.name shouldBe "foo"
      m.fullName.endsWith("program:foo") shouldBe true
  }

  "should return method `export.foo` via `cpg.method`" in {
      val cpg = code("""
        |exports.foo = (function() {
        |	var count = 0;
        |	return function() {
        |		count++;
        |		return count;
        |	};
        |})();
        |
        |this.foo();
        |""".stripMargin)

      val List(m) = cpg.method.name("foo").l
      m.name shouldBe "foo"
      m.fullName.endsWith("program:foo") shouldBe true
  }

  "mutable variables assigned to closures" should {
      val cpg = code("""
        |var foo = function() {};
        |foo();
        |
        |var bar = function() {};
        |bar();
        |bar = 2;
        |""".stripMargin)

      "be treated as a constant if not reassigned in the CPG" in {
          val List(foo) = cpg.method.name("foo").l
          foo.name shouldBe "foo"
          foo.fullName.endsWith("program:foo") shouldBe true
          val List(fooCall) = cpg.call("foo").l
          fooCall.methodFullName.endsWith("program:foo") shouldBe true
      }

      "keep the identifier assigned to the anonymous name if it is reassigned later" in {
          val List(bar) = cpg.method.name("anonymous1").l
          bar.name shouldBe "anonymous1"
          bar.fullName.endsWith("program:anonymous1") shouldBe true
          val List(barCall) = cpg.call("bar").l
          barCall.methodFullName.endsWith("program:anonymous1") shouldBe true
      }
  }

  "should name the closure a Svelte {#snippet} block declares" in {
      // A snippet is emitted as an assignment of an arrow function to the snippet name, but the
      // assignment's code is the template source rather than a `const ` declaration, so the
      // const-closure branch skips it. Without the snippet-aware branch the method stays
      // `anonymous` and `{@render row(...)}` cannot resolve to it.
      val cpg = code(
        """
        |<script lang="ts">
        |let rows = ['a'];
        |</script>
        |
        |{#snippet row(item)}
        |  <li>{item}</li>
        |{/snippet}
        |
        |<ul>{@render row(rows[0])}</ul>
        |""".stripMargin,
        "s.svelte"
      )

      val List(m) = cpg.method.name("row").l
      m.name shouldBe "row"
      m.fullName should endWith(":row")
      cpg.methodRef.methodFullNameExact(m.fullName).size shouldBe 1
  }

end ConstClosurePassTests
