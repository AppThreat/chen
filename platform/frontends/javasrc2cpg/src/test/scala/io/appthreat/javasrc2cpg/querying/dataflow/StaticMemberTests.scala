package io.appthreat.javasrc2cpg.querying.dataflow

import io.appthreat.javasrc2cpg.testfixtures.JavaDataflowFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*

/** Data flow through static members, which
  * [[io.appthreat.dataflowengineoss.passes.reachingdef.StaticMemberDefUsePass]] carries between
  * methods.
  *
  * The model is mutable rather than final: a static member is a location any method may write and
  * any method may read, with no ordering between them, so a write anywhere reaches a read anywhere.
  * The cases below pin down both halves of that - what it now finds that it could not before, and
  * what it still does not claim (a member no one writes, and a definition a local write has
  * killed).
  */
class StaticMemberTests extends JavaDataflowFixture:

  behavior of "Dataflow from static members"

  override val code: String =
      """
      |class Bar {
      |    public static String bad = "MALICIOUS";
      |    public static String good = "SAFE";
      |
      |}
      |
      |public class Foo {
      |    public static String good = "MALICIOUS";
      |    public static String bad = "SAFE";
      |
      |    public void test1() {
      |        String s = Bar.bad;
      |        System.out.println(s);
      |    }
      |
      |    public void test2() {
      |        System.out.println(Bar.bad);
      |    }
      |
      |    public void test3() {
      |        System.out.println(Bar.good);
      |    }
      |
      |    public void test4() {
      |        System.out.println(Foo.good);
      |    }
      |
      |    public void test5() {
      |        System.out.println(Foo.bad);
      |    }
      |
      |    public void test6() {
      |        Bar.bad = "SAFE";
      |        System.out.println(Bar.bad);
      |    }
      |
      |    public void test7() {
      |        Bar.good = "MALICIOUS";
      |        System.out.println(Bar.good);
      |    }
      |}
      |""".stripMargin

  private def getSources =
    val sources = cpg.literal.code("\"MALICIOUS\"").l
    if sources.size <= 0 then
      fail("Could not find any sources")
    sources.iterator

  it should "find a path for `MALICIOUS` data from different class via a variable" in {
      val source = getSources
      val sink   = cpg.method(".*test1.*").call.name(".*println.*").argument(1)

      sink.reachableBy(source).size shouldBe 1
  }

  it should "find a path for `MALICIOUS` data from a different class directly" in {
      val source = getSources
      val sink   = cpg.method(".*test2.*").call.name(".*println.*").argument(1)
      sink.reachableBy(source).size shouldBe 1
  }

  /** `Bar.good` is initialised `"SAFE"`, but `test7` assigns `"MALICIOUS"` to it, and nothing
    * orders the two methods. So the flow is real for any execution that calls `test7` first - which
    * `StaticMemberDefUsePass` reports, having no basis to claim an ordering between two methods
    * anyone may call in any order from any thread. This is the one case in this file where the
    * mutable-static model and the treat-statics-as-final wishlist in the class comment disagree,
    * and the mutable reading is the sound one for taint. `test5` and `test6` below still find
    * nothing, so the model has not simply become permissive: a member no one writes stays clean,
    * and a local write still kills the definitions that precede it.
    */
  it should "find a path for `SAFE` data that another method overwrites" in {
      val source = getSources
      val sink   = cpg.method(".*test3.*").call.name(".*println.*").argument(1)
      sink.reachableBy(source).size shouldBe 1
  }

  it should "find a path for `MALICIOUS` data from the same class" in {
      val source = getSources
      val sink   = cpg.method(".*test4.*").call.name(".*println.*").argument(1)

      sink.reachableBy(source).size shouldBe 1
  }

  it should "not find a path for `SAFE` data in the same class" in {
      val source = getSources
      val sink   = cpg.method(".*test5.*").call.name(".*println.*").argument(1)

      sink.reachableBy(source).size shouldBe 0
  }

  it should "not find a path for overwritten `MALICIOUS` data" in {
      val source = getSources
      val sink   = cpg.method(".*test6.*").call.name(".*println.*").argument(1)

      sink.reachableBy(source).size shouldBe 0
  }

  it should "find a path for overwritten `SAFE` data" in {
      val source = getSources
      val sink   = cpg.method(".*test7.*").call.name(".*println.*").argument(1)

      sink.reachableBy(source).size shouldBe 1
  }
end StaticMemberTests
