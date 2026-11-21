package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.semanticcpg.language.*

/** The template tags on the multi-unit template fixture: the METHOD of every template definition
  * carries `template-pattern`, every call to an instance carries `template-args` with the arguments
  * the instance was written with, and a dependent call keeps its unresolved full name while listing
  * the METHODs it reaches across the unit's instances. The fixture holds the correct look-alike
  * beside every seeded bug, and the explicit specialisation, whose call links to its own METHOD,
  * beside the instance calls.
  */
class CppTemplateTagsTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private implicit val resolver: NoResolve.type = NoResolve

  /** The fixture's templates, defined once and included by both units. */
  private val fixtureDir = better.files.File(
    java.nio.file.Paths.get(
      getClass.getClassLoader.getResource("templates/tmplbox.hpp").toURI
    ).getParent
  )

  private def sourceOf(name: String): String = (fixtureDir / name).contentAsString

  private val cpg = code(sourceOf("boxes_int.cpp"), "boxes_int.cpp")
      .moreCode(sourceOf("boxes_str.cpp"), "boxes_str.cpp")
      .moreCode(sourceOf("tmplbox.hpp"), "tmplbox.hpp")

  private def tagsOf(call: io.shiftleft.codepropertygraph.generated.nodes.Call, name: String) =
      call.tag.nameExact(name).value.l

  "the METHOD of every template definition" should {

      "carry template-pattern on the class template's members" in {
          val members = cpg.method.fullNameExact("TBox.get:ANY()").l ++
              cpg.method.fullNameExact("TBox.put:void(ANY)").l ++
              cpg.method.fullNameExact("TBox.audit:ANY()").l
          members.size shouldBe 5 // the pattern and the partial specialisation spell the same names
          members.foreach { m =>
              m.tag.nameExact(X2CpgDefines.TemplatePatternTag).value.l shouldBe List("true")
          }
      }

      "carry template-pattern on the partial specialisation's members" in {
          // TBox<T*> spells its members with the template's names: both METHODs the header parse
          // built carry the tag
          cpg.method.fullNameExact("TBox.get:ANY()").l.map(
            _.tag.nameExact(X2CpgDefines.TemplatePatternTag).value.l
          ) shouldBe List(List("true"), List("true"))
      }

      "carry template-pattern on function templates, used or not" in {
          (cpg.method.fullNameExact("tmax:ANY(ANY,ANY)") ++
              cpg.method.fullNameExact("tally:ANY(ANY,unsigned int)") ++
              cpg.method.fullNameExact("count_args:unsigned int(ANY)") ++
              cpg.method.fullNameExact("fill:void(ANY)") ++
              cpg.method.fullNameExact("fill_checked:void(ANY)") ++
              cpg.method.fullNameExact("probe:int(ANY)") ++
              cpg.method.fullNameExact("refill:void(ANY,ANY)")).l.foreach { m =>
              m.tag.nameExact(X2CpgDefines.TemplatePatternTag).value.l shouldBe List("true")
          }
      }

      "carry template-pattern on the class templates the bugs and their look-alikes live in" in {
          (cpg.method.fullNameExact("Scratch.stamp:void()") ++
              cpg.method.fullNameExact("ScratchGuarded.stamp:void()")).l.foreach { m =>
              m.tag.nameExact(X2CpgDefines.TemplatePatternTag).value.l shouldBe List("true")
          }
      }

      "leave the explicit specialisation a concrete method" in {
          val specialisation = cpg.method.fullNameExact("tmax:double(double,double)").head
          specialisation.tag.nameExact(X2CpgDefines.TemplatePatternTag).l shouldBe empty
      }

      "leave ordinary methods and functions untagged" in {
          (cpg.method.fullNameExact("Account.get:int()") ++
              cpg.method.fullNameExact("use_boxes:unsigned int()") ++
              cpg.method.fullNameExact("broken_boxes:int()") ++
              cpg.method.fullNameExact("use_str_boxes:unsigned int()") ++
              cpg.method.fullNameExact("broken_str_boxes:int()")).l.foreach { m =>
              m.tag.nameExact(X2CpgDefines.TemplatePatternTag).l shouldBe empty
          }
      }

      "leave the compiler-generated initialiser of a class template untagged" in {
          cpg.method.fullNameExact("Scratch.<clinit>").l.foreach { m =>
              m.tag.nameExact(X2CpgDefines.TemplatePatternTag).l shouldBe empty
          }
      }
  }

  "a call to a template instance" should {

      "carry template-args with the instance's arguments beside template-instance's signature" in {
          val instanceCalls = cpg.call
              .filter(c => c.tag.nameExact(X2CpgDefines.TemplateInstanceTag).value.l.nonEmpty)
              .l
          instanceCalls should not be empty
          instanceCalls.foreach { call =>
            val args = tagsOf(call, X2CpgDefines.TemplateArgsTag)
            args should have size 1
            args should not be tagsOf(call, X2CpgDefines.TemplateInstanceTag)
          }
      }

      "spell the instance's arguments for the class template used with two argument types" in {
          val puts = cpg.method.nameExact("use_boxes").call.codeExact("box.put(3)").head ::
              cpg.method.nameExact("use_str_boxes").call.codeExact("wbox.put(text)").head :: Nil
          tagsOf(puts.head, X2CpgDefines.TemplateArgsTag) shouldBe List("int")
          tagsOf(puts(1), X2CpgDefines.TemplateArgsTag) shouldBe List("Str")
          tagsOf(puts.head, X2CpgDefines.TemplateInstanceTag) shouldBe List("void(int &)")
      }

      "spell the instance's arguments for the function template used with two types" in {
          tagsOf(
            cpg.method.nameExact("use_boxes").call.codeExact("tmax(read, 2)").head,
            X2CpgDefines.TemplateArgsTag
          ) shouldBe List("int")
          tagsOf(
            cpg.method.nameExact("use_str_boxes").call.codeExact("tmax(3u, 4u)").head,
            X2CpgDefines.TemplateArgsTag
          ) shouldBe List("unsigned int")
      }

      "spell the instance's arguments for a call to the explicitly instantiated template" in {
          // `tmax(1.5, 2.5)` names the explicit specialisation, an instance of the template all the same
          val call = cpg.method.nameExact("use_boxes").call.codeExact("tmax(1.5, 2.5)").head
          call.methodFullName shouldBe "tmax:double(double,double)"
          tagsOf(call, X2CpgDefines.TemplateArgsTag) shouldBe empty
          tagsOf(call, X2CpgDefines.TemplateInstanceTag) shouldBe empty
      }

      "carry template-args on the calls of the seeded bugs and their look-alikes" in {
          tagsOf(
            cpg.method.nameExact("use_boxes").call.codeExact("fill_checked(&box)").head,
            X2CpgDefines.TemplateArgsTag
          ) shouldBe List("int")
          tagsOf(
            cpg.method.nameExact("use_str_boxes").call.codeExact("fill_checked(&wbox)").head,
            X2CpgDefines.TemplateArgsTag
          ) shouldBe List("Str")
          tagsOf(
            cpg.method.nameExact("broken_str_boxes").call.codeExact("fill(none)").head,
            X2CpgDefines.TemplateArgsTag
          ) shouldBe List("Str")
          tagsOf(
            cpg.method.nameExact("broken_boxes").call.codeExact("fill(none)").head,
            X2CpgDefines.TemplateArgsTag
          ) shouldBe List("int")
      }

      "carry no template tags on a call the front end does not resolve" in {
          val call = cpg.method.nameExact("use_boxes").call.nameExact("for_each").head
          tagsOf(call, X2CpgDefines.TemplateArgsTag) shouldBe empty
          tagsOf(call, X2CpgDefines.TemplateInstanceTag) shouldBe empty
      }
  }

  "a dependent call" should {

      "keep today's unresolved full name and list the METHODs it reaches across the unit's instances" in {
          val call = cpg.method.nameExact("probe").ast.isCall.nameExact("get").head
          call.methodFullName shouldBe "<unresolvedNamespace>.get:<unresolvedSignature>(0)"
          // probe<TBox<int>> reaches the box's get(), probe<Account> the account's
          call.dynamicTypeHintFullName.toList shouldBe List("Account.get:int()", "TBox.get:ANY()")
      }

      "list the class template's member a dependent call on an instance reaches" in {
          val puts = cpg.method.nameExact("refill").ast.isCall.nameExact("put").l
          puts.size shouldBe 2
          puts.foreach { put =>
            put.methodFullName shouldBe "<unresolvedNamespace>.put:<unresolvedSignature>(1)"
            put.dynamicTypeHintFullName.toList shouldBe List("TBox.put:void(ANY)")
          }
          val gets = cpg.method.nameExact("refill").ast.isCall.nameExact("get").l
          gets.size shouldBe 1
          gets.head.dynamicTypeHintFullName.toList shouldBe List("TBox.get:ANY()")
      }

      "keep the unresolved full name of the call in the seeded bug's body" in {
          val call = cpg.method.nameExact("fill").ast.isCall.nameExact("put").head
          call.methodFullName shouldBe "<unresolvedNamespace>.put:<unresolvedSignature>(1)"
      }
  }

  "ordinary code" should {

      /** A project with no template in it, the shape every template-free project has. */
      val plain = code("""
        |namespace bench {
        |    struct Gauge {
        |        int level;
        |        int read() const { return level; }
        |    };
        |}
        |int bump(int by) { return by + 1; }
        |int observe() {
        |    bench::Gauge g;
        |    g.level = 5;
        |    return g.read() + bump(3);
        |}
        |""".stripMargin)

      /** The look-alike: each template used once with a known type, beside an ordinary function. */
      val once = code("""
        |namespace shelf {
        |    template<typename T>
        |    struct Slot {
        |        T item;
        |        T take() const { return item; }
        |        void put(const T &v) { item = v; }
        |    };
        |}
        |template<typename T>
        |T twice(T value) { return value + value; }
        |
        |int ordinary() { return 1; }
        |
        |int run() {
        |    shelf::Slot<int> slot;
        |    slot.put(4);
        |    ordinary();
        |    return twice(slot.take()) + ordinary();
        |}
        |""".stripMargin)

      "keep a graph without any template tag or call hint when the project has no templates" in {
          plain.method.tag.name.l shouldBe empty
          plain.call.tag.name.l shouldBe empty
          plain.call.map(_.dynamicTypeHintFullName.toList).l.flatten shouldBe empty
          // the calls resolve exactly as they always did
          plain.method.nameExact("observe").call.codeExact("g.read()").methodFullName.l shouldBe List(
            "bench.Gauge.read:int()"
          )
          plain.method.nameExact("observe").call.codeExact("bump(3)").methodFullName.l shouldBe List(
            "bump:int(int)"
          )
      }

      "give a template used once only the tags of its own methods and calls" in {
          val patternMethods =
              once.method.filter(_.tag.nameExact(X2CpgDefines.TemplatePatternTag).value.l.nonEmpty)
                  .fullName.l
          patternMethods.toSet shouldBe Set(
            "shelf.Slot.take:ANY()",
            "shelf.Slot.put:void(ANY)",
            "twice:ANY(ANY)"
          )
          // the ordinary function beside them stays untagged and hint-less
          once.method.fullNameExact("ordinary:int()").tag.name.l shouldBe empty
          once.call.codeExact("ordinary()").foreach { call =>
            call.tag.name.l shouldBe empty
            call.dynamicTypeHintFullName.toList shouldBe empty
            call.methodFullName shouldBe "ordinary:int()"
          }
          // the instance calls carry the instance's arguments and nothing else changed on them
          once.call.codeExact("twice(slot.take())").foreach { call =>
            call.methodFullName shouldBe "twice:ANY(ANY)"
            tagsOf(call, X2CpgDefines.TemplateArgsTag) shouldBe List("int")
            tagsOf(call, X2CpgDefines.TemplateInstanceTag) shouldBe List("int(int)")
            call.dynamicTypeHintFullName.toList shouldBe empty
          }
          once.call.codeExact("slot.take()").foreach { call =>
            call.methodFullName shouldBe "shelf.Slot.take:ANY()"
            tagsOf(call, X2CpgDefines.TemplateArgsTag) shouldBe List("int")
          }
          once.call.codeExact("slot.put(4)").foreach { call =>
            call.methodFullName shouldBe "shelf.Slot.put:void(ANY)"
            tagsOf(call, X2CpgDefines.TemplateArgsTag) shouldBe List("int")
          }
          // and no call of the project reaches into a hint list
          once.call.map(_.dynamicTypeHintFullName.toList).l.flatten shouldBe empty
      }
  }
end CppTemplateTagsTests
