package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** Every common spelling of a C++ translation unit or header is parsed, and as C++: a namespace
  * would not parse as C, so a method named through its namespace proves the dialect.
  */
class SourceFileExtensionTests extends CCodeToCpgSuite:

  private def unit(ns: String) = s"namespace $ns { int f() { return 1; } }"

  private val cpg = code(unit("cxx"), "a.cxx")
      .moreCode(unit("cplusplus"), "b.c++")
      .moreCode(unit("upper_c"), "c.C")
      .moreCode(unit("upper_cpp"), "d.CPP")
      .moreCode(unit("hxx"), "e.hxx")
      .moreCode(unit("hh"), "f.hh")
      .moreCode(unit("ipp"), "g.ipp")
      .moreCode(unit("inl"), "h.inl")
      .moreCode(unit("tcc"), "i.tcc")
      .moreCode(unit("upper_h"), "j.H")
      .moreCode("int plain_c(void) { int class = 1; return class; }", "k.c")

  "C++ sources and headers" should {
      "be parsed as C++ whatever their extension" in {
          cpg.method.nameExact("f").fullName.sorted.l shouldBe List(
            "cplusplus.f:int()",
            "cxx.f:int()",
            "hh.f:int()",
            "hxx.f:int()",
            "inl.f:int()",
            "ipp.f:int()",
            "tcc.f:int()",
            "upper_c.f:int()",
            "upper_cpp.f:int()",
            "upper_h.f:int()"
          )
      }

      "leave a .c file in C, where `class` is an ordinary identifier" in {
          cpg.method.nameExact("plain_c").local.name.l shouldBe List("class")
      }
  }

  "FileDefaults" should {
      "tell C from C++ by the case of a one-letter extension" in {
          FileDefaults.isCPPFile("src/x.C") shouldBe true
          FileDefaults.isCPPFile("src/x.c") shouldBe false
          FileDefaults.isCPPFile("src/x.H") shouldBe true
          FileDefaults.isCPPFile("src/x.h") shouldBe false
          FileDefaults.isHeaderFile("src/x.H") shouldBe true
          FileDefaults.SOURCE_FILE_EXTENSIONS should contain allOf (".c", ".C", ".cxx", ".CXX")
      }
  }
end SourceFileExtensionTests
