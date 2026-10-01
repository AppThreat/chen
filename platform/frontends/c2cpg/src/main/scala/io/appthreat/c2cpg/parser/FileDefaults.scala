package io.appthreat.c2cpg.parser

/** The file name extensions c2cpg parses, and the dialect each one selects.
  *
  * Matching uses the name as stored. The one-letter extensions are case-sensitive on every
  * filesystem: `.C` and `.H` are the traditional Unix spellings of C++ files, `.c` and `.h` select
  * C. Longer extensions also match in upper case (`.CPP`, `.HPP`), as written by older Windows
  * projects.
  */
object FileDefaults:

  val C_EXT: String   = ".c"
  val CPP_EXT: String = ".cpp"

  /** Translation units compiled as C++. */
  private val CPP_SOURCE_EXTENSIONS: Set[String] =
      withUpperCase(Set(".cc", CPP_EXT, ".cxx", ".c++")) + ".C"

  /** Headers and other included fragments that only C++ code uses: inline and template
    * implementation files (`.ipp`, `.inl`, `.tcc`) are included from C++ headers.
    */
  private val CPP_HEADER_EXTENSIONS: Set[String] =
      withUpperCase(Set(".hpp", ".hh", ".hxx", ".h++", ".ipp", ".inl", ".tcc")) + ".H"

  /** C++20 module interface units. They are not parsed, but are C++ wherever they are seen. */
  private val CPP_MODULE_EXTENSIONS: Set[String] = Set(".ccm", ".cxxm", ".c++m")

  val SOURCE_FILE_EXTENSIONS: Set[String] = CPP_SOURCE_EXTENSIONS + C_EXT

  val HEADER_FILE_EXTENSIONS: Set[String] =
      CPP_HEADER_EXTENSIONS ++ Set(".h", ".i", ".h.in", ".tmh")

  private val CPP_FILE_EXTENSIONS =
      CPP_SOURCE_EXTENSIONS ++ CPP_HEADER_EXTENSIONS ++ CPP_MODULE_EXTENSIONS

  def isHeaderFile(filePath: String): Boolean =
      HEADER_FILE_EXTENSIONS.exists(filePath.endsWith)

  def isCPPFile(filePath: String): Boolean =
      CPP_FILE_EXTENSIONS.exists(filePath.endsWith)

  private def withUpperCase(extensions: Set[String]): Set[String] =
      extensions ++ extensions.map(_.toUpperCase)
end FileDefaults
