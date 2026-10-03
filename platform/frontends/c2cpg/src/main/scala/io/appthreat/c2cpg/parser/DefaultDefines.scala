package io.appthreat.c2cpg.parser

object DefaultDefines:

  /** The compiler identity every GCC-compatible compiler (gcc, clang) predefines. Headers gate
    * their function attributes on it - FFmpeg's `av_malloc_attrib`/`av_alloc_size`, glibc's
    * `__attribute_malloc__` - so without it the declared memory semantics preprocess to nothing.
    * 4.9 is the oldest version every attribute the memory passes read exists in. A user `-D`
    * overrides it.
    */
  val GNU_COMPILER: Map[String, String] =
      Map("__GNUC__" -> "4", "__GNUC_MINOR__" -> "9", "__GNUC_PATCHLEVEL__" -> "0")

  /** The type sizes of the host's data model, in bytes, as GCC and Clang predefine them: what
    * `sizeof` evaluates to when neither a compiler nor a compilation database names the target.
    * Windows is LLP64 (`long` and `wchar_t` narrower); everything else 64-bit is LP64.
    */
  lazy val HOST_TYPE_SIZES: Map[String, String] =
      typeSizes(
        windows = Option(System.getProperty("os.name")).exists(_.toLowerCase.startsWith("windows")),
        pointerBytes =
            if Option(System.getProperty("sun.arch.data.model")).contains("32") then 4 else 8,
        longDoubleBytes =
            if Option(System.getProperty("os.name")).exists(_.toLowerCase.contains("mac")) &&
              Option(System.getProperty("os.arch")).contains("aarch64")
            then 8
            else 16
      )

  def typeSizes(windows: Boolean, pointerBytes: Int, longDoubleBytes: Int): Map[String, String] =
      Map(
        "__SIZEOF_BOOL__"        -> 1,
        "__SIZEOF_SHORT__"       -> 2,
        "__SIZEOF_INT__"         -> 4,
        "__SIZEOF_LONG__"        -> (if windows || pointerBytes == 4 then 4 else 8),
        "__SIZEOF_LONG_LONG__"   -> 8,
        "__SIZEOF_INT128__"      -> 16,
        "__SIZEOF_POINTER__"     -> pointerBytes,
        "__SIZEOF_SIZE_T__"      -> pointerBytes,
        "__SIZEOF_PTRDIFF_T__"   -> pointerBytes,
        "__SIZEOF_WCHAR_T__"     -> (if windows then 2 else 4),
        "__SIZEOF_FLOAT__"       -> 4,
        "__SIZEOF_DOUBLE__"      -> 8,
        "__SIZEOF_LONG_DOUBLE__" -> (if windows then 8 else longDoubleBytes)
      ).view.mapValues(_.toString).toMap
  val DEFAULT_CALL_CONVENTIONS: Map[String, String] = Map(
    "__fastcall"   -> "__attribute((fastcall))",
    "__cdecl"      -> "__attribute((cdecl))",
    "__pascal"     -> "__attribute((pascal))",
    "__vectorcall" -> "__attribute((vectorcall))",
    "__clrcall"    -> "__attribute((clrcall))",
    "__stdcall"    -> "__attribute((stdcall))",
    "__thiscall"   -> "__attribute((thiscall))",
    "__declspec"   -> "__attribute((declspec))",
    "__restrict"   -> "__attribute((restrict))",
    "__sptr"       -> "__attribute((sptr))",
    "__uptr"       -> "__attribute((uptr))",
    "__syscall"    -> "__attribute((syscall))",
    "__oldcall"    -> "__attribute((oldcall))",
    "__unaligned"  -> "__attribute((unaligned))",
    "__w64"        -> "__attribute((w64))",
    "__asm"        -> "__attribute((asm))",
    "__based"      -> "__attribute((based))",
    "__interface"  -> "__attribute((interface))",
    "__event"      -> "__attribute((event))",
    "__hook"       -> "__attribute((hook))",
    "__unhook"     -> "__attribute((unhook))",
    "__raise"      -> "__attribute((raise))",
    "__try"        -> "__attribute((try))",
    "__except"     -> "__attribute((except))",
    "__finally"    -> "__attribute((finally))",
    "__m128"       -> "__attribute((m128))",
    "__m128d"      -> "__attribute((m128d))",
    "__m128i"      -> "__attribute((m128i))",
    "__m64"        -> "__attribute((m64))"
  )
end DefaultDefines
