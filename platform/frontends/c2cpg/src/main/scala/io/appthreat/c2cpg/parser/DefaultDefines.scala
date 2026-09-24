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
