package io.appthreat.c2cpg.parser

object DefaultDefines:
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
