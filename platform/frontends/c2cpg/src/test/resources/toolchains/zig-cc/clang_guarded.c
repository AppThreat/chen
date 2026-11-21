// zig cc embeds clang: the clang branch of a portability guard must be the one taken.
#if !defined(__clang__)
#error "this unit is compiled by a clang driver, __clang__ is not defined"
#endif

int count_leading(unsigned v) { return v == 0 ? 32 : __builtin_clz(v); }
