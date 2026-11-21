// zig c++ compiles every file as C++ with clang's macros.
#if !defined(__clang__) || !defined(__cplusplus)
#error "this unit is compiled by zig c++, its clang macros are not defined"
#endif

int clamp(int v, int low, int high) { return v < low ? low : (v > high ? high : v); }
