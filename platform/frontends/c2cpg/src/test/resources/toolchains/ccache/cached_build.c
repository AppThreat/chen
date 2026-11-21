// The build runs the compiler behind ccache; the command line names the wrapper, the unit is
// still compiled by GCC (or the clang the wrapper is given).
#if !defined(__GNUC__)
#error "this unit is compiled by a gcc-family driver behind ccache, __GNUC__ is not defined"
#endif

int add(int a, int b) { return a + b; }
