// em++ compiles every file as C++ for the wasm target.
#if !defined(__EMSCRIPTEN__)
#error "this unit is compiled by em++, __EMSCRIPTEN__ is not defined"
#endif

int add(int a, int b) { return a + b; }
