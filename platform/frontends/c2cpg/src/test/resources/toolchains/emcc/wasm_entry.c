// A source that only compiles under Emscripten, whose macros stand in for the wasm runtime.
#if !defined(__EMSCRIPTEN__)
#error "this unit is compiled by emcc, __EMSCRIPTEN__ is not defined"
#endif

int add(int a, int b) { return a + b; }
