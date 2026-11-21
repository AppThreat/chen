// A CUDA source: the host compilation is C++ with nvcc's own macros added, so code that
// checks for nvcc takes its branch and the unit preprocesses.
#if !defined(__CUDACC__)
#error "this unit is compiled by nvcc, __CUDACC__ is not defined"
#endif

extern "C" int scalar(int a, int b) { return a + b; }
