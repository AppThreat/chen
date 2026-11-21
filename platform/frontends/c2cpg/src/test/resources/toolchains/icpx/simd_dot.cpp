// The C++ form of the Intel build: icpx compiles every file as C++.
#if !defined(__INTEL_LLVM_COMPILER)
#error "this unit is compiled by icpx, __INTEL_LLVM_COMPILER is not defined"
#endif

template <typename T>
T dot(const T *a, const T *b, int n) {
    T sum = 0;
    for (int i = 0; i < n; i++) sum += a[i] * b[i];
    return sum;
}

int dot_int(const int *a, const int *b, int n) { return dot<int>(a, b, n); }
