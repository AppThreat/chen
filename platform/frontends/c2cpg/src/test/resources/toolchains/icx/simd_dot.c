// A source whose Intel-specific path only compiles when the Intel LLVM compiler built the unit.
#if !defined(__INTEL_LLVM_COMPILER)
#error "this unit is compiled by icx, __INTEL_LLVM_COMPILER is not defined"
#endif

int dot(const int *a, const int *b, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) sum += a[i] * b[i];
    return sum;
}
