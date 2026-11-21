// TI's Arm compiler defines its version macro and the Arm target macro together.
#if !defined(__TI_ARM__) || !defined(__TI_COMPILER_VERSION__)
#error "this unit is compiled by armcl, its identifying macros are not defined"
#endif

int ramp(int *out, int n) {
    for (int i = 0; i < n; i++) out[i] = i;
    return n;
}
